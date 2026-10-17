"""Every database write this service makes, in one place.

The rules enforced here are the ones `DATABASE_AND_API_CONTRACTS.md` A1 and A3
state, and they are enforced **inside one transaction**:

* one serialized writer per run: the stream head is locked `FOR UPDATE` in the
  same transaction that commits the event (`R-DAT-03`);
* the event row, the head update, the idempotency row and the outbox row commit
  atomically (`R-DAT-04`);
* a stale fencing token cannot commit (`R-RUN-03`);
* nothing follows `RUN_FINISHED` (`PROTOCOL.md` 5.3);
* the sequence is assigned by the server, never by the producer.

Only parameterized SQL is used. Nothing here logs an event payload.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .canonical import CanonicalEvent, Canonicalizer
from .errors import AbbError


def now_ms() -> int:
    """A local clock reading. A **claim**, never evidence (`PROTOCOL.md` 10.4)."""
    return int(time.time() * 1000)


@dataclass(frozen=True)
class Principal:
    """Who is calling, resolved from the bearer token."""

    user_id: str
    role: str
    scope_run_id: str | None

    def may_reach_run(self, run_id: str) -> bool:
        return self.scope_run_id is None or self.scope_run_id == run_id


@dataclass(frozen=True)
class CommittedEvent:
    """The result of a successful ingest."""

    event: CanonicalEvent
    replayed: bool


class Repository:
    """Data access for the control plane and the ingestion module."""

    def __init__(self, connect: Any, canonicalizer: Canonicalizer) -> None:
        self._connect = connect
        self._canonicalizer = canonicalizer

    # ------------------------------------------------------------------ auth

    def principal_for_token(self, token: str) -> Principal | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).digest()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.user_id, u.role, t.scope_run_id
                FROM api_tokens t
                JOIN users u ON u.user_id = t.user_id
                WHERE t.token_hash = %s
                  AND t.revoked = false
                  AND u.disabled = false
                  AND t.expires_at_ms > %s
                """,
                (token_hash, now_ms()),
            ).fetchone()
        if row is None:
            return None
        return Principal(
            user_id=str(row[0]),
            role=row[1],
            scope_run_id=str(row[2]) if row[2] is not None else None,
        )

    # ------------------------------------------------------------------ runs

    def create_run(
        self,
        *,
        task: str,
        adapter: str,
        profile: str,
        requested_coverage: str,
        policy_id: str,
        policy_version: int,
        mandate_id: str | None,
        created_by: str,
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        created_at = now_ms()
        # The task text itself is not stored in the ledger; its digest is.
        task_digest = hashlib.sha256(task.encode("utf-8")).digest()
        mode = "REPLAY" if adapter == "replay" else "LIVE_LOCAL"
        with self._connect() as conn:
            with conn.transaction():
                try:
                    conn.execute(
                        """
                        INSERT INTO runs (run_id, task_digest, adapter_name, adapter_version,
                                          mode, profile, requested_coverage, policy_id,
                                          policy_version, mandate_id, state, created_by,
                                          created_at_ms)
                        VALUES (%s, %s, %s, '0.1.0', %s, %s, %s, %s, %s, %s, 'PENDING', %s, %s)
                        """,
                        (
                            run_id,
                            task_digest,
                            adapter,
                            mode,
                            profile,
                            requested_coverage,
                            policy_id,
                            policy_version,
                            mandate_id,
                            created_by,
                            created_at,
                        ),
                    )
                except Exception as exc:
                    raise self._map_integrity_error(exc) from exc
                conn.execute(
                    """INSERT INTO event_stream_heads (run_id, next_sequence, fencing_token)
                       VALUES (%s, 0, 0)""",
                    (run_id,),
                )
        return {
            "run_id": run_id,
            "state": "PENDING",
            "declared_coverage": None,
            "created_at": created_at,
        }

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT run_id, state, declared_coverage, requested_coverage, adapter_name,
                          profile, policy_id, policy_version, created_at_ms, mandate_id
                   FROM runs WHERE run_id = %s""",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "run_id": str(row[0]),
            "state": row[1],
            "declared_coverage": row[2],
            "requested_coverage": row[3],
            "adapter": row[4],
            "profile": row[5],
            "policy_id": row[6],
            "policy_version": row[7],
            "created_at": row[8],
            "mandate_id": row[9],
        }

    def run_exists(self, run_id: str) -> bool:
        with self._connect() as conn:
            return (
                conn.execute("SELECT 1 FROM runs WHERE run_id = %s", (run_id,)).fetchone()
                is not None
            )

    # ------------------------------------------------------------- ingestion

    def ingest_event(
        self,
        *,
        run_id: str,
        body: bytes,
        idempotency_key: str | None,
        fencing_token: int | None,
        redact: dict[str, list[str]] | None = None,
    ) -> CommittedEvent:
        """Commit one proposed event, or return the one already committed.

        `redact` maps an event type to payload fields that are committed to
        instead of stored (`D-11`): the clear value and its salt go to
        `field_disclosures` in the same transaction, and only the commitment
        reaches the ledger.
        """
        with self._connect() as conn:
            with conn.transaction():
                head = conn.execute(
                    """SELECT next_sequence, fencing_token, finished
                       FROM event_stream_heads WHERE run_id = %s FOR UPDATE""",
                    (run_id,),
                ).fetchone()
                if head is None:
                    raise AbbError("NOT_FOUND", "unknown run")
                next_sequence, current_token, finished = head[0], head[1], head[2]

                # Idempotency first: a replay must not be judged by the fencing
                # token or the finished flag, because it changes nothing.
                if idempotency_key is not None:
                    existing = conn.execute(
                        """SELECT e.event_id, e.sequence, e.event_type, e.canonical_bytes,
                                  e.leaf_hash, e.source, e.created_at_ms
                           FROM event_idempotency i
                           JOIN events e ON e.event_id = i.event_id
                           WHERE i.run_id = %s AND i.idempotency_key = %s""",
                        (run_id, idempotency_key),
                    ).fetchone()
                    if existing is not None:
                        return CommittedEvent(
                            event=CanonicalEvent(
                                canonical_bytes=bytes(existing[3]),
                                leaf_hash=bytes(existing[4]),
                                run_id=run_id,
                                event_id=str(existing[0]),
                                sequence=existing[1],
                                event_type=existing[2],
                                source=existing[5],
                                created_at=existing[6],
                                idempotency_key=idempotency_key,
                            ),
                            replayed=True,
                        )

                if fencing_token is not None and fencing_token < current_token:
                    raise AbbError(
                        "STALE_FENCING_TOKEN",
                        f"lease moved on; this worker holds {fencing_token}",
                    )
                if finished:
                    raise AbbError("RUN_FINISHED", "the run accepted its last event")

                # The core assigns nothing: the server does, then the core
                # validates and produces the bytes that get stored and signed.
                event_id = str(uuid.uuid4())
                disclosures: list[tuple[str, bytes, bytes]] = []
                if redact:
                    body, disclosures = self._redact(body, redact)
                event = self._canonicalizer.assign_and_validate(
                    body,
                    run_id=run_id,
                    event_id=event_id,
                    sequence=next_sequence,
                    created_at=now_ms(),
                )

                conn.execute(
                    """INSERT INTO events (run_id, sequence, event_id, event_type,
                                           canonical_bytes, leaf_hash, source, created_at_ms)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        run_id,
                        event.sequence,
                        event.event_id,
                        event.event_type,
                        event.canonical_bytes,
                        event.leaf_hash,
                        event.source,
                        event.created_at,
                    ),
                )
                conn.execute(
                    """UPDATE event_stream_heads
                       SET next_sequence = %s, finished = %s, fencing_token = GREATEST(%s, %s)
                       WHERE run_id = %s""",
                    (
                        event.sequence + 1,
                        event.event_type == "RUN_FINISHED",
                        current_token,
                        fencing_token if fencing_token is not None else current_token,
                        run_id,
                    ),
                )
                if event.idempotency_key is not None or idempotency_key is not None:
                    conn.execute(
                        """INSERT INTO event_idempotency (run_id, idempotency_key, event_id)
                           VALUES (%s, %s, %s)""",
                        (
                            run_id,
                            idempotency_key or event.idempotency_key,
                            event.event_id,
                        ),
                    )
                for field_name, salt, value_json in disclosures:
                    conn.execute(
                        """INSERT INTO field_disclosures (event_id, field, salt, value_json)
                           VALUES (%s, %s, %s, %s)""",
                        (event.event_id, field_name, salt, value_json),
                    )
                # Only committed events are published, so the outbox row is part
                # of the same transaction (DESIGN.md 9).
                conn.execute(
                    """INSERT INTO workflow_outbox (run_id, event_id, topic)
                       VALUES (%s, %s, 'sse')""",
                    (run_id, event.event_id),
                )
        return CommittedEvent(event=event, replayed=False)

    def _redact(
        self, body: bytes, rules: dict[str, list[str]]
    ) -> tuple[bytes, list[tuple[str, bytes, bytes]]]:
        """Swap each redacted payload field for a salted commitment.

        Runs before the core canonicalizes, so the clear value never reaches
        the bytes that get hashed and signed. Only reached when the event's type
        has a rule; every other event passes through untouched.
        """

        def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
            if len({k for k, _ in items}) != len(items):
                raise AbbError("DUPLICATE_KEY", "an object has a repeated key")
            return dict(items)

        def refuse_float(_: str) -> Any:
            raise AbbError("FLOAT_NOT_ALLOWED", "protocol numbers are integers")

        try:
            event = json.loads(body, object_pairs_hook=pairs, parse_float=refuse_float)
        except ValueError as exc:
            raise AbbError("SYNTAX_ERROR", "the event body is not JSON") from exc
        if not isinstance(event, dict) or not isinstance(event.get("payload"), dict):
            # The core will say exactly what is wrong; nothing to redact here.
            return body, []
        fields = rules.get(str(event.get("event_type")), [])
        payload = event["payload"]
        disclosures: list[tuple[str, bytes, bytes]] = []
        for name in fields:
            if name not in payload:
                continue
            value_json = json.dumps(
                payload.pop(name), ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
            salt_hex, commitment = self._canonicalizer.commit(value_json)
            event.setdefault("commitments", {})[name] = commitment
            disclosures.append((name, bytes.fromhex(salt_hex), value_json))
        if not disclosures:
            return body, []
        return json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode(), disclosures

    # ----------------------------------------------------- approvals, mandates

    def store_signed_approval(
        self,
        *,
        run_id: str,
        approval_id: str,
        action_id: str,
        decision: str,
        statement: bytes,
        approver_key_id: str,
        signature: str,
        event_id: str,
    ) -> None:
        """Keep the approver's own signed statement (idempotent)."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO signed_approvals (run_id, approval_id, action_id, decision,
                                                 statement, approver_key_id, signature,
                                                 event_id, created_at_ms)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (run_id, approval_id) DO NOTHING""",
                (
                    run_id,
                    approval_id,
                    action_id,
                    decision,
                    statement,
                    approver_key_id,
                    signature,
                    event_id,
                    now_ms(),
                ),
            )

    def signed_approvals(self, run_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT approval_id, statement, approver_key_id, signature
                   FROM signed_approvals WHERE run_id = %s ORDER BY created_at_ms, approval_id""",
                (run_id,),
            ).fetchall()
        return [
            {
                "approval_id": row[0],
                "statement": bytes(row[1]),
                "key_id": row[2],
                "signature": row[3],
            }
            for row in rows
        ]

    def ensure_key(self, entry: dict[str, Any]) -> None:
        """Register a key from the verified manifest so a mandate can reference it."""
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO key_manifest (key_id, public_key, role, failure_domain,
                                             valid_from_ms, status)
                   VALUES (%s, %s, %s, %s, %s, %s)
                   ON CONFLICT (key_id) DO NOTHING""",
                (
                    entry["key_id"],
                    bytes.fromhex(entry["public_key_hex"]),
                    entry["role"],
                    entry.get("failure_domain"),
                    int(entry["valid_from"]),
                    entry["status"],
                ),
            )

    def store_mandate(
        self, *, mandate_id: str, document: bytes, signature: str, issuer_key_id: str
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO mandates (mandate_id, mandate_bytes, signature, issuer_key_id)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (mandate_id) DO NOTHING""",
                (mandate_id, document, bytes.fromhex(signature), issuer_key_id),
            )

    def mandate_of(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT m.mandate_bytes, m.signature
                   FROM runs r JOIN mandates m ON m.mandate_id = r.mandate_id
                   WHERE r.run_id = %s""",
                (run_id,),
            ).fetchone()
        if row is None:
            return None
        return {"document": bytes(row[0]), "signature": bytes(row[1]).hex()}

    def disclosures_for(self, run_id: str) -> list[dict[str, Any]]:
        """Salts and clear values still held for this run's committed fields.

        A row whose salt was shredded is simply absent, which is the point:
        the commitment in the ledger stays valid, the value is gone.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT d.event_id, d.field, d.salt, d.value_json
                   FROM field_disclosures d JOIN events e ON e.event_id = d.event_id
                   WHERE e.run_id = %s AND d.salt IS NOT NULL AND d.value_json IS NOT NULL
                   ORDER BY e.sequence, d.field""",
                (run_id,),
            ).fetchall()
        return [
            {
                "event_id": str(row[0]),
                "field": row[1],
                "salt_hex": bytes(row[2]).hex(),
                "value_json": bytes(row[3]).decode("utf-8"),
            }
            for row in rows
        ]

    def shred_field(self, event_id: str, field_name: str) -> bool:
        """Crypto-shred one committed field (`R-CMT-03`): drop salt and value.

        Touches `field_disclosures` only. The ledger row, its hash and every
        signature are untouched, and the commitment stays valid in the tree.
        """
        with self._connect() as conn:
            done = conn.execute(
                """UPDATE field_disclosures SET salt = NULL, value_json = NULL
                   WHERE event_id = %s AND field = %s""",
                (event_id, field_name),
            )
            return bool(done.rowcount)

    # ----------------------------------------------------------------- reads

    def list_events(self, run_id: str, *, after: int | None, limit: int) -> list[dict[str, Any]]:
        """Committed events only, in sequence order."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT sequence, event_id, event_type, canonical_bytes, leaf_hash,
                          source, created_at_ms
                   FROM events
                   WHERE run_id = %s AND (%s::bigint IS NULL OR sequence > %s::bigint)
                   ORDER BY sequence
                   LIMIT %s""",
                (run_id, after, after, limit),
            ).fetchall()
        return [
            {
                "sequence": row[0],
                "event_id": str(row[1]),
                "event_type": row[2],
                # The canonical bytes are UTF-8 JSON; send them verbatim so a
                # client can hash what it reads.
                "canonical": bytes(row[3]).decode("utf-8"),
                "leaf_hash": bytes(row[4]).hex(),
                "source": row[5],
                "created_at": row[6],
            }
            for row in rows
        ]

    # ------------------------------------------------- finalization and export

    #: The happy path of `PROTOCOL.md` section 6. `advance_to` walks it one
    #: legal step at a time, so every transition is recorded and the database
    #: trigger can check each one.
    HAPPY_PATH = (
        "PENDING",
        "POLICY_CHECKED",
        "DISPATCHED",
        "OBSERVING",
        "ANALYZING",
        "FINALIZING",
        "CHECKPOINTED",
        "EXPORTED",
    )

    def set_state(self, run_id: str, target: str) -> None:
        """Advance a run to `target` along the legal path, recording each step.

        Going straight from `PENDING` to `EXPORTED` is not allowed by the
        protocol, and the database refuses it, so this walks the states rather
        than pretending.
        """
        current = self.get_run(run_id)
        if current is None:
            raise AbbError("NOT_FOUND", "unknown run")
        state = str(current["state"])
        if state == target:
            return
        path = self.HAPPY_PATH
        if state not in path or target not in path:
            raise AbbError("ILLEGAL_TRANSITION", f"{state} -> {target} is not on the happy path")
        start, end = path.index(state), path.index(target)
        if end <= start:
            raise AbbError("ILLEGAL_TRANSITION", f"{state} -> {target} would go backwards")
        for step in range(start, end):
            self.record_state_transition(run_id, path[step], path[step + 1])

    def canonical_events(self, run_id: str) -> list[bytes]:
        """Every committed event's exact canonical bytes, in sequence order."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT canonical_bytes FROM events WHERE run_id = %s ORDER BY sequence",
                (run_id,),
            ).fetchall()
        return [bytes(row[0]) for row in rows]

    def policy_of(self, run_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """SELECT r.policy_id, r.policy_version, p.body_digest
                   FROM runs r
                   JOIN policy_versions p
                     ON p.policy_id = r.policy_id AND p.version = r.policy_version
                   WHERE r.run_id = %s""",
                (run_id,),
            ).fetchone()
        if row is None:
            raise AbbError("NOT_FOUND", "unknown run or policy version")
        return {
            "policy_id": row[0],
            "policy_version": int(row[1]),
            "body_digest": bytes(row[2]).hex(),
        }

    def store_checkpoint(self, *, stream_id: str, checkpoint: Any) -> None:
        """Store a checkpoint exactly as the signer returned it.

        `payload_bytes` are the bytes the signature covers; they are never
        rebuilt from the parsed payload (`R-PRO-04`).
        """
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO checkpoints (stream_id, tree_size, checkpoint_bytes,
                                            checkpoint_hash, signature, key_id, created_at_ms)
                   VALUES (%s, %s, %s, %s, %s, %s, %s)
                   ON CONFLICT (stream_id, tree_size) DO NOTHING""",
                (
                    stream_id,
                    checkpoint.tree_size,
                    checkpoint.payload_bytes,
                    bytes.fromhex(checkpoint.checkpoint_hash),
                    bytes.fromhex(checkpoint.signature),
                    str(checkpoint.payload["key_id"]),
                    int(checkpoint.payload["created_at"]),
                ),
            )

    def checkpoints(self, stream_id: str) -> list[dict[str, Any]]:
        """The checkpoint chain for a stream, oldest first."""
        import json

        with self._connect() as conn:
            rows = conn.execute(
                """SELECT checkpoint_bytes, signature, tree_size
                   FROM checkpoints WHERE stream_id = %s ORDER BY tree_size""",
                (stream_id,),
            ).fetchall()
        return [
            {
                "payload_bytes": bytes(row[0]),
                "payload": json.loads(bytes(row[0]).decode("utf-8")),
                "signature": bytes(row[1]).hex(),
                "tree_size": int(row[2]),
            }
            for row in rows
        ]

    def latest_checkpoint(self, stream_id: str) -> dict[str, Any] | None:
        """The last checkpoint, shaped for the signer's `prev_checkpoint`."""
        chain = self.checkpoints(stream_id)
        if not chain:
            return None
        last = chain[-1]
        return {"payload": last["payload"], "signature": last["signature"]}

    def append_global_log(self, *, run_id: str, record: bytes) -> int:
        """Append a run root to the global log, returning its position.

        Idempotent: a run already in the log keeps its position, so a retry
        after a crash does not create a second leaf (`R-GLB-01`). The leaf hash
        comes from the Rust core, never from Python.
        """
        leaf = self._canonicalizer.leaf_hash("ABB1-RUNROOT", record)
        with self._connect() as conn:
            with conn.transaction():
                existing = conn.execute(
                    "SELECT position FROM global_log WHERE run_id = %s FOR UPDATE",
                    (run_id,),
                ).fetchone()
                if existing is not None:
                    return int(existing[0])
                row = conn.execute(
                    "SELECT coalesce(max(position) + 1, 0) FROM global_log"
                ).fetchone()
                position = 0 if row is None else int(row[0])
                conn.execute(
                    """INSERT INTO global_log (position, run_id, record_bytes, leaf_hash)
                       VALUES (%s, %s, %s, %s)""",
                    (position, run_id, record, leaf),
                )
        return position

    # ------------------------------------------------------ artifact manifest

    def add_manifest_entry(
        self,
        *,
        run_id: str,
        event_id: str,
        digest: str,
        media_type: str,
        size: int,
        capture_method: str,
    ) -> int:
        """Append a hash-linked manifest entry and return its index (`R-ART-03`).

        The entry is canonicalized and hashed by the Rust core. The run's stream
        head is locked first, so two captures cannot take the same index.
        """
        zero = "0" * 64
        with self._connect() as conn:
            with conn.transaction():
                conn.execute(
                    "SELECT 1 FROM event_stream_heads WHERE run_id = %s FOR UPDATE", (run_id,)
                )
                last = conn.execute(
                    """SELECT idx, entry_hash FROM manifest_entries
                       WHERE run_id = %s ORDER BY idx DESC LIMIT 1""",
                    (run_id,),
                ).fetchone()
                index = 0 if last is None else int(last[0]) + 1
                prev = zero if last is None else bytes(last[1]).hex()
                captured_at = now_ms()
                entry = self._canonicalizer.canonical_json(
                    {
                        "index": index,
                        "run_id": run_id,
                        "event_id": event_id,
                        "artifact_digest": digest,
                        "media_type": media_type,
                        "size": size,
                        "capture_method": capture_method,
                        "captured_at": captured_at,
                        "prev_manifest_hash": prev,
                    }
                )
                entry_hash = self._canonicalizer.tagged_digest("ABB1-MANIFEST", entry)
                conn.execute(
                    """INSERT INTO artifacts (artifact_digest, media_type, size_bytes,
                                              object_key, status, created_at_ms)
                       VALUES (%s, %s, %s, %s, 'AVAILABLE', %s)
                       ON CONFLICT (artifact_digest) DO NOTHING""",
                    (bytes.fromhex(digest), media_type, size, digest, captured_at),
                )
                conn.execute(
                    """INSERT INTO manifest_entries (run_id, idx, event_id, artifact_digest,
                                                     capture_method, captured_at_ms, entry_bytes,
                                                     entry_hash, prev_manifest_hash)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                    (
                        run_id,
                        index,
                        event_id,
                        bytes.fromhex(digest),
                        capture_method,
                        captured_at,
                        entry,
                        entry_hash,
                        bytes.fromhex(prev),
                    ),
                )
        return index

    def manifest_entry_bytes(self, run_id: str) -> list[bytes]:
        """The exact canonical bytes of each manifest entry, in index order."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT entry_bytes FROM manifest_entries WHERE run_id = %s ORDER BY idx",
                (run_id,),
            ).fetchall()
        return [bytes(row[0]) for row in rows]

    def manifest_digests(self, run_id: str) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT artifact_digest FROM manifest_entries WHERE run_id = %s ORDER BY idx",
                (run_id,),
            ).fetchall()
        return [bytes(row[0]).hex() for row in rows]

    def global_records(self) -> list[bytes]:
        """Every run-root record, in global position order."""
        with self._connect() as conn:
            rows = conn.execute("SELECT record_bytes FROM global_log ORDER BY position").fetchall()
        return [bytes(row[0]) for row in rows]

    def global_position(self, run_id: str) -> int | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT position FROM global_log WHERE run_id = %s", (run_id,)
            ).fetchone()
        return None if row is None else int(row[0])

    def record_state_transition(
        self, run_id: str, from_state: str, to_state: str, reason: str | None = None
    ) -> None:
        with self._connect() as conn:
            with conn.transaction():
                seq = conn.execute(
                    "SELECT coalesce(max(seq), 0) + 1 FROM run_state_transitions WHERE run_id = %s",
                    (run_id,),
                ).fetchone()[0]
                try:
                    conn.execute(
                        """INSERT INTO run_state_transitions (run_id, seq, from_state, to_state,
                                                              reason, at_ms)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (run_id, seq, from_state, to_state, reason, now_ms()),
                    )
                except Exception as exc:
                    raise self._map_integrity_error(exc) from exc
                conn.execute("UPDATE runs SET state = %s WHERE run_id = %s", (to_state, run_id))

    # ------------------------------------------------------------- internals

    @staticmethod
    def _map_integrity_error(exc: Exception) -> AbbError:
        """Turn a database error into a stable code, without leaking SQL."""
        text = str(exc)
        if "ILLEGAL_TRANSITION" in text:
            return AbbError("ILLEGAL_TRANSITION", "that run-state transition is not allowed")
        if "RUN_FINISHED" in text:
            return AbbError("RUN_FINISHED", "the run accepted its last event")
        if "EVENTS_ARE_APPEND_ONLY" in text:
            return AbbError("FORBIDDEN", "committed events cannot be changed")
        name = type(exc).__name__
        if name in {"UniqueViolation", "IntegrityError"}:
            return AbbError("SEQUENCE_CONFLICT", "that row already exists")
        if name in {
            "ForeignKeyViolation",
        }:
            return AbbError("VALIDATION_FAILED", "a referenced row does not exist")
        if name in {"OperationalError", "InterfaceError"}:
            return AbbError("DEPENDENCY_UNAVAILABLE", "the database is not reachable")
        return AbbError("INTERNAL", "unexpected database error")
