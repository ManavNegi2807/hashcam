"""Database-level contract tests (`DATABASE_AND_API_CONTRACTS.md` A3, A5).

These run against a real PostgreSQL because the things under test are triggers,
`FOR UPDATE` serialization and transaction atomicity. Covers R-DAT-02, R-DAT-03,
R-DAT-04, R-DAT-06, R-RUN-03, R-TST-02 and the `ILLEGAL_TRANSITION`,
`RUN_FINISHED` and `STALE_FENCING_TOKEN` paths of `ERROR_HANDLING.md` 4.1.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

EXPECTED_TABLES = {
    "runs",
    "run_state_transitions",
    "event_stream_heads",
    "events",
    "event_idempotency",
    "artifacts",
    "policy_versions",
    "assessments",
    "checkpoints",
    "witness_signatures",
    "anchor_publications",
    "workflow_outbox",
    "global_log",
    "field_disclosures",
    "key_manifest",
    "mandates",
    "approvals",
    "users",
    "api_tokens",
    "audit_log",
    "manifest_entries",
}


def one(result: Any) -> tuple[Any, ...]:
    """`fetchone()` narrowed: a query that must return a row, and did."""
    row = result.fetchone()
    assert row is not None, "expected exactly one row"
    return tuple(row)


def insert_event(conn, run_id: str, sequence: int, event_type: str = "ACTION_REQUESTED") -> str:  # noqa: ANN001
    event_id = str(uuid.uuid4())
    canonical = f'{{"sequence":{sequence}}}'.encode()
    conn.execute(
        """
        INSERT INTO events (run_id, sequence, event_id, event_type, canonical_bytes,
                            leaf_hash, source, created_at_ms)
        VALUES (%s, %s, %s, %s, %s, %s, 'reported_by_adapter', 1760000000000)
        """,
        (run_id, sequence, event_id, event_type, canonical, hashlib.sha256(canonical).digest()),
    )
    return event_id


def test_every_contracted_table_exists(conn) -> None:  # noqa: ANN001
    """R-DAT-02: the logical tables of the contract are all present."""
    rows = conn.execute(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    ).fetchall()
    present = {row[0] for row in rows}
    missing = sorted(EXPECTED_TABLES - present)
    assert missing == [], f"missing tables: {missing}"


def test_events_reject_update_and_delete(conn, seeded) -> None:  # noqa: ANN001
    """Committed events are append-only (A3). This does not stop a superuser."""
    import psycopg

    run_id = seeded["run_id"]
    insert_event(conn, run_id, 0)

    with pytest.raises(psycopg.errors.CheckViolation) as err:
        conn.execute("UPDATE events SET event_type = 'ACTION_BLOCKED' WHERE run_id = %s", (run_id,))
    assert "EVENTS_ARE_APPEND_ONLY" in str(err.value)

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("DELETE FROM events WHERE run_id = %s", (run_id,))

    assert one(conn.execute("SELECT count(*) FROM events"))[0] == 1


def test_duplicate_sequence_is_refused(conn, seeded) -> None:  # noqa: ANN001
    import psycopg

    run_id = seeded["run_id"]
    insert_event(conn, run_id, 0)
    with pytest.raises(psycopg.errors.UniqueViolation):
        insert_event(conn, run_id, 0)


def test_no_event_after_run_finished(conn, seeded) -> None:  # noqa: ANN001
    import psycopg

    run_id = seeded["run_id"]
    insert_event(conn, run_id, 0, "RUN_FINISHED")
    conn.execute("UPDATE event_stream_heads SET finished = true WHERE run_id = %s", (run_id,))
    with pytest.raises(psycopg.errors.CheckViolation) as err:
        insert_event(conn, run_id, 1)
    assert "RUN_FINISHED" in str(err.value)


def test_illegal_run_state_transition_is_refused(conn, seeded) -> None:  # noqa: ANN001
    import psycopg

    run_id = seeded["run_id"]
    # Legal: PENDING -> POLICY_CHECKED
    conn.execute(
        """INSERT INTO run_state_transitions (run_id, seq, from_state, to_state, at_ms)
           VALUES (%s, 1, 'PENDING', 'POLICY_CHECKED', 1760000000000)""",
        (run_id,),
    )
    # Illegal: PENDING -> EXPORTED (PROTOCOL.md section 6)
    with pytest.raises(psycopg.errors.CheckViolation) as err:
        conn.execute(
            """INSERT INTO run_state_transitions (run_id, seq, from_state, to_state, at_ms)
               VALUES (%s, 2, 'PENDING', 'EXPORTED', 1760000000000)""",
            (run_id,),
        )
    assert "ILLEGAL_TRANSITION" in str(err.value)


def test_terminal_states_have_no_outgoing_transitions(conn) -> None:  # noqa: ANN001
    """FAILED, CANCELLED, POLICY_BLOCKED and EXPORTED are terminal."""
    rows = conn.execute("""SELECT from_state, to_state FROM run_state_transitions_allowed
           WHERE from_state IN ('FAILED','CANCELLED','POLICY_BLOCKED','EXPORTED')""").fetchall()
    assert rows == []


def test_leaf_hash_and_signature_lengths_are_enforced(conn, seeded) -> None:  # noqa: ANN001
    """A 32-byte digest is a schema constraint, not a convention (A2)."""
    import psycopg

    run_id = seeded["run_id"]
    # Two bytes where 32 are required.
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO events (run_id, sequence, event_id, event_type, canonical_bytes,
                                   leaf_hash, source, created_at_ms)
               VALUES (%s, 0, %s, 'ACTION_REQUESTED', %s, %s, 'reported_by_adapter', 1)""",
            (run_id, str(uuid.uuid4()), b"{}", b"\x00\x01"),
        )
    # A 64-byte signature is required on checkpoints.
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO checkpoints (stream_id, tree_size, checkpoint_bytes, checkpoint_hash,
                                        signature, key_id, created_at_ms)
               VALUES ('global', 1, %s, %s, %s, 'ed25519:x', 1)""",
            (b"{}", hashlib.sha256(b"cp").digest(), b"short"),
        )


def test_concurrent_writers_produce_a_gap_free_sequence(dsn, seeded) -> None:  # noqa: ANN001
    """R-DAT-03: one serialized writer per run, under 20 threads at once.

    Each thread does what the ingestion service does: lock the head row FOR
    UPDATE, take the next sequence, insert, bump the head, all in one
    transaction.
    """
    import psycopg

    run_id = seeded["run_id"]
    writers = 20
    errors: list[str] = []
    barrier = threading.Barrier(writers)

    def write_one() -> None:
        try:
            barrier.wait(timeout=30)
            with psycopg.connect(dsn) as conn:
                with conn.transaction():
                    sequence = one(
                        conn.execute(
                            "SELECT next_sequence FROM event_stream_heads"
                            " WHERE run_id = %s FOR UPDATE",
                            (run_id,),
                        )
                    )[0]
                    insert_event(conn, run_id, sequence)
                    conn.execute(
                        "UPDATE event_stream_heads SET next_sequence = %s WHERE run_id = %s",
                        (sequence + 1, run_id),
                    )
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=write_one) for _ in range(writers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert errors == [], errors
    with psycopg.connect(dsn) as conn:
        sequences = [
            row[0]
            for row in conn.execute(
                "SELECT sequence FROM events WHERE run_id = %s ORDER BY sequence", (run_id,)
            ).fetchall()
        ]
    assert sequences == list(range(writers)), sequences
    with psycopg.connect(dsn) as conn:
        head = one(
            conn.execute(
                "SELECT next_sequence FROM event_stream_heads WHERE run_id = %s", (run_id,)
            )
        )[0]
    assert head == writers


def test_event_head_and_outbox_commit_atomically(dsn, seeded) -> None:  # noqa: ANN001
    """R-DAT-04: if the transaction aborts, none of the three rows survive."""
    import psycopg

    run_id = seeded["run_id"]
    with psycopg.connect(dsn) as conn:
        try:
            with conn.transaction():
                event_id = insert_event(conn, run_id, 0)
                conn.execute(
                    "UPDATE event_stream_heads SET next_sequence = 1 WHERE run_id = %s", (run_id,)
                )
                conn.execute(
                    """INSERT INTO workflow_outbox (run_id, event_id, topic)
                       VALUES (%s, %s, 'sse')""",
                    (run_id, event_id),
                )
                raise RuntimeError("crash between the writes")
        except RuntimeError:
            pass

    with psycopg.connect(dsn) as conn:
        assert one(conn.execute("SELECT count(*) FROM events"))[0] == 0
        assert one(conn.execute("SELECT count(*) FROM workflow_outbox"))[0] == 0
        assert (
            one(
                conn.execute(
                    "SELECT next_sequence FROM event_stream_heads WHERE run_id = %s", (run_id,)
                )
            )[0]
            == 0
        )


def test_idempotency_key_is_unique_per_run(conn, seeded) -> None:  # noqa: ANN001
    import psycopg

    run_id = seeded["run_id"]
    event_id = insert_event(conn, run_id, 0)
    conn.execute(
        "INSERT INTO event_idempotency (run_id, idempotency_key, event_id) VALUES (%s, 'k1', %s)",
        (run_id, event_id),
    )
    second = insert_event(conn, run_id, 1)
    with pytest.raises(psycopg.errors.UniqueViolation):
        conn.execute(
            """INSERT INTO event_idempotency (run_id, idempotency_key, event_id)
               VALUES (%s, 'k1', %s)""",
            (run_id, second),
        )


def test_global_log_allows_one_position_per_run(conn, seeded) -> None:  # noqa: ANN001
    import psycopg

    run_id = seeded["run_id"]
    digest = hashlib.sha256(b"record").digest()
    conn.execute(
        "INSERT INTO global_log (position, run_id, record_bytes, leaf_hash) VALUES (0, %s, %s, %s)",
        (run_id, b"{}", digest),
    )
    with pytest.raises(psycopg.errors.UniqueViolation):
        conn.execute(
            """INSERT INTO global_log (position, run_id, record_bytes, leaf_hash)
               VALUES (1, %s, %s, %s)""",
            (run_id, b"{}", digest),
        )


def test_migration_is_recorded_and_forward_only(conn) -> None:  # noqa: ANN001
    versions = [row[0] for row in conn.execute("SELECT version FROM schema_migrations").fetchall()]
    assert versions == [1, 2]
