"""Relaying a human's signed approval into the ledger (`PROTOCOL.md` 5.6, D-16).

The control plane **never holds an approver's key**. A person signs a decision
on their own device with `abb approve`; this module receives the signed
statement, has the Rust core check it against the key manifest, compares it with
what was actually requested, and only then commits `HUMAN_APPROVAL_GRANTED` or
`_DENIED`.

That check is a convenience and a guard, not the proof. The verifier re-checks
the same signature offline from the receipt, so a control plane that lied here
would be caught. A valid signature shows that a key signed; it does not show
which person held the key (`R-APR-08`).
"""

from __future__ import annotations

import base64
import json
import subprocess
from typing import Any

from .errors import AbbError
from .repository import Repository, now_ms

#: What `abb approval check` writes to stderr, mapped to API error codes.
_CHECK_ERRORS = {
    "BAD_SIGNATURE": "BAD_SIGNATURE",
    "UNKNOWN_APPROVER": "UNKNOWN_APPROVER",
    "VALIDATION_FAILED": "VALIDATION_FAILED",
}


class ApprovalRelay:
    """Verify a signed approval and commit the event for it."""

    def __init__(
        self,
        *,
        repository: Repository,
        abb_path: str,
        key_manifest_path: str | None,
        clock: Any = now_ms,
    ) -> None:
        self._repo = repository
        self._abb = abb_path
        self._keys = key_manifest_path
        self._clock = clock

    # ------------------------------------------------------------------ check

    def _check(self, *, key_id: str, statement_b64: str, signature: str) -> dict[str, str]:
        if not self._keys:
            # Fail closed: without a manifest there is nothing to check against.
            raise AbbError(
                "DEPENDENCY_UNAVAILABLE", "no approver key manifest is configured on this service"
            )
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    self._abb,
                    "approval",
                    "check",
                    "--keys",
                    self._keys,
                    "--key-id",
                    key_id,
                    "--statement-b64",
                    statement_b64,
                    "--signature",
                    signature,
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "the approval checker is unavailable") from exc
        if done.returncode != 0:
            said = done.stderr.decode("utf-8", "replace")
            for marker, code in _CHECK_ERRORS.items():
                if marker in said:
                    raise AbbError(code, marker.replace("_", " ").lower())
            raise AbbError("VALIDATION_FAILED", "the approval was not accepted")
        return dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )

    def _requested(self, run_id: str, approval_id: str) -> dict[str, Any]:
        """The `HUMAN_APPROVAL_REQUESTED` payload for this approval, from the ledger."""
        for raw in self._repo.canonical_events(run_id):
            event = json.loads(raw)
            if (
                event.get("event_type") == "HUMAN_APPROVAL_REQUESTED"
                and event["payload"].get("approval_id") == approval_id
            ):
                payload: dict[str, Any] = event["payload"]
                return payload
        raise AbbError("NOT_FOUND", "no approval was requested with that id on this run")

    # ----------------------------------------------------------------- submit

    def submit(
        self,
        run_id: str,
        *,
        approval_id: str,
        statement_b64: str,
        key_id: str,
        signature: str,
    ) -> dict[str, Any]:
        checked = self._check(key_id=key_id, statement_b64=statement_b64, signature=signature)
        requested = self._requested(run_id, approval_id)

        if checked["run_id"] != run_id or checked["approval_id"] != approval_id:
            raise AbbError("APPROVAL_MISMATCH", "the statement is for a different run or approval")
        if checked["action_id"] != requested["action_id"]:
            raise AbbError("APPROVAL_MISMATCH", "the statement is for a different action")
        if checked["summary_digest"] != requested["summary_digest"]:
            # The approver signed something other than what was requested.
            raise AbbError("APPROVAL_MISMATCH", "the approver signed a different summary")

        decision = checked["decision"]
        expires_at = int(checked["expires_at"])
        if decision == "GRANTED" and expires_at <= self._clock():
            raise AbbError("APPROVAL_EXPIRED", "the approval had already expired when relayed")

        if any(a["approval_id"] == approval_id for a in self._repo.signed_approvals(run_id)):
            raise AbbError("APPROVAL_ALREADY_DECIDED", "this approval already has a decision")

        run = self._repo.get_run(run_id)
        if run is None:  # pragma: no cover - the route checks first
            raise AbbError("NOT_FOUND", "unknown run")

        if decision == "GRANTED":
            event_type = "HUMAN_APPROVAL_GRANTED"
            payload: dict[str, Any] = {
                "approval_id": approval_id,
                "action_id": checked["action_id"],
                # We know a key, not a person (R-APR-08), so the key id is also the id.
                "approver_id": key_id,
                "approver_key_id": key_id,
                "expires_at": expires_at,
                "approval_signature": signature,
            }
        else:
            event_type = "HUMAN_APPROVAL_DENIED"
            payload = {
                "approval_id": approval_id,
                "action_id": checked["action_id"],
                "approver_id": key_id,
                "approver_key_id": key_id,
                "reason": "denied by the approver",
                "approval_signature": signature,
            }

        coverage = run["declared_coverage"] or run["requested_coverage"]
        body = json.dumps(
            {
                "event_type": event_type,
                "source": "verified_by_black_box",
                "provenance": {
                    "adapter_name": run["adapter"],
                    "adapter_version": "0.1.0",
                    "execution_id": "control-plane-relay",
                    "mode": "REPLAY" if run["adapter"] == "replay" else "LIVE_LOCAL",
                    "observed_coverage": coverage,
                },
                "payload": payload,
            }
        ).encode("utf-8")
        committed = self._repo.ingest_event(
            run_id=run_id,
            body=body,
            idempotency_key=f"{approval_id}-decision",
            fencing_token=None,
        )
        self._repo.store_signed_approval(
            run_id=run_id,
            approval_id=approval_id,
            action_id=checked["action_id"],
            decision=decision,
            statement=base64.b64decode(statement_b64),
            approver_key_id=key_id,
            signature=signature,
            event_id=committed.event.event_id,
        )
        return {
            "approval_id": approval_id,
            "decision": decision,
            "event_id": committed.event.event_id,
            "sequence": committed.event.sequence,
            "expires_at": expires_at if decision == "GRANTED" else None,
        }
