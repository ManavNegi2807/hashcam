"""The stdin/stdout approval protocol the run console uses, as one reusable piece.

`APPROVAL_PENDING <json>` goes out on stdout with the exact text the approver must be shown; ONE
line of JSON comes back on stdin from `abb approve` (or `{}` for "nobody"). Silence, a denial or an
error leave the action unsent. Same contract as `demo_guarded.py`, used by `demo_endpoint.py`.
"""

from __future__ import annotations

import json
import queue
from typing import Any

from policy.engine import Decision, Policy


class Bridge:
    def __init__(self, answers: queue.Queue[str | None], wait_seconds: int, policy: Policy) -> None:
        self._answers = answers
        self._wait = wait_seconds
        self._policy = policy
        self.asked = 0
        self.key_id: str | None = None

    def _decide(self, pending: dict[str, str], run_id: str) -> dict[str, str] | None:
        self.asked += 1
        print(
            "APPROVAL_PENDING "
            + json.dumps(
                {
                    "run_id": run_id,
                    "action_id": pending["action_id"],
                    "approval_id": pending["approval_id"],
                    "summary": pending["summary"],
                    "summary_digest": pending["summary_digest"],
                }
            ),
            flush=True,
        )
        try:
            raw = self._answers.get(timeout=self._wait)
        except queue.Empty:
            print("no answer in time: the action stays unsent", flush=True)
            return None
        try:
            signed = json.loads(raw) if raw is not None else None
        except ValueError:
            signed = None
        if not isinstance(signed, dict) or not signed.get("signature"):
            return None
        self.key_id = signed.get("key_id")
        return {k: str(signed[k]) for k in ("statement_b64", "key_id", "signature")}

    def approver(self, run_id: str) -> Any:
        """The function a gateway-driven adapter calls when policy says 'needs approval'."""

        def approve(gw: Any, action: Any) -> Decision:
            pending = next(p for p in gw.pending_approvals() if p["action_id"] == action.action_id)
            signed = self._decide(pending, run_id)
            if signed is None:
                return Decision(
                    outcome="REQUIRE_APPROVAL",
                    reason_codes=("APPROVAL_NOT_RECEIVED",),
                    policy_id=self._policy.policy_id,
                    policy_version=self._policy.version,
                    input_digest="",
                )
            answer: Decision = gw.submit_approval(
                action,
                statement_b64=signed["statement_b64"],
                key_id=signed["key_id"],
                signature=signed["signature"],
            )
            return answer

        return approve
