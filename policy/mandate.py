"""The signed mandate as a deterministic policy input (`PROTOCOL.md` 5.7, D-16).

A mandate says what the human allowed this agent to do in this run. The gateway
treats it like any other policy input: no clock, no network, no model. It blocks
an out-of-mandate action before dispatch, and the verifier re-checks the same
rules afterwards from the events alone, so a gateway that skipped this check is
caught rather than trusted.

The signature is never checked here in Python. `abb mandate check` (the Rust
core) does it, so there is one implementation of the signing rules. This module
only reads a document that check already accepted.

A mandate is evidence of the instructions. It is not enforcement by itself.
"""

from __future__ import annotations

import base64
import json
import subprocess
from dataclasses import dataclass
from typing import Any

from policy.engine import Action, host_matches, host_of


class MandateError(Exception):
    """The mandate could not be accepted. The run must not start with it."""


@dataclass(frozen=True)
class SignedMandate:
    """A mandate the Rust core has verified against the key manifest."""

    document: dict[str, Any]
    document_b64: str
    signature: str
    digest: str
    issuer_key_id: str

    @property
    def mandate_id(self) -> str:
        return str(self.document["mandate_id"])

    @classmethod
    def verified(
        cls, *, document_b64: str, signature: str, keys_path: str, abb_path: str
    ) -> SignedMandate:
        """Check the signature with `abb mandate check`, then read the fields."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    abb_path,
                    "mandate",
                    "check",
                    "--keys",
                    keys_path,
                    "--document-b64",
                    document_b64,
                    "--signature",
                    signature,
                ],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MandateError("the mandate checker is unavailable") from exc
        if done.returncode != 0:
            raise MandateError(done.stderr.decode("utf-8", "replace").strip()[:200] or "refused")
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        document = json.loads(base64.b64decode(document_b64))
        return cls(
            document=document,
            document_b64=document_b64,
            signature=signature,
            digest=fields["mandate_digest"],
            issuer_key_id=fields["issuer_key_id"],
        )

    # ------------------------------------------------------------ the rules

    def window_violation(self, now_ms: int) -> str | None:
        """Outside `not_before`/`not_after`? Both are time claims, not evidence."""
        if not self.document["not_before"] <= now_ms <= self.document["not_after"]:
            return "MANDATE_VIOLATION"
        return None

    def violation(self, action: Action, *, authorized_so_far: int, spent_so_far: int) -> str | None:
        """The reason code for the first rule the action breaks, or `None`.

        The same four rules the verifier applies to dispatched actions: action
        type, host, `max_actions`, and the spend bound.
        """
        doc = self.document
        if action.action_type not in doc["allowed_action_types"]:
            return "MANDATE_VIOLATION"
        host = host_of(action.target)
        if host is None or not any(host_matches(host, p) for p in doc["allowed_hosts"]):
            return "MANDATE_VIOLATION"
        if authorized_so_far + 1 > doc["max_actions"]:
            return "MANDATE_VIOLATION"
        limit = doc.get("max_spend_minor_units")
        if limit is not None and action.amount_minor_units is not None:
            if spent_so_far + action.amount_minor_units > limit:
                return "MANDATE_VIOLATION"
        return None
