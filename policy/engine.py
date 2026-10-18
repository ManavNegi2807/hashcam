"""The deterministic policy engine.

`DESIGN.md` 12 and `R-POL-01..06`. Three properties matter more than the rule
set itself:

* **deterministic**: the same policy document and the same action always give
  the same decision. No clock, no randomness, no network, no model;
* **versioned**: every decision records the policy id and version it came from,
  and the digest of the input it judged;
* **the only thing that can authorize**. ML, prompt-guard and anomaly output is
  advisory and cannot reach this code (`AGENTS.md` 3.17, `R-POL-05`).

The policy document is a JSON file under `policy/versions/`. It is immutable
once published: a change is a new version, never an edit (`R-POL-06`).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import pathsafe

VERSIONS_DIR = Path(__file__).resolve().parent / "versions"

Outcome = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]

#: Every reason code this engine can produce. A decision carries codes, not
#: prose, so a receipt reader and the UI can group them.
REASON_CODES = (
    "ALLOWED_BY_POLICY",
    "DOMAIN_NOT_ALLOWED",
    "DOMAIN_DENIED",
    "ACTION_TYPE_NOT_ALLOWED",
    "OVER_ACTION_LIMIT",
    "OVER_AMOUNT_LIMIT",
    "APPROVAL_REQUIRED",
    "TARGET_NOT_A_URL",
    "MANDATE_VIOLATION",
    "APPROVAL_GRANTED",
    "APPROVAL_DENIED",
    "PROMPT_GUARD_ESCALATION",
    "SSRF_BLOCKED",
    "BUDGET_RESERVE_REACHED",
    "PROVIDER_QUOTA_EXHAUSTED",
    "PAYMENT_KEY_NOT_TEST_MODE",
    "PAYMENT_KEY_MISSING",
    "ENRICHMENT_NOT_RUN",
)

#: Payload fields an offline check reads. A policy may not hide them: a receipt
#: whose approvals, mandate or decisions cannot be re-checked without them would
#: turn `PASS` into `UNKNOWN` by the policy author's choice (`R-CMT-06`).
PROTECTED_FIELDS = frozenset(
    {
        "action_id",
        "approval_id",
        "summary_digest",
        "approver_id",
        "approver_key_id",
        "expires_at",
        "approval_signature",
        "policy_id",
        "policy_version",
        "reason_codes",
        "input_digest",
        "decision",
        "action_type",
        "target",
        "amount_minor_units",
        "mandate_digest",
        "mandate_issuer_key_id",
        "mandate_signature",
        "adapter",
        "requested_coverage",
        "declared_coverage",
        "in_scope_actions",
        "final_state",
        "event_count",
        "outcome",
        "artifact_digest",
        "manifest_index",
        "evidence_event_ids",
        "text_digest",
        "params_digest",
    }
)


@dataclass(frozen=True)
class Action:
    """What an adapter proposes to do, before it does it."""

    action_id: str
    action_type: str
    target: str
    #: Integer minor units, because protocol numbers are integers (`R-PRO-03`).
    amount_minor_units: int | None = None
    params: dict[str, Any] = field(default_factory=dict)

    def params_digest(self) -> str:
        """A digest of the parameters, so a decision names what it judged.

        The parameters themselves may be sensitive, so the ledger records this
        digest; the clear values stay with the gateway (`R-POL-03`).
        """
        encoded = json.dumps(self.params, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class Decision:
    """A decision, with everything needed to record it as an event."""

    outcome: Outcome
    reason_codes: tuple[str, ...]
    policy_id: str
    policy_version: int
    input_digest: str

    @property
    def allows_dispatch(self) -> bool:
        """Only `ALLOW` lets an action reach the adapter.

        `REQUIRE_APPROVAL` is not a yes: it is a yes *after* a signed approval,
        which arrives in Step 9. Until then it blocks dispatch.
        """
        return self.outcome == "ALLOW"


def host_of(target: str) -> str | None:
    """The host of a URL, or `None` when the target is not one."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(target)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed.hostname.lower()


def host_matches(host: str, pattern: str) -> bool:
    """Exact host, or a `*.suffix` pattern (`PROTOCOL.md` 5.7)."""
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return host == pattern[2:] or host.endswith(suffix)
    return host == pattern


class Policy:
    """One immutable policy version."""

    def __init__(self, body: dict[str, Any], *, source: str = "<memory>") -> None:
        self.body = body
        self.source = source
        self.policy_id = str(body["policy_id"])
        self._redaction = self._checked_redaction(body.get("redaction", {}))
        self.version = int(body["version"])
        # The digest covers the document as published, so a receipt can name it.
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        self.body_digest = hashlib.sha256(canonical).hexdigest()

    @classmethod
    def load(cls, policy_id: str, version: int, *, directory: Path | None = None) -> Policy:
        directory = directory or VERSIONS_DIR
        path = directory / f"{policy_id}.v{version}.json"
        body = json.loads(pathsafe.read_text(path))
        if body.get("policy_id") != policy_id or int(body.get("version", -1)) != version:
            raise ValueError(f"{path} does not declare {policy_id} v{version}")
        return cls(body, source=str(path))

    # -------------------------------------------------------------- redaction

    @staticmethod
    def _checked_redaction(raw: Any) -> dict[str, list[str]]:
        """Refuse a policy that hides a field a required offline check needs."""
        if not isinstance(raw, dict):
            raise ValueError("redaction must be an object of event type -> field names")
        rules: dict[str, list[str]] = {}
        for event_type, fields in raw.items():
            if not isinstance(fields, list) or not all(isinstance(f, str) and f for f in fields):
                raise ValueError(f"redaction for {event_type} must be a list of field names")
            hidden = sorted(set(fields) & PROTECTED_FIELDS)
            if hidden:
                raise ValueError(
                    f"redaction for {event_type} would hide {hidden}, which an offline check "
                    "needs (R-CMT-06)"
                )
            rules[str(event_type)] = list(fields)
        return rules

    def redaction_rules(self) -> dict[str, list[str]]:
        """Event type -> payload fields to commit to instead of storing (`D-11`)."""
        return {k: list(v) for k, v in self._redaction.items()}

    # ------------------------------------------------------------- evaluation

    def evaluate(
        self,
        action: Action,
        *,
        actions_so_far: int = 0,
        signals: dict[str, str] | None = None,
    ) -> Decision:
        """Judge one action. Pure: no clock, no network, no state but the count.

        `signals` are advisory inputs such as the prompt guard's worst verdict. They
        can only make a decision *stricter*, and only if the policy says how: no
        signal can turn a deny or an approval gate into an allow (`R-PIG-05`).
        """
        reasons: list[str] = []
        outcome: Outcome = "ALLOW"

        def deny(code: str) -> None:
            nonlocal outcome
            outcome = "DENY"
            reasons.append(code)

        # 1. Action type.
        allowed_types = self.body.get("allowed_action_types", [])
        if action.action_type not in allowed_types:
            deny("ACTION_TYPE_NOT_ALLOWED")

        # 2. Host, for anything that names a URL.
        if action.action_type in self.body.get("action_types_needing_target", []):
            host = host_of(action.target)
            if host is None:
                deny("TARGET_NOT_A_URL")
            else:
                denied = self.body.get("denied_hosts", [])
                allowed = self.body.get("allowed_hosts", [])
                if any(host_matches(host, pattern) for pattern in denied):
                    deny("DOMAIN_DENIED")
                elif allowed and not any(host_matches(host, pattern) for pattern in allowed):
                    deny("DOMAIN_NOT_ALLOWED")

        # 3. Rate limit on actions per run.
        max_actions = self.body.get("max_actions")
        if isinstance(max_actions, int) and actions_so_far >= max_actions:
            deny("OVER_ACTION_LIMIT")

        # 4. Spend limit.
        max_amount = self.body.get("max_amount_minor_units")
        if (
            isinstance(max_amount, int)
            and action.amount_minor_units is not None
            and action.amount_minor_units > max_amount
        ):
            deny("OVER_AMOUNT_LIMIT")

        # 5. Approval gates. A deny wins: an approval cannot unblock something
        # the policy forbids outright.
        if outcome == "ALLOW" and self._needs_approval(action):
            outcome = "REQUIRE_APPROVAL"
            reasons.append("APPROVAL_REQUIRED")

        # 6. An advisory signal may escalate an allow, if the policy names how.
        if (
            outcome == "ALLOW"
            and signals
            and signals.get("prompt_verdict") == "BLOCK_BY_POLICY"
            and self.body.get("prompt_guard_escalation") == "REQUIRE_APPROVAL"
        ):
            outcome = "REQUIRE_APPROVAL"
            reasons.append("PROMPT_GUARD_ESCALATION")

        if outcome == "ALLOW":
            reasons.append("ALLOWED_BY_POLICY")

        for code in reasons:
            if code not in REASON_CODES:
                # A reason code that is not declared would reach a receipt and
                # mean nothing to its reader.
                raise ValueError(f"undeclared reason code {code}")

        return Decision(
            outcome=outcome,
            reason_codes=tuple(reasons),
            policy_id=self.policy_id,
            policy_version=self.version,
            input_digest=self._input_digest(action, signals),
        )

    def _needs_approval(self, action: Action) -> bool:
        gates = self.body.get("approval_required", {})
        if action.action_type in gates.get("action_types", []):
            return True
        host = host_of(action.target)
        if host and any(host_matches(host, p) for p in gates.get("hosts", [])):
            return True
        for fragment in gates.get("target_contains", []):
            if fragment in action.target:
                return True
        threshold = gates.get("amount_minor_units_over")
        return bool(
            isinstance(threshold, int)
            and action.amount_minor_units is not None
            and action.amount_minor_units > threshold
        )

    def _input_digest(self, action: Action, signals: dict[str, str] | None = None) -> str:
        """Digest of exactly what was judged, including the policy version."""
        material = {
            "policy_id": self.policy_id,
            "version": self.version,
            "action_type": action.action_type,
            "target": action.target,
            "params_digest": action.params_digest(),
            "amount_minor_units": action.amount_minor_units,
        }
        if signals:
            material["signals"] = signals
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()
