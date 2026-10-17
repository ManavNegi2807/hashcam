"""The advisory channels in real receipts (Step 10; `R-SEM-*`, `R-PIG-*`, `R-UI-05`).

Same rules as the rest of the suite: a real signer, a real API, a real database,
the offline verifier. What these add: the semantic monitor and the prompt guard
write ordinary events, so they are as tamper-evident as everything else, and
their findings are advisory. A finding never changes whether a receipt is
`VALID`, and a guard verdict never authorizes anything.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.tamper.test_approvals_mandate import (  # noqa: E402
    ctx,  # noqa: F401  (a pytest fixture, imported so this module can use it)
    events_of,
    produce,
    reasons,
)
from tests.tamper.test_tamper_suite import (  # noqa: E402
    details_for,
    failing_dimensions,
    mutate,
    verify,
)


def types_of(context: dict[str, Any]) -> list[str]:
    return [e["event_type"] for e in events_of(context)]


def test_a_normal_run_carries_both_channels_and_both_pass(ctx: dict[str, Any]) -> None:
    context = produce(ctx, "bank_change_approval", approve="GRANTED")
    code, report = verify(context, context["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    assert report["dimensions"]["semantic_assessment"] == "PASS"
    assert report["dimensions"]["prompt_security_assessment"] == "PASS"
    assert "SEMANTIC_INVARIANT_CHECKED" in types_of(context)
    assert "PROMPT_SECURITY_ANALYSIS_COMPLETED" in types_of(context)
    # The wording keeps the limits attached to the result (R-PIG-10, R-UI-05).
    assert "not a complete prompt-injection defence" in reasons(
        report, "prompt_security_assessment"
    )
    assert "only what was observed" in reasons(report, "semantic_assessment")


def test_a_poisoned_page_is_flagged_but_the_receipt_stays_valid(ctx: dict[str, Any]) -> None:
    """A finding is advisory: it must not make a receipt INVALID or appear as proof."""
    context = produce(ctx, "poisoned_page", approve=None)
    code, report = verify(context, context["receipt"])
    assert report["dimensions"]["prompt_security_assessment"] == "FAIL"
    assert report["overall"] == "VALID", report
    assert code == 0
    text = reasons(report, "prompt_security_assessment")
    assert "not proof of an attack" in text
    flagged = [
        e
        for e in events_of(context)
        if e["event_type"] == "PROMPT_SECURITY_ANALYSIS_COMPLETED"
        and e["payload"]["verdict"] != "ALLOW"
    ]
    assert flagged
    payload = flagged[0]["payload"]
    assert payload["classifier_available"] is False
    assert payload["reason_codes"]
    assert len(payload["source_digest"]) == 64
    # The page text itself is not in the ledger, only its digest.
    assert b"session token" not in json.dumps(events_of(context)).encode()


def test_with_a_default_policy_a_flag_does_not_stop_the_next_action(ctx: dict[str, Any]) -> None:
    """The guard authorizes and blocks nothing by itself (R-PIG-05)."""
    context = produce(ctx, "poisoned_page", approve=None)
    dispatched = [
        e["payload"]["action_id"]
        for e in events_of(context)
        if e["event_type"] == "ACTION_DISPATCHED"
    ]
    assert dispatched == ["p-1", "p-2"]


def test_a_policy_may_turn_the_signal_into_a_stricter_decision(ctx: dict[str, Any]) -> None:
    context = produce(ctx, "poisoned_page", policy_name="guarded", approve=None)
    _, report = verify(context, context["receipt"])
    dispatched = [
        e["payload"]["action_id"]
        for e in events_of(context)
        if e["event_type"] == "ACTION_DISPATCHED"
    ]
    assert dispatched == ["p-1"], "the second action should have been held for approval"
    held = [
        e
        for e in events_of(context)
        if e["event_type"] == "ACTION_BLOCKED" and e["payload"]["action_id"] == "p-2"
    ]
    assert held
    assert "PROMPT_GUARD_ESCALATION" in held[0]["payload"]["reason_codes"]
    assert "HUMAN_APPROVAL_REQUESTED" in types_of(context)
    assert report["overall"] == "VALID", report


def test_an_unobserved_nav_is_unknown_not_pass(ctx: dict[str, Any]) -> None:
    """R-SEM-04: nothing observed must not read as nothing wrong."""
    context = produce(ctx, "unobserved_nav", approve=None)
    _, report = verify(context, context["receipt"])
    assert report["dimensions"]["semantic_assessment"] == "UNKNOWN"
    # No page text was read, so the guard has nothing to say either.
    assert report["dimensions"]["prompt_security_assessment"] == "UNKNOWN"
    assert report["overall"] == "VALID"


class _RecklessPolicy:
    """Stands in for a policy that wrongly allows everything."""

    def __new__(cls, real: Any) -> Any:
        from policy.engine import Decision, Policy

        class Reckless(Policy):
            def evaluate(self, action: Any, **_: Any) -> Any:
                return Decision(
                    outcome="ALLOW",
                    reason_codes=("ALLOWED_BY_POLICY",),
                    policy_id=self.policy_id,
                    policy_version=self.version,
                    input_digest=self._input_digest(action),
                )

        return Reckless(real.body)


def test_the_semantic_monitor_catches_what_a_wrong_policy_let_through(ctx: dict[str, Any]) -> None:
    """A bank change dispatched with no human grant: the policy said yes, the monitor says no."""
    context = produce(
        ctx, "bank_change_approval", policy_name="default", approve=None, _policy=_RecklessPolicy
    )
    code, report = verify(context, context["receipt"])
    assert report["dimensions"]["semantic_assessment"] == "FAIL"
    # Advisory: the receipt as a whole is not made invalid by a semantic finding.
    assert report["overall"] == "VALID", report
    assert code == 0
    text = reasons(report, "semantic_assessment")
    named = " ".join(str(d.get("locator")) for d in details_for(report, "semantic_assessment"))
    assert "INV-BANK-CHANGE-NEEDS-APPROVAL" in named, named
    assert "event sequence" in text  # the exact range (R-SEM-03)
    assert "signal, not a verdict" in text
    assert "SEMANTIC_VIOLATION_DETECTED" in types_of(context)


def test_editing_a_semantic_result_breaks_the_receipt_like_any_other_event(
    ctx: dict[str, Any],
) -> None:
    """An advisory record is an ordinary leaf: changing it is detected and named."""
    context = produce(
        ctx, "bank_change_approval", policy_name="default", approve=None, _policy=_RecklessPolicy
    )

    def change(document: dict[str, Any]) -> None:
        for event in document["events"]:
            canonical = base64.b64decode(event["canonical_b64"])
            if b'"result":"FAIL"' in canonical:
                edited = canonical.replace(b'"result":"FAIL"', b'"result":"PASS"')
                event["canonical_b64"] = base64.b64encode(edited).decode("ascii")
                return
        raise AssertionError("no failing semantic record to edit")

    code, report = mutate(context, "semantic-edit", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
