"""Tests for local-only mock payments and policy-gateway ordering."""

from __future__ import annotations

import json
from typing import Any, Literal

import pytest

from adapters.payments.adapter import IN_SCOPE_ACTIONS, PaymentAdapter
from adapters.payments.client import Declined, MockPaymentClient, Unclear
from adapters.playwright.adapter import MemorySink
from policy.engine import Action, Decision, Policy
from services.worker.gateway import Gateway


def real_policy() -> Policy:
    return Policy.load("company-spend", 1)


def judge(amount: int, target: str = "https://mock-payments.local/charge") -> Decision:
    action = Action("a", "payment", target, amount_minor_units=amount, params={"vendor": "Acme"})
    return real_policy().evaluate(action)


def test_policy_spending_tiers_and_local_target() -> None:
    assert judge(1200).outcome == "ALLOW"
    assert judge(5000).outcome == "ALLOW"
    assert judge(5001).outcome == "REQUIRE_APPROVAL"
    assert judge(50000).outcome == "REQUIRE_APPROVAL"
    assert judge(50001).outcome == "DENY"
    assert "OVER_AMOUNT_LIMIT" in judge(90000).reason_codes
    assert judge(1000, "https://evil.example/charge").outcome == "DENY"


def test_mock_success_is_local_and_idempotent() -> None:
    client = MockPaymentClient()
    client.check_key()
    first = client.charge(
        amount_minor_units=1200, currency="USD", description="invoice", idempotency_key="same"
    )
    second = client.charge(
        amount_minor_units=1200, currency="usd", description="invoice", idempotency_key="same"
    )
    assert first == second
    assert first.payment_id.startswith("mock_")
    assert first.status == "simulated_succeeded"
    assert client.charge_calls == 1


def test_mock_decline_and_unknown_scenarios() -> None:
    with pytest.raises(Declined):
        MockPaymentClient("decline").charge(
            amount_minor_units=100, currency="usd", description="x", idempotency_key="d"
        )
    with pytest.raises(Unclear):
        MockPaymentClient("unknown").charge(
            amount_minor_units=100, currency="usd", description="x", idempotency_key="u"
        )


@pytest.mark.parametrize("amount", [0, -1, 100_001])
def test_invalid_amounts_are_rejected(amount: int) -> None:
    with pytest.raises(ValueError):
        MockPaymentClient().charge(
            amount_minor_units=amount, currency="usd", description="x", idempotency_key="k"
        )


class Relay:
    def __init__(self, decision: str) -> None:
        self.decision = decision

    def submit(self, **_: Any) -> dict[str, str]:
        return {"decision": self.decision}


def approver_saying(answer: str) -> Any:
    def approve(gateway: Gateway, action: Action) -> Decision:
        return gateway.submit_approval(action, statement_b64="stmt", key_id="key", signature="sig")

    approve.relay = Relay("GRANTED" if answer == "ALLOW" else "DENIED")  # type: ignore[attr-defined]
    return approve


def adapter_for(
    approver: Any = None, scenario: Literal["success", "decline", "unknown"] = "success"
) -> tuple[PaymentAdapter, MemorySink, MockPaymentClient]:
    sink = MemorySink()
    policy = real_policy()
    client = MockPaymentClient(scenario)
    adapter = PaymentAdapter(
        Gateway(
            sink=sink,
            policy=policy,
            provenance=PaymentAdapter(None, client).provenance(),
            in_scope_actions=IN_SCOPE_ACTIONS,
            approvals=getattr(approver, "relay", None),
        ),
        client,
        approver=approver,
        run_key="test",
    )
    return adapter, sink, client


def event_types(sink: MemorySink) -> list[str]:
    return [event["event_type"] for event in sink.events]


def test_small_payment_is_gated_recorded_and_simulated() -> None:
    adapter, sink, client = adapter_for()
    outcome = adapter.pay(
        vendor="Acme", amount_minor_units=1200, currency="usd", note="private note"
    )
    assert outcome.status == "PAID"
    assert outcome.payment_id is not None and outcome.payment_id.startswith("mock_")
    assert client.charge_calls == 1
    kinds = event_types(sink)
    assert kinds.index("ACTION_REQUESTED") < kinds.index("ACTION_AUTHORIZED")
    assert kinds.index("ACTION_AUTHORIZED") < kinds.index("ACTION_DISPATCHED")
    assert kinds.index("ACTION_DISPATCHED") < kinds.index("API_CALL_OBSERVED")
    assert kinds[-1] == "ACTION_SUCCEEDED"
    assert "private note" not in json.dumps(sink.events)


def test_approval_is_required_before_mock_charge() -> None:
    adapter, sink, client = adapter_for()
    outcome = adapter.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="x")
    assert outcome.status == "BLOCKED"
    assert client.charge_calls == 0
    assert "HUMAN_APPROVAL_REQUESTED" in event_types(sink)


def test_denied_approval_never_charges_but_granted_approval_does_once() -> None:
    denied, _, denied_client = adapter_for(approver=approver_saying("DENY"))
    assert (
        denied.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="x").status
        == "BLOCKED"
    )
    assert denied_client.charge_calls == 0

    granted, sink, granted_client = adapter_for(approver=approver_saying("ALLOW"))
    assert (
        granted.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="x").status
        == "PAID"
    )
    assert granted_client.charge_calls == 1
    assert "ACTION_SUCCEEDED" in event_types(sink)


def test_over_cap_is_blocked_before_mock_charge() -> None:
    adapter, sink, client = adapter_for()
    outcome = adapter.pay(vendor="Acme", amount_minor_units=90000, currency="usd", note="x")
    assert outcome.status == "BLOCKED" and "OVER_AMOUNT_LIMIT" in outcome.detail
    assert client.charge_calls == 0
    assert "ACTION_BLOCKED" in event_types(sink)


def test_decline_and_uncertain_outcomes_are_recorded_without_retry() -> None:
    declined, sink, client = adapter_for(scenario="decline")
    assert (
        declined.pay(vendor="Acme", amount_minor_units=1000, currency="usd", note="x").status
        == "DECLINED"
    )
    assert client.charge_calls == 1
    assert "ACTION_FAILED" in event_types(sink)

    unclear, sink2, client2 = adapter_for(scenario="unknown")
    assert (
        unclear.pay(vendor="Acme", amount_minor_units=1000, currency="usd", note="x").status
        == "OUTCOME_UNKNOWN"
    )
    assert client2.charge_calls == 1
    assert "OUTCOME_UNKNOWN" in event_types(sink2)
