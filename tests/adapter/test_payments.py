"""Paying with fake money through the gateway: policy tiers, the client's protections, the order.

Everything here runs against a LOCAL STAND-IN that imitates the shape of Stripe's reply. It proves
the parts that are ours: the policy tiers, that a payment is never sent before the gateway allows
it, that a live key can never be used, that nothing is retried, and what gets recorded. It says
nothing about how the real Stripe test mode behaves: that needs your test key
(`tools/check_stripe_live.py`) and is UNVERIFIED until you run it.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from adapters.payments.adapter import IN_SCOPE_ACTIONS, PaymentAdapter
from adapters.payments.client import (
    KEY_ENV,
    AuthRejected,
    Declined,
    NotTestMode,
    StripeTestClient,
    Unclear,
)
from adapters.playwright.adapter import MemorySink
from policy.engine import Action, Decision, Policy
from services.worker.gateway import Gateway

SENTINEL = "SECRETSENTINEL123"
TEST_KEY = f"sk_test_{SENTINEL}"


class Stand_in(ThreadingHTTPServer):
    reply: tuple[int, dict[str, Any]] = (200, {})
    seen: list[dict[str, Any]]
    hang: bool = False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_POST(self) -> None:
        server: Stand_in = self.server  # type: ignore[assignment]
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        server.seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        if server.hang:
            threading.Event().wait(3)
            return
        status, payload = server.reply
        if not payload:
            amount = int(dict(p.split("=") for p in body.split("&"))["amount"])
            payload = {
                "id": "pi_test_1",
                "status": "succeeded",
                "amount": amount,
                "livemode": False,
            }
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture()
def stripe() -> Iterator[Stand_in]:
    server = Stand_in(("127.0.0.1", 0), Handler)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_ENV, TEST_KEY)


def client_for(server: Stand_in, timeout: float = 5.0) -> StripeTestClient:
    return StripeTestClient(f"http://127.0.0.1:{server.server_address[1]}", timeout=timeout)


# ---- the real policy file, judged without any network -------------------------------------


def real_policy() -> Policy:
    return Policy.load("company-spend", 1)


def judge(amount: int, target: str = "https://api.stripe.com/v1/payment_intents") -> Decision:
    action = Action("a", "payment", target, amount_minor_units=amount, params={"vendor": "Acme"})
    return real_policy().evaluate(action)


def test_small_payments_go_through_on_their_own() -> None:
    assert judge(1200).outcome == "ALLOW"
    assert judge(5000).outcome == "ALLOW"  # exactly 50.00 is still inside the free tier


def test_payments_over_fifty_wait_for_a_signed_approval() -> None:
    decision = judge(5001)
    assert decision.outcome == "REQUIRE_APPROVAL"
    assert judge(18000).outcome == "REQUIRE_APPROVAL"
    assert judge(50000).outcome == "REQUIRE_APPROVAL"


def test_payments_over_five_hundred_are_refused_outright() -> None:
    decision = judge(50001)
    assert decision.outcome == "DENY"
    assert "OVER_AMOUNT_LIMIT" in decision.reason_codes


def test_a_refusal_cannot_be_turned_into_an_approval() -> None:
    # Over the cap stays DENY even though it is also over the approval threshold.
    assert judge(90000).outcome == "DENY"


def test_only_the_payment_service_address_is_allowed() -> None:
    decision = judge(1000, "https://evil.example/v1/payment_intents")
    assert decision.outcome == "DENY"
    assert "DOMAIN_NOT_ALLOWED" in decision.reason_codes


def test_other_kinds_of_action_are_not_allowed() -> None:
    action = Action("a", "form_submit", "https://api.stripe.com/x")
    assert real_policy().evaluate(action).outcome == "DENY"


# ---- the client's protections -------------------------------------------------------------


def test_a_live_key_is_refused_before_any_request(
    stripe: Stand_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, "sk_live_" + "x" * 20)
    with pytest.raises(NotTestMode):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )
    assert stripe.seen == []  # nothing was sent anywhere


def test_a_missing_key_is_refused(stripe: Stand_in, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(KEY_ENV)
    with pytest.raises(AuthRejected):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )
    assert stripe.seen == []


def test_the_request_carries_the_test_card_token_and_an_idempotency_key(stripe: Stand_in) -> None:
    client_for(stripe).charge(
        amount_minor_units=1234, currency="USD", description="d", idempotency_key="abc"
    )
    sent = stripe.seen[0]
    assert sent["headers"]["Idempotency-Key"] == "abc"
    assert sent["headers"]["Authorization"] == f"Bearer {TEST_KEY}"
    assert "payment_method=pm_card_visa" in sent["body"]
    assert "amount=1234" in sent["body"] and "currency=usd" in sent["body"]
    assert "4242" not in sent["body"]  # no card number is ever handled


def test_a_reply_that_is_not_test_mode_is_not_trusted(stripe: Stand_in) -> None:
    stripe.reply = (200, {"id": "pi_1", "status": "succeeded", "amount": 1000, "livemode": True})
    with pytest.raises(NotTestMode):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )


def test_a_reply_without_livemode_is_not_trusted(stripe: Stand_in) -> None:
    stripe.reply = (200, {"id": "pi_1", "status": "succeeded", "amount": 1000})
    with pytest.raises(NotTestMode):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )


def test_a_reply_for_a_different_amount_is_not_a_success(stripe: Stand_in) -> None:
    stripe.reply = (200, {"id": "pi_1", "status": "succeeded", "amount": 999, "livemode": False})
    with pytest.raises(Unclear):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )


def test_a_declined_card_is_reported_as_declined(stripe: Stand_in) -> None:
    stripe.reply = (402, {"error": {"type": "card_error", "code": "card_declined"}})
    with pytest.raises(Declined):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )


def test_a_rejected_key_is_reported_as_such(stripe: Stand_in) -> None:
    stripe.reply = (401, {"error": {"type": "invalid_request_error"}})
    with pytest.raises(AuthRejected):
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )


def test_the_hard_ceiling_cannot_be_raised_by_any_policy(stripe: Stand_in) -> None:
    with pytest.raises(NotTestMode):
        client_for(stripe).charge(
            amount_minor_units=100_001, currency="usd", description="d", idempotency_key="k"
        )
    assert stripe.seen == []


def test_the_key_never_appears_in_an_error(stripe: Stand_in) -> None:
    stripe.reply = (401, {"error": {}})
    with pytest.raises(AuthRejected) as caught:
        client_for(stripe).charge(
            amount_minor_units=1000, currency="usd", description="d", idempotency_key="k"
        )
    assert SENTINEL not in str(caught.value) and SENTINEL not in repr(caught.value)


def test_an_unencrypted_remote_address_is_refused() -> None:
    with pytest.raises(ValueError):
        StripeTestClient("http://api.stripe.com")


# ---- the order of things, through the real gateway ----------------------------------------


class Relay:
    """Stands in for the control plane that checks and records a signed approval."""

    def __init__(self, decision: str) -> None:
        self.decision = decision

    def submit(self, **_: Any) -> dict[str, str]:
        return {"decision": self.decision}


def approver_saying(answer: str) -> Any:
    """An approver that goes through the gateway's OWN approval path (as the real one does)."""

    def approve(gateway: Gateway, action: Action) -> Decision:
        return gateway.submit_approval(action, statement_b64="stmt", key_id="key", signature="sig")

    approve.relay = Relay("GRANTED" if answer == "ALLOW" else "DENIED")  # type: ignore[attr-defined]
    return approve


def adapter_for(
    stripe: Stand_in, approver: Any = None, timeout: float = 5.0
) -> tuple[PaymentAdapter, MemorySink]:
    sink = MemorySink()
    policy = real_policy()
    body = {**policy.body, "allowed_hosts": ["127.0.0.1"]}  # the stand-in's address
    client = client_for(stripe, timeout)
    adapter = PaymentAdapter(
        Gateway(
            sink=sink,
            policy=Policy(body),
            provenance=PaymentAdapter(None, client).provenance(),
            in_scope_actions=IN_SCOPE_ACTIONS,
            approvals=getattr(approver, "relay", None),
        ),
        client,
        approver=approver,
        run_key="t",
    )
    return adapter, sink


def types(sink: MemorySink) -> list[str]:
    return [e["event_type"] for e in sink.events]


def test_a_small_payment_is_recorded_in_order_and_sent_once(stripe: Stand_in) -> None:
    adapter, sink = adapter_for(stripe)
    out = adapter.pay(vendor="Acme", amount_minor_units=1200, currency="usd", note="inv 1")
    assert out.status == "PAID" and out.payment_id == "pi_test_1"
    assert len(stripe.seen) == 1
    kinds = types(sink)
    assert kinds.index("ACTION_REQUESTED") < kinds.index("ACTION_AUTHORIZED")
    assert kinds.index("ACTION_AUTHORIZED") < kinds.index("ACTION_DISPATCHED")
    assert kinds.index("ACTION_DISPATCHED") < kinds.index("API_CALL_OBSERVED")
    assert kinds[-1] == "ACTION_SUCCEEDED"


def test_a_payment_needing_approval_is_not_sent_without_one(stripe: Stand_in) -> None:
    adapter, sink = adapter_for(stripe)
    out = adapter.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="inv 2")
    assert out.status == "BLOCKED"
    assert stripe.seen == []  # nothing reached the payment service
    assert "HUMAN_APPROVAL_REQUESTED" in types(sink)


def test_a_denied_approval_sends_nothing(stripe: Stand_in) -> None:
    adapter, _ = adapter_for(stripe, approver=approver_saying("DENY"))
    out = adapter.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="x")
    assert out.status == "BLOCKED"
    assert stripe.seen == []


def test_a_granted_approval_sends_exactly_one_payment(stripe: Stand_in) -> None:
    adapter, sink = adapter_for(stripe, approver=approver_saying("ALLOW"))
    out = adapter.pay(vendor="Acme", amount_minor_units=18000, currency="usd", note="x")
    assert out.status == "PAID"
    assert len(stripe.seen) == 1 and "amount=18000" in stripe.seen[0]["body"]
    assert "ACTION_SUCCEEDED" in types(sink)


def test_a_payment_over_the_cap_is_refused_and_never_sent(stripe: Stand_in) -> None:
    adapter, sink = adapter_for(stripe)
    out = adapter.pay(vendor="Acme", amount_minor_units=90000, currency="usd", note="x")
    assert out.status == "BLOCKED" and "OVER_AMOUNT_LIMIT" in out.detail
    assert stripe.seen == []
    assert "ACTION_BLOCKED" in types(sink)


def test_the_approver_is_shown_the_amount_and_who_is_paid() -> None:
    action = Action(
        "p",
        "payment",
        "https://api.stripe.com/v1/payment_intents",
        amount_minor_units=18000,
        params={"vendor": "Acme Cloud Ltd", "currency": "usd"},
    )
    summary = Gateway.approval_summary(action)
    assert "PAY 180.00 USD to Acme Cloud Ltd" in summary


def test_a_live_key_is_blocked_and_recorded_without_any_request(
    stripe: Stand_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, "sk_live_" + "y" * 20)
    adapter, sink = adapter_for(stripe)
    out = adapter.pay(vendor="Acme", amount_minor_units=1000, currency="usd", note="x")
    assert out.status == "NOT_TEST_MODE"
    assert stripe.seen == []
    blocked = [e for e in sink.events if e["event_type"] == "ACTION_BLOCKED"]
    assert blocked and "PAYMENT_KEY_NOT_TEST_MODE" in blocked[0]["payload"]["reason_codes"]
    assert "sk_live" not in json.dumps(sink.events)


def test_no_answer_is_unknown_and_is_never_retried(stripe: Stand_in) -> None:
    stripe.hang = True
    adapter, sink = adapter_for(stripe, timeout=0.5)
    out = adapter.pay(vendor="Acme", amount_minor_units=1000, currency="usd", note="x")
    assert out.status == "OUTCOME_UNKNOWN"
    assert len(stripe.seen) == 1  # exactly one attempt
    assert "OUTCOME_UNKNOWN" in types(sink)


def test_a_declined_payment_is_recorded_as_failed(stripe: Stand_in) -> None:
    stripe.reply = (402, {"error": {"type": "card_error", "code": "card_declined"}})
    adapter, sink = adapter_for(stripe)
    out = adapter.pay(vendor="Acme", amount_minor_units=1000, currency="usd", note="x")
    assert out.status == "DECLINED"
    assert "ACTION_FAILED" in types(sink)


def test_the_free_text_and_the_key_never_reach_the_record(stripe: Stand_in) -> None:
    adapter, sink = adapter_for(stripe)
    adapter.pay(vendor="Acme", amount_minor_units=1200, currency="usd", note="PRIVATE-NOTE-77")
    blob = json.dumps(sink.events)
    assert "PRIVATE-NOTE-77" not in blob and SENTINEL not in blob
