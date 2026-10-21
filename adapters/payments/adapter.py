"""An agent pays a bill. Every payment passes the policy gateway first.

The order is fixed and cannot be skipped from here:

1. the payment is an `Action` (type `payment`, with its amount) and the gateway records the request;
2. the policy decides: allow, require a person's signed approval, or deny (cap, wrong host);
3. only if the decision allows dispatch is the payment service called, once, with an idempotency
   key;
4. what came back (or that it is unknown) is recorded as it is.

Coverage is declared `STEP_OBSERVED`, never `STEP_GATED`: the code path here is gated, but no bypass
test battery exists for it, so claiming more would be a false claim (`R-COV-01`). The money is test
money (local mock simulation); see `client.py` for the protections that keep it that way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from adapters.base import Coverage, Provenance
from adapters.payments.client import (
    AuthRejected,
    Declined,
    NotTestMode,
    Payment,
    PaymentError,
    MockPaymentClient,
    Unclear,
)
from policy.engine import Action

ADAPTER_NAME = "payments-local-mock"
ADAPTER_VERSION = "0.1.0"
IN_SCOPE_ACTIONS = ["payment"]
CEILING_COVERAGE: Coverage = "STEP_OBSERVED"
COVERAGE_REASON = (
    "payments go through the gateway in this adapter, and the payment service's answer is "
    "recorded, "
    "but there is no bypass test battery for this adapter, so a stronger claim is not made"
)


@dataclass(frozen=True)
class Outcome:
    # PAID, BLOCKED, DECLINED, AUTH_FAILED, NOT_TEST_MODE, OUTCOME_UNKNOWN or FAILED
    status: str
    detail: str = ""
    payment_id: str | None = None


class PaymentAdapter:
    def __init__(
        self,
        gateway: Any,
        client: MockPaymentClient,
        *,
        approver: Any = None,
        run_key: str = "run",
    ) -> None:
        self.gateway = gateway
        self.client = client
        self._approver = approver
        self._run_key = run_key
        self._counter = 0

    def provenance(self) -> Provenance:
        return Provenance(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            execution_id=f"payments-{self._run_key}"[:60],
            mode="LIVE_LOCAL",
            observed_coverage=CEILING_COVERAGE,
        )

    def pay(self, *, vendor: str, amount_minor_units: int, currency: str, note: str) -> Outcome:
        self._counter += 1
        action = Action(
            action_id=f"pay-{self._counter}",
            action_type="payment",
            target=self.client.endpoint(),
            amount_minor_units=amount_minor_units,
            params={
                "vendor": vendor[:80],
                "currency": currency.lower(),
                # The free text may be sensitive: only a digest of it is recorded.
                "note_digest": hashlib.sha256(note.encode()).hexdigest(),
                "via": self.client.host,
            },
        )

        # 1-2. The request is recorded and judged. Nothing has been sent anywhere yet.
        try:
            self.client.check_key()  # a non-test key stops here, before even asking policy
        except NotTestMode as exc:
            self.gateway.deny(action, "PAYMENT_KEY_NOT_TEST_MODE")
            return Outcome("NOT_TEST_MODE", str(exc))
        except AuthRejected as exc:
            self.gateway.deny(action, "PAYMENT_KEY_MISSING")
            return Outcome("AUTH_FAILED", str(exc))

        decision = self.gateway.request(action)
        if decision.outcome == "REQUIRE_APPROVAL" and self._approver is not None:
            decision = self._approver(self.gateway, action)
        if not decision.allows_dispatch:
            return Outcome("BLOCKED", ",".join(decision.reason_codes))

        # 3. Dispatch exactly once. The idempotency key makes a repeated call harmless.
        self.gateway.dispatch(action)
        key = hashlib.sha256(f"{self._run_key}:{action.action_id}".encode()).hexdigest()[:32]
        try:
            payment: Payment = self.client.charge(
                amount_minor_units=amount_minor_units,
                currency=currency,
                description=f"Hascham test payment to {vendor}"[:120],
                idempotency_key=key,
            )
        except Declined as exc:
            self.gateway.failed(action, error_code="PAYMENT_DECLINED", retryable=False)
            return Outcome("DECLINED", str(exc))
        except AuthRejected as exc:
            self.gateway.failed(action, error_code="PAYMENT_AUTH_FAILED", retryable=False)
            return Outcome("AUTH_FAILED", str(exc))
        except NotTestMode as exc:
            self.gateway.failed(action, error_code="PAYMENT_NOT_TEST_MODE", retryable=False)
            return Outcome("NOT_TEST_MODE", str(exc))
        except Unclear:
            self.gateway.outcome_unknown(
                action,
                reason="the payment service gave no clear answer; the payment may have happened",
            )
            return Outcome(
                "OUTCOME_UNKNOWN", "not retried: the first attempt may have taken effect"
            )
        except PaymentError as exc:
            self.gateway.failed(action, error_code="PAYMENT_FAILED", retryable=False)
            return Outcome("FAILED", str(exc))

        # 4. What came back, as the service said it.
        observed = self.gateway.observe_api_call(
            action,
            method="POST",
            host=self.client.host,
            status_code=200,
            body_digest=hashlib.sha256(
                f"{payment.payment_id}:{payment.status}:{payment.amount_minor_units}".encode()
            ).hexdigest(),
            extra={
                "provider_execution_id": payment.payment_id,
                "usage": {"amount_minor_units": payment.amount_minor_units, "simulated": True},
            },
        )
        self.gateway.succeeded(action, evidence=[observed.event_id])
        return Outcome("PAID", payment.status, payment.payment_id)
