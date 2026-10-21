"""A deterministic, local-only mock payment gateway for demos and tests.

No API keys, network requests, card data, external service, or real money are involved.
The gateway simulates outcomes and keeps an in-memory idempotency ledger for one process.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

HARD_CEILING_MINOR_UNITS = 100_000
CURRENCIES = ("usd", "eur", "gbp", "inr")
MOCK_BASE = "https://mock-payments.local"
MOCK_SCENARIOS = ("success", "decline", "unknown")


class PaymentError(Exception):
    """Base class for simulated payment failures."""


class NotTestMode(PaymentError):
    """Compatibility exception; local simulation never supports live mode."""


class Declined(PaymentError):
    """The mock gateway declined the simulated payment."""


class AuthRejected(PaymentError):
    """Compatibility exception; the local mock requires no authentication."""


class Unclear(PaymentError):
    """The simulated outcome is uncertain and must not be retried automatically."""


@dataclass(frozen=True)
class Payment:
    payment_id: str
    status: str
    amount_minor_units: int
    currency: str


class MockPaymentClient:
    """A local fake payment service. No methods perform network I/O."""

    def __init__(self, scenario: Literal["success", "decline", "unknown"] = "success") -> None:
        if scenario not in MOCK_SCENARIOS:
            raise ValueError(f"scenario must be one of {MOCK_SCENARIOS}")
        self.scenario = scenario
        self._idempotency: dict[str, Payment | Exception] = {}
        self.charge_calls = 0

    @property
    def host(self) -> str:
        return "mock-payments.local"

    def endpoint(self) -> str:
        return f"{MOCK_BASE}/charge"

    def check_key(self) -> None:
        """No credentials are required for the local simulation."""
        return None

    def charge(
        self, *, amount_minor_units: int, currency: str, description: str, idempotency_key: str
    ) -> Payment:
        if not isinstance(amount_minor_units, int) or isinstance(amount_minor_units, bool) or amount_minor_units <= 0:
            raise ValueError("the amount must be a positive whole number of minor units")
        if amount_minor_units > HARD_CEILING_MINOR_UNITS:
            raise ValueError("over the hard ceiling for simulated payments")
        currency = currency.lower()
        if currency not in CURRENCIES:
            raise ValueError(f"currency must be one of {CURRENCIES}")
        if not idempotency_key or len(idempotency_key) > 200:
            raise ValueError("an idempotency key is required")

        previous = self._idempotency.get(idempotency_key)
        if previous is not None:
            if isinstance(previous, Exception):
                raise previous
            return previous

        self.charge_calls += 1
        if self.scenario == "decline":
            error = Declined("mock gateway simulated a decline")
            self._idempotency[idempotency_key] = error
            raise error
        if self.scenario == "unknown":
            error = Unclear("mock gateway simulated an uncertain outcome")
            self._idempotency[idempotency_key] = error
            raise error

        digest = hashlib.sha256(idempotency_key.encode()).hexdigest()[:16]
        payment = Payment(f"mock_{digest}", "simulated_succeeded", amount_minor_units, currency)
        self._idempotency[idempotency_key] = payment
        return payment
