"""A Stripe client that can only ever spend TEST money.

Stripe's test mode is a separate, official sandbox: test keys start with `sk_test_` (or
`rk_test_`), the test card is a published token (`pm_card_visa`), and no real money, card or bank
account is involved. This client adds three protections on top of that:

* a key that does not start with a test prefix is **refused before any request is made**, so a live
  key set by mistake can never be used;
* every reply must say `"livemode": false`; if it does not, the payment is treated as FAILED and
  nothing is trusted;
* a hard ceiling (`HARD_CEILING_MINOR_UNITS`) that no policy can raise.

The key is read from the environment variable `STRIPE_TEST_KEY` that the user sets. It is sent
only in the `Authorization` header and is never printed, logged, stored or put in an error.
A payment is created with an idempotency key, so asking twice can never charge twice, and it is
never retried here: an unclear outcome is reported as unknown.

Standard library only. Plain `http://` is accepted only for a loopback base URL (tests).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

KEY_ENV = "STRIPE_TEST_KEY"
LIVE_BASE = "https://api.stripe.com"
TEST_PREFIXES = ("sk_test_", "rk_test_")
#: The published Stripe test token for a Visa test card. No card number is ever handled here.
TEST_PAYMENT_METHOD = "pm_card_visa"
#: No policy can raise this: 1,000.00 in any currency.
HARD_CEILING_MINOR_UNITS = 100_000
CURRENCIES = ("usd", "eur", "gbp", "inr")


class PaymentError(Exception):
    """Base class: the payment did not complete as asked."""


class NotTestMode(PaymentError):
    """The key or the reply was not test mode. Nothing was (or will be) trusted."""


class Declined(PaymentError):
    """Stripe answered and said no (for example a declined test card)."""


class AuthRejected(PaymentError):
    """Stripe did not accept the key."""


class Unclear(PaymentError):
    """No clear answer (timeout, dropped connection). The payment MAY have happened."""


@dataclass(frozen=True)
class Payment:
    payment_id: str
    status: str  # Stripe's own word, e.g. "succeeded"
    amount_minor_units: int
    currency: str


def _key() -> str:
    key = os.environ.get(KEY_ENV, "")
    if not key:
        raise AuthRejected(f"{KEY_ENV} is not set")
    if not key.startswith(TEST_PREFIXES):
        # Say nothing about the key itself, only that it is not a test key.
        raise NotTestMode(f"{KEY_ENV} is not a Stripe TEST key (it must start with sk_test_)")
    return key


class StripeTestClient:
    def __init__(self, base_url: str = LIVE_BASE, timeout: float = 30.0) -> None:
        parts = urlparse(base_url)
        loopback = parts.hostname in {"127.0.0.1", "localhost", "::1"}
        if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
            raise ValueError("the payment service address must be https (http only on loopback)")
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout

    @property
    def host(self) -> str:
        return urlparse(self.base_url).netloc

    def endpoint(self) -> str:
        return f"{self.base_url}/v1/payment_intents"

    def check_key(self) -> None:
        """Raises unless a test key is set. Makes no request."""
        _key()

    def charge(
        self,
        *,
        amount_minor_units: int,
        currency: str,
        description: str,
        idempotency_key: str,
    ) -> Payment:
        if not isinstance(amount_minor_units, int) or amount_minor_units <= 0:
            raise ValueError("the amount must be a positive whole number of minor units")
        if amount_minor_units > HARD_CEILING_MINOR_UNITS:
            raise NotTestMode("over the hard ceiling for test payments")
        currency = currency.lower()
        if currency not in CURRENCIES:
            raise ValueError(f"currency must be one of {CURRENCIES}")
        key = _key()  # refuses a non-test key before anything is sent
        body = urlencode(
            {
                "amount": amount_minor_units,
                "currency": currency,
                "payment_method": TEST_PAYMENT_METHOD,
                "confirm": "true",
                "automatic_payment_methods[enabled]": "true",
                "automatic_payment_methods[allow_redirects]": "never",
                "description": description[:200],
            }
        ).encode()
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self.endpoint(),
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {key}",
                "Idempotency-Key": idempotency_key,
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                raw = response.read(200_000)
        except urllib.error.HTTPError as exc:
            detail = _read_error(exc)
            if exc.code in (401, 403):
                raise AuthRejected("Stripe did not accept the key") from None
            if exc.code == 402 or detail.get("type") == "card_error":
                raise Declined(str(detail.get("code") or "declined")[:60]) from None
            raise PaymentError(f"Stripe answered HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise Unclear("no clear answer from the payment service") from None
        return _parse(raw, amount_minor_units, currency)


def _read_error(exc: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        parsed = json.loads(exc.read(20_000)).get("error", {})
    except (ValueError, AttributeError, OSError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse(raw: bytes, amount: int, currency: str) -> Payment:
    try:
        data = json.loads(raw)
    except ValueError:
        raise Unclear("the reply could not be read") from None
    if not isinstance(data, dict) or data.get("livemode") is not False:
        # Anything other than an explicit test-mode reply is not trusted at all.
        raise NotTestMode("the reply did not say it was test mode; nothing was trusted")
    status = str(data.get("status", ""))
    payment_id = str(data.get("id", ""))
    if not payment_id.startswith("pi_") or data.get("amount") != amount:
        raise Unclear("the reply did not match the request")
    if status != "succeeded":
        raise Declined(f"status {status}"[:60])
    return Payment(payment_id, status, amount, currency)
