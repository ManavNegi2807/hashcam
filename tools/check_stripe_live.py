"""One real check of Stripe TEST mode with YOUR test key: a single 1.00 test payment.

    set STRIPE_TEST_KEY=sk_test_...        (in your own window; this script never prints it)
    python tools/check_stripe_live.py

What it does: asks this project's own client (`adapters/payments/client.py`) to make ONE payment of
1.00 USD with Stripe's published test card token. It prints only whether the call worked, the
payment id Stripe returned, its status, and whether Stripe said `livemode: false`. It prints no
key, no header and no raw reply. A live key (anything not starting with `sk_test_`) is refused
before any request is made, so nothing real can be charged.

It calls the client directly, not through the gateway: it checks that Stripe test mode answers the
way the client expects, nothing more. Paste the output back to Claude.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from adapters.payments.client import (  # noqa: E402
    KEY_ENV,
    AuthRejected,
    Declined,
    NotTestMode,
    PaymentError,
    StripeTestClient,
    Unclear,
)


def main() -> int:
    if not os.environ.get(KEY_ENV):
        print(f"{KEY_ENV} is not set in this window, so nothing was called.")
        return 2
    client = StripeTestClient()
    try:
        client.check_key()
    except NotTestMode as exc:
        print(f"{exc}. Nothing was called.")
        return 2
    print(f"{KEY_ENV} is set and is a test key (not shown).")
    print("Asking Stripe test mode for one payment of 1.00 USD with the test card token...")
    try:
        payment = client.charge(
            amount_minor_units=100,
            currency="usd",
            description="Hascham live check (test money)",
            idempotency_key="hascham-check-" + uuid.uuid4().hex[:16],
        )
    except AuthRejected:
        print("FAILED: Stripe did not accept the key. Check that it is a current test key.")
        return 1
    except NotTestMode as exc:
        print(f"FAILED: {exc}")
        return 1
    except Declined as exc:
        print(f"FAILED: Stripe declined it ({exc}).")
        return 1
    except Unclear:
        print(
            "UNKNOWN: no clear answer. A test payment may or may not exist; check your dashboard."
        )
        return 1
    except PaymentError as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"OK: payment {payment.payment_id} status {payment.status} (livemode: false)")
    print("Done. This output holds no key. Paste it back.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
