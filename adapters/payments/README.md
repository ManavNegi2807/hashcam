# adapters/payments — pay bills with fake money (Stripe test mode)

**Status:** `TESTED` against a local stand-in that imitates the shape of Stripe's reply (`tests/adapter/test_payments.py`): policy tiers, the order (never sent before the gateway allows), a live key refused, no retries. It says nothing about how real Stripe test mode behaves. One real test-mode call is a manual check
(`tools/check_stripe_live.py`) and is `UNVERIFIED` until you run it with your own key. No real money, ever: the project's rules forbid it.

| File | What it does |
|---|---|
| `client.py` | A Stripe client that can only spend TEST money: a key without a test prefix is refused before any request; every reply must say `livemode: false`; a hard ceiling no policy can raise; idempotency keys. The key comes from `STRIPE_TEST_KEY` and is never printed or stored. |
| `adapter.py` | Every payment passes the gateway first (policy `company-spend`: auto up to 50.00, signed approval up to 500.00, refused above). |

Run: `python tools/demo_pay.py ...` (`docs/DEMO.md`, "Company payments with fake money").
