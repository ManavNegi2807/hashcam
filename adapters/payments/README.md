# adapters/payments — local mock payment gateway

**Status:** Local-only simulation. No Stripe integration, API key, card data, external HTTP request, or real money is used. The mock supports deterministic success, decline, and uncertain outcomes; default demo behavior is success. Idempotency keys prevent duplicate simulated charges within a client instance.

| File | What it does |
|---|---|
| `client.py` | `MockPaymentClient`: in-process local payment simulation with amount/currency validation, a hard ceiling, idempotency, and selectable outcomes. |
| `adapter.py` | Every simulated payment passes the gateway first (policy `company-spend`: auto up to 50.00, signed approval over 50.00 up to 500.00, refused above). The gateway records simulated outcomes. |

Run: `python tools/demo_pay.py ...` (`docs/DEMO.md`, "Company payments with fake money"). The dashboard still requires an approver key for the human approval flow; the mock gateway itself requires no credentials.
