# services/worker — lease, fencing, gateway host

**Status:** `TESTED` through the contract tests that drive it against a real PostgreSQL
(`tests/contract/test_gateway_trace.py`, `test_sse_and_lease.py`) and the adapter and tamper suites that run every
action through it. Not covered: more than one worker process at once outside those tests.
**Built in:** Step 3, Step 5 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-HKC-03, R-RUN-03, R-SVC-05, R-POL-04

Postgres lease with a monotonically increasing fencing token instead of Temporal. Untrusted for ledger integrity.

| File | What it does |
|---|---|
| `gateway.py` | The policy gateway: every action is decided before it is sent, and each decision is recorded. |
| `lease.py` | The lease and fencing token that stop a stale worker from writing. |
| `event_sink.py` | Sends events to the ledger service. |
| `approval_client.py` | Asks for, and relays, a person's signed approval. It never signs. |
