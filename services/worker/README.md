# services/worker — lease, fencing, gateway host

**Status:** `SPECIFIED`. Empty slice — no code here yet.
**Built in:** Step 3, Step 5 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-HKC-03, R-RUN-03, R-SVC-05, R-POL-04

Postgres lease with a monotonically increasing fencing token instead of Temporal. Untrusted for ledger integrity.
