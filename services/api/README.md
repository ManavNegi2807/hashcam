# services/api — one FastAPI service (control plane + ingestion + SSE)

**Status:** `TESTED` for the endpoints listed below, against a real PostgreSQL.
**Built in:** Step 3 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-HKC-01, R-DAT-01..06, R-PRO-04/05, R-RUN-01, R-RUN-03,
R-SVC-01/02/03/05, and the ingestion error codes of `ERROR_HANDLING.md` 4.1.

Hackathon cut (`D-13`): ingestion lives inside this service rather than a
separate Litestar process. The split waits for a benchmark that shows it is
needed (`R-SVC-04`) — no throughput figure is claimed anywhere.

## Endpoints that exist

| Method and path | Role | Notes |
|---|---|---|
| `GET /api/v1/health` | none | Liveness. Returns no configuration, DSN or token |
| `GET /api/v1/ready` | none | Checks the database; `DEPENDENCY_UNAVAILABLE` when it is down |
| `POST /api/v1/runs` | operator, admin | Creates a run and its stream head |
| `GET /api/v1/runs/{run_id}` | any valid token in scope | Run detail |
| `POST /api/v1/runs/{run_id}/events` | adapter, operator, admin | Propose one event |
| `GET /api/v1/runs/{run_id}/events` | in scope | Cursor pagination, `limit` up to 200 |
| `GET /api/v1/runs/{run_id}/stream` | in scope | SSE; resumes with `Last-Event-ID` |

Everything else in `DATABASE_AND_API_CONTRACTS.md` Part B — artifacts,
approvals, mandates, receipts, verification, the global log, the key manifest,
admin tokens — is **absent**, not stubbed. An endpoint that cannot do its job
yet would otherwise return something that looks like an answer.

## How an event becomes bytes

1. The adapter POSTs a body with `event_type`, `source`, `provenance`,
   `payload` and optionally `artifact_refs`, `policy_ref`, `commitments`,
   `created_at` or `x_*` fields.
2. The service locks the run's stream head `FOR UPDATE`, reads the next
   sequence, and mints an `event_id`.
3. The **raw body** plus those assigned fields go to `abb event canon`
   (`core/abb-event`). The Rust core canonicalizes and validates; the service
   never parses the event JSON itself. That is why a duplicate key or a float
   in the body is still refused — a permissive Python parse would have hidden
   both.
4. The returned canonical bytes and leaf hash are stored verbatim, together
   with the head update, the idempotency row and the outbox row, in **one**
   transaction.

The cost is one subprocess per event. It is the deliberate trade of this cut; a
PyO3 binding to the same crate replaces it later, never a second JCS.

## Rules a reader should be able to rely on

* The producer cannot choose `sequence`, `run_id`, `event_id`,
  `protocol_version` or `schema_version`; supplying a conflicting value is a
  422, not a silent override (`PROTOCOL.md` 5.3).
* A duplicate `Idempotency-Key` returns the original event with
  `IDEMPOTENT_REPLAY` and HTTP 200, and is served even to a worker whose lease
  was taken over, because a replay changes nothing.
* A fencing token below the current one is refused with `STALE_FENCING_TOKEN`
  (`R-RUN-03`).
* Nothing follows `RUN_FINISHED`, enforced in the transaction and again by a
  database trigger.
* An out-of-scope request is `403` whether or not the run exists, so a scoped
  token cannot probe which runs are real.
* Every response carries `X-Request-Id`. Errors use the `problem+json` shape of
  `ERROR_HANDLING.md` 3 and never contain SQL, a path or a traceback.
* This service holds no signer key and signs nothing (`R-SIG-01`).

## Running it

```bash
ABB_DB_DSN=postgresql://abb@127.0.0.1:5432/abb \
ABB_BIN=core/target/debug/abb \
uvicorn services.api.main:build --factory
```

Both variables are required; neither has a default, and a missing one is an
error rather than a guess.

## Known gaps

* No rate limiting or backpressure yet, so `RATE_LIMITED` and `BACKPRESSURE`
  are defined in `errors.py` but never returned.
* The outbox is written but nothing drains it; SSE reads committed events
  directly. A poller arrives with the worker slice.
* SSE polls the database every 50 ms by default. `LISTEN`/`NOTIFY` would be
  better and is not done.
* No TLS, no CORS policy, no auth beyond bearer tokens in the database.
