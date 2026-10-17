# TinyFish capability spike

**Status (2026-10-17):** `MEASURED` for the items marked so below, from **two live runs**
(plus wallet reads) made through the session's TinyFish connector with the user's
approval (cap $1). The project's own Python client (`adapters/tinyfish/http_client.py`) was then run
**once for real** by the user with their own `TINYFISH_API_KEY` (see "First run of the
project's client" below). One successful run is a smoke test, not a guarantee.

Two runs are a small sample. Nothing below is a guarantee about the service.

## What was run

| | Run 1 | Run 2 |
|---|---|---|
| Start URL | `https://example.com` | `https://example.com` |
| Goal | read the page heading | read the first sentence |
| `num_of_steps` | 6 | 3 |
| Result | `Example Domain` | the documentation sentence |
| Wallet after | $15.904 | $15.856 |

Wallet before the first run: **$15.00**. Rate card read from `GET /v1/wallet`: Agent
**$0.016 per step**, Browser $0.002 per minute, Fetch / Research / Search $0, Monitor
$0.005 per run.

## `R-TFY-08` items

| Item | Answer | Basis |
|---|---|---|
| Per-step records | `steps[]` with an `action` text and links to a screenshot / HTML. **No page URL and no event type per step.** The adapter records the text as `reported_by_adapter` and says the page URL was not reported | `MEASURED` (2 runs) |
| Actual credit use per operation | **Agent: steps x $0.016.** Run 2: 3 steps, wallet fell $0.048 = 3 x $0.016 exactly. **The run response carries no usage or cost field**, so cost is derived from `num_of_steps` and the wallet rate | `MEASURED` on run 2; run 1 is not usable (below) |
| Balance reliability | After run 1 the balance **rose** to $15.904 from $15.00 although 6 steps cost about $0.096. A credit of about $1.00 was apparently added in between; its cause is unknown. A wallet-delta-only meter would have read negative spend. The client therefore uses `max(steps x rate, wallet drop)` and never a rise | `MEASURED` once; cause `UNKNOWN` |
| Errors and cancellation | Documented, not triggered live: 400 `INVALID_INPUT`, 401 `MISSING_API_KEY`/`INVALID_API_KEY`, 403, 429 `RATE_LIMIT_EXCEEDED`, billing codes `BILLING_FAILURE`/`BILLING_REJECTED`. Cancel exists for async/SSE runs only (`POST /v1/runs/{id}/cancel`), not for synchronous `/run` | from the published docs; **not observed** |
| Quotas and rate limits | Numbers **UNKNOWN** (the docs name the error, not the limit) | |
| Artifact availability and retention | Screenshot/HTML links are returned; **how long they live is UNKNOWN** | |
| Timestamp semantics | `created_at`, `started_at`, `finished_at` exist; clock source and precision **UNKNOWN** | |
| Pre-execution gating: can an action be held back before it runs? | **No such control found** in the documented request fields. The caller can restrict the start URL and cap steps and duration; it cannot approve each action. So TinyFish stays **`STEP_OBSERVED` at most** | published docs; **not disproved live** |
| Evidence-retention terms | **UNKNOWN** | |
| Spend of this spike | About **$0.144** by the step rate (9 steps); the wallet itself also moved by the unexplained credit | `MEASURED` |

## What was built

`adapters/tinyfish/http_client.py` (standard library only):

* key read **only** from the environment variable `TINYFISH_API_KEY`, sent only as the
  `X-API-Key` header; never printed, logged, stored or placed in an error message;
* only the **agent** operation is live; `search_fetch` raises `NotSupported`;
* each run sends hard caps (`agent_config.max_steps`, `max_duration_seconds`); our own
  deadline cancels the run and the outcome is recorded `OUTCOME_UNKNOWN`, never retried;
* 429 is surfaced as `RateLimited` with `Retry-After`, never retried; billing errors end the
  attempt with no fallback;
* the policy gateway judges the **start URL** before anything is sent.

`adapters/tinyfish/adapter.py` adds opt-in, the $15 ceiling with a $3 reserve (kept across
restarts), and records the provider execution id, `usage` as integers and the time seen.

## What is tested, and what is not

* `TESTED` against a local fake that follows the **published** shapes: 17 tests in
  `tests/adapter/test_tinyfish_http.py` (cost rule, balance rise, key handling, 429, billing,
  failed run, deadline and cancel, unsupported operation, end-to-end through the adapter),
  with two deliberate mutations of the cost rule caught.
* **`MEASURED` once** (user run, 2026-10-17): the client and the `tools/demo_tinyfish.py` receipt
  path against the real service, one successful run, receipt `VALID`.
* **`UNVERIFIED`**: the real error bodies (only one failure was seen, see below); the step cap
  (`--step-cap`); behavior under rate limits, timeouts and cancel.

## Coverage claim

TinyFish stays `STEP_OBSERVED` at most (`R-COV-04`, `R-COV-06`, `D-14`). The steps it reports
are its own words (`reported_by_adapter`). A valid receipt shows the record is unchanged, not
that TinyFish did what it says.

## First run of the project's client (user, 2026-10-17)

* **Attempt 1:** refused before any work (client mapped it to `AUTH_FAILED`; the provider code was
  not shown, so the cause was not recorded). The wallet read with the same key had worked.
  Nothing was charged. The client at that time always sent `max_steps`, which the docs say
  needs beta access (else 403 FORBIDDEN). **The cause is a hypothesis, not confirmed.**
* **Attempt 2** (no `max_steps` sent; 60 s duration cap and our deadline only): `SUCCEEDED`, the
  provider answered with the page sentence; recorded spend rose from $0.15 to $0.20 (5 cents,
  consistent with 3 steps x $0.016 rounded up, but the step count was not printed); 12 events,
  receipt `VALID`, coverage `STEP_OBSERVED`. The agent said the page has no formal heading,
  which is the provider's own reading.
* Consequence: by default there is **no provider-enforced step cap**; cost is bounded by the
  duration cap, our deadline and the budget ceiling, not by a step limit.

## To make the first run from this project

1. Set `TINYFISH_API_KEY` yourself in your own shell or Windows environment. Do not paste it
   into chat or a file.
2. `python tools/demo_tinyfish.py --dsn ...` (dry run: prints the worst-case cost and calls
   nothing), then add `--yes-spend` to make one real call (about 8 cents at the defaults).
3. Replace the `UNVERIFIED` lines above with what the run shows.

## Runs that never start work (2026-10-18)

`MEASURED` from TinyFish's own run records (read-only, through the connector):

* Five agent runs about **Manchester** (start pages `example.com` and the Manchester article on
  `en.wikipedia.org`) stayed `RUNNING` with **0 steps** until this project's 90-second deadline
  cancelled them. A sixth, made through the connector with the same goal and **no deadline**,
  was still `RUNNING` with no step count after 4 minutes and was cancelled by hand.
* A run about **Spain** (start page `example.com`) finished in 29 s with 4 steps and a full answer.
* None of the cancelled runs cost anything visible: the wallet balance did not move
  ($17.744 before and after the 4-minute test).
* **Cause: UNKNOWN.** Waiting longer did not help in the one test made. Whether the topic matters,
  or the service was stuck, is not known; six runs is a small sample.
* Cost note from the wallet's rate card: the browser is billed per minute ($0.002) and the agent per
  step ($0.016). A run with 0 steps showed no charge in the one case measured.
