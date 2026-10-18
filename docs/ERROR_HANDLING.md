# Agent Black Box: Error Handling

**Version:** Draft 0.1
**Related:** `PROTOCOL.md` (sections 6, 11.4, 16), `DESIGN.md` (sections 7, 13), `DATABASE_AND_API_CONTRACTS.md`, `SECURITY.md`, `TESTING.md`
**Claim status:** `SPECIFIED`. Nothing here is `IMPLEMENTED` or `TESTED` for v10.

---

## 1. Principles

1. **Integrity fails closed.** If the signer, the ledger or a proof is in doubt, stop and say so. Never "fix" it silently.
2. **Never guess an outcome.** If a remote action may have happened, record `OUTCOME_UNKNOWN` and reconcile. Do not retry blindly.
3. **Missing is not pass.** Unavailable evidence is `UNKNOWN` or `INCOMPLETE`, never `PASS`.
4. **Advisory failures never block integrity.** ML, prompt guard and anomaly failures degrade the report, not the cryptographic result.
5. **No paid fallback.** When a budget is exhausted, stop; do not switch to another paid operation.
6. **One error shape.** Every API error has a stable `code`, a human message and a `request_id`.
7. **Errors never leak secrets.** Messages and logs are redacted.
8. **Record, then act.** Anything that matters is committed as an event before the next step depends on it.

## 2. Error classes

| Class | Examples | Default handling |
|---|---|---|
| Client error | Bad JSON, unknown field, size over limit, bad token | Reject with 4xx; nothing committed |
| Protocol violation | Wrong sequence, event after `RUN_FINISHED`, illegal state transition | Reject; log; do not retry |
| Integrity failure | Fork, root mismatch, corrupt signer state, digest mismatch | Fail closed; alert; manual recovery |
| Policy outcome | Action denied, approval required | Not an error. Recorded as `ACTION_BLOCKED` or `HUMAN_APPROVAL_REQUESTED` |
| Adapter failure | Browser crash, timeout, provider error | `ACTION_FAILED` or `OUTCOME_UNKNOWN` depending on certainty |
| Dependency outage | Database down, MinIO down, witness or anchor unreachable | Retry with backoff; degrade honestly |
| Budget or quota | TinyFish credits low or exhausted | Stop optional calls; record; no fallback |
| Verifier outcome | Unsupported version, missing artifact | Reported as a result (`UNSUPPORTED`, `INCOMPLETE`), not as a crash |
| Internal bug | Unhandled exception | 500 with `request_id`; no stack trace to client; alert |

## 3. API error format

All HTTP errors use `application/problem+json` (RFC 9457 style):

```json
{
  "type": "https://abb.example/errors/SEQUENCE_CONFLICT",
  "title": "Sequence conflict",
  "status": 409,
  "code": "SEQUENCE_CONFLICT",
  "detail": "Expected sequence 12 but received 14.",
  "request_id": "7f0c...",
  "retryable": false
}
```

- `code` is stable and documented below. Clients branch on `code`, not on `detail`.
- `retryable` tells clients whether the same request may be retried unchanged.
- `detail` never contains secrets, stack traces, file paths or SQL.
- The `type` URL is a placeholder until a docs site exists.

## 4. Error code catalog

### 4.1 Ingestion and API

| Code | HTTP | Retryable | Meaning |
|---|---|---|---|
| `UNAUTHENTICATED` | 401 | no | Missing or invalid token |
| `FORBIDDEN` | 403 | no | Token lacks the role or run scope |
| `NOT_FOUND` | 404 | no | Unknown run, event or artifact |
| `VALIDATION_FAILED` | 422 | no | Schema or field rule violated |
| `CANONICAL_FORM_INVALID` | 422 | no | Not strict canonical JSON (float, duplicate key, bad UTF-8) |
| `PAYLOAD_TOO_LARGE` | 413 | no | Over event or upload size limit |
| `UNKNOWN_EVENT_TYPE` | 422 | no | Event type not in the protocol |
| `SEQUENCE_CONFLICT` | 409 | no | Sequence not the next expected |
| `IDEMPOTENT_REPLAY` | 200 | n/a | Duplicate idempotency key; returns the original event |
| `RUN_FINISHED` | 409 | no | Run already finished; no more events |
| `ILLEGAL_TRANSITION` | 409 | no | Run-state transition not allowed |
| `STALE_FENCING_TOKEN` | 409 | no | Worker lease was taken over |
| `RATE_LIMITED` | 429 | yes, after `Retry-After` | Too many requests |
| `BACKPRESSURE` | 503 | yes | Ingestion queue full |
| `DEPENDENCY_UNAVAILABLE` | 503 | yes | Database or object store not reachable |
| `INTERNAL` | 500 | maybe | Unexpected error; see `request_id` |

### 4.2 Signer (from `PROTOCOL.md` 11.4)

| Code | Meaning | Handling |
|---|---|---|
| `UNAUTHORIZED` | Caller not authenticated for this stream | Fix credentials |
| `UNKNOWN_STREAM` | No state and no valid genesis | Send genesis |
| `BAD_GENESIS` | Genesis request invalid | Do not retry unchanged |
| `NOT_EXTENDING` | Result does not extend the previous checkpoint | Integrity alert |
| `SIZE_REGRESSION` | Would shrink the stream | Integrity alert |
| `FORK_DETECTED` | Conflicts with something already signed | Integrity alert, stop that stream |
| `BAD_APPEND_EVIDENCE` | Append data malformed | Do not retry unchanged |
| `ROOT_MISMATCH` | `expected_root` differs from the computed root | Integrity alert |
| `BAD_EVENT` | Event not strict canonical or wrong run | Fix and resend |
| `GAP_OR_OVERLAP` | Sequence not continuous from signer state | Resync from signer state |
| `RATE_LIMITED` | Signing rate limit | Retry later |
| `STATE_CORRUPT` | Signer state damaged | **Fail closed**; recovery ceremony |

### 4.3 Adapters, policy, budget

| Code | Meaning |
|---|---|
| `ADAPTER_TIMEOUT` | Adapter did not finish in time; outcome may be unknown |
| `ADAPTER_CRASH` | Adapter process died |
| `ADAPTER_BAD_RESPONSE` | Provider response failed schema checks |
| `PROVIDER_QUOTA_EXHAUSTED` | Provider quota or credits are gone |
| `BUDGET_RESERVE_REACHED` | Local reserve threshold hit; optional calls stop |
| `PAYMENT_KEY_NOT_TEST_MODE` | The payment key is not a Stripe TEST key; refused before policy and before any request |
| `PAYMENT_KEY_MISSING` | No payment test key is set; nothing was attempted |
| `ENRICHMENT_NOT_RUN` | Web enrichment was not run (for example no TinyFish key); the alert says so, it is not a verdict |
| `POLICY_DENIED` | Deterministic deny (recorded as `ACTION_BLOCKED`) |
| `APPROVAL_REQUIRED` | Waiting for a signed approval |
| `APPROVAL_EXPIRED` | Approval used after `expires_at` |
| `APPROVAL_MISMATCH` | Approval's action or summary digest does not match |
| `MANDATE_VIOLATION` | Action outside the signed mandate |

### 4.4 Artifacts

| Code | Meaning |
|---|---|
| `ARTIFACT_DIGEST_MISMATCH` | Bytes do not match the digest; artifact marked `CORRUPT` |
| `ARTIFACT_MISSING` | Object not in storage |
| `UPLOAD_INCOMPLETE` | Temporary upload never finalized; cleaned up |
| `MEDIA_TYPE_REJECTED` | Type not allowed |

## 5. Recovery by failure point

The key crash windows (from v9 §20):

| Crash or failure | State left behind | Recovery |
|---|---|---|
| After artifact upload, before metadata commit | Orphan object in temporary area | Cleanup job removes it; the action is retried from the idempotency key |
| After metadata commit, before event commit | Artifact row with no event | Reconciler either commits the `ARTIFACT_CAPTURED` event (same idempotency key) or marks the row abandoned |
| After event commit, before outbox delivery | Event exists, SSE or workflow not told | Outbox poller redelivers; consumers are idempotent |
| After events committed, before checkpoint | Run in `FINALIZING` | Finalizer resumes and asks the signer for the checkpoint; signer returns the identical checkpoint if already signed |
| Signer signed, response lost | Signer state ahead of the caller | Caller resends; signer returns the stored identical checkpoint (idempotent) |
| Checkpoint signed, global append not done | Run in `CHECKPOINTED` | Append to global log retried; `EXPORTED` is blocked until done |
| Worker dies mid-action | Action state unknown | New worker takes lease with a higher fencing token; if the remote effect is uncertain, record `OUTCOME_UNKNOWN` |
| Database failover or restore | Possibly older state | Signer and witnesses detect a smaller tree; stop, compare with anchors, run `abb verify-global` |

## 6. Retry rules

- **Retry only when safe:** read-only calls, idempotent writes with the same idempotency key, and actions the adapter marks `retryable` **and** that have no uncertain remote effect.
- **Never retry** an irreversible or non-idempotent remote action after a timeout or crash. Record `OUTCOME_UNKNOWN`, reconcile (check the remote state), then decide.
- Backoff: exponential with jitter, capped; maximum attempts per operation type set in config.
- Retries reuse the **same** idempotency key.
- A stale worker (lower fencing token) must stop at once; its writes are rejected with `STALE_FENCING_TOKEN`.
- Retries are bounded by the run's timeout and the budget guard.

## 7. Degraded modes

| Situation | Behavior | What the receipt shows |
|---|---|---|
| Prompt classifier unavailable | Deterministic checks only | `classifier_available = false` |
| Anomaly model unavailable | Rules baseline only, or none | `behavior_anomaly_assessment = UNKNOWN` |
| Witness unreachable | Run completes; global checkpoint pending witness | `witness_quorum` is `UNKNOWN` (optional in `LOCAL_ONLY`, required in `CONNECTED_EVIDENCE`) |
| Anchor publication fails | Retry later; do not block runs | `anchor_match = UNKNOWN` |
| TinyFish unreachable or out of credit | Stop TinyFish operations; no fallback to another paid path | Run fails or is `OUTCOME_UNKNOWN`; budget event recorded |
| MinIO down | New artifact capture fails; events that need an artifact wait | `artifact_availability = UNKNOWN` |
| Database down | API returns `DEPENDENCY_UNAVAILABLE`; workers pause | None; nothing is committed |
| Signer down | Runs queue in `FINALIZING`; events still commit | Receipt export waits |
| Signer state corrupt | **No signing** until recovery | Export blocked; alert |

## 8. Run-level outcomes

| Outcome | When | Final state |
|---|---|---|
| Success | All actions completed and finalized | `EXPORTED` |
| Policy blocked | Deterministic deny before dispatch | `POLICY_BLOCKED` |
| Cancelled | User or timeout cancelled | `CANCELLED` |
| Failed | Unrecoverable error with known state | `FAILED` |
| Unknown outcome | A remote effect may have happened | `OUTCOME_UNKNOWN`, then reconciled or finalized with the unknown stated |

Every terminal run still gets a final event and a checkpoint, so even a failed run has a verifiable record.

## 9. Verifier and CLI errors

The verifier reports problems as **results**, not crashes. It never stops at the first failure and fills every dimension it can (`PROTOCOL.md` 16).

CLI exit codes:

| Code | Meaning |
|---|---|
| 0 | `VALID` |
| 1 | `INVALID` |
| 2 | `INCOMPLETE` |
| 3 | `PARTIAL` |
| 4 | `UNSUPPORTED` |
| 64 | Usage error (bad arguments) |
| 65 | Input unreadable or rejected before verification (too large, bad archive) |
| 70 | Internal verifier error (a bug; report it) |

Malformed input must produce a clear result or code 65, never a panic.

## 10. What users see

- Messages say what happened, what it means and what to do. They never show stack traces, paths or secrets.
- Integrity problems are shown plainly: "The record does not match its signature at event 12." with the event ID.
- `UNKNOWN` and `NOT_INDEPENDENT` have their own visual state; they are never shown as green.
- A blocked action shows the rule that blocked it (policy ID and version) and how to request approval.
- Unknown-outcome runs show what could not be confirmed and the reconciliation status.

## 11. Logging and alerting

- Structured logs with `request_id`, `run_id`, `event_id` and error `code`. Secrets and sensitive fields redacted.
- Alert immediately on: `FORK_DETECTED`, `ROOT_MISMATCH`, `STATE_CORRUPT`, `NOT_EXTENDING`, `SIZE_REGRESSION`, repeated `UNAUTHENTICATED`, disk space low, budget reserve reached.
- Operational logs are separate from the evidence ledger.

## 12. Testing the error paths

Every code in section 4 needs at least one test, and every row of section 5 needs a fault-injection test. See `TESTING.md` sections 6 and 7.
