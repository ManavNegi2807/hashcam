# Agent Black Box: Testing

**Version:** Draft 0.1
**Related:** `REQUIREMENTS.md`, `PROTOCOL.md` (section 17), `DESIGN.md` (section 19), `SECURITY.md` (section 15), `ERROR_HANDLING.md`
**Claim status:** the plan is `SPECIFIED`. Today only the Python **prototype** has tests: 21 pytest tests pass (canonicalization, chain, verify, masking, guard). No v10 capability is `TESTED`.

---

## 1. Purpose and rules

1. A capability is **not** labeled `TESTED` until an automated or reproducible test proves it (v9 §20, §22).
2. A benchmark or evaluation result is `MEASURED` only with a recorded run (data, command, date, version).
3. Every requirement in `REQUIREMENTS.md` has at least one test or an explicit "manual review" note.
4. Every bug fix adds a test that fails before the fix.
5. Tests never use real secrets, real money, or real personal data.
6. Tests are deterministic. Randomness uses a recorded seed.

## 2. Test layers

| Layer | What | Tools (proposed) | When it runs |
|---|---|---|---|
| Unit | Pure functions: JCS, hashing, tree, proofs, policy rules, guards | `cargo test`, `pytest` | Every commit |
| Property | Merkle proofs for any tree size; JCS round-trips; ordering | `proptest` (Rust), `hypothesis` (Python) | Every commit |
| Conformance vectors | Fixed inputs and outputs shared by Rust and Python | JSON vector files, `abb vectors check` | Every commit |
| Contract | HTTP endpoints, DB constraints, signer API against `DATABASE_AND_API_CONTRACTS.md` | `pytest` with a real PostgreSQL (testcontainers), `schemathesis` or similar against the OpenAPI file | Every commit |
| Integration | Service chain: API, ingestion, signer, MinIO, exporter, verifier | Docker Compose `testing` profile | Pull request |
| Fault injection | Crashes between steps, dependency outages, restore | Scripted kill and network faults | Nightly and before release |
| Tamper suite | Every way to alter history, caught by the verifier | Dedicated test module | Every commit |
| Concurrency | Many writers per run, stale workers | `pytest` with threads/async, DB locks | Pull request |
| Fuzz | Verifier and parsers on malformed input | `cargo-fuzz`, `atheris` | Nightly |
| Adapter | Replay, Playwright gating, TinyFish behavior | `pytest`, Playwright, recorded provider responses | Replay and mocked: every commit. Live: manual |
| Security | Section 9 | Mixed | Pull request and release |
| ML evaluation | Baselines versus models | Notebooks or scripts with recorded outputs | On change |
| UI | Screens and accessibility | Playwright, axe | Pull request |
| End to end | The demo script | One scripted run | Before release |

## 3. Conformance vectors (first thing to build)

Created before production receipts are emitted (`PROTOCOL.md` section 17). Stored in `vectors/` as JSON. Rust and Python must produce identical results.

| Set | Cases |
|---|---|
| JCS | Key order, Unicode escapes, number rejection (floats, NaN, huge ints), duplicate keys, lone surrogates, nesting limit |
| Hashing | Each domain tag with a known input; leaf and node hashes |
| Merkle | Sizes 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17; inclusion and consistency proofs for each; malformed proofs |
| Checkpoints | Genesis, extension, equal-size replay, regression, fork, wrong key, key rotation |
| Manifest | Valid chain, broken link, wrong digest |
| Global log | Runs 1 to 5 appended, deleted run, altered root, injected run root |
| Field commitments | Correct disclosure, wrong salt, wrong value, reused salt, shredded salt |
| Approvals and mandate | Valid and invalid signatures, wrong `summary_digest`, expired, out-of-mandate host, over `max_actions` |
| Receipts | Valid, modified event, bad signature, bad consistency proof, missing artifact, unknown version, truncated, malformed |
| Verifier statuses | One receipt for each overall result and for each cell of the required-dimension table that can change it |

Example values in `PROTOCOL.md` are placeholders. Real vectors come from the reference implementation and are then frozen.

## 4. Tamper suite (the core promise)

Each case builds a valid receipt or database, applies one change, and asserts the verifier result and the **named broken point**.

| # | Change | Expected |
|---|---|---|
| TS-01 | Edit one byte of one event | `evidence_integrity` `FAIL`, event named |
| TS-02 | Reorder two events | `FAIL`, sequence named |
| TS-03 | Delete one event from the middle | `FAIL` (gap) |
| TS-04 | Truncate the tail after a checkpoint | `consistency` or `evidence_integrity` `FAIL` |
| TS-05 | Insert an event | `FAIL` |
| TS-06 | Change a checkpoint root | `checkpoint_signatures` `FAIL` |
| TS-07 | Replace a checkpoint with an older one (rollback) | Signer, witness or anchor mismatch |
| TS-08 | Fork: two different histories with the same prefix | `FORK_DETECTED` at signer; verifier flags |
| TS-09 | Swap an artifact file | `artifact_manifest_integrity` `FAIL` |
| TS-10 | Break a manifest link | `FAIL` |
| TS-11 | Delete a whole run | `abb verify-global` reports the gap |
| TS-12 | Alter a run root in the global log | `global_log_inclusion` `FAIL` |
| TS-13 | Wrong key in the key manifest | `checkpoint_signatures` `FAIL` |
| TS-14 | Forged approval signature | `policy_assessment` `FAIL` |
| TS-15 | `STEP_GATED` run with a dispatch that has no authorization | `observation_coverage` `FAIL` |
| TS-16 | Tamper the receipt container (path traversal, nested zip, zip bomb) | Rejected before verification, exit 65 |

## 5. Contract tests

- Every table in `DATABASE_AND_API_CONTRACTS.md` Part A has tests for its constraints: unique `(run_id, sequence)`, rejected `UPDATE`/`DELETE` on `events`, illegal state transitions, fencing token rule, manifest chain.
- Every endpoint in Part B has tests for: success, each error code in `ERROR_HANDLING.md` it can return, auth and role checks, idempotency, pagination, and the SSE resume with `Last-Event-ID`.
- The OpenAPI document is generated from the code and compared with the contract file in CI.
- CLI tests check exit codes and JSON output stability.

## 6. Storage and concurrency tests

- Concurrent writers to one run: sequence is gap-free and unique.
- Duplicate delivery with the same idempotency key returns the same event.
- A stale worker (lower fencing token) cannot commit.
- Crash between artifact upload, metadata commit, event commit and checkpoint: recovery matches `ERROR_HANDLING.md` section 5.
- Deleting or modifying rows, transaction rollback, backup restore and whole-database rollback are each detected or handled as specified.
- Artifact corruption and missing-object cases.

## 7. Fault injection

Run against the `testing` Compose profile. Each row of `ERROR_HANDLING.md` section 5 and section 7 has a scripted fault:

kill the worker mid-action; kill ingestion between commit and outbox; kill the signer after state write; drop the network to MinIO; take the witness offline; fill the disk; corrupt the signer state file (expect fail closed); restore an older database dump (expect detection).

Pass condition: no committed history is lost or silently changed, every unknown outcome is recorded, and degraded modes are shown honestly.

## 8. Signer and witness tests

- Arbitrary-root signing attempt: rejected (`ROOT_MISMATCH`).
- Gap, overlap, reordered sequence, event after `RUN_FINISHED`, wrong `event_type`: rejected with the right code.
- Idempotent replay returns the identical checkpoint.
- State corruption: signer fails closed; recovery ceremony restores.
- Global stream: a run root without a matching signer-signed checkpoint is rejected.
- Witness extension check; quorum with one witness down; two witnesses in one `failure_domain` give `NOT_INDEPENDENT`.

## 9. Security tests

The checklist in `SECURITY.md` section 15 becomes automated tests where possible: SSRF (private IPs, redirects, DNS rebinding), token scope, secret leakage scan of logs and images, non-root container check, archive attacks, and authorization boundaries. Tenant isolation tests are required before any multi-tenancy is enabled.

## 10. Adapter tests

| Adapter | Tests |
|---|---|
| Replay | Deterministic output for the same scenario; always labeled `REPLAY` |
| Local Playwright | Navigation, clicks, form submits, downloads and network requests all pass the gateway; **bypass attempts** (direct requests, popups, new tabs, service workers) are blocked or lower the declared coverage. `STEP_GATED` is not claimed until these pass |
| TinyFish | Mocked responses for quota exhaustion, timeout, malformed response, provenance fields; a hard check that no paid fallback happens when the budget is exhausted. Live tests only inside the $15 plan and only when opted in |

## 11. ML and security module evaluation

- **Semantic invariants:** each invariant has known-good and known-bad regression traces and points to the failing event range. Missing steps give `UNKNOWN`.
- **Prompt guard:** deterministic checks tested on attacks and on benign hard negatives (security docs, quoted injections, code blocks, legitimate system-prompt examples). Report false positives and false negatives. The classifier, if ever enabled, is evaluated the same way after license review.
- **Anomaly auditor:** rules baseline first. Split by scenario family and time. Report precision, recall, false-positive rate, calibration where relevant, and per-scenario results. Do not call scores probabilities unless calibrated. Any result is `MEASURED` only with the recorded run.
- **Circularity check:** a test asserts policy outcomes are not model features.
- **Isolation check:** disabling ML must not change any cryptographic result or authorization decision.

## 12. UI tests

Playwright tests for the dashboard, run explorer, receipt viewer and approval screen. Checks: every verifier dimension is shown, `UNKNOWN` and `NOT_INDEPENDENT` are not rendered as green, escaping of event content, keyboard navigation, contrast 4.5:1, visible focus, reduced-motion support. The UI never decides validity; tests assert it only displays verifier output.

## 13. CI pipeline

| Stage | Contents | Blocks merge |
|---|---|---|
| Lint and types | `ruff`, `mypy`, `cargo clippy`, `cargo fmt --check`, `eslint`, `tsc` | Yes |
| Unit, property, vectors | Rust and Python | Yes |
| Contract | With PostgreSQL and MinIO containers | Yes |
| Tamper suite | Section 4 | Yes |
| Security scan | Secret scan, `pip-audit`, `cargo audit`, `npm audit`, image scan | Yes (high severity) |
| Integration | Compose `testing` profile | Yes |
| Fuzz | Short run per commit, long nightly | Nightly |
| Fault injection | Nightly and release | Release |
| End to end demo | Script in section 15 | Release |

## 14. Release gates (v9 §20, plus the review additions)

A release requires all of:

- [ ] Conformance vectors pass in Rust and Python; CLI and WASM agree (if WASM is shipped).
- [ ] Tamper suite TS-01 to TS-16 passes.
- [ ] Signer tests pass, including fail-closed on corrupt state.
- [ ] Concurrency, idempotency and fencing tests pass.
- [ ] Fault-injection suite passes and restore from backup is verified.
- [ ] Security checklist passes; no secrets in logs, receipts or images.
- [ ] Playwright bypass tests pass for any run labeled `STEP_GATED`.
- [ ] No paid fallback when the TinyFish budget is exhausted.
- [ ] Fresh checkout starts with Docker Compose and shuts down cleanly.
- [ ] Claims in the README and demo match the claims ledger.
- [ ] License review done for every dependency and model.

## 15. End-to-end demo test

The demo script from `PRODUCT_REQUIREMENTS.md` section 9, automated:

1. Start from a fresh checkout with one command.
2. Run a replay scenario that needs approval; sign the approval.
3. Export and verify the receipt: `VALID`, coverage stated.
4. Edit one event: `INVALID`, event named.
5. Swap one artifact: integrity `FAIL`.
6. Delete a run: `abb verify-global` flags it.
7. Check that the acceptance criterion in the architecture (section 23) holds.

## 16. Test data

- Replay scenarios and fixtures are synthetic and committed.
- No real personal data; fake names and numbers only; test card or wallet values are clearly fake and testnet only.
- Keys used in tests are generated per run or are committed test-only keys marked as such and never reused elsewhere.
- Recorded provider responses are scrubbed of secrets before they are committed.

## 17. Coverage and metrics

- Track line and branch coverage for Rust crypto and the ingestion service; target to be set after the first benchmark, not claimed in advance.
- Track mutation testing on the Merkle and verifier code if time allows.
- Record fuzzing runtime and corpus size.
- Test results go in the claims ledger: `SPECIFIED` → `IMPLEMENTED` → `TESTED`, with a link to the passing CI run.

## 18. Current state and first tests to write

| Item | State |
|---|---|
| Prototype tests (canon, chain, verify, mask, guard) | 21 pass; they test the prototype, not v10 |
| v10 vectors, tamper suite, contract tests | Not written |

Suggested order: (1) JCS and hashing vectors, (2) Merkle tree and proofs with property tests, (3) checkpoint and signer tests, (4) tamper suite on a Replay run, (5) global log and `verify-global`, (6) contract tests as the API appears.
