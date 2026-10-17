# Agent Black Box: Implementation Plan (hackathon build)

**Version:** Draft 0.1
**Date:** 2026-10-15
**Authority order:** `PROTOCOL.md` wins over every other document, then `AGENTS.md` rules, then `DESIGN.md`, then the rest.
**Claim status:** see the progress line below and the claims ledger in section 7. Statuses are per capability, not per plan.

## Progress

| Step | State | Evidence |
|---|---|---|
| 0 | **Done except Docker** (25) | The prototype came from `Agent_Black_Box_Project.zip` in Downloads (the archive of the first request had not included it). Its own suite is **21 passed** (the claim is now confirmed) and **25 passed** after Step 0 (3 for parameter logging, 1 for the launcher). `.dockerignore`, a ledger launcher, compose wiring (signing key only on the `ledger` service, ports local-only, non-root) and parameter logging (digest plus masked values) are written. **`docker build` and the secrets-not-in-image check were never run: no Docker daemon** |
| 0b | **Done** | `pytest -q tests/security` → 19 passed |
| 1 | **Done** | `pytest -q tests/contract` → 43 passed; `mypy --strict` clean; vector regeneration byte-identical |
| 2 | **Done** | `cargo test --workspace` → 89 passed (incl. 7 property tests); `cargo fmt --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean; `abb vectors check` → **141 passed, 0 failed**; six mutated vectors each caught |
| 3 | **Done** | `pytest -q` → 105 passed against a real PostgreSQL 18.4; `ruff check`, `ruff format --check` and `mypy` clean. Compose files written but **never run** (no Docker daemon available) |
| 4 | **Done** | `cargo test --workspace` → 150 passed (34 of them the signer, 2 for `abb attest`); `pytest -q` → 126 passed, incl. 13 HTTP contract tests against the running binary and 4 fault tests; `ruff`/`mypy`/`cargo fmt`/`cargo clippy -D warnings` clean; compose isolation check → OK |
| 5 | **Done** | `python tools/demo.py` runs the whole path and exits 0; `pytest -q tests/tamper` → 14 passed (TS-01..06, TS-12, TS-16, coverage honesty); `abb verify` on an untouched receipt → `VALID`, exit 0 |
| 6 | **Done except MinIO** | `pytest tests/tamper tests/contract/test_artifact_store.py` → passes; the demo swaps an artifact and `abb verify` names it by digest; the manifest head is bound into the signed checkpoint. **No MinIO backend exists**: no Docker daemon and no MinIO binary were available, so artifacts use a local content-addressed store behind the same interface |
| 8 | **Done, independence not demonstrable on one machine** | witness (own key, own anti-rollback state, rebuilds the tree before signing) and append-only anchor file implemented; `witness_quorum` / `anchor_match` verified; 10 witness/anchor tests pass; the demo shows a rollback the local check cannot see and the anchor can |
| 9 | **Done** | Rust: `abb approve`, `abb approval check`, `abb mandate sign/check`, `abb commit`; `cargo test --workspace` → 228 passed (52 new, incl. 33 verifier tests; four rules mutation-checked); `abb vectors check` → **190 passed** (49 new: approvals, mandate, commitments; the 10 earlier sets byte-identical). Python: relay, mandate gate, redaction at ingestion, crypto-shredding; `pytest tests/tamper/test_approvals_mandate.py` → **27 passed** against the real signer, API, PostgreSQL and verifier (TS-14 included) |
| 7 | **Done for HTTP(S) and WebSocket; the claim is measured, not assumed** | `tests/adapter` (gating, bypass, SSRF): 14 bypass probes against a local site, each also shown to be stopped by the policy layer alone and by the SSRF layer alone; negative controls (an ungated adapter, an adapter without WebSocket gating) are caught and fall to `STEP_OBSERVED`. `tools/demo_playwright.py` declares `STEP_GATED` only after the battery passes and records its digest as `evidence_ref`. The battery found a real hole in the first version (redirect hops were not routed); fixed and pinned by a test. **Not covered:** WebRTC and other transports; DNS rebinding between check and fetch is `UNVERIFIED` |
| 10 | **Done, with a plain-HTML dashboard** | semantic monitor (4 invariants, known-good/bad/unobserved traces), deterministic prompt guard (`MEASURED` on a 57-item hand-written corpus only: `docs/PROMPT_GUARD_EVAL.md`), verifier support for both, dashboard with browser tests incl. axe in light and dark. **Deviation:** the dashboard is static HTML, **not** Next.js/shadcn (question Q19). A bug caught on the way: the monitor read the worker's private event list, which lacked the control plane's approval event, and reported a false failure on a correct run; it now reads the ledger |
| 11 | **Done; TinyFish integrated, first project-client run pending the user's key** | anomaly rules (policy outcomes are never an input; failure is contained), replay drift, a real TinyFish HTTP client (`adapters/tinyfish/http_client.py`: key only from `TINYFISH_API_KEY`, agent operation only, step and time caps, cancel on our deadline, no retry, no fallback) behind the opt-in adapter ($15 ceiling, $3 reserve, cost = steps x per-step rate cross-checked with the wallet). `docs/TINYFISH_SPIKE.md`: two live runs through the session connector (about $0.14): cost law `MEASURED`, per-step records have no page URL, no usage field, one unexplained +$1 balance credit. The client is `TESTED` against a local fake of the published API only; run once live by the user (one success, receipt `VALID`; step cap `UNVERIFIED`). No model exists, so `R-ANO-06..08` are not met |

Step 1 deviation from the plan as written, worth knowing: the plan said the vector
*expectations* would be filled in by the Rust core in Step 2. Instead a documented Python
reference generator (`vectors/tools/`) produced them now, and the self-check tests verify
them through independent algorithms (iterative frontier, RFC 6962 proof verification,
signature verification). `AGENTS.md` 3.10 allows exactly this one second implementation,
for the test-vector cross-check. Step 2's Rust core must reproduce the frozen bytes; until
it does, cross-language agreement stays `UNVERIFIED`.

---

## 0. What I read, and what is missing

Read in full (Phase 0), from `docs/`: `README.md`, `AGENTS.md`, `PRODUCT_REQUIREMENTS.md`, `Agent_Black_Box_Final_Architecture_v10.md`, `PROTOCOL.md`, `DESIGN.md`, `REQUIREMENTS.md`, `DATABASE_AND_API_CONTRACTS.md`, `SECURITY.md`, `ERROR_HANDLING.md`, `TESTING.md`. All 11 documents are present.

**Missing, and this blocks part of Step 0:**

| Expected by the brief | Status here |
|---|---|
| `AGENT_NOTES.md` | **Not present.** Not in the archive. |
| Prototype code: `ledger/`, `agent/`, `guard/`, `payment/`, `ui/`, `tests/` | **Not present.** The archive contains documents only. |
| `requirements.txt`, `Dockerfile`, `docker-compose.yml`, `secrets/` | **Not present.** |
| `pytest -q` (expected: 21 tests pass) | **Not run.** There is no code and no test file to run. I will not state a test result I did not produce. |

Consequence: the "21 passing tests" claim cannot be confirmed from this workspace, and Step 0 (prototype fixes: `.dockerignore`, ledger launcher, compose wiring, log action params) cannot be executed until the prototype tree is supplied. See question Q1 and Step 0 below for the two options.

---

## 1. Scope for this build

### 1.1 In scope (the hackathon cut, `DESIGN.md` 3.1, order from 20.1)

| Concern | What we build |
|---|---|
| API, ingestion, SSE | **One FastAPI service** with an ingestion module (`R-HKC-01`) |
| Database | **Plain PostgreSQL**, ordinary tables, forward-only migrations (`R-HKC-02`) |
| Orchestration | **Postgres lease + fencing token** in the worker, same safety rules as Temporal (`R-HKC-03`, `R-RUN-03`) |
| Crypto core | **Rust library + `abb` CLI**, including `abb verify-global` (`R-CRY-06`, `R-GLB-05`) |
| Signer | **Separate signer service** that recomputes roots from a stored frontier (`D-12`, `R-SIG-01`..`13`) |
| Global log | Stream `global`, run-root leaves, `abb verify-global` (`D-10`, `R-GLB-01`..`06`) |
| Artifacts | **MinIO**, content-addressed, hash-linked manifest bound into the checkpoint (`R-ART-01`..`07`, `R-DAT-08`..`12`) |
| Adapters | **Replay** (default, deterministic), then **local Playwright** with real bypass tests (`R-ADP-01`..`04`, `R-COV-03`) |
| Policy | Deterministic versioned policy gateway in the dispatch path (`R-POL-01`..`06`) |
| Receipts | `*.abbreceipt` ZIP export + offline CLI verifier with all 16 dimensions (`R-REC-01`..`05`) |
| Tamper demo | Edited event, swapped artifact, deleted run (`R-HKC-07`, TS-01..TS-16) |
| Witness + anchor | One witness on a **second device** + append-only **Git anchor** file (`D-10`, `D-15`, `R-WIT-03`..`05`) |
| Approvals | Signed approvals, then signed mandate, then field commitments (`D-16`, `D-11`) |
| Advisory channels | Semantic invariants, deterministic prompt guard (classifier off), rules-only anomaly baseline (`D-17`, `D-18`) |
| Dashboard | Next.js audit dashboard, five separate channels, receipt viewer (`R-UI-01`..`05`) — **UI tool choice is question Q9, asked before any UI code** |
| TinyFish | Capability **spike only**, `STEP_OBSERVED` at most, hard $15 budget cap (`R-TFY-01`..`10`, `D-14`) |

### 1.2 Deferred (explicitly out of this build)

Temporal, the Litestar split, TimescaleDB hypertables, IPFS, the WASM verifier, any trained ML model (Isolation Forest / supervised), multi-tenancy, the ONNX prompt classifier, mainnet or real money, and the optional payment extension unless you say otherwise (question Q4). Each sits behind an interface so full v10 can be added without a protocol change (`R-HKC-06`).

Deferred does **not** mean undocumented: `REQUIREMENTS.md` rows for deferred items stay `SPECIFIED` and the claims ledger (section 7) shows them as such.

### 1.3 Rules that bind every step

- Secrets are read from files or environment variables and are never printed, logged, committed or embedded in an image or receipt (`AGENTS.md` 3.14–3.16).
- `TESTED` only with a passing test in the same change; `MEASURED` only with a recorded run (`AGENTS.md` 3.1).
- No crypto is invented. JCS (RFC 8785), SHA-256, RFC 6962 tree hashing, pure Ed25519, fixed domain tags, integers only, exact canonical bytes stored (`AGENTS.md` 3.6–3.13).
- The signer computes roots itself; API, worker and adapters never hold the signer key.
- ML, anomaly and prompt-guard output is advisory. Only deterministic policy blocks or authorizes.
- Missing evidence is `UNKNOWN` or `INCOMPLETE`, never `PASS`. `STEP_GATED` only after bypass tests pass. TinyFish is `STEP_OBSERVED` at most.
- No protocol semantics change without a new `D-nn`, new vectors and your approval.

---

## 2. Target repository layout

```
core/            Rust workspace: abb-jcs, abb-merkle, abb-checkpoint, abb-verify, abb-cli (binary `abb`)
signer/          Separate signer service (Rust, reuses core; own key volume, no DB role)
services/api/    One FastAPI service: control plane + ingestion module + SSE + exporter
services/worker/ Lease/fencing worker, policy gateway host, adapter driver
adapters/        replay/, playwright/, tinyfish/
policy/          Deterministic policy engine + versioned policy documents
security/        semantic/, prompt_guard/, anomaly/   (all advisory)
ui/              Next.js dashboard (after Q9 is answered)
vectors/         Conformance vectors, shared by Rust and Python
deploy/          docker-compose.yml, profiles, .dockerignore, migrations
tests/           contract/, integration/, tamper/, fault/, security/
docs/            The 11 documents + this plan
prototype/       The existing Python prototype, kept runnable, not migrated in place (D-09)
```

---

## 3. Implementation steps (slices)

Each step: goal, requirement and decision IDs, files, tests written **first**, an acceptance command, risks and what the step does **not** cover, and size.

### Step 0 — Prototype fixes and repo hygiene

**Goal.** Make the existing prototype safe to build and run, and create the empty v10 skeleton, without touching protocol code.

**Covers.** `R-OPS-03`, `R-OPS-05`, `R-POL-03` (action params recorded), `R-SYS-06`, `D-09`, `AGENTS.md` 3.14–3.16.

**Files.**
- `prototype/.dockerignore` — must exclude `secrets/`, `*.db`, `*.pem`, `.env`, `shots/`, `__pycache__/`, `.git/`.
- `prototype/docker-compose.yml` — add the ledger service, its launcher command, health check, non-root user, named volumes; keep ports local.
- `prototype/ledger/__main__.py` (or equivalent launcher) — start the ledger with keys read from a mounted path; never echo key material.
- `prototype/agent/run_step.py` — log the action parameters (digest plus masked values) so a decision is reconstructable; masking via the existing `ledger/mask.py`.
- New empty skeleton: the directories in section 2 with a `README` stub each.
- `.gitignore`, `deploy/.dockerignore`.

**Tests first.**
- `tests/security/test_dockerignore.py`: build context file list contains no path under `secrets/`, no `*.pem`, no `.env`.
- `tests/security/test_no_secret_in_logs.py`: run a prototype step with a fake key and assert the captured log and stdout contain neither the key bytes nor any `-----BEGIN`.
- `tests/contract/test_action_params_logged.py`: a recorded step carries `params_digest` and masked params; raw card/OTP/password values never appear.
- Re-run the prototype suite unchanged — no test may be weakened (`AGENTS.md` 3.23).

**Acceptance check.**
```bash
pytest -q prototype/tests tests/security tests/contract
docker build -f prototype/Dockerfile prototype/ -t abb-prototype:dev && docker run --rm abb-prototype:dev ls -a /app | grep -c secrets   # expect 0
```
Success = all tests pass (the prototype's own count reported as the real number, whatever it is) and the `grep -c` prints `0`.

**Risks and gaps.** **Blocked:** the prototype tree is not in this workspace (section 0). Two options — (a) you supply the prototype repository and I do Step 0 as written; (b) I do Step 0b only (skeleton, `.gitignore`, `deploy/.dockerignore`, CI lint scaffold) and the prototype fixes move to whenever the code arrives. Not covered: any v10 behavior; the prototype stays a demo and is not migrated (`D-09`).

**Size.** Small (0b alone: small).

---

### Step 1 — Protocol freeze slice + conformance vectors

**Goal.** Freeze the parts of `abb/1` used first (JCS, hashing and domain tags, Merkle tree and proofs, checkpoints, global-log leaves) as machine-readable vectors before any implementation depends on them.

**Covers.** `R-PRO-01`..`R-PRO-09`, `R-CRY-01`, `R-CRY-02`, `R-TST-01`, `R-REC-11`, `D-01`, `D-03`, `D-06`, `D-10`.

**Files.**
- `vectors/jcs/*.json` — key order, Unicode escapes, non-BMP ordering (the UTF-16 code-unit rule that the prototype's `sorted()` gets wrong), float/NaN/huge-integer rejection, duplicate keys, lone surrogates, nesting and size limits.
- `vectors/hashing/*.json` — every domain tag in `PROTOCOL.md` 4 with a fixed input: `ABB1-EVENT`, `ABB1-CHECKPOINT`, `ABB1-MANIFEST`, `ABB1-WITNESS`, `ABB1-KEYROTATE`, `ABB1-RUNROOT`, `ABB1-FIELD`, `ABB1-APPROVAL`, `ABB1-MANDATE`; plus leaf `0x00` and node `0x01` hashes and the untagged artifact digest (`D-03`).
- `vectors/merkle/*.json` — tree sizes 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17; inclusion and consistency proofs for each; malformed proofs (index ≥ size, wrong path length, non-hex, extra elements).
- `vectors/checkpoint/*.json` — genesis, extension, equal-size idempotent replay, size regression, fork, wrong key, rotation record.
- `vectors/global/*.json` — runs 1..5 appended, altered run root, injected root.
- `vectors/README.md` — how a vector is generated and frozen.
- `docs/PROTOCOL.md` — status line for the frozen subset, and the open items it closes.

**Tests first.** The vectors *are* the tests. Added now, consumed by Steps 2 and 3:
- `tests/contract/test_vectors_shape.py` — every vector file parses, has `input`, `expect`, and a `protocol_version`, and no vector contains a float.
- A deliberately failing placeholder runner (`abb vectors check` does not exist yet) so the red state is visible before Step 2.

**Acceptance check.**
```bash
pytest -q tests/contract/test_vectors_shape.py
python -c "import json,glob; print(len(glob.glob('vectors/**/*.json', recursive=True)))"
```
Success = shape tests pass and the count matches the table in `TESTING.md` 3 for the frozen sets.

**Risks and gaps.** Expected values must come from a reference implementation, so Step 1 and Step 2 are partly circular: the first pass writes inputs and the rule being tested, Step 2 fills expectations, and the vectors are then frozen and never silently edited (`AGENTS.md` 3.24). Open item from `PROTOCOL.md` 20 that this step must answer: the exact byte layout of the signer `append` batch and the request digest used by `caller_attestation` — that is **not** covered here and moves to Step 4, which needs a decision (question Q7). Not covered: receipt-level vectors (Step 5), approvals/mandate/commitment vectors (Step 9).

**Size.** Medium.

---

### Step 2 — Rust core and `abb` CLI

**Goal.** One Rust core implementing JCS, SHA-256 domain-separated hashing, the RFC 6962 tree, proofs, checkpoints, Ed25519 and the receipt verifier, exposed through the `abb` CLI, passing every Step 1 vector.

**Covers.** `R-CRY-01`..`R-CRY-06`, `R-PRO-02`, `R-PRO-03`, `R-PRO-06`, `R-REC-02`..`R-REC-05`, `R-REC-07`, `R-GLB-05`, `R-TST-01`, `D-01`, `D-04`, `D-05`, `D-19`.

**Files.**
- `core/abb-jcs/` — RFC 8785 serializer + strict parser (integer-only, duplicate-key rejection, UTF-8 and surrogate validation, size/depth limits).
- `core/abb-merkle/` — `MTH`, inclusion and consistency proofs, frontier type, malformed-proof rejection.
- `core/abb-checkpoint/` — payload layout, signing bytes, `checkpoint_hash`, chain rules, key manifest and rotation records.
- `core/abb-verify/` — the 16 dimensions, the per-profile required/optional table, overall-result precedence.
- `core/abb-cli/` — `abb canon`, `abb merkle root|proof|verify`, `abb keygen`, `abb vectors check`, `abb verify`, `abb verify-global` (`verify-global` wired to a real database in Step 3; here it reads a file of run roots).
- `core/Cargo.toml` with pinned dependencies; license check recorded (`AGENTS.md` 3.11 / question Q5).

**Tests first.**
- `cargo test` unit tests per crate, driven by `vectors/`.
- `proptest`: inclusion proof verifies for every `(size, index)` up to 256; consistency proof verifies for every `first ≤ second`; JCS round-trip is a fixed point.
- Negative tests: no panic on any malformed input (fuzz seed corpus from the malformed vectors) — the verifier must return a result or exit 65, never a panic (`ERROR_HANDLING.md` 9).
- Cross-language check: a thin Python harness reads the same vectors and must agree byte-for-byte (`R-CRY-06` applies to Rust-only crypto; the Python side is a *checker*, not a second implementation).

**Acceptance check.**
```bash
cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace
abb vectors check            # expect: all vectors pass, exit 0
pytest -q tests/contract/test_vector_crosscheck.py
```
Success = clean lint, all Rust tests pass, `abb vectors check` exits 0, cross-check passes.

**Risks and gaps.** JCS number formatting and non-BMP sorting are the classic failure points; they get dedicated vectors. Crate choice is open (question Q5: `ed25519-dalek` vs `ring`, JCS crate vs hand-rolled, and the license of each). Not covered: anything touching the database, the signer service, or receipts built from real runs.

**Size.** Large.

---

### Step 3 — Plain PostgreSQL + one FastAPI service (ingestion, lease, fencing, SSE)

**Goal.** A single FastAPI service that validates, canonicalizes and commits events atomically, serializes writers per run, enforces fencing, and streams committed events over SSE.

**Covers.** `R-HKC-01`..`R-HKC-03`, `R-DAT-01`..`R-DAT-06`, `R-PRO-04`, `R-PRO-05`, `R-RUN-01`, `R-RUN-03`, `R-SVC-01`..`R-SVC-05`, `R-TST-02`, all ingestion error codes in `ERROR_HANDLING.md` 4.1.

**Files.**
- `deploy/migrations/0001_init.sql` — every table in `DATABASE_AND_API_CONTRACTS.md` A2, the append-only trigger on `events`, the legal-transition trigger, the A3 invariants, the A4 roles and grants, the A5 indexes.
- `services/api/main.py`, `routes_runs.py`, `routes_events.py`, `routes_sse.py`, `ingest.py`, `canonical.py` (calls the Rust core over a thin binding or subprocess — no second crypto implementation), `errors.py` (RFC 9457 shape), `auth.py` (bearer tokens, roles, run scope).
- `services/worker/lease.py` — Postgres lease with a monotonic fencing token.
- `deploy/docker-compose.yml` — `core` profile: postgres, api, worker. Ports local only, non-root, health checks.

**Tests first (contract tests, real PostgreSQL via testcontainers).**
- Unique and gap-free `(run_id, sequence)` under 20 concurrent writers.
- `UPDATE`/`DELETE` on `events` rejected by the trigger and by the role grant.
- Illegal run-state transition rejected (`ILLEGAL_TRANSITION`).
- Lower fencing token rejected (`STALE_FENCING_TOKEN`).
- Duplicate `Idempotency-Key` returns the original event (`IDEMPOTENT_REPLAY`, HTTP 200).
- Event after `RUN_FINISHED` rejected (`RUN_FINISHED`, 409).
- Non-canonical input rejected: float, `NaN`, duplicate key, bad UTF-8, oversize (`CANONICAL_FORM_INVALID`, `PAYLOAD_TOO_LARGE`).
- `canonical_bytes` stored byte-identical to `abb canon` output for the same event (this is the `R-PRO-04` test).
- Event row + head update + outbox row commit atomically; killing the process mid-transaction leaves none of them.
- SSE sends only committed events and resumes correctly from `Last-Event-ID`.
- Token scope: an adapter token cannot read another run (`SECURITY.md` 15).

**Acceptance check.**
```bash
docker compose -f deploy/docker-compose.yml --profile core up -d
pytest -q tests/contract -k "ingest or events or sse or fencing or idempotency"
```
Success = all listed contract tests pass against a real PostgreSQL, and `GET /health` returns 200 with no secret in the body.

**Risks and gaps.** `FOR UPDATE` serialization is a throughput limit; we do **not** benchmark or tune here (`R-SVC-04` stays `SPECIFIED`). Not covered: signing, checkpoints, artifacts, receipts, policy decisions.

**Size.** Large.

---

### Step 4 — Separate signer that recomputes roots

**Goal.** An isolated signer with its own key volume and no database role, which rebuilds the root from canonical event bytes and its stored frontier, validates everything in `PROTOCOL.md` 11.2, persists state durably, and fails closed.

**Covers.** `R-SIG-01`..`R-SIG-13`, `R-GLB-02`, `R-CRY-03`, `R-CRY-05`, `R-OPS-03`, `D-12`, all signer codes in `ERROR_HANDLING.md` 4.2.

**Files.**
- `signer/src/main.rs` — `POST /sign`, `GET /state/{stream_id}`, `GET /health`; nothing else.
- `signer/src/state.rs` — hash-chained append-only state log per stream `{stream_id, tree_size, root_hash, checkpoint_hash, key_id, transition_metadata}`; durable write before response.
- `signer/src/validate.rs` — the nine checks of `PROTOCOL.md` 11.2 in order, plus `caller_attestation` verification and rate limiting.
- `services/api/signer_client.py` — the only caller; sends canonical event bytes, never a root.
- `deploy/docker-compose.yml` — signer on its own network and key volume, not mounted anywhere else.
- `docs/PROTOCOL.md` 11.1 — fill in the exact `append` batch byte layout and the request digest (needs question Q7).

**Tests first.**
- Arbitrary-root attempt: caller sends `expected_root` that differs → `ROOT_MISMATCH`, nothing signed.
- Caller sends only leaf hashes, no events → rejected (`BAD_APPEND_EVIDENCE`).
- Gap, overlap, reordered sequence, unknown `event_type`, event after `RUN_FINISHED`, wrong `run_id` → the exact code from 4.2 each.
- Unknown stream without valid genesis → `UNKNOWN_STREAM` / `BAD_GENESIS`.
- Non-extending or smaller tree → `NOT_EXTENDING` / `SIZE_REGRESSION`.
- Fork (two different histories, same prefix) → `FORK_DETECTED` (tamper case TS-08).
- Empty batch → identical stored checkpoint returned (idempotent); response lost and resent → identical checkpoint again.
- Corrupt state file → signer refuses to sign, exits non-zero on the signing path, logs `STATE_CORRUPT`; it never resets (fault case from `TESTING.md` 7).
- Global stream: a run-root record whose checkpoint is not in the signer's own state log → rejected (`R-GLB-02`).
- Secret test: the signer's logs, responses and `/health` never contain key bytes.
- Compose test: the key volume is not mounted into api, worker or ui.

**Acceptance check.**
```bash
cargo test -p abb-signer
pytest -q tests/contract/test_signer_api.py tests/fault/test_signer_state_corrupt.py
docker compose config | python tools/check_key_volume_isolation.py   # expect: OK
```
Success = every error code above is produced by its own test, idempotent replay returns the identical checkpoint, and the isolation check prints `OK`.

**Risks and gaps.** The `caller_attestation` digest layout is an open protocol item (Q7); choosing it wrongly means a vector rewrite. A single signer cannot defeat theft of its host plus backups — documented, not fixed here (`R-SIG-06`, `SECURITY.md` 16). Not covered: witnesses, anchors (Step 8).

**Size.** Large.

---

### Step 5 — Replay adapter, policy gateway, receipt export, tamper demo

**Goal.** The first end-to-end path: a deterministic replay run that is policy-gated, finalized, checkpointed, appended to the global log, exported as a receipt, and verified offline — plus the tamper demo.

**Covers.** `R-ADP-01`..`R-ADP-04`, `R-POL-01`..`R-POL-06`, `R-COV-01`, `R-COV-02`, `R-COV-05`, `R-COV-07`, `R-REC-01`..`R-REC-06`, `R-GLB-01`, `R-GLB-03`, `R-GLB-04`, `R-HKC-07`, `R-CLM-04` (partly), `D-04`, `D-14`.

**Files.**
- `adapters/replay/` — scenario files (committed, synthetic), deterministic executor, always `mode = REPLAY`.
- `adapters/base.py` — the adapter contract of `DESIGN.md` 13.1 (all 12 fields).
- `policy/engine.py`, `policy/versions/default.v1.json` — allowlists, denylists, action constraints, domain restrictions, rate limits, approval gates, high-risk handling; decisions recorded with policy id/version, input digest, decision, reason codes.
- `services/worker/gateway.py` — the pre-dispatch gate: `ACTION_REQUESTED` → `ACTION_AUTHORIZED`/`ACTION_BLOCKED` → `ACTION_DISPATCHED`.
- `services/api/export.py` — `*.abbreceipt` ZIP builder (`receipt.json` JCS + `artifacts/`), bounded, no path traversal, no nested archives.
- `services/api/finalize.py` — freeze prefix, request checkpoint, append run root to `global`, block `EXPORTED` until the global checkpoint covers it.
- `tests/tamper/` — the TS suite harness.

**Tests first.**
- Replay determinism: same scenario twice → identical event bytes except the time claims, and identical root for a fixed clock (`R-ADP-04`).
- Coverage honesty: a `STEP_GATED` run where a dispatch has no earlier authorization → `observation_coverage = FAIL` (TS-15, `R-COV-07`).
- Tamper suite TS-01..TS-06, TS-09..TS-12, TS-16 against a real exported receipt, each asserting both the dimension result and the **named** broken point.
- Receipt vectors from `TESTING.md` 3: valid, modified event, bad signature, bad consistency proof, missing artifact, unknown version, truncated, malformed.
- Overall-result matrix: one receipt per `VALID` / `INVALID` / `INCOMPLETE` / `PARTIAL` / `UNSUPPORTED` (`D-05`, `D-19`).
- Exit codes 0/1/2/3/4/64/65 from the CLI (`ERROR_HANDLING.md` 9).
- A receipt contains no secret and no clear sensitive value.

**Acceptance check.**
```bash
python tools/demo_replay.py --scenario vendor_bank_update          # creates a run, finalizes, exports
abb verify out/run-<id>.abbreceipt --profile LOCAL_ONLY --json     # expect overall VALID, exit 0
python tools/tamper.py --event 3 && abb verify out/run-<id>.abbreceipt   # expect INVALID, event 3 named, exit 1
pytest -q tests/tamper
```
Success = `VALID` on the untouched receipt, `INVALID` naming event 3 after the edit, and the whole tamper suite green.

**Risks and gaps.** Artifacts are not yet real (Step 6), so `artifact_manifest_integrity` is `NOT_APPLICABLE` here and TS-09/TS-10 land in Step 6 if they need MinIO; the plan keeps them here only for the file-based path. Deleted-run detection (TS-11) needs a witnessed or anchored global checkpoint to be fully honest — in this step it compares against the signer's own state and is labeled as such; the independent version is Step 8. Not covered: approvals (Step 9) — the demo scenario's approval is recorded but not yet **signed**, and the receipt must say so.

**Size.** Large.

---

### Step 6 — MinIO artifacts and the manifest

**Goal.** Real artifact capture: content-addressed objects, digest verified after upload and before export, a hash-linked manifest whose head is bound into the signed checkpoint.

**Covers.** `R-ART-01`..`R-ART-07`, `R-DAT-08`..`R-DAT-12`, `R-PRO-07`, `D-03`.

**Files.** `services/artifacts/` (the single upload path), `deploy/docker-compose.yml` (MinIO, local ports, non-root), `services/api/export.py` (artifact folder, digest re-check), migration for `artifacts` / `manifest_entries` if not already present.

**Tests first.** Digest mismatch on upload → `ARTIFACT_DIGEST_MISMATCH`, row `CORRUPT`; missing object → `ARTIFACT_MISSING` and `artifact_availability = UNKNOWN` (never `PASS`); broken manifest link → `artifact_manifest_integrity = FAIL` (TS-10); swapped artifact file in the receipt → `FAIL` naming the entry (TS-09); crash between upload and metadata commit → orphan cleaned up, action retried on the same idempotency key; worker cannot overwrite an existing object; media type rejection.

**Acceptance check.**
```bash
docker compose --profile core up -d minio
pytest -q tests/contract/test_artifacts.py tests/tamper/test_artifact_swap.py
python tools/demo_replay.py --with-artifacts && abb verify out/run-<id>.abbreceipt   # expect VALID
```

**Risks and gaps.** A matching digest proves bytes, not genuineness — must be stated in the UI and receipt wording (`R-ART-07`). Not covered: object-lock or versioning (edition and license review first, `R-DAT-10`).

**Size.** Medium.

---

### Step 7 — Local Playwright with real gating and bypass tests

**Goal.** The only path that can honestly claim `STEP_GATED`: navigation, clicks, form submits, downloads and relevant network requests all pass the gateway before dispatch, proven by bypass tests.

**Covers.** `R-ADP-01`, `R-COV-03`, `R-COV-07`, `R-TST-04`, `D-14`, release gate "Playwright bypass tests pass".

**Files.** `adapters/playwright/` (CDP/route interception, one gateway chokepoint), `deploy/docker-compose.yml` `playwright` profile, `tests/adapter/test_playwright_gating.py`, `tests/adapter/test_playwright_bypass.py`, a local static test site under `tests/fixtures/site/`.

**Tests first.** Each in-scope action type produces `ACTION_REQUESTED` before any network effect; bypass attempts — direct `fetch` from page context, `window.open` popups, a new tab, a service worker, a redirect chain, a form target `_blank` — are either blocked or **downgrade** the declared coverage; a run that cannot gate everything must export `STEP_OBSERVED`, and a `STEP_GATED` claim with an ungated action must fail `observation_coverage`; SSRF cases (private IPs, redirects, DNS rebinding) blocked.

**Acceptance check.**
```bash
pytest -q tests/adapter/test_playwright_gating.py tests/adapter/test_playwright_bypass.py
python tools/demo_playwright.py && abb verify out/run-<id>.abbreceipt --json | python -c "import sys,json; d=json.load(sys.stdin); print(d['run']['declared_coverage'])"
```
Success = all bypass tests pass **and** the printed coverage matches what the bypass results justify. Until these pass, nothing is labeled `STEP_GATED` anywhere (`AGENTS.md` 3.4).

**Risks and gaps.** Browser escape surface is large; the honest outcome may be `STEP_OBSERVED`, and that is an acceptable result for this step. Not covered: headful human-in-the-loop flows, authenticated real sites.

**Size.** Large.

---

### Step 8 — Global-log witness on a second device + Git anchor

**Goal.** Make deleted-run detection independent: one witness with its own key and anti-rollback state on a second device, and an append-only anchor file in a public Git repository.

**Covers.** `R-GLB-04`..`R-GLB-06`, `R-WIT-01`..`R-WIT-10`, `R-HKC-05`, `D-10`, `D-15`, `D-02`.

**Files.** `witness/` service (own state, extension check before signing, `failure_domain`), `tools/anchor_git.py` (one line per global checkpoint: `tree_size`, `checkpoint_hash`, `published_at`), `core/abb-cli` (`verify-global` against a database and an anchor), `services/api/routes_global.py`.

**Tests first.** Witness refuses a non-extending checkpoint (`NOT_EXTENDING`), a fork (`FORK_DETECTED`), a regression (`SIZE_REGRESSION`); two witnesses sharing a `failure_domain`, or sharing it with the signer, give `witness_quorum = NOT_INDEPENDENT` — never `PASS`, never green (TS-07, `R-WIT-03`); anchor in the signer's own repository → `NOT_INDEPENDENT`; anchored `tree_size` larger than the receipt's log → `anchor_match = FAIL`; **delete a whole run** → `abb verify-global` names the missing run against the anchored root (TS-11); altered run root → `global_log_inclusion = FAIL` (TS-12); witness offline → `witness_quorum = UNKNOWN` (optional in `LOCAL_ONLY`, required in `CONNECTED_EVIDENCE`); Git commit time is not treated as a trusted timestamp (`R-WIT-09`).

**Acceptance check.**
```bash
python tools/demo_delete_run.py --run <id>
abb verify-global --db "$ABB_DB_URL" --anchor anchors/global.log   # expect: missing run <id> reported, exit 1
pytest -q tests/contract/test_witness.py tests/tamper/test_delete_run.py
```

**Risks and gaps.** With one witness the quorum of `D-02` (2-of-3) is not met; the honest report is `PARTIAL` / `NOT_INDEPENDENT`, and we must not describe the cut as meeting the quorum. Needs a second device and a public repository (questions Q10, Q11). Not covered: trusted timestamping, transparency-service anchors.

**Size.** Medium.

---

### Step 9 — Signed approvals, then signed mandate, then field commitments

**Goal.** Make "a human allowed exactly this action" a verifiable check, then "the agent stayed inside the mandate", then hide sensitive values without breaking proofs.

**Covers.** `R-APR-01`..`R-APR-08`, `R-CMT-01`..`R-CMT-07`, `R-REC-05`, `D-11`, `D-16`.

**Files.** `core/abb-cli` (`abb approve --request <id> --key <file>`), `services/api/routes_approvals.py` (relays signatures, never holds approver keys), `services/api/routes_mandates.py`, `policy/mandate.py` (mandate as a deterministic policy input), `services/api/ingest.py` (redaction before canonicalization, 16-byte CSPRNG salt per field per event, `field_disclosures` writes), `core/abb-verify` (`mandate_compliance`, disclosure recomputation), `vectors/approval/`, `vectors/mandate/`, `vectors/commitment/`.

**Tests first.** Valid approval verifies and gates dispatch; forged signature → `policy_assessment = FAIL` (TS-14); wrong `summary_digest` → `APPROVAL_MISMATCH`; dispatch after `expires_at` → `APPROVAL_EXPIRED`; approver key missing from the manifest with role `approver` → `FAIL`; out-of-mandate host and over `max_actions` → `MANDATE_VIOLATION` at the gateway **and** `mandate_compliance = FAIL` at the verifier; no mandate → `NOT_APPLICABLE`; commitment vectors: correct disclosure, wrong salt, wrong value, reused salt (rejected), **shredded salt** → leaf hash, inclusion proof and signatures all still valid while the dependent dimension reports `UNKNOWN` (`R-CMT-03`, `R-CMT-05`); a policy that hides a field a required offline check needs is rejected (`R-CMT-06`); the clear value never appears in `events`, logs or the receipt.

**Acceptance check.**
```bash
abb keygen --out keys/approver && python tools/demo_approval.py   # approver signs on a separate key file
abb verify out/run-<id>.abbreceipt --keys keys/manifest.json --json   # expect policy_assessment PASS
pytest -q tests/contract/test_approvals.py tests/contract/test_mandate.py tests/contract/test_commitments.py
```

**Risks and gaps.** A signed approval proves a key signed, not which human held it — wording fixed in docs and UI (`R-APR-08`). Approver client is CLI-first (question Q8). Not covered: WebAuthn/P-256 (a later protocol version), key custody for real approvers.

**Size.** Large.

---

### Step 10 — Semantic invariants, deterministic prompt guard, dashboard

**Goal.** The three advisory channels plus the audit dashboard that displays verifier output and nothing of its own.

**Covers.** `R-SEM-01`..`R-SEM-07`, `R-PIG-01`..`R-PIG-10`, `R-UI-01`..`R-UI-05`, `D-17`.

**Files.** `security/semantic/` (invariants + known-good/known-bad regression traces), `security/prompt_guard/` (deterministic checks and the `classify(input) -> verdict, score, reasons` adapter interface only — no vendored Prompt Chainmail code or model, `R-PIG-08`), `ui/` (Next.js dashboard, run explorer, policy view, receipt viewer, assessments, approval screen, global-log view).

**Tests first.** Each invariant has a known-good and a known-bad trace and names the failing event range; a missing or unobserved step gives `UNKNOWN`, never `PASS` (`R-SEM-04`); a semantic finding cannot grant permission and can only trigger a policy-defined escalation (`R-SEM-07`); prompt guard tested on attacks **and** benign hard negatives (security docs, quoted injections, code blocks) with false positives and negatives reported; `classifier_available = false` recorded while the classifier is off (`D-17`); guard verdict never authorizes (`R-PIG-05`); UI Playwright + axe tests: every dimension rendered, `UNKNOWN` and `NOT_INDEPENDENT` are **not** green, event content escaped, keyboard navigation, 4.5:1 contrast, visible focus, reduced motion; a test asserts the UI calls the verifier and never computes validity itself (`R-SVC-01`, `R-UI-04`).

**Acceptance check.**
```bash
pytest -q tests/security/test_semantic.py tests/security/test_prompt_guard.py
cd ui && npm run lint && npx tsc --noEmit && npx playwright test
```

**Risks and gaps.** **Before any UI code I must tell you which UI tools would help and ask which you want** (`AGENTS.md` 8 and the standing preference) — that is question Q9, and this step does not start until it is answered. Prompt-guard precision and recall are reported, not claimed. Not covered: the ONNX classifier (license review first), invariant mining.

**Size.** Large.

---

### Step 11 — TinyFish spike, replay drift, rules-only anomaly baseline

**Goal.** Learn what TinyFish can actually evidence, under a hard budget, and add two advisory extras.

**Covers.** `R-TFY-01`..`R-TFY-10`, `R-COV-04`, `R-COV-06`, `R-ANO-01`..`R-ANO-11`, `D-14`, `D-18`, `D-19`.

**Files.** `adapters/tinyfish/` (opt-in, budget guard, metering capture), `docs/TINYFISH_SPIKE.md` (the recorded findings), `security/anomaly/rules.py`, `tools/replay_drift.py`.

**Tests first (all mocked; live calls only on your explicit go-ahead).** Quota exhaustion → `PROVIDER_QUOTA_EXHAUSTED` and **no paid fallback**; reserve threshold → `BUDGET_RESERVE_REACHED` stops optional calls; timeout → `OUTCOME_UNKNOWN`, never a blind retry of an irreversible action; malformed provider response → `ADAPTER_BAD_RESPONSE`; `mode = LIVE_EXTERNAL` without `evidence_ref` declared `STEP_GATED` → `observation_coverage = FAIL` (`R-COV-06`); provenance fields recorded; circularity test: policy outcomes are not anomaly features (`R-ANO-05`); isolation test: disabling the anomaly module changes no cryptographic result and no authorization (`R-ANO-11`); replay drift reports added/removed/reordered actions as advisory only.

**Acceptance check.**
```bash
pytest -q tests/adapter/test_tinyfish_mocked.py tests/security/test_anomaly_rules.py
python tools/replay_drift.py --run-a <id> --run-b <id>
```
Live spike acceptance = `docs/TINYFISH_SPIKE.md` records each item of `R-TFY-08` with the real observed answer or an explicit `UNKNOWN`, plus the actual spend.

**Risks and gaps.** Needs a TinyFish key and your approval to spend (questions Q6, Q12). Until the spike proves pre-dispatch gating, TinyFish stays `STEP_OBSERVED` at most, and no ML result is labeled `MEASURED` without a recorded run. Not covered: any trained model.

**Size.** Medium.

---

### Step 12 — Deferred (not in this build)

Temporal, Litestar split, TimescaleDB telemetry, IPFS, WASM verifier, trained anomaly model, ONNX prompt classifier, multi-tenancy, the payment extension (unless Q4 says yes), hardening items in `SECURITY.md` 11–13 beyond what earlier steps test. Each stays `SPECIFIED` behind an interface.

---

## 4. Dependency and ordering graph

```
Step 0 (hygiene / prototype fixes)   ── independent, do first
Step 1 (vectors)  ──►  Step 2 (Rust core + CLI)
Step 2  ──►  Step 3 (Postgres + FastAPI)      [API needs abb canon for canonical bytes]
Step 2  ──►  Step 4 (signer)                  [signer reuses the core]
Step 3  ──►  Step 4                            [signer is called by the API]
Step 3 + Step 4  ──►  Step 5 (replay, policy, receipt, tamper)
Step 5  ──►  Step 6 (MinIO artifacts)
Step 5  ──►  Step 7 (Playwright gating)
Step 5 + Step 6  ──►  Step 8 (witness + anchor)
Step 5  ──►  Step 9 (approvals → mandate → commitments)
Step 5 + Step 9  ──►  Step 10 (semantic, prompt guard, dashboard)
Step 7 + Step 9  ──►  Step 11 (TinyFish spike, drift, anomaly rules)
```

(Q9 and Q12 were answered on 2026-10-17: design skills for the UI, replay-only for TinyFish.)

Hard blockers: nothing starts before Step 1 is frozen; Step 5 cannot start without both 3 and 4; Step 10's UI work cannot start before question Q9 is answered; Step 11's live calls cannot start before Q6 and Q12.

Parallelizable once Step 5 is green: 6, 7 and 9 touch mostly separate trees.

---

## 5. Demo checklist (`PRODUCT_REQUIREMENTS.md` 9)

| # | Demo beat | Minimum steps needed |
|---|---|---|
| 1 | Run a replay scenario that fills a form and needs approval | 1, 2, 3, 4, 5 (signed approval needs 9; without 9 the approval is recorded but unsigned and the receipt must say so) |
| 2 | Export the receipt, verify it: `VALID`, coverage stated honestly | 1, 2, 3, 4, 5 |
| 3 | Edit one event in the database, verify again: `INVALID`, event named | 5 (tamper harness) |
| 4 | Swap an artifact file: artifact integrity fails | 6 |
| 5 | Delete a whole run: `abb verify-global` flags the gap | 5 for the local version, **8** for the independently anchored version |
| 6 | Show a `STEP_OBSERVED` TinyFish-style run labeled as such | 11, and only if the spike is done |

**Must-demo path (smallest honest demo): Steps 1 → 2 → 3 → 4 → 5 → 6 → 8.** Beats 1–5 all work with those. Beat 1 becomes fully honest ("signed approval") only with Step 9, and beat 6 is optional.

Demo requirement from `R-CLM-04` / `PRODUCT_REQUIREMENTS.md` 10: fresh checkout to working demo in one command, under 10 minutes. That is a target to **measure**, not to claim.

---

## 6. Questions I need answered before I start

I am not guessing any of these.

| # | Question | Why it blocks |
|---|---|---|
| Q1 | **Where is the prototype code and `AGENT_NOTES.md`?** This workspace has documents only. Do you want (a) to supply the prototype repository so Step 0 runs as written, or (b) Step 0b (skeleton + hygiene only) and the prototype fixes later? | Step 0 cannot run; the "21 passing tests" claim is unconfirmed. |
| Q2 | **Project name.** "Agent Black Box" is a working title. Keep it for code, package and CLI names (`abb`)? | Crate, package, CLI and container names are hard to change later. |
| Q3 | **License** for the protocol, the verifier and the rest. The verifier is meant to be open so trust does not depend on you. | Needed before any dependency decision and before publishing. |
| Q4 | **Is the optional testnet payment extension in the demo?** (`D-08`, `R-EXT-01`..`05`) | Decides whether Step 12 stays deferred. |
| Q5 | **Rust crate choices and license tolerance.** Any crate with BSL / SSPL / AGPL / non-commercial terms is off unless you approve it (`AGENTS.md` 11). | Step 2 picks the Ed25519 and JCS crates. |
| Q6 | **Security contact / disclosure address.** Currently `TBD`. | Required before this repository is published. |
| Q7 | **Answered by D-20, pending your confirmation.** The signer `append` batch carries base64 canonical bytes, and `caller_attestation` signs `"ABB1-SIGNREQ" || 0x00 || JCS(request without the attestation)`. `ABB1-SIGNREQ` is a transport tag, not one of the nine protocol tags, so it does not bump `protocol_version`: the attestation never enters a receipt. Written up in `PROTOCOL.md` 11.1 and `signer/README.md`. Say if you want it different and I will change it with new vectors. | Implemented in Step 4. |
| Q8 | **Approver client:** CLI first, as `DESIGN.md` says? Or do you want the browser WebCrypto path in this build? | Step 9 scope. |
| Q9 | **UI tools.** Before any dashboard code I must ask which you want. Candidates I can use: an Artifact/HTML prototype for a fast clickable mock, a component library (shadcn/ui as the documents specify), a design-system generator, and a motion/animation helper. Which do you want, and do you want a static mock approved before the real Next.js build? | Step 10 does not start without your answer (standing preference, `AGENTS.md` 8). |
| Q10 | **Second device for the witness** — is one available (teammate's laptop, small VPS)? If not, the honest result is `NOT_INDEPENDENT` and I will label it that way. | Step 8's independence claim. |
| Q11 | **Public Git repository for the anchor**, and is it under the same administrator as the signer? (If yes → `NOT_INDEPENDENT`.) | Step 8. |
| Q12 | **TinyFish:** do you have a key and do you authorize spending against the $15 plan, with the allocation of `R-TFY-09` and a hard stop at the reserve? Live calls need your explicit go-ahead (`AGENTS.md` 11). | Step 11's live spike. |
| Q13 | **First pilot vertical** (finance back-office / compliance filings / IT operations) — only affects which replay scenario I write first. | Step 5 scenario content. |
| Q14 | **Do you want me to continue automatically through the steps, or stop for your go-ahead after each one?** The brief's default is stop after each. | Phase 2 cadence. |
| Q16 | **`psycopg` is LGPL-3.0.** It is the standard PostgreSQL driver for Python and is used as a library, which LGPL permits, but it is copyleft and your licence rules say to ask (`AGENTS.md` 11). Keep it, or switch to `pg8000` (BSD-3-Clause, pure Python)? The data layer is one module behind a DB-API interface, so the swap is cheap now and gets dearer later. | Licence posture and the dependency list. |
| Q15 | **New, found while building `abb-verify`: `PROTOCOL.md` 16.2 does not say what a *required* dimension that is `NOT_INDEPENDENT` makes the overall result.** `INCOMPLETE` is defined over `UNKNOWN` only, and `PARTIAL` requires every required dimension to be `PASS` or `NOT_APPLICABLE`. In `CONNECTED_EVIDENCE`, `witness_quorum` and `anchor_match` are required and can both be `NOT_INDEPENDENT`, so the case is reachable. I implemented it as `INCOMPLETE` (the independence evidence is missing) and wrote a test that says so, rather than deciding it silently. Confirm, or pick another result and I will record it as a decision with new vectors. | Affects the overall result of any `CONNECTED_EVIDENCE` receipt with same-domain witnesses. |
| Q18 | **New, found in Step 7: the receipt header's coverage was not coming from the run.** The exporter filled `declared_coverage` and `observed_coverage` from the run's *requested* coverage, so a run that declared `STEP_OBSERVED` showed `STEP_GATED` in its own receipt, and the check that declared may not exceed observed could never fire. Now the builder and the verifier both derive them from the signed events (last `COVERAGE_DECLARED`; lowest provenance `observed_coverage`), the header must match, and a run with no declaration is `UNKNOWN`. No byte or tag changes. Confirm this reading of `PROTOCOL.md` 7, or say how you want it. | Section 7 wording; affects every receipt's coverage line. |
| Q19 | **The dashboard is plain HTML, not the Next.js/React/Tailwind/shadcn stack `R-UI-01` names.** No `npm` download was approved, and a static page keeps the trusted surface small. Keep it, or do you want the Next.js build? | `R-UI-01` only; the SSE live view (`R-UI-03`) is also not built. |
| Q20 | **Two Playwright compromises.** (1) The WebSocket gate uses a private Playwright API, so `playwright==1.64.0` is pinned and an upgrade must rerun `tests/adapter`. (2) The probe browser runs with `--disable-features=LocalNetworkAccessChecks`, because that check only protects loopback targets and would make the self-test report "gated" for a hole it merely masks. Accept both? | Whether a Playwright upgrade is allowed without a human re-reading the bypass results. |
| Q17 | **New, found in Step 9: `R-CMT-05` has nothing to attach to.** It says a dimension that needs an undisclosed field must report `UNKNOWN`. Because `R-CMT-06` already forbids hiding any field a deterministic check reads, none of the 16 dimensions needs a hidden field. So the receipt reports the hidden fields as unknown content in `evidence_integrity` (a note, not a status change) and no dimension turns `PASS` because of them. Is that the intended reading, or should a hidden field downgrade some dimension? | Wording of `R-CMT-05`; no byte changes. |

---

## 7. Claims ledger

Status values: `SPECIFIED` (written down) · `IMPLEMENTED` (code exists) · `TESTED` (a test passes) · `MEASURED` (recorded run) · `UNVERIFIED`.

**As of Step 5 the demo works end to end.** A replay run is policy-gated, finalized by
the separate signer, appended to the global log, exported as a `*.abbreceipt` and verified
offline by `abb verify` with every required dimension `PASS`. Editing one event in the
receipt makes it `INVALID` and the verifier names that event by id and sequence; editing
the database and re-exporting makes it `INVALID` with one summary finding; deleting the
whole run makes `abb verify-global` report the gap.

What the demo still cannot show, and says so while running: no artifact (Step 6), no
*signed* approval (Step 9, so the gated action simply is not dispatched), and no witness
or anchor (Step 8), which means the deleted-run check compares against the local global
checkpoint rather than an independent one.

**As of Step 4** the signing path is `TESTED`: the signer recomputes roots from canonical
bytes, refuses an arbitrary root, keeps a hash-chained durable state log, fails closed on
a broken chain, refuses a second live process on the same state directory, and refuses a
run root it never signed. What that still does **not** give: no receipt exists, so nothing
is verifiable offline yet; no witness or anchor, so a rollback of this machine is not
detectable; and key rotation is not implemented. The claim "the signer prevents forks"
stays unmade — what is tested is that it refuses to sign a conflicting extension, which
is not the same as preventing a fork by an attacker who holds the host.

**As of Step 3** the ledger's write path is `TESTED` against a real PostgreSQL: canonical
bytes identical to the Rust core, a gap-free sequence under 20 concurrent writers, atomic
commit of event plus head plus outbox, fencing, idempotency, append-only triggers, legal
state transitions, token scope, and SSE resume. What is **not** established: the Compose
stack has never been started, there is no signer, no checkpoint, no receipt, so a stored
event is not yet signed evidence — only a correctly recorded one.

**As of Step 2** the cryptographic primitives are `TESTED` in the implementation that
ships (Rust), and the 141 frozen vectors pass in both Rust and Python, so cross-language
agreement for those sets is established. What that does **not** cover: there is no
signer service, no ingestion, no receipt, no WASM build and no database, so none of the
claims forbidden by `R-CLM-03` may be made — in particular not "the signer prevents
forks" (the chain *rules* are tested, the service does not exist), not "the system
detects rollback" (only a file-backed comparison is tested), and not "CLI and WASM
agree" (there is no WASM). Everything else below is `SPECIFIED`. A row moves only in the same change that produces the code or the passing test.

| Capability | Step | Status now | Moves to `IMPLEMENTED` when | Moves to `TESTED` when |
|---|---|---|---|---|
| JCS canonical encoding (RFC 8785) | 1, 2 | **TESTED** in Rust (`abb-jcs`), cross-checked in Python | `abb-jcs` exists | JCS vectors pass in `abb vectors check` |
| Domain-separated SHA-256 hashing | 1, 2 | **TESTED** in Rust (`abb-checkpoint::tags`), cross-checked | `abb-merkle`/hash module exists | hashing vectors pass |
| RFC 6962 Merkle tree + proofs | 1, 2 | **TESTED** in Rust (`abb-merkle`), incl. property tests to size 200 | tree code exists | all size vectors + proptest pass |
| Checkpoint signing (Ed25519) | 2, 4 | **TESTED** in Rust (`abb-checkpoint`); the signer service is still SPECIFIED | checkpoint crate exists | checkpoint vectors pass |
| Offline receipt verifier, 16 dimensions | 2, 5 | **TESTED**: `abb verify` reports all 16 dimensions and names the broken point; `VALID`/`INVALID`/`INCOMPLETE` exercised | — | receipt vectors (still to freeze) |
| `abb verify-global` | 2, 8 | **IMPLEMENTED file-backed, TESTED** (deleted run and anchor mismatch caught); no `--db` yet | `--db` form exists | TS-11, TS-12 on a real database |
| Exact canonical bytes stored (never rebuilt from JSONB) | 3 | **TESTED**: stored bytes compared byte-for-byte with `abb event canon` | — | — |
| One serialized writer, gap-free sequence | 3 | **TESTED**: 20 concurrent writers, sequence 0..19, no gaps | — | — |
| Fencing token stops a stale worker | 3 | **TESTED** end to end through the lease and the API | — | — |
| Idempotent event intake | 3 | **TESTED**, including a replay served to a taken-over worker | — | — |
| SSE with `Last-Event-ID` replay | 3 | **TESTED**: committed events only, resume after a sequence, close on `RUN_FINISHED` | — | — |
| Signer recomputes roots, refuses caller roots | 4 | **TESTED**: arbitrary root and digests-instead-of-bytes both refused | — | — |
| Signer fails closed on corrupt state | 4 | **TESTED**: edited, truncated and line-removed logs all stop the binary, which never resets itself | — | — |
| Fork / regression / gap rejection | 4 | **TESTED** in the signer: gap, overlap, reorder, wrong run, bad type, post-`RUN_FINISHED`, non-extending, regression, and a second live signer refused | validation exists | one test per error code passes |
| Deterministic replay adapter | 5 | **IMPLEMENTED and used by the demo**; a determinism test is still to write | — | repeated-run comparison |
| Deterministic versioned policy gateway | 5 | **TESTED** through the tamper suite and the demo: allow, deny and approval-gate paths all recorded with policy id, version and reason codes | — | — |
| Coverage labels honest (`STEP_GATED` rule) | 5, 7 | **Receipt-level check TESTED**: a dispatch without an earlier authorization fails `observation_coverage`, and over-claimed coverage fails. Playwright is still Step 7, so no live-browser `STEP_GATED` claim is made | bypass tests exist | Playwright bypass tests pass |
| Receipt export (`*.abbreceipt`) | 5 | **TESTED**: built by `abb receipt build`, container limits and TS-16 attacks covered | — | — |
| Tamper detection: edit / reorder / delete / insert / truncate | 5 | **TESTED**: TS-01 names the edited event by id and sequence; TS-02..06 caught | — | — |
| Global log of run roots | 5, 8 | **Vectors and `verify-global` TESTED**; the append path and database are SPECIFIED | `global_log` + append path exist | TS-11, TS-12, `R-GLB-02` test pass |
| Artifact provenance + manifest head in checkpoint | 6 | **TESTED** (TS-09, TS-10, removed manifest, missing files → `PARTIAL`); local store only, MinIO backend SPECIFIED | MinIO backend exists | — |
| Playwright `STEP_GATED` | 7 | **TESTED** for local HTTP(S) + WebSocket on one probe site; `STEP_GATED` is declared only when the self-test passes. Other transports and DNS rebinding are `UNVERIFIED` | a live run against a real third-party site | — |
| Independent witness | 8 | **Procedure and verifier TESTED**: refuses a root it cannot rebuild, a rollback, a fork, a non-prefix; same-domain → `NOT_INDEPENDENT`. **Real independence UNVERIFIED**: no second device was used | a witness runs on a different machine | — |
| Git anchor | 8 | **File and verifier TESTED** (mismatch, larger-than-log, shared domain → `NOT_INDEPENDENT`); pushed to a public repository **UNVERIFIED** (no repository supplied) | published to a repository under another administrator | — |
| Signed human approvals | 9 | **TESTED**: signed grant gates dispatch; forged signature, wrong summary, expired, missing signed statement, key missing from manifest, wrong role, signed denial then dispatch, replay of a decided approval. **A signature shows a key signed, not which person held it** | the approver client is a CLI; WebCrypto is not built | — |
| Signed mandate + `mandate_compliance` | 9 | **TESTED**: in-mandate passes; out-of-mandate action blocked at the gateway; a gateway that skipped the check is caught by the verifier and the action is named; loosened or removed document; non-issuer key refused at registration. The verifier checks **dispatched** actions, not proposals | — | — |
| Salted field commitments + crypto-shredding | 9 | **TESTED**: the clear value is absent from events, the receipt and the database event bytes; correct disclosure verifies; wrong value, wrong salt and reused salt fail; shredding leaves the ledger valid. `R-CMT-05` is met only as stated in Q17 | — | — |
| Semantic invariants | 10 | **TESTED** (4 invariants, each with good, bad and unobserved traces; mutation-checked) | mining of rules (`R-SEM-05`) is deferred | — |
| Deterministic prompt guard (classifier off) | 10 | **TESTED**; **MEASURED** on a small hand-written corpus (30 attacks, 27 benign): recall 0.80, precision 0.83, false-positive rate 0.19, all misses and false alarms listed. **Not a complete defence** | a reviewed classifier; a real-traffic corpus | — |
| Dashboard | 10 | **TESTED** (30 browser tests, axe clean in light and dark); plain HTML, not the Next.js stack of `R-UI-01` | SSE live view (`R-UI-03`); a WASM verifier | — |
| TinyFish adapter (`STEP_OBSERVED` max) | 11 | **TESTED** against a mock and against a local fake of the published API (17 + 31 tests); live cost rule **MEASURED** on 2 connector runs. **MEASURED once** (user run: success, receipt `VALID`); step cap, rate limits, cancel **UNVERIFIED** | one run by the user with their own key | — |
| Replay drift | 11 | **TESTED** (added, removed, reordered, hosts, outcome; the tool refuses a non-receipt cleanly) | — | — |
| Anomaly rules baseline | 11 | **TESTED** (circularity and isolation tests pass). **Not `MEASURED`**: no evaluation on real runs was recorded | an evaluation on labeled runs | — |
| Temporal, Litestar split, Timescale, IPFS, WASM, ML model | 12 | SPECIFIED | — (deferred) | — |

Claims we must **not** make until the matching row above is `TESTED` (`R-CLM-03`): the signer prevents forks; the system detects rollback; Playwright is fully gated; TinyFish exposes step-level evidence; semantic invariants catch real violations; the prompt classifier is production-ready; ML beats a baseline; artifact capture is genuine; CLI and WASM agree.

---

## 8. Risks and the cut-first fallback

| Risk | Impact | What I do |
|---|---|---|
| Prototype tree missing (section 0) | Step 0 blocked, and the "21 tests" claim unverifiable | Ask Q1; proceed with Step 0b meanwhile |
| JCS details (non-BMP ordering, number formatting) wrong | Every downstream hash wrong | Vectors first (Step 1), cross-language check (Step 2) |
| Signer `append` layout undecided (Q7) | Step 4 and its vectors churn | Decide as `D-20` before Step 4 starts |
| Scope too large for the time available | Nothing finished | Must-demo path only (section 5), everything else behind interfaces |
| `STEP_GATED` cannot be proven for Playwright | Overstated safety claim | Ship `STEP_OBSERVED` and say so; never label `STEP_GATED` without the bypass tests |
| No second device / anchor repository | Independence claim overstated | Report `NOT_INDEPENDENT`; never show it as green |
| TinyFish API differs from assumptions, or credits run out | Demo beat 6 lost | Replay is the default path; hard stop at the reserve; no paid fallback |
| Restrictive license in a dependency (BSL / SSPL / AGPL) | Cannot ship | Ask before adding (Q5); prompt classifier stays off (`D-17`) |
| A secret leaks into a log, image or receipt | Serious | Secret-scan tests in Steps 0, 4 and 5; CI secret scan blocks merges |
| Claims drift ahead of evidence | Loss of trust | Claims ledger updated in the same change as the code |

**If time runs out, cut in this order (first to go first):** 11 (TinyFish, drift, anomaly) → 10 (semantic, prompt guard, dashboard; keep a minimal receipt viewer only if cheap) → 9 (commitments first, then mandate; keep signed approvals if the demo claims them) → 7 (Playwright; the demo runs on replay) → 8 (witness/anchor; then say plainly that deleted-run detection is local-only and not independent). **Never cut:** Steps 1–6. They are the must-demo path and the honest core of the product.

---

## 9. Per-step reporting contract (Phase 2)

For each step I will: restate the step with its requirement IDs and acceptance check; write the tests or vectors first and show them **failing**; implement the smallest change that makes them pass; run the full relevant suite plus lint and type checks and show the real output; update the documents the step touches (`PROTOCOL.md`, `DATABASE_AND_API_CONTRACTS.md`, the `REQUIREMENTS.md` status column) and the claims ledger in section 7; then report what changed, which tests pass, what was **not** tested, and any new questions — and wait for your go-ahead unless you answer Q14 with "continue automatically".
