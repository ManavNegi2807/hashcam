# Agent Black Box

**A flight recorder for web agents.** It records what an AI agent did as a signed, tamper-evident history, checks risky actions against rules before they run, asks a human to sign off where policy says so, and produces a **receipt** that anyone can verify offline without trusting us.

> **Honest status (2026-10-18):** this repository holds a working system built in steps 0-11 of `IMPLEMENTATION_PLAN.md`: a Rust core and `abb` CLI, a separate signer, a FastAPI ledger service on PostgreSQL, a policy gateway, replay, Playwright, TinyFish and fake-money payment adapters, advisory security modules, endpoint review, a local audit dashboard with a run graph, and the original Python prototype in `prototype/`. Each claim below carries a status. Not built: Temporal, the Next.js dashboard, the SSE live view, the WASM verifier, a trained anomaly model, real-money payments (forbidden). The numbered requirements are not all met; `REQUIREMENTS.md` says which are.

> **What it is not:** it does not prove an agent is honest or correct, and it does not prove a real-world action happened unless the observation itself is trustworthy. It is tamper-**evident**, not hack-proof.

---

## What it gives you

| Idea | In one line | Status |
|---|---|---|
| Signed run history | Every step is a canonical event in a Merkle tree with signed checkpoints | `TESTED` (Rust core, separate signer). The prototype's hash chain is kept in `prototype/` |
| Offline verifier | `abb verify` checks a receipt on 16 dimensions and names the broken point | `TESTED`. The WASM verifier is `SPECIFIED` only |
| Pre-action rules | A deterministic policy allows, denies or asks for approval before an action | `TESTED` (`policy/`, `services/worker/gateway.py`) |
| Honest coverage labels | Each receipt says `TASK_LEVEL`, `STEP_OBSERVED` or `STEP_GATED` | `TESTED`: Playwright claims `STEP_GATED` only after a bypass battery; TinyFish is capped at `STEP_OBSERVED` |
| Signed human approvals | The approver signs the exact action on their own device (`abb approve`) | `TESTED`. A signature shows a key signed, not which human held it |
| Global log and witnesses | Detects a whole run being deleted; a witness co-signs | `TESTED` for detection; independence is `UNVERIFIED` on one machine (`NOT_INDEPENDENT`) |
| Advisory checks | Semantic invariants, prompt-injection guard, anomaly rules. Never authorize anything | `TESTED`; the guard is `MEASURED` on a small hand-written corpus only |
| Local pages | An audit view and a task page on `127.0.0.1` (plain HTML) | `TESTED` (browser tests). Read routes lack a Host-header check: `SECURITY.md` section 16 |
| Run graph | A graph of each run in FalkorDB, or drawn from the receipt. Never a verdict | `TESTED`; the store tests need a FalkorDB (`services/graph/README.md`) |
| Endpoint review | Reported events scored by explainable rules, alerts, a signed analyst decision | `TESTED` on **simulated** events; isolation is simulated |
| Fake-money payments | Stripe test mode under a spend policy and a signed approval | `TESTED` against a stand-in; live test mode `UNVERIFIED` until you run it |

Claim statuses: `SPECIFIED` (written down), `IMPLEMENTED` (code exists), `TESTED` (a test passes), `MEASURED` (recorded benchmark), `UNVERIFIED` (not established).

## Documents

Start with the first two, then go deeper.

| File | What it is |
|---|---|
| `PRODUCT_REQUIREMENTS.md` | Who it is for, goals, features, MVP scope, risks |
| `Agent_Black_Box_Final_Architecture_v10.md` | The target architecture (v9 plus the review changes) |
| `DESIGN.md` | Design by area, trust boundaries, hackathon cut, decisions |
| `PROTOCOL.md` | Byte-level protocol: encoding, hashing, events, Merkle tree, checkpoints, signer, receipts. Wins over every other document |
| `REQUIREMENTS.md` | 199 testable requirements with priority and status |
| `DATABASE_AND_API_CONTRACTS.md` | Tables, ledger endpoints, SSE, CLI, and the local dashboard API (Part E) |
| `SECURITY.md` | Threat model, controls, key management, known limits |
| `ERROR_HANDLING.md` | Error codes, retries, crash recovery, degraded modes |
| `TESTING.md` | Test layers, vectors, tamper suite, release gates, where each test folder fits |
| `IMPLEMENTATION_PLAN.md` | The step plan, progress, and the claims ledger (what is `TESTED`, `MEASURED`, `UNVERIFIED`) |
| `DEMO.md` | How to run each mode, what it shows and what it does not |
| `MEASUREMENTS.md` | Recorded measurements and how they were made |
| `PROMPT_GUARD_EVAL.md` | The prompt guard's results on its small corpus (written by `tools/eval_prompt_guard.py`) |
| `TINYFISH_SPIKE.md` | What was learned from the TinyFish spike |
| `AGENTS.md` | Rules for AI coding agents working in this repo |
| `../prototype/AGENT_NOTES.md` | Short project rules and status for the coding agent (prototype) |

Each code folder also has its own `README.md` with a status line (`services/`, `adapters/`, `policy/`, `security/`, `endpoint/`, `tools/`, `ui/`, `deploy/`, `core/`, `signer/`, `vectors/`).

## Quick start

The current system is built and run as described in the top-level `README.md` ("Run it"): build the Rust core, set `ABB_BIN`, `ABB_SIGNER_BIN` and `ABB_TEST_DSN`, then `python tools/demo.py` for the end-to-end demo and `python tools/ui_server.py --receipts <dir>` for the pages on `http://127.0.0.1:8765`. `DEMO.md` covers every mode. Optional: `--enable-runs` (task page) and `--falkordb redis://127.0.0.1:6390` (graph store).

The original prototype (Python, FastAPI, plain HTML) is kept and still runs on its own: see `../prototype/README.md`.

```bash
pytest -q          # Python tests; many need PostgreSQL, the Rust binaries or Chromium and skip or error without them
cargo test --manifest-path core/Cargo.toml
```

Never commit anything in `secrets/`. `deploy/.dockerignore` keeps `secrets/` out of the build context (tested in `tests/security/test_build_context_hygiene.py`).

## Target system (v10) in brief

- **Core:** Rust library and CLI (RFC 8785 JCS, SHA-256 Merkle tree, Ed25519), a separate signer that recomputes roots, PostgreSQL, an S3-compatible artifact store, FastAPI. The Next.js dashboard of v10 is **not** built; the pages are plain HTML.
- **Adapters:** Replay (default, deterministic), local Playwright (the gated path), TinyFish (optional, observed only), and fake-money payments (Stripe test mode).
- **Profiles:** `LOCAL_ONLY` (default, works offline) and `CONNECTED_EVIDENCE` (adds witnesses, anchors, TinyFish).
- **Hackathon cut:** one FastAPI service, plain PostgreSQL, a Postgres lease instead of Temporal, Rust CLI first. Same protocol.

Repository layout:

```
core/        Rust: jcs, merkle, checkpoint, event, receipt, verify, cli (abb)
signer/      Separate signer service (shares the core workspace)
services/    api/ (FastAPI + ingestion), worker/ (gateway host), artifacts/, dashboard/, graph/
adapters/    replay/, playwright/, tinyfish/, payments/
policy/      Deterministic policy engine, mandates, policy versions
security/    semantic/, prompt_guard/, anomaly/ (advisory only)
endpoint/    Endpoint review: events, scoring, alerts, opt-in collector
ui/          Plain HTML pages (audit view, task page, alerts, graph)
tools/       Demos, live checks, the local server
vectors/     Conformance test vectors (shared by Rust and Python)
deploy/      docker-compose.yml (profiles core, graph, storage), Dockerfiles, .dockerignore
docs/        The documents listed above
tests/       adapter, contract, endpoint, fault, graph, security, tamper, ui
prototype/   The original Python prototype
```

## Demo (the goal of the hackathon build)

1. Run a replay scenario that needs a signed approval.
2. Export the receipt and verify it: `VALID`, with coverage stated honestly.
3. Edit one event in the database: the verifier says `INVALID` and names the event.
4. Swap an artifact: artifact integrity fails.
5. Delete a whole run: `abb verify-global` flags the gap.

## Honest limits

- Actions the adapter or gateway never saw are invisible; coverage labels say so.
- A compromised capture host can fabricate evidence before it is hashed.
- A valid hash does not prove a screenshot is genuine or a page truthful.
- One machine with all its backups rolled back is not detectable without an external anchor.
- Timestamps are claims unless a trusted timestamp is attached.
- A signed approval proves a key signed, not which human held the key.
- The prompt-injection guard and anomaly auditor are not complete defenses.

More in `SECURITY.md` section 16.

## Contributing

Read `AGENTS.md` first (it applies to people too). Work in small slices, add a test with every change, and do not label anything `TESTED` without a passing test. Security issues: a disclosure contact is not set yet (`TBD`); set one before publishing this repository.

## License

Not chosen yet. Decide before publishing. Check third-party licenses before adding dependencies (TimescaleDB edition; MinIO's community edition is archived, so the S3 store was tested on SeaweedFS; FalkorDB's server is SSPL-licensed; Prompt Chainmail is BSL 1.1).

## Name

The name is still open. "Agent Black Box" is a working title.
