# Agent Black Box

**A flight recorder for web agents.** It records what an AI agent did as a signed, tamper-evident history, checks risky actions against rules before they run, asks a human to sign off where policy says so, and produces a **receipt** that anyone can verify offline without trusting us.

> **Honest status:** this repository holds a working **prototype** (Python, FastAPI, plain HTML, 21 passing tests) and the **design documents for the target system (v10)**. Nothing in v10 is implemented or tested yet. Every claim below is labeled.

> **What it is not:** it does not prove an agent is honest or correct, and it does not prove a real-world action happened unless the observation itself is trustworthy. It is tamper-**evident**, not hack-proof.

---

## What it gives you

| Idea | In one line | Status |
|---|---|---|
| Signed run history | Every step is a canonical event in a Merkle tree with signed checkpoints | v10: `SPECIFIED`. Prototype: hash chain with signatures (`IMPLEMENTED`, tested) |
| Offline verifier | A small CLI checks a receipt and names the broken point | v10: `SPECIFIED`. Prototype: Python verifier |
| Pre-action rules | Deterministic policy allows, denies or asks for approval before an action | Prototype: allowlist and limits. v10: `SPECIFIED` |
| Honest coverage labels | Each receipt says `TASK_LEVEL`, `STEP_OBSERVED` or `STEP_GATED` | v10: `SPECIFIED` |
| Signed human approvals | The approver signs the exact action on their own device | v10: `SPECIFIED` (prototype records only a name) |
| Global log | Detects a whole run being deleted | v10: `SPECIFIED` |
| Advisory checks | Semantic invariants, prompt-injection guard, anomaly score. Never authorize anything | v10: `SPECIFIED` |

Claim statuses: `SPECIFIED` (written down), `IMPLEMENTED` (code exists), `TESTED` (a test passes), `MEASURED` (recorded benchmark), `UNVERIFIED` (not established).

## Documents

Start with the first two, then go deeper.

| File | What it is |
|---|---|
| `PRODUCT_REQUIREMENTS.md` | Who it is for, goals, features, MVP scope, risks |
| `Agent_Black_Box_Final_Architecture_v10.md` | The target architecture (v9 plus the review changes) |
| `DESIGN.md` | Design by area, trust boundaries, hackathon cut, decisions |
| `PROTOCOL.md` | Byte-level protocol: encoding, hashing, events, Merkle tree, checkpoints, signer, receipts |
| `REQUIREMENTS.md` | 199 testable requirements with priority and prototype status |
| `DATABASE_AND_API_CONTRACTS.md` | Tables, endpoints, SSE, CLI |
| `SECURITY.md` | Threat model, controls, key management, known limits |
| `ERROR_HANDLING.md` | Error codes, retries, crash recovery, degraded modes |
| `TESTING.md` | Test layers, vectors, tamper suite, release gates |
| `AGENTS.md` | Rules for AI coding agents working in this repo |
| `AGENT_NOTES.md` | Short project rules and status for the coding agent |

## Quick start (prototype)

The prototype is the only runnable code today.

```bash
# 1. Create a signing key (kept only by the ledger). See the prototype README for the exact command.
# 2. Run with Docker
docker compose up --build
# 3. Open http://localhost:8000, enter a run ID, then Load, Verify, and Tamper.
```

Without Docker:

```bash
pip install -r requirements.txt
DB_PATH=log.db SHOTS_DIR=shots PUBLIC_KEY_PATH=secrets/public_key.pem uvicorn ui.api:build --factory
```

Run the tests:

```bash
pytest -q
```

Never commit anything in `secrets/`. Known gap: there is no `.dockerignore` yet, so a plain `COPY . .` can copy `secrets/` into an image. Fixing that is the first task in the build list.

## Target system (v10) in brief

- **Core:** Rust library and CLI (RFC 8785 JCS, SHA-256 Merkle tree, Ed25519), a separate signer that recomputes roots, PostgreSQL, MinIO, FastAPI, Next.js dashboard.
- **Adapters:** Replay (default, deterministic), local Playwright (the gated path), TinyFish (optional, observed only until proven).
- **Profiles:** `LOCAL_ONLY` (default, works offline) and `CONNECTED_EVIDENCE` (adds witnesses, anchors, TinyFish).
- **Hackathon cut:** one FastAPI service, plain PostgreSQL, a Postgres lease instead of Temporal, Rust CLI first. Same protocol.

Planned repository layout (not created yet):

```
core/        Rust: jcs, merkle, checkpoint, verify, cli (abb)
signer/      Separate signer service
services/    api/ (FastAPI + ingestion), worker/, artifacts/
adapters/    replay/, playwright/, tinyfish/
policy/      Deterministic policy engine and gateway
security/    semantic/, prompt_guard/, anomaly/
ui/          Next.js dashboard
vectors/     Conformance test vectors (shared by Rust and Python)
deploy/      docker-compose.yml, profiles, .dockerignore
docs/        The documents listed above
tests/       contract, integration, tamper, fault, security
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

Not chosen yet. Decide before publishing. Check third-party licenses before adding dependencies (TimescaleDB edition, MinIO edition, Prompt Chainmail is BSL 1.1).

## Name

The name is still open. "Agent Black Box" is a working title.
