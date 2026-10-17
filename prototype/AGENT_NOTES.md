# Agent Black Box — project context (read this first)

AzinHack hackathon project, built with TinyFish. An AI web agent whose every step is
recorded in a signed hash chain. The agent PREPARES payments but can never send them;
a human approves and signs on a TESTNET. Anyone can verify the log offline with only
the public key.

## Layout
- ledger/   canon.py (canonical JSON + SHA-256), chain.py (hash chain + Ed25519 sign),
            verify.py (verifier), store.py (SQLite insert-only + screenshots by hash),
            mask.py (card/OTP/password masking), anchor.py (public anchor, truncation check),
            api.py (FastAPI: runs, entries, verify, payment approve; Bearer read/pay tokens)
- agent/    run_step.py (single gateway: step limit, guard, record, masked output),
            graph.py (LangGraph plan -> act loop)
- guard/    policy.py (site allowlist, recipient allowlist, spend limit, human approval)
- payment/  payment.py (pending -> approved -> 30s cooling -> sent / cancelled / rejected)
- ui/       api.py (FastAPI demo UI + tamper demo), index.html (plain HTML, no build step)
- tests/    21 pytest tests (canon, chain, verify, mask, guard) — all must keep passing
- docs/     DESIGN.md, REQUIREMENTS.md, architecture, flow diagram (source of truth for intent)
- Dockerfile, docker-compose.yml, requirements.txt (pinned), README.md, CHANGES.md

## Status
Done and tested: ledger, mask, guard, payment, run_step, graph, anchor, ledger API, UI.
NOT done / NOT tested: Docker was never run; real TinyFish client does not exist yet;
ledger API has no launcher (compose cannot start it); no real user auth; runs are in memory.

## Rules
1. Run `python -m pytest -q tests` before and after every change. Keep all tests green.
2. Never touch the entry format (BODY_KEYS in verify.py, body in chain.py) without
   updating verify, store, ui and tests together.
3. Secrets: never commit or print keys or API tokens. TinyFish key comes from an env var.
   The signing private key must never enter the Docker image.
4. Testnet only. Do not describe the project as bank-ready, certified or hack-proof.
   Correct wording: tamper-evident.
5. ML, if added, is a warning layer OUTSIDE the trust path (never inside chain/verify/signature).
   Log every ML verdict as its own ledger entry.
6. Code style: small files, short Hinglish comments like the existing code, standard library
   where possible, pinned dependencies.
7. Do not invent features in docs. Say what is built and what is only planned.
