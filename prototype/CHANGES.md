# Changes: Step 1 (Core Ledger)

## New files
- ledger/__init__.py   package marker
- ledger/canon.py      canonical JSON, SHA-256 helpers
- ledger/chain.py      hash chain + Ed25519 signing (Chain class)
- ledger/verify.py     verifier: link, hash, signature checks
- ledger/store.py      SQLite insert-only storage + screenshot files by hash
- ledger/mask.py       masks card, OTP, password

## Tests (pytest, 15 pass)
- tests/test_canon.py   key order, no spaces, hash changes on edit
- tests/test_chain.py   genesis prev, prev links, sequential n
- tests/test_verify.py  OK, edit, delete, reorder, bad signature, wrong key
- tests/test_mask.py    card, password, OTP masked

## Docs changed (DESIGN.md)
- New section 11a: extra controls (encryption, access control, pinning, second check, anchor)
- New section 11b: more security ideas by priority (Must, Should, Could, Future)

## Not yet built
- Step 2: agent/run_step.py, agent/graph.py, guard/policy.py, payment/payment.py, ledger/anchor.py, ledger/api.py, tests/test_guard.py
- Step 3: ui/api.py, ui/index.html, Dockerfile, docker-compose.yml, README.md
