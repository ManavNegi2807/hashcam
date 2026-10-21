# tools — runnable demos, checks and the local server

**Status:** `TESTED` where a test drives the tool (the demos through `tests/ui/` and `tests/tamper/`, the checkers through `tests/security/`);
the `check_*_live.py` tools make a real network call with your own key and are `UNVERIFIED` until you run them.

| Tool | What it does |
|---|---|
| `ui_server.py` | The audit dashboard on `127.0.0.1` (`--enable-runs` adds the run console, `--falkordb` the graph store). |
| `demo.py` | The main demo: replay, approval, receipt, tamper. |
| `demo_guarded.py`, `demo_playwright.py`, `demo_realsite.py` | A risky task waiting for a signed approval; a real browser with measured coverage; a real website with an approval gate. |
| `demo_tinyfish.py`, `check_tinyfish_live.py` | One real TinyFish run recorded in a receipt; one live Search or Research check. Spends credit. |
| `demo_pay.py` | Local mock payments under a spend policy; no external payment service or API key. |
| `demo_endpoint.py`, `endpoint_daemon.py`, `measure_endpoint.py` | Endpoint review end to end; the opt-in collector; measurement on synthetic events. |
| `approval_bridge.py` | The stdin/stdout approval protocol the run console uses. |
| `remote_witness.py` | A witness on a second computer co-signs a checkpoint. |
| `replay_drift.py` | How a second run of a task differs from the first (advisory). |
| `eval_prompt_guard.py` | Measures the prompt guard and writes `docs/PROMPT_GUARD_EVAL.md`. |
| `check_key_volume_isolation.py` | Checks that no key volume is shared and the signer stays unreachable. |
