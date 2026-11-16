# tools — runnable demos, checks and the local server

**Status:** `TESTED` where a test drives the tool (the demos through `tests/ui/` and `tests/tamper/`, the checkers through `tests/security/`);
the `check_*_live.py` tools make a real network call with your own key and are `UNVERIFIED` until you run them.

| Tool | What it does |
|---|---|
| `ui_server.py` | The audit dashboard on `127.0.0.1` (`--enable-runs` adds the run console, `--falkordb` the graph store). |
| `build_site.py` | Builds the public site in `site/`: copies the shared theme and styles from `ui/`, turns `ui/fx3d.js` and `ui/readable.js` into classic scripts (so the pages work from `file://`), copies the extension's byte-identical files, builds the verifier as WebAssembly and writes the offline sample data. No animation library is copied. |
| `make_brand_assets.py` | Makes the logo assets for `site/` from the master image `docs/brand/hashcam-logo.png`: `brand.css` (the mark and a faint watermark as `data:` URIs) and the favicon in each page. Needs Pillow; a one-off design tool, not a build step. `TESTED`: `tests/ui/test_branding.py`. |
| `make_license.py` | Runs on the owner's computer: `init` makes the Ed25519 key pair (private key saved OUTSIDE the repo, never printed; public key written to `site/pro/pubkey.js`), `sign` prints a Pro licence key for a buyer, `check` verifies one. Needs `cryptography`. `TESTED`: `tests/ui/test_pro.py`. See `docs/PRO.md`. |
| `launcher.ps1` | The one-click start behind `HashCam.bat`, `HashCam-Extension-Setup.bat` and `HashCam-Stop.bat` (Windows; root `README.md`). `TESTED`: `tests/ui/test_launcher.py`. |
| `recorder.py` | The local service the HashCam Recorder Chrome extension talks to (`extension/README.md`). |
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
