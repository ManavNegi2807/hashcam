# ui — audit dashboard and task page

**Status:** `TESTED` (browser tests, axe in light and dark). **Built in:** Step 10, extended by the run console, alerts and graph.
**Requirements:** R-UI-01 (partly: **plain HTML, not Next.js/React/Tailwind/shadcn**), R-UI-02..05.

Plain HTML, CSS and JavaScript, served by a small local server (`tools/ui_server.py`, `services/dashboard/`). It shows what
`abb verify --json` says and never computes validity itself (tested). `UNKNOWN` and `NOT_INDEPENDENT` are never green and no status
relies on color alone. Receipt content is inserted as text. The approval *screen* displays approvals; signing happens on the approver's
own device with `abb approve`. **Not built:** the SSE live view (R-UI-03), the WASM verifier.

| File | What it is |
|---|---|
| `index.html`, `app.js` | The audit view: pick a receipt, see the verdict and its dimensions, the events, approvals, and the **Alerts** and **Graph** sections. |
| `alerts.js` | The Alerts section: flagged scores with the rules that fired, web evidence and the analyst's signed decision. |
| `graph.js` | Draws the run graph (from FalkorDB when connected, else straight from the receipt, and says which). A picture, never a verdict. |
| `run.html`, `run.js` | The task page (chat board): pick a task, see the worst-case cost, confirm, watch the run, sign and approve. Only with `--enable-runs`. |
| `style.css`, `chat.css`, `format.js`, `fx.js`, `vendor/` | Shared styles, formatting helpers, and the vendored motion library (`vendor/README.md`). |

Known issues in this copy (2026-10-18): `tools/ui_server.py` imports `python-dotenv` (it loads a `.env` file), but no requirements file lists it, so a fresh install fails at start until `pip install python-dotenv`. The page titles now read "Hashcam" while `tests/ui/test_vendor_and_motion.py` expects "Hascham audit view", so that test will fail until one of them is changed.

Run (read-only audit view):
`python tools/ui_server.py --receipts <dir> --keys <key_manifest.json>`

Optional: `--enable-runs` (the task page; spends TinyFish credit, needs the environment in `docs/DEMO.md`) and
`--falkordb redis://127.0.0.1:6390` (store the graph in FalkorDB; see `services/graph/README.md`).
