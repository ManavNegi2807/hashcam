# ui — audit dashboard and task page

**Status:** `TESTED` (browser tests, axe in light and dark). **Built in:** Step 10, extended by the run console, alerts and graph.
**Requirements:** R-UI-01 (partly: **plain HTML, not Next.js/React/Tailwind/shadcn**), R-UI-02..05.

Plain HTML, CSS and JavaScript, served by a small local server (`tools/ui_server.py`, `services/dashboard/`). It shows what
`abb verify --json` says and never computes validity itself (tested). `UNKNOWN` and `NOT_INDEPENDENT` are never green and no status
relies on color alone. Receipt content is inserted as text. The approval *screen* displays approvals; signing happens on the approver's
own device with `abb approve`. **Not built here:** the SSE live view (R-UI-03). The browser build of the verifier (WebAssembly) is in the public website, `site/`, not in this audit view.

| File | What it is |
|---|---|
| `index.html`, `app.js` | The audit view: pick a receipt, see the verdict and its dimensions, the events, approvals, and the **Alerts** and **Graph** sections. |
| `alerts.js` | The Alerts section: flagged scores with the rules that fired, web evidence and the analyst's signed decision. |
| `graph.js` | Draws the run graph (from FalkorDB when connected, else straight from the receipt, and says which). A picture, never a verdict. |
| `run.html`, `run.js` | The task page (chat board): pick a task, see the worst-case cost, confirm, watch the run, sign and approve. Only with `--enable-runs`. |
| `console.html`, `console.js`, `console.css` | **HashCam Console** at `/console`: attach an agent, live sessions from the local recorder (read-only; the pairing token stays on the server), a receipt viewer (drop a `.abbreceipt`, see `abb verify`'s verdict as falling dominoes, events, replay, graph) and the how-it-works explainers. `TESTED`: `tests/ui/test_console.py`. |
| `fx3d.js` | The animation styles: the path of every action (five cards joined by rails, a light pulse, a refused request stops at the gateway), paper-cut receipts, flat stacked event bars, the synthwave hero grid, the CSS-3D Merkle tree, maths steps, the cartoon explainer, the domino verdict and the glow atom. Each has a reduced-motion still version. Most now animate with the Web Animations API on one expo-out easing (`EASE`) and hand changed digests to `window.HCMotion.settle` (the site's hex scramble) when it is there; the cartoon explainer (console) and the signing-formula line (extension) still use GSAP. `tools/build_site.py` turns it into the classic script `site/fx3d.js`. Copied byte for byte to `extension/` (a test checks). |
| `motion.js`, `motion.css` | The **motion layer** the console and the public site share (one expo-out easing; only transform, opacity and stroke-dashoffset animate): staggered reveals, the telemetry core in the hero, a hex scramble for digests, the cursor-following card light, and "A risky step, from start to seal". Classic script and plain CSS, no library. `tools/build_site.py` copies both unchanged into `site/` (a test checks they match). `TESTED`: `tests/ui/test_console_motion.py`. |
| `readable.js` | **Plain words instead of JSON**, for every screen that shows what an agent did: one sentence per step ("Stopped from opening evil.test"), the verifier's verdict restated, and the rules for what is never shown (values behind password/token/key/card names, secret-looking text, URL query strings, and the raw record of a sensitive agent). Raw JSON is only behind a closed "Technical details" opener. An ES module (console, extension) that `tools/build_site.py` also turns into the classic script `site/readable.js`. Copied byte for byte to `extension/` (a test checks). `TESTED`: `tests/ui/test_readable.py` (53). |
| `theme.css` | The **Night Observatory** design tokens shared with the extension. Verdict colours are reserved: green only for VALID/PASS, red for INVALID/FAIL, violet for UNKNOWN/PARTIAL/NOT_INDEPENDENT. |
| `style.css`, `chat.css`, `format.js`, `fx.js`, `vendor/` | Shared styles, formatting helpers, and the vendored motion library (`vendor/README.md`). |

Known issues in this copy (2026-10-18): `tools/ui_server.py` imports `python-dotenv` (it loads a `.env` file), but no requirements file lists it, so a fresh install fails at start until `pip install python-dotenv`. The page titles now read "Hashcam" while `tests/ui/test_vendor_and_motion.py` expects "Hascham audit view", so that test will fail until one of them is changed.

Run (read-only audit view):
`python tools/ui_server.py --receipts <dir> --keys <key_manifest.json>`

The console's live view reads the recorder at `--recorder http://127.0.0.1:8770` (default) with the token from `--recorder-token-file` (default `~/.hashcam/recorder-token`). Approvals and the kill switch are not in the console: they need the passkey, which lives in the extension.

Optional: `--enable-runs` (the task page; spends TinyFish credit, needs the environment in `docs/DEMO.md`) and
`--falkordb redis://127.0.0.1:6390` (store the graph in FalkorDB; see `services/graph/README.md`).
