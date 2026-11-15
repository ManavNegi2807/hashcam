# site: the public HashCam website

**Status:** `TESTED`: `tests/ui/test_site.py` (needs the full stack), `tests/ui/test_site_pages.py` (33),
`tests/ui/test_motion.py` (25), `tests/ui/test_fallback.py` (39) and `tests/ui/test_readable.py` (53). The deployed copy is only as fresh as the
last merge to `main`.

Plain HTML, vanilla CSS and zero-dependency JavaScript (no animation library, no CDN), no build step
for the pages themselves, and no network use except the optional read of your own recorder on
`127.0.0.1`. It works from `file://` (double-click `index.html`) and from the web.

## Logo and watermark

The favicon, the mark beside the wordmark and the faint page watermark all come from one master image,
`docs/brand/hashcam-logo.png`, through `tools/make_brand_assets.py` (needs Pillow; run it again if the
master changes). `brand.css` and the favicon in each page's `<head>` are generated: small images
embedded as `data:` URIs, so the pages make no image request and work offline. The watermark is one
tone, feathered at its edges, fixed behind the page and deaf to the pointer; it is hidden when printed.
`TESTED`: `tests/ui/test_branding.py`. At 16px on a 1x screen the mark is recognisable but soft;
from 20px up, and at 2x, it is crisp.

## Motion

`motion.css` and `motion.js` (unchanged copies of `ui/motion.css` and `ui/motion.js`, which the console
uses too; plus the shared animations in `fx3d.js`) use the browser's own Web
Animations API and CSS. One easing everywhere, an expo-out `cubic-bezier(0.16, 1, 0.3, 1)`; only
`transform`, `opacity` and `stroke-dashoffset` animate, so no frame repaints or reflows the layout.
Entrances stagger 60ms apart; digests scramble through hex for ~320ms and lock left to right into the
real value; cards light their border where the pointer is (`--mouse-x`, `--mouse-y`); the hero is a
telemetry core, not a circle. Everything has a still version under `prefers-reduced-motion`. Endless
loops (the rings, the grid, the stripes) are constant-speed on purpose, so they stay linear. They
pause while scrolled out of view.

`tests/ui/test_motion.py` checks the above in a real Chromium: no console error, a `layout-shift` of
0 on a normal load over http (the test allows 0.001; and 0.01 from `file://`, where there is no header
to preload the font and the late font swap moves the header text by about 0.003), nothing but
compositor properties animating, the scramble landing on the real SHA-256, and a still page under
reduced motion. The telemetry core is dark translucent glass without a live backdrop blur (a blur is
recomputed every frame the grid rolls behind it), and `vercel.json` preloads the font with a `Link`
header so the font swap does not shift the page.

**Not measured:** frame rate on a GPU. In a headless software renderer the sandbox holds 60 fps and
the top of the home page about 30 fps while the hero's rings turn.

| Page | What it is |
|---|---|
| `index.html` | Hero, the four-stop telemetry bus, a four-step walkthrough, attach guide, a 30-second quickstart, live sessions, the receipt checker and how-it-works. |
| `sandbox.html` | The **Gatekeeper Sandbox**: four test flights, a fake-money escrow meter, a held gate that needs a signature, a radar that explains each decision, a hash-chained ledger you can tamper with, and an exported receipt that checks itself. |
| `range.html` | The **HashCam Range**: 8 levels to test your own AI agent on this site. It checks the record your run left (sandbox export or extension receipt) in the browser, then scores it pass / fail / unknown, with a share link and a badge. Limits are shown, **not enforced yet**. Design for what comes next: [`docs/AGENT_RANGE.md`](../docs/AGENT_RANGE.md). |

## The sandbox is a simulation

Everything in it runs in the page with the browser's own Web Crypto: SHA-256 for the chain and an
ephemeral ECDSA P-256 key (non-extractable, gone when the tab closes) for the person's signature. It
uses a **simplified chain format** so each step is visible; it is **not** the real `.abbreceipt`
format and `abb verify` cannot read it. The money is fake and the amounts are smaller than the real
spend tiers so every branch can be reached. The real verifier is the one under "Check a receipt".

## Plain words, not JSON

Steps are written as sentences (`readable.js`, generated from `ui/readable.js`). Raw records are
behind a closed "Technical details" opener and are never shown for a sensitive agent or a step that
holds a secret. The only raw JSON on purpose is the sandbox's tamper box and the exported receipt's
"Show the raw record" opener, which hold made-up data.

## Checking a receipt: WebAssembly first, JavaScript if it cannot run

The "Check a receipt" box runs the real verifier (`verifier.wasm`, the same Rust code as
`abb verify`). If that cannot load or run (the file is missing, the browser blocks WebAssembly), the
page falls back to `fallback.js`, a second checker in plain JavaScript with the browser's own Web
Crypto, and says on the page which one gave the answer.

The fallback checks the cryptographic core: every event is exactly canonical, in order and in the
signed Merkle tree; each checkpoint's Ed25519 signature against the key manifest (needs a browser
with Ed25519 in Web Crypto, otherwise it says UNKNOWN); the checkpoint chain and its consistency
proofs; and the run's place in the global log. **It does not check coverage, policy, the mandate,
approvals, artifacts, witnesses or anchors**, so those stay UNKNOWN, it can say INVALID but **never
VALID**, and its best answer is INCOMPLETE. For the full verdict use `abb verify` or a browser where
WebAssembly runs.

It is held to the project's own evidence: the conformance vectors (Merkle roots, inclusion and
consistency proofs, malformed proofs, canonical JSON and the 15 inputs it must reject, domain tags)
and a corpus of genuine and tampered receipts compared with `abb verify` itself.
`TESTED`: `tests/ui/test_fallback.py`. Not covered: a receipt with several checkpoints from a real
recorder run (only the proof vectors pin that arithmetic), and artifact entries inside the ZIP other
than `receipt.json`.

## Files you should not edit by hand

`python tools/build_site.py [--samples --dsn ...]` regenerates these; a test checks they match:

* `theme.css`, `console.css`: copies of `ui/`.
* `fx3d.js`, `readable.js`: the classic-script builds of `ui/fx3d.js` and `ui/readable.js`.
* `verifier.wasm`: `core/abb-wasm`, the same Rust verify path as `abb verify --json`. **It must be
  committed**: when it was missing from the repository the live site answered 404 for it and the
  sample buttons failed with "HTTP status code is not ok". A test checks it exists and is not
  git-ignored. Needs `rustup target add wasm32-unknown-unknown` to rebuild.
* `offline-data.js`: the verifier and the sample receipts as base64, loaded only on `file://`
  (a page opened from disk cannot `fetch()` a neighbouring file).
* `samples/`: one genuine receipt, the same with one event edited, and a demo key manifest.

## See it

```bash
python -m http.server 8000 --directory site
```

then open `http://localhost:8000/` and `http://localhost:8000/sandbox.html`, or open
`site/index.html` straight from disk.

## Deploy (Vercel)

In the project's **Settings → General**, set **Root Directory** to `site`. Framework Preset `Other`,
no build command, no install command, output directory `.`. `vercel.json` here adds clean URLs and a
strict content security policy (own files only, WebAssembly allowed, connections only to the site
itself and `127.0.0.1`/`localhost`), which is why there are no inline scripts or styles.
