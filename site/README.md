# site: the public HashCam website

**Status:** `TESTED`: `tests/ui/test_site.py` (needs the full stack), `tests/ui/test_site_pages.py` (22)
and `tests/ui/test_readable.py` (53). The deployed copy is only as fresh as the last merge to `main`.

Plain HTML, vanilla CSS and JavaScript with no libraries beyond the vendored GSAP, no build step for
the pages themselves, and no network use except the optional read of your own recorder on
`127.0.0.1`. It works from `file://` (double-click `index.html`) and from the web.

| Page | What it is |
|---|---|
| `index.html` | Hero, the four-stop telemetry bus, a four-step walkthrough, attach guide, a 30-second quickstart, live sessions, the receipt checker and how-it-works. |
| `sandbox.html` | The **Gatekeeper Sandbox**: four test flights, a fake-money escrow meter, a held gate that needs a signature, a radar that explains each decision, a hash-chained ledger you can tamper with, and an exported receipt that checks itself. |

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
