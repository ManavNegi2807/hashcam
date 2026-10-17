# ui — audit dashboard

**Status:** `TESTED` (browser tests, axe in light and dark). **Built in:** Step 10.
**Requirements:** R-UI-01 (partly: **plain HTML, not Next.js/React/Tailwind/shadcn**), R-UI-02..05.

A static page plus a small read-only local server (`tools/ui_server.py`). It shows what
`abb verify --json` says and never computes validity itself (tested). `UNKNOWN` and
`NOT_INDEPENDENT` are never green and no status relies on color alone. Receipt content is
inserted as text. The approval *screen* displays approvals; signing happens on the approver's
own device with `abb approve`. **Not built:** the SSE live view (R-UI-03), the WASM verifier.

Run: `python tools/ui_server.py --receipts <dir> --keys <key_manifest.json>`.
