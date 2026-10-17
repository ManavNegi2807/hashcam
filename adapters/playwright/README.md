# adapters/playwright — local browser adapter

**Status:** `TESTED` for HTTP(S) and WebSocket gating on a local probe site; `UNVERIFIED` for
anything else (see the limits). **Built in:** Step 7 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-ADP-01, R-COV-03, R-COV-07, R-TST-04, D-14.

Every request the browser context makes goes through one route handler: the request is
recorded, SSRF rules and policy decide, and only an allow is dispatched. The adapter follows
redirects itself so each hop is gated; service workers are blocked. Whether it may claim
`STEP_GATED` is **measured**, not assumed: `self_test()` runs 14 bypass probes and a hole in any
of them lowers the declaration to `STEP_OBSERVED`, with the report's digest as the evidence.

Limits, stated: only HTTP(S) and WebSocket traffic is gated (WebRTC and other transports are
not); client-side DOM actions that send nothing are out of scope; DNS rebinding between the
SSRF check and the fetch is **not** closed (`UNVERIFIED`); the WebSocket gate uses a private
Playwright API, so the version is pinned and an upgrade must rerun the bypass tests.

Files: `adapter.py`, `probe_site.py`. Tests: `tests/adapter/`. Demo: `tools/demo_playwright.py`.
