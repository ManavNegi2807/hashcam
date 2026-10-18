# adapters — execution adapters

**Status:** `TESTED` for each adapter listed below (see its README for the exact claim).
**Built in:** Steps 5, 7, 11 of `docs/IMPLEMENTATION_PLAN.md`, plus the payments adapter added after.
**Requirements:** R-ADP-01..04

| Folder | What it is | Coverage it may claim |
|---|---|---|
| `replay/` | Deterministic scripted scenarios, zero cost | `STEP_GATED` on its own gateway path, labeled `mode = REPLAY` |
| `playwright/` | A real Chromium with every request through the gateway | `STEP_GATED` only after the bypass battery passes |
| `tinyfish/` | TinyFish Browse, Search, Research (optional, spends credit) | capped at `STEP_OBSERVED` |
| `payments/` | Pays bills with fake money through Stripe test mode | gateway-decided; a live key is refused |

Every adapter returns the normalised result of DESIGN.md 13.1.
