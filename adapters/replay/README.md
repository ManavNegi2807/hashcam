# adapters/replay — deterministic replay adapter

**Status:** `TESTED` through the tamper suite and `tools/demo.py`, which run its scenarios end to end through the gateway, receipt export and the verifier.
**Built in:** Step 5 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-ADP-01/02/04, R-COV-02

Default, zero cost, deterministic. Output is always labeled `mode = REPLAY`.
Scenarios are JSON files in `scenarios/`; `adapter.py` plays one through the gateway.
