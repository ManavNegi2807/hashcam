# security — advisory analysis modules

**Status:** `TESTED` for all three modules (each README states its own limits). The prompt guard is also `MEASURED`, on a small hand-written corpus only. The anomaly module has rules and a drift comparison but **no trained model**; the optional Isolation Forest for endpoint events lives in `endpoint/model.py` and is trained on synthetic events.
**Built in:** Steps 10-11 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-SEM, R-PIG, R-ANO

All three modules are advisory. None of them can authorize or block an action.
See `semantic/`, `prompt_guard/` and `anomaly/`.
