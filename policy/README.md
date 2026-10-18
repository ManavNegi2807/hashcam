# policy — deterministic policy engine

**Status:** `TESTED` through the gateway trace, approvals-and-mandate and tamper tests
(`tests/contract/test_gateway_trace.py`, `tests/tamper/test_approvals_mandate.py`, `tests/tamper/test_tamper_suite.py`).
**Built in:** Step 5 of `docs/IMPLEMENTATION_PLAN.md`.
**Requirements:** R-POL-01..06, R-APR-06

Versioned, deterministic decisions. Only this engine authorizes or blocks; ML and guard output is advisory (AGENTS.md 3.17).

| Path | What it is |
|---|---|
| `engine.py` | Turns an action and a policy version into `ALLOW`, `DENY` or `REQUIRE_APPROVAL`, with reason codes. |
| `mandate.py` | Checks an action against a signed mandate. |
| `versions/*.json` | The policy versions in use (`default`, `guarded`, `local-site`, `realsite-guarded`, `redacting`, `tinyfish-demo`, `tinyfish-answers`, `company-spend`, `company-spend-standin`, `endpoint-monitor`). A version is never edited in place; a change is a new version. |
