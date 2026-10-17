# adapters/tinyfish - optional remote adapter

**Status:** `TESTED` against a scripted mock and a local fake of the published API; the cost rule is `MEASURED` on two live connector runs. this project's own client was run once against the real service by the user (smoke test, one successful run, receipt `VALID`). The provider-enforced step cap is `UNVERIFIED`.
**Built in:** Step 11. **Requirements:** R-TFY-01..08, R-COV-04/06.

Opt-in per run, a hard ceiling counted from the provider's own metering, a reserve below which
optional calls stop, no paid fallback, no blind retry after a timeout. Capped at `STEP_OBSERVED`
until a spike proves pre-dispatch gating (D-14). See `docs/TINYFISH_SPIKE.md` for what was measured and what is still unknown.

`http_client.py` is the real client (stdlib only): key only from `TINYFISH_API_KEY`, agent operation only, step and time caps on every run, cancel on our deadline, no retry. `tools/demo_tinyfish.py --yes-spend` makes one real, recorded run.
