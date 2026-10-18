# tests/integration — service-chain integration tests

**Status:** `SPECIFIED`. Empty slice: no tests here yet. `docs/TESTING.md` section 2 names an "Integration" layer (API, ingestion, signer,
object store, exporter and verifier together, run through a Docker Compose `testing` profile). That profile does not exist
(`deploy/docker-compose.yml` has the profiles `core`, `graph` and `storage`), so today the chain is covered piece by piece in `tests/contract/`,
`tests/tamper/` and by `tools/demo.py`.
