# services/graph — a graph of each run (FalkorDB)

**Status:** `TESTED`. The builder tests need nothing; the store tests run against a real FalkorDB and are **skipped**
unless `ABB_TEST_FALKORDB` is set (for example `redis://127.0.0.1:6390`), so a run without it does not cover the store.
`UNVERIFIED`: a FalkorDB reached any other way than loopback, and graphs larger than a single run.
**Requirements:** R-UI-02, R-UI-05 (a picture, never a verdict). **Tests:** `tests/graph/test_graph.py`, `tests/ui/test_graph_page.py`.

The graph is a **copy of what is inside a receipt**, drawn so a person can see how an action, the policy that decided it,
the signed approval that settled it and the provider call that billed it connect. It is not evidence and never says whether
a receipt is valid: only `abb verify` does (R-SVC-01).

| File | What it does |
|---|---|
| `build.py` | Pure and deterministic: a receipt summary in, nodes and edges out. Every id carries the run id, so two runs never collide. |
| `store.py` | FalkorDB over the Redis protocol. Only a loopback address is accepted. Every value is a query parameter; labels and relations come from fixed lists. |

Model: nodes `Run`, `Action`, `Policy`, `Approval`, `Mandate`, `Call`; links `REQUESTED`, `NEXT`, `DECIDED_BY`,
`APPROVED_BY`, `GOVERNED_BY`, `BILLED`. One database graph per run, named `hascham-<run id>`; saving a run replaces it.

If FalkorDB is missing or down, the page draws the same graph straight from the receipt and says so.

Run: start the database with `docker compose -f deploy/docker-compose.yml --profile graph up -d graph` (`deploy/README.md`), then
`python tools/ui_server.py --receipts <dir> --falkordb redis://127.0.0.1:6390` (or set `ABB_FALKORDB_URL`).

Known limits: the database has no password and relies on its `127.0.0.1`-only port binding; anyone with local access can
read or change the graph (it is an index, so a changed graph cannot make a receipt valid or invalid). The graph name uses the
receipt's run id, which is receipt data (see `docs/SECURITY.md` section 16).
