# services — runtime services

**Status:** `TESTED` for the parts listed below (see each folder's README for what is and is not covered).
**Built in:** Steps 3-6, 10 and 11 of `docs/IMPLEMENTATION_PLAN.md`, plus the run console, graph and artifact store added after.
**Requirements:** R-SVC-01..06

| Folder | What it is |
|---|---|
| `api/` | The FastAPI service: event ingestion, leases and fencing, SSE, receipt export. Needs PostgreSQL. |
| `worker/` | The policy gateway host: lease, event sink and approval client. Untrusted for ledger integrity. |
| `artifacts/` | The one path by which bytes enter evidence storage: a local store and an S3-compatible store. |
| `dashboard/` | The local audit server (`tools/ui_server.py`) and the optional run console. |
| `graph/` | A graph of each run, kept in FalkorDB (or drawn straight from the receipt). Never a verdict. |
