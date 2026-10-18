# services/artifacts — the one path by which bytes enter evidence storage

**Status:** `TESTED`: the local store (`tests/contract/test_artifact_store.py`), and the S3 request signing against AWS's published example. The S3 store tests ran against SeaweedFS
(`tests/contract/test_s3_store.py`) and are **skipped** unless `ABB_TEST_S3`, `ABB_S3_ACCESS_KEY`, `ABB_S3_SECRET_KEY` and `ABB_BIN` are set. `UNVERIFIED`: MinIO itself (not tested; its community edition was archived upstream in April 2026) and any server over a network.
**Requirements:** R-ART-01..07, R-DAT-09, R-DAT-11, R-DAT-12.

| File | What it does |
|---|---|
| `store.py` | Local store. Bytes enter only through `put`; the digest comes from the Rust core and is compared with any claim; an existing object is never overwritten; every read is re-verified. |
| `s3_store.py` | The same rules on an S3-compatible object server. Configured by `ABB_S3_ENDPOINT`, `ABB_S3_ACCESS_KEY`, `ABB_S3_SECRET_KEY` (never printed). |
| `s3.py` | A very small S3 client (AWS Signature V4, standard library only). Plain `http://` only for loopback; credentials never appear in an error. |
| `component.py` | The designated component: store the bytes, then register them with the ledger. |
