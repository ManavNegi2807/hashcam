# Agent Black Box: Database and API Contracts

**Version:** Draft 0.1
**Related:** `PROTOCOL.md` (byte-level rules), `DESIGN.md` (sections 6, 9), `ERROR_HANDLING.md` (error codes), `SECURITY.md` (roles)
**Claim status:** `SPECIFIED`. These are contracts to build against, not a migration and not implemented. Where this file and `PROTOCOL.md` disagree, `PROTOCOL.md` wins.

Conventions: IDs are lowercase UUIDs; times are Unix milliseconds (`bigint`) and are **claims**; hashes and digests are `bytea` (32 bytes) in the database and lowercase hex (64 chars) in JSON; signatures are 64 bytes (`bytea`) and 128 hex chars in JSON. Numbers in protocol JSON are integers only.

---

# Part A. Database contract (PostgreSQL)

## A1. Principles

- Protocol-critical rows live in ordinary PostgreSQL tables. TimescaleDB, if used, only holds telemetry.
- The exact signed bytes (`canonical_bytes`) are stored. They are never rebuilt from JSONB.
- One serialized writer per run: lock `event_stream_heads` with `SELECT ... FOR UPDATE` in the same transaction that commits the next event.
- Event row, head update and outbox row commit **atomically**.
- Committed events are append-only. A trigger rejects `UPDATE` and `DELETE` on `events`. This does **not** stop a database administrator; checkpoints, witnesses and anchors do.
- Migrations are forward-only, versioned and tested from an empty database.

## A2. Tables

```sql
-- Runs and state
CREATE TABLE runs (
  run_id              uuid PRIMARY KEY,
  task_digest         bytea   NOT NULL,
  adapter_name        text    NOT NULL,
  adapter_version     text    NOT NULL,
  mode                text    NOT NULL CHECK (mode IN ('REPLAY','LIVE_LOCAL','LIVE_EXTERNAL')),
  profile             text    NOT NULL CHECK (profile IN ('LOCAL_ONLY','CONNECTED_EVIDENCE')),
  requested_coverage  text    NOT NULL CHECK (requested_coverage IN ('TASK_LEVEL','STEP_OBSERVED','STEP_GATED')),
  declared_coverage   text    CHECK (declared_coverage IN ('TASK_LEVEL','STEP_OBSERVED','STEP_GATED')),
  policy_id           text    NOT NULL,
  policy_version      integer NOT NULL,
  mandate_id          text    REFERENCES mandates(mandate_id),
  state               text    NOT NULL,   -- see PROTOCOL.md section 6
  created_by          text    NOT NULL,
  created_at_ms       bigint  NOT NULL
);

CREATE TABLE run_state_transitions (
  run_id      uuid   NOT NULL REFERENCES runs(run_id),
  seq         integer NOT NULL,
  from_state  text   NOT NULL,
  to_state    text   NOT NULL,
  reason      text,
  at_ms       bigint NOT NULL,
  PRIMARY KEY (run_id, seq)
);
-- Legal (from, to) pairs are enforced by a trigger that mirrors PROTOCOL.md section 6.

-- Event ledger
CREATE TABLE event_stream_heads (
  run_id         uuid PRIMARY KEY REFERENCES runs(run_id),
  next_sequence  bigint  NOT NULL DEFAULT 0,
  fencing_token  bigint  NOT NULL,
  finished       boolean NOT NULL DEFAULT false
);

CREATE TABLE events (
  run_id           uuid   NOT NULL REFERENCES runs(run_id),
  sequence         bigint NOT NULL,
  event_id         uuid   NOT NULL UNIQUE,
  event_type       text   NOT NULL,
  canonical_bytes  bytea  NOT NULL,      -- JCS bytes, exactly as signed
  leaf_hash        bytea  NOT NULL CHECK (octet_length(leaf_hash) = 32),
  source           text   NOT NULL CHECK (source IN ('reported_by_adapter','observed_by_local_gateway','verified_by_black_box')),
  created_at_ms    bigint NOT NULL,      -- a claim
  PRIMARY KEY (run_id, sequence)
);

CREATE TABLE event_idempotency (
  run_id           uuid NOT NULL,
  idempotency_key  text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
  event_id         uuid NOT NULL REFERENCES events(event_id),
  PRIMARY KEY (run_id, idempotency_key)
);

CREATE TABLE workflow_outbox (
  outbox_id     bigserial PRIMARY KEY,
  run_id        uuid   NOT NULL,
  event_id      uuid   NOT NULL,
  topic         text   NOT NULL,          -- 'sse' | 'workflow' | 'assessment'
  delivered_at_ms bigint,
  attempts      integer NOT NULL DEFAULT 0
);

-- Artifacts and manifest
CREATE TABLE artifacts (
  artifact_digest  bytea PRIMARY KEY CHECK (octet_length(artifact_digest) = 32),  -- SHA-256(raw bytes)
  media_type       text   NOT NULL,
  size_bytes       bigint NOT NULL,
  object_key       text   NOT NULL UNIQUE,   -- derived from the digest
  status           text   NOT NULL CHECK (status IN ('PENDING','AVAILABLE','CORRUPT','ABANDONED')),
  created_at_ms    bigint NOT NULL
);

CREATE TABLE manifest_entries (
  run_id              uuid   NOT NULL REFERENCES runs(run_id),
  idx                 integer NOT NULL,                  -- 0,1,2... no gaps
  event_id            uuid   NOT NULL REFERENCES events(event_id),
  artifact_digest     bytea  NOT NULL REFERENCES artifacts(artifact_digest),
  capture_method      text   NOT NULL,
  captured_at_ms      bigint NOT NULL,
  entry_bytes         bytea  NOT NULL,                   -- JCS of the manifest entry
  entry_hash          bytea  NOT NULL,
  prev_manifest_hash  bytea  NOT NULL,
  PRIMARY KEY (run_id, idx)
);

-- Checkpoints, witnesses, anchors, global log
CREATE TABLE checkpoints (
  stream_id            text   NOT NULL,                 -- run UUID or 'global'
  tree_size            bigint NOT NULL,
  checkpoint_bytes     bytea  NOT NULL,                 -- JCS payload
  checkpoint_hash      bytea  NOT NULL UNIQUE,
  signature            bytea  NOT NULL CHECK (octet_length(signature) = 64),
  key_id               text   NOT NULL,
  created_at_ms        bigint NOT NULL,
  PRIMARY KEY (stream_id, tree_size)
);

CREATE TABLE global_log (
  position      bigint PRIMARY KEY,
  run_id        uuid   NOT NULL UNIQUE REFERENCES runs(run_id),
  record_bytes  bytea  NOT NULL,                        -- JCS run-root record
  leaf_hash     bytea  NOT NULL
);

CREATE TABLE witness_signatures (
  stream_id        text   NOT NULL,
  checkpoint_hash  bytea  NOT NULL REFERENCES checkpoints(checkpoint_hash),
  witness_id       text   NOT NULL,
  failure_domain   text   NOT NULL,
  signature        bytea  NOT NULL CHECK (octet_length(signature) = 64),
  received_at_ms   bigint NOT NULL,
  PRIMARY KEY (checkpoint_hash, witness_id)
);

CREATE TABLE anchor_publications (
  anchor_id        bigserial PRIMARY KEY,
  checkpoint_hash  bytea  NOT NULL REFERENCES checkpoints(checkpoint_hash),
  tree_size        bigint NOT NULL,
  location         text   NOT NULL,                     -- e.g. Git repo URL and path
  anchor_domain    text   NOT NULL,
  published_at_ms  bigint NOT NULL,
  evidence         text
);

-- Policy and assessments
CREATE TABLE policy_versions (
  policy_id     text    NOT NULL,
  version       integer NOT NULL,
  body_json     jsonb   NOT NULL,
  body_digest   bytea   NOT NULL,
  created_at_ms bigint  NOT NULL,
  PRIMARY KEY (policy_id, version)
);

CREATE TABLE assessments (
  assessment_id bigserial PRIMARY KEY,
  run_id        uuid NOT NULL REFERENCES runs(run_id),
  channel       text NOT NULL CHECK (channel IN ('POLICY','SEMANTIC','PROMPT_SECURITY','BEHAVIOR_ANOMALY')),
  event_id      uuid REFERENCES events(event_id),       -- the signed event that carries it
  detail_json   jsonb NOT NULL,
  created_at_ms bigint NOT NULL
);

-- Extensions (D-11, D-16) and identity
CREATE TABLE field_disclosures (
  event_id    uuid NOT NULL,
  field       text NOT NULL,
  salt        bytea,           -- NULL after crypto-shredding
  value_json  bytea,           -- NULL after crypto-shredding
  PRIMARY KEY (event_id, field)
);

CREATE TABLE key_manifest (
  key_id          text PRIMARY KEY,
  public_key      bytea NOT NULL,
  role            text NOT NULL CHECK (role IN ('signer','witness','approver','mandate_issuer')),
  failure_domain  text,
  valid_from_ms   bigint NOT NULL,
  status          text NOT NULL CHECK (status IN ('active','retired','revoked')),
  last_trusted_checkpoint bytea
);

CREATE TABLE mandates (
  mandate_id     text PRIMARY KEY,
  mandate_bytes  bytea NOT NULL,
  signature      bytea NOT NULL,
  issuer_key_id  text  NOT NULL REFERENCES key_manifest(key_id)
);

CREATE TABLE approvals (
  approval_id    uuid PRIMARY KEY,
  run_id         uuid NOT NULL REFERENCES runs(run_id),
  action_id      text NOT NULL,
  summary_digest bytea NOT NULL,
  status         text NOT NULL CHECK (status IN ('REQUESTED','GRANTED','DENIED','EXPIRED')),
  approver_key_id text REFERENCES key_manifest(key_id),
  expires_at_ms  bigint NOT NULL
);

CREATE TABLE users (
  user_id   uuid PRIMARY KEY,
  name      text NOT NULL,
  role      text NOT NULL CHECK (role IN ('admin','operator','adapter','approver','auditor')),
  disabled  boolean NOT NULL DEFAULT false
);

CREATE TABLE api_tokens (
  token_id     uuid PRIMARY KEY,
  user_id      uuid NOT NULL REFERENCES users(user_id),
  token_hash   bytea NOT NULL UNIQUE,       -- hash only; the token is shown once
  scope_run_id uuid,                        -- optional restriction to one run
  expires_at_ms bigint NOT NULL,
  revoked      boolean NOT NULL DEFAULT false
);

CREATE TABLE audit_log (
  audit_id   bigserial PRIMARY KEY,
  at_ms      bigint NOT NULL,
  actor      text   NOT NULL,
  action     text   NOT NULL,
  target     text,
  request_id text,
  result     text   NOT NULL
);
```

## A2.1 Implementation status (2026-10-15, Step 3)

`deploy/migrations/0001_init.sql` creates every table above and is run from
empty by each contract test, so the schema is `TESTED`. Differences from the
sketch, all additive:

* `schema_migrations` records the applied version; migrations are forward-only.
* `run_state_transitions_allowed` holds the legal `(from, to)` pairs of
  `PROTOCOL.md` section 6 as data, and a trigger checks every insert against
  it. Terminal states have no outgoing rows, and a test asserts that.
* Triggers on `events` reject `UPDATE` and `DELETE`, and reject an insert when
  the stream head says the run is finished. **A superuser can disable a trigger**
  — this is defence in depth, not the integrity guarantee (`R-DAT-06`).
* `CHECK (octet_length(...) = 32 or 64)` on every digest and signature column.
* `runs` references `policy_versions(policy_id, version)`, so a run cannot name
  a policy version that does not exist (`R-POL-06`).

Not implemented: the least-privilege roles and grants of A4 (the service
currently connects as one role), and the A6 backup and restore procedure.

## A3. Constraints and invariants

| Invariant | How it is enforced |
|---|---|
| `(run_id, sequence)` is unique and gap-free | Primary key plus `event_stream_heads.next_sequence` under `FOR UPDATE` |
| No event after `RUN_FINISHED` | `event_stream_heads.finished` checked in the insert transaction |
| Stale worker cannot commit | Insert requires `fencing_token >= event_stream_heads.fencing_token` |
| Events are append-only | Trigger raises on `UPDATE` or `DELETE`; the ingestion role has no such grant |
| Legal run-state transitions only | Trigger checks `(from_state, to_state)` against the table in `PROTOCOL.md` section 6 |
| Manifest chain is intact | `idx` has no gaps; `prev_manifest_hash` equals the previous `entry_hash` |
| Artifact digest equals its object key | Application check on upload and on export; mismatch sets `CORRUPT` |
| One global position per run | `UNIQUE (run_id)` on `global_log` |
| Every checkpoint extends the last | Checked by the signer before signing and by the verifier |

## A4. Roles and grants

| DB role | Grants |
|---|---|
| `abb_ingest` | `INSERT` on `events`, `event_idempotency`, `workflow_outbox`, `manifest_entries`, `artifacts`; `UPDATE` on `event_stream_heads`, `artifacts.status`, `workflow_outbox.delivered_at_ms`; `SELECT` where needed. **No** `UPDATE` or `DELETE` on `events` |
| `abb_api` | `SELECT` on most tables; `INSERT`/`UPDATE` on `runs`, `run_state_transitions`, `approvals`, `users`, `api_tokens`; no write on `events` |
| `abb_reader` | `SELECT` only (auditor and exporter) |
| `abb_exporter` | `SELECT` on ledger tables and `field_disclosures` (only if disclosure is requested) |
| `abb_migrate` | DDL, used only by migrations |
| signer | **No database role.** It keeps its own state log on its volume |

## A5. Indexes (starting set, tune after benchmark)

`events(run_id, sequence)` (primary key), `events(event_type)`, `workflow_outbox(delivered_at_ms) WHERE delivered_at_ms IS NULL`, `assessments(run_id, channel)`, `global_log(position)`, `witness_signatures(stream_id)`.

## A6. Backup and restore

Back up PostgreSQL, MinIO, the signer state log, keys and the key manifest together. After a restore, compare the restored latest checkpoint and global tree size against the signer state and the latest anchor **before** accepting writes. A restore that is older than the anchor is an incident (`ERROR_HANDLING.md` section 5).

---

# Part B. HTTP API contract

Base path `/api/v1`. JSON, UTF-8. All times are Unix ms. Auth is `Authorization: Bearer <token>`. Errors use the format and codes in `ERROR_HANDLING.md`. Proposed; nothing is implemented.

## B1. General rules

- **Versioning:** the path carries the API version. Breaking changes need `/api/v2`.
- **Idempotency:** write endpoints that create events take `Idempotency-Key` (1 to 128 ASCII printable chars). The same key returns the original result.
- **Pagination:** cursor based: `?limit=50&cursor=<opaque>`; responses include `next_cursor` or `null`. Max `limit` 200.
- **Rate limits:** `429` with `Retry-After`. Limits are per token.
- **Request ID:** every response has `X-Request-Id`.
- **Canonical bytes:** event ingestion accepts the event as JSON, but the server canonicalizes with JCS and stores the bytes. Clients MAY send already-canonical bytes; the server rejects non-canonical forms that change meaning (floats, duplicate keys).

## B2. Endpoints

### Runs (control plane, roles `operator`, `admin`)

| Method and path | Purpose | Success |
|---|---|---|
| `POST /runs` | Create a run | `201` with run |
| `GET /runs` | List runs (filters: `state`, `adapter`, `since`) | `200` page |
| `GET /runs/{run_id}` | Run detail and current state | `200` |
| `POST /runs/{run_id}/cancel` | Request cancellation | `202` |
| `GET /runs/{run_id}/events` | List committed events | `200` page |
| `GET /runs/{run_id}/stream` | SSE of committed events | `200` event stream |
| `GET /runs/{run_id}/assessments` | The assessment channels, separate | `200` |

`POST /runs` request:

```json
{
  "task": "Update vendor bank details on portal X",
  "adapter": "replay",
  "profile": "LOCAL_ONLY",
  "requested_coverage": "STEP_GATED",
  "policy_id": "default",
  "policy_version": 3,
  "mandate_id": null
}
```

Response `201`:

```json
{
  "run_id": "0b1d9c0e-5f0b-4f3a-9d4e-0d6a1a2b3c4d",
  "state": "PENDING",
  "declared_coverage": null,
  "created_at": 1760540000000
}
```

### Event ingestion (role `adapter`, scoped to one run)

| Method and path | Purpose | Success |
|---|---|---|
| `POST /runs/{run_id}/events` | Propose one event | `201` committed event, or `200 IDEMPOTENT_REPLAY` |

Request (envelope fields the client supplies; the server assigns `sequence`, `event_id`, `created_at` if absent and canonicalizes):

```json
{
  "event_type": "ACTION_REQUESTED",
  "source": "reported_by_adapter",
  "provenance": {
    "adapter_name": "replay",
    "adapter_version": "0.1.0",
    "execution_id": "exec-001",
    "mode": "REPLAY",
    "observed_coverage": "STEP_GATED"
  },
  "payload": {
    "action_id": "a-1",
    "action_type": "form_submit",
    "target": "https://portal.example/vendor/42",
    "params_digest": "<hex64>"
  }
}
```

Response `201`:

```json
{ "event_id": "…", "run_id": "…", "sequence": 7, "leaf_hash": "<hex64>", "committed": true }
```

Rules: the server rejects unknown event types, wrong run, event after `RUN_FINISHED`, events over size limits, and stale fencing tokens (`X-Fencing-Token` header from the worker lease).

### Artifacts (role `adapter`)

| Method and path | Purpose |
|---|---|
| `POST /runs/{run_id}/artifacts` | Upload bytes (`Content-Type` is the media type; header `X-Artifact-SHA256`) |
| `GET /artifacts/{digest}` | Download after digest verification (`auditor`, `operator`) |

The server hashes the bytes, compares with `X-Artifact-SHA256`, stores under the digest, creates the manifest entry and returns `{ "artifact_digest", "manifest_index", "size" }`.

### Policy (roles `admin`, `operator`)

| Method and path | Purpose |
|---|---|
| `GET /policies` , `GET /policies/{id}/versions/{n}` | Read |
| `POST /policies/{id}/versions` | Create a new immutable version |
| `POST /policy/evaluate` | Dry-run a proposed action (no event written) |

### Approvals (role `approver`)

| Method and path | Purpose |
|---|---|
| `GET /approvals?status=REQUESTED` | Pending approvals for this approver |
| `GET /approvals/{approval_id}` | The exact summary to be signed |
| `POST /approvals/{approval_id}/decision` | Submit the signed decision |

Decision request:

```json
{
  "decision": "GRANTED",
  "approver_key_id": "ed25519:…",
  "expires_at": 1760543600000,
  "approval_signature": "<hex128>"
}
```

The server verifies the signature against the key manifest, checks `action_id`, `summary_digest` and expiry, then commits `HUMAN_APPROVAL_GRANTED` or `_DENIED`. It never holds the approver's private key.

### Mandates (roles `admin`, `operator`)

| Method and path | Purpose |
|---|---|
| `POST /mandates` | Register a signed mandate (document plus signature) |
| `GET /mandates/{id}` | Read |

### Receipts and verification

| Method and path | Purpose |
|---|---|
| `POST /runs/{run_id}/receipt` | Build a receipt (async; returns `202` with a job). **Not implemented as an endpoint in Step 5**: export is a library call (`services/api/export.py`) driven by `tools/demo.py`. The endpoint arrives with the dashboard |
| `GET /runs/{run_id}/receipt` | Download `*.abbreceipt` once ready |
| `POST /verify` | Server-side convenience verification of an uploaded receipt (the offline CLI remains authoritative) |

Verification response:

```json
{
  "overall": "VALID",
  "dimensions": {
    "evidence_integrity": "PASS",
    "checkpoint_signatures": "PASS",
    "consistency": "PASS",
    "global_log_inclusion": "PASS",
    "observation_coverage": "PASS",
    "policy_assessment": "PASS",
    "witness_quorum": "NOT_APPLICABLE",
    "anchor_match": "NOT_APPLICABLE"
  },
  "details": [ { "dimension": "…", "event_id": "…", "message": "…" } ]
}
```

### Implementation status (2026-10-15, Step 3)

Implemented and tested: `POST /runs`, `GET /runs/{run_id}`,
`POST /runs/{run_id}/events`, `GET /runs/{run_id}/events`,
`GET /runs/{run_id}/stream`, `GET /health`, `GET /ready`.

Absent rather than stubbed, so nothing returns a result it did not compute:
`POST /runs/{run_id}/cancel`, `GET /runs/{run_id}/assessments`, every artifact,
policy, approval, mandate, receipt and verification endpoint, the global-log and
key-manifest reads, and `POST /admin/tokens`. Each arrives with its step.

Notes on what is implemented:

* `POST /runs/{run_id}/events` takes the **raw body**. The server assigns
  `protocol_version`, `schema_version`, `run_id`, `event_id` and `sequence`, and
  supplies `created_at` only when the producer omitted it. A producer value that
  disagrees with an assigned field is `422`, not a silent override.
* `Idempotency-Key` replay returns `200` with `code: IDEMPOTENT_REPLAY`.
* `X-Fencing-Token` below the current lease gives `409 STALE_FENCING_TOKEN`.
* Pagination uses the sequence number as the cursor; `limit` is 1 to 200.
* Rate limiting and backpressure are **not** implemented, so `RATE_LIMITED` and
  `BACKPRESSURE` are never returned yet.

### Logs, keys, admin

| Method and path | Role | Purpose |
|---|---|---|
| `GET /global-log` , `GET /global-log/latest` | auditor | Global log entries and latest checkpoint |
| `GET /key-manifest` | public | Verification keys (also published out of band) |
| `GET /checkpoints?stream_id=…` | auditor | Checkpoints with witness signatures |
| `GET /health` , `GET /ready` | none | Liveness and readiness (no secrets) |
| `POST /admin/tokens` , `DELETE /admin/tokens/{id}` | admin | Manage tokens |

## B3. SSE contract

`GET /runs/{run_id}/stream`

- Only **committed** events are sent.
- Each message: `id: <sequence>`, `event: <event_type>`, `data: <canonical event JSON>`.
- `Last-Event-ID` resumes after that sequence.
- A comment line `: keepalive` every 15 seconds.
- **Status (Step 3):** implemented and tested. The `id:` field is the event's
  sequence number, so `Last-Event-ID` resumes exactly after it. The stream is
  served by polling committed events every 50 ms; `LISTEN`/`NOTIFY` is a later
  improvement.
- On `RUN_FINISHED` the server sends the event and closes the stream.

## B4. Internal signer API (not public)

Reachable only from the ingestion service over the `signer` network.

| Method and path | Purpose |
|---|---|
| `POST /sign` | Request a checkpoint for a stream (body in `PROTOCOL.md` 11.1) |
| `GET /state/{stream_id}` | Last accepted checkpoint (idempotent re-delivery) |
| `GET /health` | Liveness |

Response `200`: `{ "checkpoint": { "payload": {…}, "signature": "<hex128>" } }`. Errors use the signer codes in `ERROR_HANDLING.md` section 4.2.

**Implementation status (2026-10-16, Step 4).** All three routes are implemented and tested against the running binary.

- The `200` body also carries `payload_b64` (the exact canonical payload bytes the signature covers) and `checkpoint_hash`, so a caller stores the signed bytes rather than re-serializing the payload object (`R-PRO-04`). Both fields are additive.
- Every request must carry `caller_attestation` as defined by **D-20** (`PROTOCOL.md` 11.1). `abb attest --key <file> --stdin` builds and signs the body, so the Python service never canonicalizes anything itself.
- Error statuses: `UNAUTHORIZED` 401, `UNKNOWN_STREAM` 404, `RATE_LIMITED` 429, `STATE_CORRUPT` 503, extension conflicts (`NOT_EXTENDING`, `SIZE_REGRESSION`, `FORK_DETECTED`, `ROOT_MISMATCH`, `GAP_OR_OVERLAP`) 409, malformed input (`BAD_GENESIS`, `BAD_EVENT`, `BAD_APPEND_EVIDENCE`) 422.
- `GET /state/{stream_id}` returns `{stream_id, tree_size, root_hash, checkpoint_hash, checkpoint}` or `404 UNKNOWN_STREAM`.
- Not implemented: key rotation, so the signer never emits a transition record.

## B5. Witness API

`POST /witness/sign` takes a global checkpoint and the consistency proof from the witness's last seen checkpoint. The witness verifies extension against its own state, then returns its signature or an error (`NOT_EXTENDING`, `FORK_DETECTED`, `SIZE_REGRESSION`).

---

# Part C. CLI contract (`abb`, Rust)

| Command | Purpose | Notes |
|---|---|---|
| `abb verify <receipt> [--keys <manifest>] [--profile LOCAL_ONLY\|CONNECTED_EVIDENCE] [--json]` | Verify a receipt offline | Exit codes in `ERROR_HANDLING.md` section 9 |
| `abb verify-global --db <url> --anchor <git-url-or-file>` | Compare global log in the database with the latest witnessed or anchored checkpoint | Reports missing or altered runs |
| `abb canon <file>` | Print JCS bytes (hex) of a JSON file | For test vectors |
| `abb merkle root\|proof\|verify …` | Tree utilities | For test vectors |
| `abb keygen --out <dir>` | Generate an Ed25519 key | For signer, witness, approver |
| `abb approve --request <id> --key <file>` | Sign an approval statement on the approver's device | |
| `abb vectors check` | Run built-in conformance vectors | |
| `abb attest --key <file> (--file \| --stdin)` | Canonicalize a signer request and sign it with the ingestion key; prints `signature` and `body_hex` | Added in Step 4 (D-20). The ingestion service calls it so the request layout has one implementation |
| `abb event canon (--file \| --stdin) [--strict] [--run-id --event-id --sequence --created-at]` | Validate one event envelope; print its canonical bytes, digest and Merkle leaf hash | Added in Step 3. With the assignment flags it is the ingestion path: the producer's raw bytes plus the fields only the server may choose. `--strict` requires the bytes to be canonical already, which is the signer's rule |

All commands are deterministic, read their inputs from files or URLs given on the command line, and never print private keys.

**Implementation status (2026-10-15, Step 2).**

| Command | State |
|---|---|
| `abb canon <file> [--text] [--sha256]` | Implemented and tested. Prints hex by default, as above |
| `abb merkle root` / `proof` / `verify` | Implemented and tested. Leaves come from `--synthetic <n>` or `--leaves <file>` (one base64 leaf per line) |
| `abb merkle consistency` / `verify-consistency` | Added beyond the table above, same shape, for consistency proofs |
| `abb keygen --out <dir> [--role ...]` | Implemented and tested. Writes the private key to a file, prints only the `key_id` and public key, refuses to overwrite an existing key. File permissions are **not** restricted on Windows and the command says so |
| `abb vectors check [--dir <dir>]` | Implemented and tested: 141 cases, exit 0 |
| `abb verify-global --roots <file> [--anchor <file>] [--keys <manifest>]` | Partly implemented: it reads a **file** of run roots plus a signed global checkpoint, not `--db <url>`. Without `--keys` it reports the signature as `UNKNOWN`; without `--anchor` it says the rollback question is unanswered. The `--db` form arrives with Step 3 |
| `abb verify <receipt> [--keys] [--profile] [--json]` | Implemented and tested. Reports all 16 dimensions, names the broken point, exits 0/1/2/3/4 by overall result and 65 for a container it refuses |
| `abb receipt build --bundle <file> --out <file>` | Added in Step 5. Turns the service's export bundle into a `*.abbreceipt`, computing every proof and the canonical layout |
| `abb digest (--file \| --stdin)` | Added in Step 6. The untagged artifact digest (`D-03`) and size |
| `abb witness sign --key --state --keys --domain --checkpoint --records` | Added in Step 8. Rebuilds the global tree from the records, checks the signer's signature and its own saved state, then signs a witness statement. Refuses `ROOT_MISMATCH`, `SIZE_REGRESSION`, `FORK_DETECTED`, `NOT_EXTENDING`, `BAD_CHECKPOINT` |
| `abb anchor append --file --checkpoint` | Added in Step 8. Appends `tree_size checkpoint_hash published_at` to an append-only anchor file; refuses to go backwards or to anchor a different hash at an anchored size |
| `abb approve --key --run-id --action-id --approval-id --decision --expires-at (--summary \| --summary-digest)` | Added in Step 9. Signs an approval on the approver's own device. With `--summary` it prints what is being signed and refuses (`APPROVAL_MISMATCH`) if the text does not hash to `--summary-digest` |
| `abb approval check --keys --key-id --statement-b64 --signature` | Added in Step 9. Checks role and signature; prints the statement's fields. Refuses `BAD_SIGNATURE`, `UNKNOWN_APPROVER`, `VALIDATION_FAILED` |
| `abb mandate sign --key --file` / `abb mandate check --keys --document-b64 --signature` | Added in Step 9. The issuer signs; the service checks against the manifest (`UNKNOWN_ISSUER`, `BAD_SIGNATURE`) |
| `abb commit (--value-json \| --stdin) [--salt-hex]` | Added in Step 9. A salted commitment to one value; `--stdin` keeps a secret out of the process list. 16-byte CSPRNG salt unless one is given |
| `abb leaf --tag <ABB1-...> (--file \| --stdin)` | Added in Step 5. The Merkle leaf hash of tagged data, so no caller reimplements it |
| `abb approve --request <id> --key <file>` | Not implemented. Step 9 |

The `--db <url>` option of `verify-global` in the table above is still the target shape.

---

# Part D. Contract change rules

- Anything that changes canonical bytes, tags, tree rules or checkpoint layout needs a new `protocol_version` (`PROTOCOL.md` section 18).
- A new API field is additive. A removed or renamed field is a breaking change.
- Database migrations never rewrite `events`, `checkpoints` or `global_log` rows.
- Every endpoint and table here gets a contract test (`TESTING.md` section 5).
