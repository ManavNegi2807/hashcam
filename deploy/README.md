# deploy — Compose, profiles, migrations

**Status:** migrations are `TESTED` (every contract test runs them from empty).
The `core` Compose profile was **run for the first time on 2026-10-18** (Docker 29.1.3, Windows,
linux/arm64) and **found five bugs** that are now fixed: the API image missed the `signer/`
crate, `pathsafe.py` and `policy/`; PostgreSQL 18 wants its volume at `/var/lib/postgresql`;
the signer's state folder was not writable by its user; and the signer's health check started a
second signer. After the fixes all three services are healthy, and **measured**: the API answers
`/api/v1/health` (200) and refuses an unauthenticated request (401); PostgreSQL and the signer are
not published to the host; the signer cannot reach or resolve the database; the API container
holds no signer key; both run as non-root with a read-only filesystem and no capabilities; no
password is in a container's environment (`R-OPS-04`, `R-SIG-01`, `R-SIG-02`, `R-OPS-03`).
**Not tested:** a complete signed run through the containers (finalizing runs in a separate
process, not in the API), `R-OPS-02` (images are pinned by tag, not by digest), a restore of the
signer key, and the "one command from a fresh checkout" claim: the key volumes below are still
filled by hand.
**Requirements:** R-OPS-01..08, R-DAT-01/02, R-HKC-02.

## Files

| File | What it is |
|---|---|
| `migrations/0001_init.sql` | The whole schema of `DATABASE_AND_API_CONTRACTS.md` Part A, forward-only, with the append-only and legal-transition triggers |
| `docker-compose.yml` | The `core` profile: PostgreSQL and the one FastAPI service |
| `api.Dockerfile` | Two stages: build `abb` with Rust, run the service on Python without build tools |
| `signer.Dockerfile` | The signer alone: one binary, no Python, no database client |
| `signer-entrypoint.sh` | Reads the ingestion **public** key from its secret file; echoes no key |
| `entrypoint.sh` | Assembles the DSN from a secret file; never echoes the password |
| `.dockerignore` | Keeps `secrets/`, keys, databases and build output out of every build context |

## Keys, before the first run

```bash
abb keygen --out deploy/secrets/signer --role signer     # the signing key
abb keygen --out deploy/secrets/ingest --role approver   # the ingestion key pair
cp deploy/secrets/ingest/approver.pub deploy/secrets/ingestion_public_key
```

Then put `signer.key` on the `signer_keys` volume and `approver.key` on
`ingestion_keys`, through a pipe so no host folder is shared with a container (this is what
worked; the owners must match the users in the compose file):

```bash
docker volume create abb_signer_keys && docker volume create abb_ingestion_keys
docker run -i --rm -v abb_signer_keys:/keys alpine:3.21 sh -c \
  'cat > /keys/signer.key && chown 10002:10002 /keys/signer.key && chmod 400 /keys/signer.key' \
  < deploy/secrets/signer/signer.key
docker run -i --rm -v abb_ingestion_keys:/ingestion alpine:3.21 sh -c \
  'cat > /ingestion/ingestion.key && chown 10001:10001 /ingestion/ingestion.key && chmod 400 /ingestion/ingestion.key' \
  < deploy/secrets/ingest/approver.key
```

(On Git Bash for Windows set `MSYS_NO_PATHCONV=1` first.) Do not use `docker compose down -v`
afterwards unless you mean to lose these volumes: it deletes them and the keys must be put back. Nothing under `deploy/secrets/` is committed, and
`tools/check_key_volume_isolation.py` fails the build if any service other than
the signer names `signer_keys` (`R-OPS-03`).

The signer's key should be generated on a machine that is not the host, with an
encrypted offline backup (`R-SIG-13`). That is documented and **not tested**:
there is no restore test yet.

## Before the first run

```bash
mkdir -p deploy/secrets
# Any strong local value. This file is ignored by git and by Docker builds.
head -c 24 /dev/urandom | base64 > deploy/secrets/postgres_password
docker compose -f deploy/docker-compose.yml --profile core up --build
```

## Running the tests against a database

The contract tests need a real PostgreSQL (`TESTING.md` 5). Either point them at
the compose database or at any throwaway cluster:

```bash
ABB_TEST_DSN=postgresql://abb@127.0.0.1:5432/postgres \
ABB_BIN=core/target/debug/abb \
pytest -q tests/contract
```

They create one database per test and drop it afterwards, so they never touch
an existing schema. Without `ABB_TEST_DSN` they skip with a message rather than
passing.

## What is deliberately absent

`signer` (Step 4, with its own key volume mounted nowhere else), `minio`
(Step 6), `witness` (Step 8), `ui` (Step 10), and the `replay`, `playwright`,
`tinyfish`, `ipfs`, `llm` and `testing` profiles. They arrive with their steps
rather than being declared empty now.

Backup and restore (`R-OPS-06`) is not implemented or tested. The signer's state
log and keys are part of what must be backed up together with PostgreSQL
(`DATABASE_AND_API_CONTRACTS.md` A6).

## Artifact storage (profile `storage`)

The deck's MinIO slot. MinIO's community edition was archived upstream in April 2026 and no longer
publishes images, so this profile runs **SeaweedFS 4.48** (Apache-2.0, pinned by digest) as the
S3-compatible server. The code (`services/artifacts/s3_store.py`) only speaks the S3 API.

1. Create the identity file, never committed (`deploy/secrets/` is git-ignored). Make up an access key and
   a long random secret yourself and put them in `deploy/secrets/s3.json`:
   `{"identities":[{"name":"abb","credentials":[{"accessKey":"...","secretKey":"..."}],"actions":["Admin","Read","Write","List"]}]}`
2. `docker compose -f deploy/docker-compose.yml --profile storage up -d storage` (published on
   `127.0.0.1:8333` only; authentication is on).
3. Point the project at it: set `ABB_S3_ENDPOINT=http://127.0.0.1:8333`, `ABB_S3_ACCESS_KEY` and
   `ABB_S3_SECRET_KEY` in the window that runs the server.

The container drops all capabilities except the three the image needs to start (`CHOWN`, `SETUID`,
`SETGID`; found on the first run). **Measured:** healthy, and the 15 store tests pass against it.
**Not tested:** TLS between the project and the store (loopback only here), replicas, backups.

## Run-graph database (profile `graph`)

```bash
docker compose -f deploy/docker-compose.yml --profile graph up -d graph
python tools/ui_server.py --receipts RUNS --falkordb redis://127.0.0.1:6390
```

FalkorDB (image pinned by digest, SSPL-licensed server) holds a **copy** of each run's structure so the
audit page can draw it. The receipt stays the only source of truth: delete the `falkor_data` volume and
nothing is lost, the page rebuilds the graph on the next view. The container is read-only with all
capabilities dropped, but it runs as root inside, and it has **no password**: that is acceptable only
because the port is bound to 127.0.0.1. Do not publish it on another interface. `--falkordb` refuses any
address that is not this computer.
