# deploy — Compose, profiles, migrations

**Status:** migrations are `TESTED` (every contract test runs them from empty).
The Compose files are `IMPLEMENTED` but **never run**: no Docker daemon was
available when Step 3 was built, so `R-OPS-01`, `R-OPS-02`, `R-OPS-04` and the
"one command from a fresh checkout" claim are all unverified.
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
`ingestion_keys`. Nothing under `deploy/secrets/` is committed, and
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
