"""Fixtures for the contract tests: a real PostgreSQL and a fresh schema.

`TESTING.md` section 5 requires these tests to run against a real database, not
a stub, because what is being tested is `FOR UPDATE` serialization, triggers and
transaction atomicity. There is no in-memory substitute for that.

The database comes from `ABB_TEST_DSN`. If it is not set, the tests skip with a
message that says how to provide one; they never fall back to something weaker
and call it a pass.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
MIGRATION = REPO / "deploy" / "migrations"

SKIP_REASON = (
    "no PostgreSQL for the contract tests. Set ABB_TEST_DSN, e.g. "
    "ABB_TEST_DSN=postgresql://abb@127.0.0.1:55432/postgres, or start the "
    "compose 'core' profile."
)


def _psycopg():  # noqa: ANN202 - imported lazily so collection works without it
    try:
        import psycopg
    except ImportError:  # pragma: no cover - environment dependent
        pytest.skip("psycopg is not installed; see requirements-dev.txt")
    return psycopg


@pytest.fixture(scope="session")
def admin_dsn() -> str:
    dsn = os.environ.get("ABB_TEST_DSN")
    if not dsn:
        pytest.skip(SKIP_REASON)
    return dsn


@pytest.fixture(scope="session")
def migration_sql() -> str:
    assert MIGRATION.is_dir(), f"{MIGRATION} is missing"
    import pathsafe

    return pathsafe.read_migrations(MIGRATION)


@pytest.fixture
def dsn(admin_dsn: str, migration_sql: str) -> Iterator[str]:
    """A fresh, empty, migrated database per test, dropped afterwards."""
    psycopg = _psycopg()
    name = f"abb_test_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    test_dsn = _with_database(admin_dsn, name)
    try:
        with psycopg.connect(test_dsn, autocommit=True) as conn:
            conn.execute(migration_sql)
        yield test_dsn
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as conn:
            conn.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
                (name,),
            )
            conn.execute(f'DROP DATABASE IF EXISTS "{name}"')


def _with_database(dsn: str, database: str) -> str:
    """Swap the database name in a URL-style DSN."""
    head, _, _tail = dsn.rpartition("/")
    return f"{head}/{database}"


@pytest.fixture
def conn(dsn: str):  # noqa: ANN201 - psycopg connection
    psycopg = _psycopg()
    with psycopg.connect(dsn, autocommit=True) as connection:
        yield connection


@pytest.fixture
def seeded(conn):  # noqa: ANN001, ANN201
    """A policy version, an adapter token and one run in PENDING.

    Returns the ids the tests need. Everything here is synthetic
    (`TESTING.md` 16): no real names, no real keys.
    """
    import hashlib

    run_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    token = "test-adapter-token"
    token_hash = hashlib.sha256(token.encode()).digest()

    conn.execute(
        """
        INSERT INTO policy_versions (policy_id, version, body_json, body_digest, created_at_ms)
        VALUES ('default', 1, '{"allow": []}', %s, 1760000000000)
        """,
        (hashlib.sha256(b"policy").digest(),),
    )
    conn.execute(
        "INSERT INTO users (user_id, name, role) VALUES (%s, 'test adapter', 'adapter')",
        (user_id,),
    )
    conn.execute(
        """
        INSERT INTO api_tokens (token_id, user_id, token_hash, scope_run_id, expires_at_ms)
        VALUES (%s, %s, %s, %s, 4000000000000)
        """,
        (str(uuid.uuid4()), user_id, token_hash, run_id),
    )
    conn.execute(
        """
        INSERT INTO runs (run_id, task_digest, adapter_name, adapter_version, mode, profile,
                          requested_coverage, policy_id, policy_version, state, created_by,
                          created_at_ms)
        VALUES (%s, %s, 'replay', '0.1.0', 'REPLAY', 'LOCAL_ONLY', 'STEP_GATED',
                'default', 1, 'PENDING', 'test', 1760000000000)
        """,
        (run_id, hashlib.sha256(b"task").digest()),
    )
    conn.execute(
        "INSERT INTO event_stream_heads (run_id, next_sequence, fencing_token) VALUES (%s, 0, 1)",
        (run_id,),
    )
    return {"run_id": run_id, "user_id": user_id, "token": token}


@pytest.fixture
def operator_token(conn) -> str:  # noqa: ANN001
    """An unscoped operator token, for the endpoints an adapter may not use."""
    import hashlib
    import uuid as _uuid

    token = "test-operator-token"
    user_id = str(_uuid.uuid4())
    conn.execute(
        "INSERT INTO users (user_id, name, role) VALUES (%s, 'test operator', 'operator')",
        (user_id,),
    )
    conn.execute(
        """INSERT INTO api_tokens (token_id, user_id, token_hash, scope_run_id, expires_at_ms)
           VALUES (%s, %s, %s, NULL, 4000000000000)""",
        (str(_uuid.uuid4()), user_id, hashlib.sha256(token.encode()).digest()),
    )
    return token
