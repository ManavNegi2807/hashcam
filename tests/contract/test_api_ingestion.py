"""HTTP contract tests for the one FastAPI service.

Covers `DATABASE_AND_API_CONTRACTS.md` Part B, the ingestion error codes of
`ERROR_HANDLING.md` 4.1, and R-HKC-01, R-PRO-04, R-PRO-05, R-RUN-01, R-RUN-03,
R-SVC-02, R-SVC-03, R-SVC-05, R-DAT-05.

The single most important test here is
`test_stored_canonical_bytes_are_byte_identical_to_the_rust_core`: if the
service ever stores bytes the Rust core would not produce, every signature over
them is meaningless (R-PRO-04).
"""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def abb_binary() -> str | None:
    import os
    import shutil

    from_env = os.environ.get("ABB_BIN")
    if from_env and Path(from_env).is_file():
        return from_env
    found = shutil.which("abb")
    if found:
        return found
    for candidate in (
        REPO / "core" / "target" / "debug" / "abb.exe",
        REPO / "core" / "target" / "debug" / "abb",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


@pytest.fixture
def client(dsn: str):  # noqa: ANN201
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from services.api.main import build_app

    abb = abb_binary()
    if abb is None:
        pytest.skip("the abb binary is required for canonicalization; set ABB_BIN")
    app = build_app(dsn=dsn, abb_path=abb)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def adapter_headers(token: str, fencing_token: int = 1) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Fencing-Token": str(fencing_token),
    }


def event_body(
    event_type: str = "ACTION_REQUESTED", payload: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "event_type": event_type,
        "source": "reported_by_adapter",
        "provenance": {
            "adapter_name": "replay",
            "adapter_version": "0.1.0",
            "execution_id": "exec-001",
            "mode": "REPLAY",
            "observed_coverage": "STEP_GATED",
        },
        "payload": payload
        if payload is not None
        else {
            "action_id": "a-1",
            "action_type": "form_submit",
            "target": "https://portal.example/vendor/42",
            "params_digest": "ab" * 32,
        },
    }


# --------------------------------------------------------------------------- #
# health and request ids
# --------------------------------------------------------------------------- #


def test_health_is_open_and_leaks_nothing(client) -> None:  # noqa: ANN001
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    body = response.text.lower()
    for forbidden in ("password", "dsn", "postgresql://", "secret", "token"):
        assert forbidden not in body, body
    assert response.headers.get("X-Request-Id")


def test_every_response_carries_a_request_id(client, seeded, operator_token) -> None:  # noqa: ANN001
    ok = client.get(f"/api/v1/runs/{seeded['run_id']}", headers=adapter_headers(seeded["token"]))
    missing = client.get(
        f"/api/v1/runs/{uuid.uuid4()}", headers={"Authorization": f"Bearer {operator_token}"}
    )
    assert ok.status_code == 200, ok.text
    assert ok.headers.get("X-Request-Id")
    assert missing.headers.get("X-Request-Id")
    assert missing.status_code == 404
    assert missing.json()["code"] == "NOT_FOUND"


def test_scope_is_checked_before_existence(client, seeded) -> None:  # noqa: ANN001
    """A scoped token must not be able to probe which runs exist.

    So an out-of-scope request is 403 whether or not the run is real.
    """
    unknown = client.get(f"/api/v1/runs/{uuid.uuid4()}", headers=adapter_headers(seeded["token"]))
    assert unknown.status_code == 403
    assert unknown.json()["code"] == "FORBIDDEN"


# --------------------------------------------------------------------------- #
# runs
# --------------------------------------------------------------------------- #


def test_create_a_run_with_the_contracted_body(client, conn, seeded, operator_token) -> None:  # noqa: ANN001
    # `seeded` provides policy default/1; a run must reference a real policy
    # version (R-POL-06), so creating one without it is a 422, not a 500.
    response = client.post(
        "/api/v1/runs",
        headers={"Authorization": f"Bearer {operator_token}"},
        json={
            "task": "Update vendor bank details on portal X",
            "adapter": "replay",
            "profile": "LOCAL_ONLY",
            "requested_coverage": "STEP_GATED",
            "policy_id": "default",
            "policy_version": 1,
            "mandate_id": None,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "PENDING"
    assert body["declared_coverage"] is None
    assert uuid.UUID(body["run_id"])
    # A stream head must exist, or the first event could not be sequenced.
    head = conn.execute(
        "SELECT next_sequence, finished FROM event_stream_heads WHERE run_id = %s",
        (body["run_id"],),
    ).fetchone()
    assert head == (0, False)


def test_an_adapter_token_cannot_create_a_run(client, seeded) -> None:  # noqa: ANN001
    response = client.post(
        "/api/v1/runs",
        headers={"Authorization": f"Bearer {seeded['token']}"},
        json={
            "task": "x",
            "adapter": "replay",
            "profile": "LOCAL_ONLY",
            "requested_coverage": "STEP_GATED",
            "policy_id": "default",
            "policy_version": 1,
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "FORBIDDEN"


# --------------------------------------------------------------------------- #
# authentication and scope
# --------------------------------------------------------------------------- #


def test_missing_and_bad_tokens_are_refused(client, seeded) -> None:  # noqa: ANN001
    url = f"/api/v1/runs/{seeded['run_id']}/events"
    assert client.post(url, json=event_body()).status_code == 401
    bad = client.post(url, headers=adapter_headers("not-a-token"), json=event_body())
    assert bad.status_code == 401
    assert bad.json()["code"] == "UNAUTHENTICATED"


def test_an_adapter_token_cannot_reach_another_run(client, seeded, conn) -> None:  # noqa: ANN001
    """SECURITY.md 15: token scope. The token is scoped to its own run."""
    import hashlib

    other_run = str(uuid.uuid4())
    conn.execute(
        """INSERT INTO runs (run_id, task_digest, adapter_name, adapter_version, mode, profile,
                             requested_coverage, policy_id, policy_version, state, created_by,
                             created_at_ms)
           VALUES (%s, %s, 'replay', '0.1.0', 'REPLAY', 'LOCAL_ONLY', 'STEP_GATED', 'default', 1,
                   'PENDING', 'test', 1760000000000)""",
        (other_run, hashlib.sha256(b"other").digest()),
    )
    conn.execute(
        "INSERT INTO event_stream_heads (run_id, next_sequence, fencing_token) VALUES (%s, 0, 1)",
        (other_run,),
    )
    response = client.post(
        f"/api/v1/runs/{other_run}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body(),
    )
    assert response.status_code == 403
    assert response.json()["code"] == "FORBIDDEN"


# --------------------------------------------------------------------------- #
# ingestion
# --------------------------------------------------------------------------- #


def test_events_are_committed_with_server_assigned_sequences(client, seeded, conn) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    for expected in range(3):
        response = client.post(
            f"/api/v1/runs/{run_id}/events",
            headers=adapter_headers(seeded["token"]),
            json=event_body(),
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert body["sequence"] == expected
        assert body["committed"] is True
        assert len(body["leaf_hash"]) == 64
        assert uuid.UUID(body["event_id"])

    rows = conn.execute(
        "SELECT sequence, event_type FROM events WHERE run_id = %s ORDER BY sequence", (run_id,)
    ).fetchall()
    assert [row[0] for row in rows] == [0, 1, 2]
    # Every committed event is announced on the outbox exactly once (R-DAT-04).
    assert conn.execute("SELECT count(*) FROM workflow_outbox").fetchone()[0] == 3


def test_stored_canonical_bytes_are_byte_identical_to_the_rust_core(client, seeded, conn) -> None:  # noqa: ANN001
    """R-PRO-04: the stored bytes are the ones the Rust core produces.

    The test rebuilds the envelope the server must have built, asks the `abb`
    binary to canonicalize it, and compares bytes. If this drifts, every
    signature over a stored event is worthless.
    """
    run_id = seeded["run_id"]
    response = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body(),
    )
    assert response.status_code == 201, response.text
    stored, event_id, created_at = conn.execute(
        "SELECT canonical_bytes, event_id, created_at_ms FROM events WHERE run_id = %s", (run_id,)
    ).fetchone()

    envelope = {
        "protocol_version": "abb/1",
        "schema_version": 1,
        "run_id": run_id,
        "event_id": str(event_id),
        "sequence": 0,
        "created_at": created_at,
        **event_body(),
    }
    abb = abb_binary()
    assert abb is not None
    done = subprocess.run(  # noqa: S603
        [abb, "event", "canon", "--stdin"],
        input=json.dumps(envelope).encode(),
        capture_output=True,
        check=True,
    )
    lines = dict(line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line)
    assert bytes(stored).hex() == lines["canonical_hex"], "stored bytes differ from the Rust core"
    assert response.json()["leaf_hash"] == lines["leaf_hash"]


def test_a_duplicate_idempotency_key_returns_the_original_event(client, seeded, conn) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    headers = adapter_headers(seeded["token"]) | {"Idempotency-Key": "act-1-requested"}
    first = client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body())
    assert first.status_code == 201, first.text

    second = client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body())
    assert second.status_code == 200
    assert second.json()["code"] == "IDEMPOTENT_REPLAY"
    assert second.json()["event_id"] == first.json()["event_id"]
    assert second.json()["sequence"] == first.json()["sequence"]
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 1


def test_a_stale_fencing_token_cannot_commit(client, seeded, conn) -> None:  # noqa: ANN001
    """R-RUN-03: a newer worker took the lease; the old one must stop."""
    run_id = seeded["run_id"]
    conn.execute("UPDATE event_stream_heads SET fencing_token = 7 WHERE run_id = %s", (run_id,))
    stale = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"], fencing_token=6),
        json=event_body(),
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "STALE_FENCING_TOKEN"
    assert conn.execute("SELECT count(*) FROM events").fetchone()[0] == 0

    current = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"], fencing_token=7),
        json=event_body(),
    )
    assert current.status_code == 201, current.text


def test_nothing_follows_run_finished(client, seeded) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    finished = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body(
            "RUN_FINISHED",
            {"final_state": "CHECKPOINTED", "event_count": 1, "outcome": "ok"},
        ),
    )
    assert finished.status_code == 201, finished.text
    after = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body(),
    )
    assert after.status_code == 409
    assert after.json()["code"] == "RUN_FINISHED"


ENVELOPE_PREFIX = (
    b'{"event_type":"ACTION_REQUESTED","source":"reported_by_adapter",'
    b'"provenance":{"adapter_name":"replay","adapter_version":"0.1.0",'
    b'"execution_id":"e1","mode":"REPLAY","observed_coverage":"STEP_GATED"},'
)


@pytest.mark.parametrize(
    ("raw_payload", "expected_code"),
    [
        (b'"payload":{"amount":1.5}}', "FLOAT_NOT_ALLOWED"),
        (b'"payload":{"amount":1,"amount":2}}', "DUPLICATE_KEY"),
        (b'"payload":{"n":NaN}}', "NAN_OR_INFINITY"),
        (b'"payload":{"big":9007199254740992}}', "INT_OUT_OF_RANGE"),
        (b'"payload":{"n":-0}}', "MINUS_ZERO"),
        (b'"payload":{"n":01}}', "LEADING_ZERO"),
    ],
)
def test_non_canonical_bodies_are_refused_with_the_protocol_code(
    client: Any,
    seeded: dict[str, Any],
    raw_payload: bytes,
    expected_code: str,
) -> None:
    """R-PRO-03 and R-PRO-05, surfaced from the Rust core.

    The body is posted as **raw bytes**. That matters: a duplicate key or a
    float would not survive being parsed and re-serialized by the service, so
    this test is what proves the raw bytes reach the core.
    """
    response = client.post(
        f"/api/v1/runs/{seeded['run_id']}/events",
        headers=adapter_headers(seeded["token"]) | {"Content-Type": "application/json"},
        content=ENVELOPE_PREFIX + raw_payload,
    )
    assert response.status_code in (413, 422), response.text
    assert response.json()["code"] == expected_code, response.text


def test_a_producer_cannot_choose_its_own_sequence(client, seeded) -> None:  # noqa: ANN001  # noqa: ANN001
    """PROTOCOL.md 5.3: adapters propose events, they do not number them."""
    response = client.post(
        f"/api/v1/runs/{seeded['run_id']}/events",
        headers=adapter_headers(seeded["token"]) | {"Content-Type": "application/json"},
        content=ENVELOPE_PREFIX + b'"sequence":99,"payload":{}}',
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_FAILED"


def test_unknown_event_types_are_refused(client, seeded) -> None:  # noqa: ANN001
    response = client.post(
        f"/api/v1/runs/{run_id_of(seeded)}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body("CHECKPOINT_CREATED", {"root": "x"}),
    )
    assert response.status_code == 422
    assert response.json()["code"] == "UNKNOWN_EVENT_TYPE"


def test_oversize_events_are_refused(client, seeded) -> None:  # noqa: ANN001
    response = client.post(
        f"/api/v1/runs/{run_id_of(seeded)}/events",
        headers=adapter_headers(seeded["token"]),
        json=event_body("ACTION_REQUESTED", {"blob": "x" * 70_000}),
    )
    assert response.status_code == 413
    assert response.json()["code"] in {"SIZE_EXCEEDED", "PAYLOAD_TOO_LARGE", "STRING_TOO_LONG"}


def run_id_of(seeded: dict[str, Any]) -> str:
    return str(seeded["run_id"])


def test_listing_events_is_paginated_and_ordered(client, seeded) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    for _ in range(5):
        client.post(
            f"/api/v1/runs/{run_id}/events",
            headers=adapter_headers(seeded["token"]),
            json=event_body(),
        )
    page = client.get(
        f"/api/v1/runs/{run_id}/events?limit=2", headers=adapter_headers(seeded["token"])
    )
    assert page.status_code == 200, page.text
    body = page.json()
    assert [item["sequence"] for item in body["items"]] == [0, 1]
    assert body["next_cursor"] is not None

    second = client.get(
        f"/api/v1/runs/{run_id}/events?limit=2&cursor={body['next_cursor']}",
        headers=adapter_headers(seeded["token"]),
    )
    assert [item["sequence"] for item in second.json()["items"]] == [2, 3]
