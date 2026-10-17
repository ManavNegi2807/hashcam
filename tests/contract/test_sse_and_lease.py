"""SSE replay and the Postgres lease.

Covers `R-DAT-05` (committed events only, resume with `Last-Event-ID`),
`DATABASE_AND_API_CONTRACTS.md` B3, and `R-HKC-03` / `R-RUN-03` (the fencing
token that replaces Temporal in the hackathon cut).
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.contract.test_api_ingestion import (  # noqa: E402
    abb_binary,
    adapter_headers,
    event_body,
)


@pytest.fixture
def client(dsn: str):  # noqa: ANN201
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from services.api.main import build_app

    abb = abb_binary()
    if abb is None:
        pytest.skip("the abb binary is required; set ABB_BIN")
    app = build_app(dsn=dsn, abb_path=abb, sse_poll_seconds=0.01)
    with TestClient(app, raise_server_exceptions=False) as test_client:
        yield test_client


def finish_body() -> dict[str, Any]:
    return event_body(
        "RUN_FINISHED", {"final_state": "CHECKPOINTED", "event_count": 3, "outcome": "ok"}
    )


def read_stream(client, url: str, headers: dict[str, str]) -> list[dict[str, str]]:  # noqa: ANN001
    """Read an SSE stream to its end, returning one dict per message."""
    messages: list[dict[str, str]] = []
    with client.stream("GET", url, headers=headers) as response:
        assert response.status_code == 200, response.read()
        assert response.headers["content-type"].startswith("text/event-stream")
        current: dict[str, str] = {}
        for raw in response.iter_lines():
            line = raw.rstrip("\r")
            if line == "":
                if current:
                    messages.append(current)
                    current = {}
                continue
            if line.startswith(":"):
                current["comment"] = line[1:].strip()
                continue
            field, _, value = line.partition(":")
            current[field.strip()] = value.strip()
    return messages


def test_sse_sends_only_committed_events_and_closes_on_run_finished(client, seeded) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    headers = adapter_headers(seeded["token"])
    for _ in range(2):
        assert (
            client.post(
                f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body()
            ).status_code
            == 201
        )
    assert (
        client.post(
            f"/api/v1/runs/{run_id}/events", headers=headers, json=finish_body()
        ).status_code
        == 201
    )

    messages = read_stream(client, f"/api/v1/runs/{run_id}/stream", headers)
    assert [m["id"] for m in messages] == ["0", "1", "2"]
    assert [m["event"] for m in messages] == [
        "ACTION_REQUESTED",
        "ACTION_REQUESTED",
        "RUN_FINISHED",
    ]
    # The data is the canonical event itself, so a client can hash what it read.
    assert messages[0]["data"].startswith('{"created_at":')
    assert '"sequence":0' in messages[0]["data"]


def test_last_event_id_resumes_after_that_sequence(client, seeded) -> None:  # noqa: ANN001
    run_id = seeded["run_id"]
    headers = adapter_headers(seeded["token"])
    for _ in range(3):
        client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body())
    client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=finish_body())

    resumed = read_stream(client, f"/api/v1/runs/{run_id}/stream", headers | {"Last-Event-ID": "1"})
    assert [m["id"] for m in resumed] == ["2", "3"]


def test_a_bad_last_event_id_is_a_validation_error(client, seeded) -> None:  # noqa: ANN001
    response = client.get(
        f"/api/v1/runs/{seeded['run_id']}/stream",
        headers=adapter_headers(seeded["token"]) | {"Last-Event-ID": "not-a-number"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_FAILED"


def test_the_stream_is_scoped_like_every_other_route(client, seeded) -> None:  # noqa: ANN001
    import uuid

    response = client.get(
        f"/api/v1/runs/{uuid.uuid4()}/stream", headers=adapter_headers(seeded["token"])
    )
    assert response.status_code == 403


# --------------------------------------------------------------------------- #
# the lease
# --------------------------------------------------------------------------- #


def lease_store(dsn: str):  # noqa: ANN201
    import psycopg

    from services.worker.lease import LeaseStore

    @contextmanager
    def connect():  # noqa: ANN202
        with psycopg.connect(dsn) as conn:
            yield conn

    return LeaseStore(connect)


def test_taking_the_lease_raises_the_fencing_token_monotonically(dsn, seeded) -> None:  # noqa: ANN001
    store = lease_store(dsn)
    run_id = seeded["run_id"]
    first = store.acquire(run_id, "worker-a")
    second = store.acquire(run_id, "worker-b")
    third = store.acquire(run_id, "worker-c")
    assert first.fencing_token < second.fencing_token < third.fencing_token
    assert store.holds(third)
    assert not store.holds(first)


def test_an_unknown_run_has_no_lease(dsn) -> None:  # noqa: ANN001
    import uuid

    store = lease_store(dsn)
    assert store.current_token(str(uuid.uuid4())) is None
    with pytest.raises(LookupError):
        store.acquire(str(uuid.uuid4()), "worker-a")


def test_a_taken_over_worker_cannot_commit_but_the_new_one_can(client, dsn, seeded) -> None:  # noqa: ANN001
    """R-RUN-03 end to end: the old token is refused, the new one works."""
    store = lease_store(dsn)
    run_id = seeded["run_id"]
    old = store.acquire(run_id, "worker-a")
    new = store.acquire(run_id, "worker-b")

    stale = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"], fencing_token=old.fencing_token),
        json=event_body(),
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "STALE_FENCING_TOKEN"

    fresh = client.post(
        f"/api/v1/runs/{run_id}/events",
        headers=adapter_headers(seeded["token"], fencing_token=new.fencing_token),
        json=event_body(),
    )
    assert fresh.status_code == 201, fresh.text


def test_an_idempotent_replay_is_served_even_to_a_stale_worker(client, dsn, seeded) -> None:  # noqa: ANN001
    """A replay changes nothing, so it returns the original rather than 409.

    This is deliberate: the alternative is a worker that cannot find out what
    it already committed.
    """
    store = lease_store(dsn)
    run_id = seeded["run_id"]
    mine = store.acquire(run_id, "worker-a")
    headers = adapter_headers(seeded["token"], fencing_token=mine.fencing_token) | {
        "Idempotency-Key": "a-1-requested"
    }
    first = client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body())
    assert first.status_code == 201, first.text

    store.acquire(run_id, "worker-b")  # takeover
    replay = client.post(f"/api/v1/runs/{run_id}/events", headers=headers, json=event_body())
    assert replay.status_code == 200
    assert replay.json()["code"] == "IDEMPOTENT_REPLAY"
    assert replay.json()["event_id"] == first.json()["event_id"]
