"""The run graph: built from a receipt summary, stored in FalkorDB, drawn by the page.

The builder tests need nothing. The store tests need a FalkorDB on this computer and are skipped
unless ABB_TEST_FALKORDB (for example redis://127.0.0.1:6390) is set. The graph is a picture of
what is inside a receipt; none of these tests (or the code) treat it as a verdict.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import pytest

from services.graph.build import build
from services.graph.store import FalkorStore, GraphUnavailable, parse_url

FALKOR = os.environ.get("ABB_TEST_FALKORDB")


def event(sequence: int, kind: str, **payload: Any) -> dict[str, Any]:
    return {"sequence": sequence, "event_type": kind, "payload": payload}


def summary(run_id: str | None = None) -> dict[str, Any]:
    return {
        "run": {"run_id": run_id or str(uuid.uuid4()), "adapter_name": "playwright"},
        "witnesses": 1,
        "anchors": 0,
        "events": [
            event(0, "RUN_STARTED", adapter="playwright"),
            event(
                1, "ACTION_REQUESTED", action_id="a-1", action_type="navigate", target="https://x"
            ),
            event(
                2,
                "ACTION_AUTHORIZED",
                action_id="a-1",
                decision="ALLOW",
                policy_id="p",
                policy_version="1",
            ),
            event(3, "ACTION_SUCCEEDED", action_id="a-1"),
            event(
                4,
                "ACTION_REQUESTED",
                action_id="a-2",
                action_type="form_submit",
                target="https://x/f",
            ),
            event(
                5,
                "ACTION_AUTHORIZED",
                action_id="a-2",
                decision="REQUIRE_APPROVAL",
                policy_id="p",
                policy_version="1",
            ),
            event(
                6, "ACTION_REQUESTED", action_id="a-3", action_type="download", target="https://bad"
            ),
            event(7, "ACTION_BLOCKED", action_id="a-3", reason_codes=["HOST_NOT_ALLOWED"]),
            event(8, "RUN_FINISHED", outcome="SUCCEEDED"),
        ],
        "approvals": [
            {
                "approval_id": "approval-0001",
                "action_id": "a-2",
                "decision": "APPROVE",
                "key_id": "k",
            }
        ],
        "mandate": {"mandate_id": "mandate-0001"},
    }


def by_name(graph: dict[str, Any], label: str, name: str) -> dict[str, Any]:
    return next(n for n in graph["nodes"] if n["label"] == label and n["name"] == name)


def test_each_action_gets_the_status_its_events_say() -> None:
    graph = build(summary())
    assert by_name(graph, "Action", "a-1")["status"] == "succeeded"
    assert by_name(graph, "Action", "a-3")["status"] == "blocked"
    # a-2 was waiting for a person; the signed approval then settles it as approved
    assert by_name(graph, "Action", "a-2")["status"] == "approved"


def test_an_unapproved_gated_action_is_shown_as_needing_approval() -> None:
    plain = summary()
    plain["approvals"] = []
    assert by_name(build(plain), "Action", "a-2")["status"] == "needs approval"


def test_a_denial_is_shown_as_denied_never_as_done() -> None:
    denied = summary()
    denied["approvals"][0]["decision"] = "DENY"
    assert by_name(build(denied), "Action", "a-2")["status"] == "denied"


def test_the_links_say_who_asked_who_decided_and_who_approved() -> None:
    graph = build(summary())
    names = {n["id"]: f"{n['label']}:{n['name']}" for n in graph["nodes"]}
    links = {(names[e["src"]], e["type"], names[e["dst"]]) for e in graph["edges"]}
    assert ("Action:a-1", "NEXT", "Action:a-2") in links
    assert ("Action:a-2", "DECIDED_BY", "Policy:p v1") in links
    assert ("Action:a-2", "APPROVED_BY", "Approval:approval-000") in links
    assert any(src.startswith("Run:") and rel == "GOVERNED_BY" for src, rel, _ in links)
    assert any(src.startswith("Run:") and rel == "REQUESTED" for src, rel, _ in links)


def test_the_run_node_carries_the_outcome_but_the_graph_holds_no_verdict() -> None:
    graph = build(summary())
    run = next(n for n in graph["nodes"] if n["label"] == "Run")
    assert run["outcome"] == "SUCCEEDED"
    keys = {key for n in graph["nodes"] for key in n}
    assert not keys & {"valid", "verdict", "verified", "overall"}


def test_the_same_summary_always_gives_the_same_graph() -> None:
    fixed = summary("run-fixed")
    assert build(fixed) == build(fixed)


def test_two_runs_never_share_a_node_id() -> None:
    first = {n["id"] for n in build(summary("run-one"))["nodes"]}
    second = {n["id"] for n in build(summary("run-two"))["nodes"]}
    assert first.isdisjoint(second)


def test_long_or_odd_values_are_cut_and_never_break_the_builder() -> None:
    odd = summary()
    odd["events"][1]["payload"]["target"] = "https://x/" + "a" * 5000
    odd["events"][1]["payload"]["action_type"] = 7  # not text: ignored, not a crash
    graph = build(odd)
    action = by_name(graph, "Action", "a-1")
    assert len(action["target"]) <= 200
    assert action["action_type"] == ""


@pytest.mark.parametrize("url", ["redis://10.0.0.5:6379", "redis://example.com:6379", "evil:1"])
def test_only_this_computer_is_accepted_as_the_database_address(url: str) -> None:
    with pytest.raises(GraphUnavailable):
        parse_url(url)


def test_the_loopback_address_is_accepted() -> None:
    assert parse_url("redis://127.0.0.1:6390") == ("127.0.0.1", 6390)


def test_a_missing_database_is_reported_not_raised_as_a_crash() -> None:
    store = FalkorStore("redis://127.0.0.1:1")  # nothing listens here
    with pytest.raises(GraphUnavailable):
        store.save("run-x", build(summary("run-x")))


# ---- against a real FalkorDB ---------------------------------------------------------------

needs_falkor = pytest.mark.skipif(
    not FALKOR, reason="set ABB_TEST_FALKORDB to run against FalkorDB"
)


@needs_falkor
def test_a_graph_saved_in_falkordb_reads_back_the_same() -> None:
    data = summary()
    graph = build(data)
    store = FalkorStore(str(FALKOR))
    run_id = data["run"]["run_id"]
    store.save(run_id, graph)
    back = store.load(run_id)
    assert {n["id"] for n in back["nodes"]} == {n["id"] for n in graph["nodes"]}
    assert {(e["src"], e["type"], e["dst"]) for e in back["edges"]} == {
        (e["src"], e["type"], e["dst"]) for e in graph["edges"]
    }
    # a question the DATABASE answered
    assert back["actions_by_status"] == {"approved": 1, "blocked": 1, "succeeded": 1}


@needs_falkor
def test_saving_again_replaces_the_graph_instead_of_adding_to_it() -> None:
    data = summary()
    store = FalkorStore(str(FALKOR))
    run_id = data["run"]["run_id"]
    for _ in range(3):
        store.save(run_id, build(data))
    assert len(store.load(run_id)["nodes"]) == len(build(data)["nodes"])


@needs_falkor
def test_query_syntax_inside_a_value_is_stored_as_text_and_runs_nothing() -> None:
    data = summary()
    nasty = '"}) DETACH DELETE n //'
    data["events"][1]["payload"]["target"] = nasty
    store = FalkorStore(str(FALKOR))
    run_id = data["run"]["run_id"]
    store.save(run_id, build(data))
    back = store.load(run_id)
    assert any(n.get("target") == nasty for n in back["nodes"])
    assert len(back["nodes"]) == len(build(data)["nodes"])  # nothing was deleted


@needs_falkor
def test_two_runs_stay_in_separate_graphs() -> None:
    one, two = summary(), summary()
    store = FalkorStore(str(FALKOR))
    store.save(one["run"]["run_id"], build(one))
    store.save(two["run"]["run_id"], build(two))
    ids = {n["id"] for n in store.load(one["run"]["run_id"])["nodes"]}
    assert all(i.startswith(one["run"]["run_id"]) for i in ids)
