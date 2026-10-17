"""The TinyFish adapter, against a scripted fake (`R-TFY-01`..`R-TFY-07`, `R-COV-04`, `R-COV-06`).

Every test here is **mocked**: no network, no key, no spend. They prove the parts
that are ours: opt-in, the budget, error handling, and what gets recorded. They say
nothing about how the real service behaves; that is what the capability spike is
for, and it has not been run.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

import pytest

from adapters.base import Provenance
from adapters.playwright.adapter import MemorySink
from adapters.tinyfish.adapter import (
    CEILING_COVERAGE,
    COVERAGE_REASON,
    IN_SCOPE_ACTIONS,
    OptInRequired,
    TinyFishAdapter,
)
from adapters.tinyfish.budget import ALLOCATION_CENTS, CEILING_CENTS, Budget, BudgetReserveReached
from adapters.tinyfish.client import (
    FakeTinyFishClient,
    ProviderTimeout,
    QuotaExhausted,
    good_answer,
    parse_reply,
)
from policy.engine import Policy
from services.worker.gateway import Gateway

REPO = Path(__file__).resolve().parents[2]
HOST = "api.tinyfish.test"
URL = f"https://{HOST}/start"
PROV = Provenance("tinyfish", "0.1.0", "t", "LIVE_EXTERNAL", "STEP_OBSERVED")


def policy(hosts: tuple[str, ...] = (HOST,)) -> Policy:
    return Policy(
        {
            "policy_id": "external",
            "version": 1,
            "allowed_action_types": ["api_call"],
            "action_types_needing_target": ["api_call"],
            "allowed_hosts": list(hosts),
            "max_actions": 100,
        }
    )


def make(
    *script: Any,
    opt_in: bool = True,
    budget: Budget | None = None,
    estimate: int | None = None,
    remaining: int | None = None,
    hosts: tuple[str, ...] = (HOST,),
) -> tuple[TinyFishAdapter, MemorySink, FakeTinyFishClient, Budget]:
    sink = MemorySink()
    gateway = Gateway(
        sink=sink, policy=policy(hosts), provenance=PROV, in_scope_actions=IN_SCOPE_ACTIONS
    )
    client = FakeTinyFishClient(
        host=HOST, script=list(script), estimate=estimate, remaining=remaining
    )
    budget = budget or Budget()
    return (
        TinyFishAdapter(gateway, client, budget, opt_in=opt_in, clock_ms=lambda: 1234),
        sink,
        client,
        budget,
    )


def of(sink: MemorySink, event_type: str) -> list[dict[str, Any]]:
    return [e for e in sink.events if e["event_type"] == event_type]


# ------------------------------------------------------------------- opt-in


def test_nothing_runs_without_an_explicit_opt_in() -> None:
    adapter, sink, client, _ = make(good_answer(), opt_in=False)
    with pytest.raises(OptInRequired):
        adapter.run_agent("do a thing", URL)
    assert client.calls == []
    assert sink.events == []


# ------------------------------------------------------------------ success


def test_a_successful_agent_run_records_metering_and_the_providers_claims() -> None:
    adapter, sink, _client, budget = make(good_answer(cents=40, steps=2, execution_id="exec-7"))
    outcome = adapter.run_agent("update the vendor record", URL)
    assert outcome.status == "SUCCEEDED" and outcome.execution_id == "exec-7"
    assert budget.spent_cents == 40 and budget.remaining_cents == CEILING_CENTS - 40

    api = of(sink, "API_CALL_OBSERVED")[0]["payload"]
    # R-TFY-06: operation, provider execution id, metering as returned, when it was seen.
    assert api["provider_execution_id"] == "exec-7"
    assert api["usage"] == {"cents": 40, "steps_billed": 2}
    assert api["usage_observed_at"] == 1234
    assert api["host"] == HOST

    reported = [e for e in of(sink, "BROWSER_OBSERVATION")]
    assert len(reported) == 2
    # The provider's account of its steps is labelled as exactly that.
    assert {e["source"] for e in reported} == {"reported_by_adapter"}
    assert of(sink, "API_CALL_OBSERVED")[0]["source"] == "observed_by_local_gateway"
    assert [r["payload"]["observation_kind"] for r in reported] == ["navigated", "navigated"]


def test_the_search_fetch_and_agent_operations_are_separate_calls() -> None:
    adapter, _, client, _ = make(good_answer(), good_answer())
    adapter.search_fetch("find the vendor page", URL)
    adapter.run_agent("update it", URL)
    assert [kind for kind, _ in client.calls] == ["search_fetch", "agent"]


def test_the_task_text_is_never_recorded_only_its_digest() -> None:
    adapter, sink, _, _ = make(good_answer())
    adapter.run_agent("SECRET-TASK-TEXT account 12345", URL)
    blob = json.dumps(sink.events)
    assert "SECRET-TASK-TEXT" not in blob
    assert "task_digest" not in blob or len(of(sink, "ACTION_REQUESTED")) == 1


# ----------------------------------------------------------------- coverage


def test_coverage_is_capped_at_observed_and_says_why() -> None:
    assert CEILING_COVERAGE == "STEP_OBSERVED"
    assert "not gated" in COVERAGE_REASON
    adapter, _, _, _ = make()
    prov = adapter.provenance()
    assert prov.mode == "LIVE_EXTERNAL"
    assert prov.observed_coverage == "STEP_OBSERVED"


# ------------------------------------------------------------------- budget


def test_the_planned_allocation_adds_up_to_the_ceiling() -> None:
    assert sum(ALLOCATION_CENTS.values()) == CEILING_CENTS == 1500


def test_once_the_ceiling_is_reached_no_call_is_made() -> None:
    adapter, sink, client, _ = make(good_answer(), budget=Budget(spent_cents=1500))
    outcome = adapter.run_agent("anything", URL)
    assert outcome.status == "QUOTA_EXHAUSTED"
    assert client.calls == []
    blocked = of(sink, "ACTION_BLOCKED")[0]["payload"]
    assert "PROVIDER_QUOTA_EXHAUSTED" in blocked["reason_codes"]


def test_a_call_that_would_reach_the_reserve_is_not_made() -> None:
    # 1500 ceiling, 300 reserve: 1180 spent leaves 320; a 40-cent call would leave 280.
    adapter, sink, client, _ = make(good_answer(), budget=Budget(spent_cents=1180), estimate=40)
    outcome = adapter.run_agent("anything", URL)
    assert outcome.status == "RESERVE_REACHED"
    assert client.calls == []
    assert "BUDGET_RESERVE_REACHED" in of(sink, "ACTION_BLOCKED")[0]["payload"]["reason_codes"]


def test_a_call_just_outside_the_reserve_is_allowed() -> None:
    adapter, _, client, _ = make(
        good_answer(cents=20), budget=Budget(spent_cents=1100), estimate=100
    )
    assert adapter.run_agent("x", URL).status == "SUCCEEDED"  # leaves exactly the 300 reserve
    assert len(client.calls) == 1


def test_an_unknown_cost_is_not_treated_as_free() -> None:
    """With no estimate the call is assumed to cost at least a cent."""
    adapter, _, client, _ = make(good_answer(), budget=Budget(spent_cents=1200))  # leaves 300
    assert adapter.run_agent("x", URL).status == "RESERVE_REACHED"
    assert client.calls == []


def test_the_providers_own_remaining_credit_wins_when_it_is_lower() -> None:
    adapter, _, client, budget = make(good_answer(), remaining=250, estimate=10)
    outcome = adapter.run_agent("x", URL)
    # Only 250 cents left at the provider, which is inside the 300 reserve.
    assert outcome.status == "RESERVE_REACHED"
    assert client.calls == []
    assert budget.remaining_cents == 250


def test_the_spend_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "spend.json"
    first = Budget.load(path)
    first.record(125)
    assert Budget.load(path).spent_cents == 125


def test_metered_usage_can_only_go_up() -> None:
    with pytest.raises(ValueError, match="negative"):
        Budget().record(-1)


def test_the_reserve_error_is_its_own_kind() -> None:
    with pytest.raises(BudgetReserveReached):
        Budget(spent_cents=1300).check(10)


# ----------------------------------------------------------- failure modes


def test_a_provider_that_reports_no_quota_ends_the_attempt_with_no_fallback() -> None:
    adapter, sink, client, _ = make(QuotaExhausted(), good_answer())
    outcome = adapter.run_agent("x", URL)
    assert outcome.status == "QUOTA_EXHAUSTED"
    failed = of(sink, "ACTION_FAILED")[0]["payload"]
    assert failed["error_code"] == "PROVIDER_QUOTA_EXHAUSTED" and failed["retryable"] is False
    # The second scripted answer was never used: nothing tried another route.
    assert len(client.calls) == 1


def test_a_timeout_is_an_unknown_outcome_and_is_never_retried() -> None:
    adapter, sink, client, budget = make(ProviderTimeout(), good_answer())
    outcome = adapter.run_agent("x", URL)
    assert outcome.status == "OUTCOME_UNKNOWN"
    assert len(of(sink, "OUTCOME_UNKNOWN")) == 1
    assert len(client.calls) == 1  # a blind retry could repeat an irreversible action
    assert budget.spent_cents == 0  # nothing was metered, so nothing is charged


@pytest.mark.parametrize(
    "answer",
    [
        None,
        "not an object",
        {},
        {**good_answer(), "execution_id": ""},
        {**good_answer(), "steps": "nope"},
        {**good_answer(), "steps": [{"kind": "x"}]},
        {**good_answer(), "usage": {"cents": -5}},
        {**good_answer(), "usage": {"cents": 1.5}},
        {**good_answer(), "usage": {"steps_billed": 2}},
        {**good_answer(), "usage": "free"},
        {**good_answer(), "result": 7},
    ],
)
def test_a_malformed_answer_is_a_failed_action_and_is_not_charged(answer: Any) -> None:
    adapter, sink, _client, budget = make(answer)
    outcome = adapter.run_agent("x", URL)
    assert outcome.status == "BAD_RESPONSE"
    assert of(sink, "ACTION_FAILED")[0]["payload"]["error_code"] == "ADAPTER_BAD_RESPONSE"
    assert budget.spent_cents == 0
    assert of(sink, "BROWSER_OBSERVATION") == []  # nothing the provider "said" is believed


def test_parse_reply_accepts_a_good_answer() -> None:
    reply = parse_reply(good_answer(cents=7, steps=3))
    assert reply.usage.cents == 7 and len(reply.steps) == 3


def test_policy_decides_whether_the_request_may_be_sent_at_all() -> None:
    adapter, sink, client, _ = make(good_answer(), hosts=("somewhere.else",))
    outcome = adapter.run_agent("x", URL)
    assert outcome.status == "BLOCKED"
    assert client.calls == []
    assert "DOMAIN_NOT_ALLOWED" in of(sink, "ACTION_BLOCKED")[0]["payload"]["reason_codes"]


# ------------------------------------------------------------ no live client


def test_no_module_other_than_the_http_client_can_reach_the_network() -> None:
    """Only `http_client.py` may import a way to the network; the adapter never does."""
    forbidden = {"urllib", "http", "socket", "requests", "httpx", "aiohttp", "websockets", "ssl"}
    for path in (REPO / "adapters" / "tinyfish").glob("*.py"):
        if path.name == "http_client.py":  # the one module meant to
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path.name} imports {name}"


def test_there_is_no_fallback_path_in_the_adapter_source() -> None:
    text = (REPO / "adapters" / "tinyfish" / "adapter.py").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#", '"')))
    for word in ("while ", "for attempt", "retry(", "fallback("):
        assert word not in code, word
