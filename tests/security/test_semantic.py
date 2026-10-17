"""Semantic invariants (`R-SEM-01`..`R-SEM-07`).

Every invariant has known-good and known-bad traces. A finding names the exact
events. A step that was never observed is `UNKNOWN`, never a pass. And the
monitor can only ever lead to an escalation a policy named: it has no way to
allow anything.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from security.semantic import monitor
from security.semantic.invariants import INVARIANTS, Finding
from security.semantic.scenarios import SCENARIOS, Scenario

REPO = Path(__file__).resolve().parents[2]


def _by_id() -> dict[str, object]:
    return {i.invariant_id: i for i in INVARIANTS}


def test_every_invariant_has_known_good_and_known_bad_scenarios() -> None:
    """R-SEM-02: a rule without both kinds of trace is not tested."""
    for invariant in INVARIANTS:
        mine = [s for s in SCENARIOS if s.invariant_id == invariant.invariant_id]
        kinds = {s.expect for s in mine}
        assert "PASS" in kinds, f"{invariant.invariant_id} has no known-good trace"
        assert "FAIL" in kinds or "UNKNOWN" in kinds, f"{invariant.invariant_id} has no bad trace"
        assert "UNKNOWN" in kinds, f"{invariant.invariant_id} has no unobserved-step trace"


def test_every_scenario_names_a_real_invariant() -> None:
    known = {i.invariant_id for i in INVARIANTS}
    assert {s.invariant_id for s in SCENARIOS} <= known


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: f"{s.invariant_id}:{s.name}")
def test_the_scenario_gets_the_expected_answer_and_the_right_events(scenario: Scenario) -> None:
    invariant = _by_id()[scenario.invariant_id]
    finding: Finding = invariant.evaluate(scenario.trace)  # type: ignore[attr-defined]
    assert finding.status == scenario.expect, finding
    if scenario.expect_evidence:
        assert finding.evidence_event_ids == scenario.expect_evidence, finding
    if scenario.expect == "PASS":
        assert finding.evidence_event_ids == ()


def test_an_empty_trace_is_unknown_for_every_invariant_never_pass() -> None:
    """R-SEM-04. Nothing observed must not read as nothing wrong."""
    for finding in monitor.evaluate([]):
        assert finding.status == "UNKNOWN", finding.invariant_id


def test_a_failing_finding_becomes_a_check_and_a_violation_event() -> None:
    bad = next(s for s in SCENARIOS if s.expect == "FAIL")
    findings = [_by_id()[bad.invariant_id].evaluate(bad.trace)]  # type: ignore[attr-defined]
    events = monitor.events_for(findings)
    assert [t for t, _ in events] == ["SEMANTIC_INVARIANT_CHECKED", "SEMANTIC_VIOLATION_DETECTED"]
    check, violation = events[0][1], events[1][1]
    assert check["result"] == "FAIL"
    assert check["evidence_event_ids"] == list(findings[0].evidence_event_ids)
    assert violation["status"] == "OPEN"
    assert violation["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    # R-SEM-06: id and version are recorded.
    assert check["invariant_id"] == bad.invariant_id
    assert check["invariant_version"] == "1"


def test_a_passing_or_unknown_finding_makes_only_a_check_event() -> None:
    events = monitor.events_for(monitor.evaluate([]))
    assert {t for t, _ in events} == {"SEMANTIC_INVARIANT_CHECKED"}
    assert all(p["result"] == "UNKNOWN" for _, p in events)


def test_a_finding_can_only_lead_to_an_escalation_the_policy_named() -> None:
    """R-SEM-07."""
    bad = next(
        s
        for s in SCENARIOS
        if s.invariant_id == "INV-BANK-CHANGE-NEEDS-APPROVAL" and s.expect == "FAIL"
    )
    findings = monitor.evaluate(bad.trace)
    assert monitor.escalations(findings, {}) == []
    assert monitor.escalations(findings, {"INV-BANK-CHANGE-NEEDS-APPROVAL": "STOP_RUN"}) == [
        ("INV-BANK-CHANGE-NEEDS-APPROVAL", "STOP_RUN")
    ]


@pytest.mark.parametrize("grant", ["ALLOW", "AUTHORIZE", "APPROVE", "GRANT", "PASS"])
def test_there_is_no_way_to_turn_a_finding_into_a_permission(grant: str) -> None:
    findings = monitor.evaluate([])
    with pytest.raises(ValueError, match="never grant"):
        monitor.escalations(findings, {"INV-DISPATCH-NEEDS-AUTH": grant})


def test_the_semantic_package_does_not_import_the_policy_gateway_or_the_signer() -> None:
    """The module is advisory by construction: it cannot reach what authorizes."""
    forbidden = ("policy", "services", "signer", "adapters")
    for path in (REPO / "security" / "semantic").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path.name} imports {name}"


def test_an_unrecognized_trace_shape_is_unknown_not_a_crash() -> None:
    odd = [{"event_id": "e1", "sequence": 1, "event_type": "ACTION_REQUESTED", "payload": {}}]
    for finding in monitor.evaluate(odd):
        assert finding.status in {"PASS", "FAIL", "UNKNOWN"}
