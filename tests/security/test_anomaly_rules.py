"""Behavior-anomaly rules and replay drift (`R-ANO-01`..`R-ANO-11`).

Beyond "each rule fires when it should", two properties are tested that matter more:
the rules never read a policy outcome (`R-ANO-05`: otherwise the channel would just
echo the policy channel), and the whole module can fail without changing anything
else (`R-ANO-11`).
"""

from __future__ import annotations

import ast
import base64
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

from security.anomaly import drift, rules
from security.semantic.scenarios import TraceBuilder

REPO = Path(__file__).resolve().parents[2]


def trace(*steps: tuple[str, dict[str, Any]]) -> list[dict[str, Any]]:
    b = TraceBuilder()
    for event_type, payload in steps:
        b.add(event_type, **payload)
    return b.events


def request(
    i: int, kind: str = "navigate", target: str = "https://portal.example/x"
) -> tuple[str, dict[str, Any]]:
    return "ACTION_REQUESTED", {"action_id": f"a{i}", "action_type": kind, "target": target}


NORMAL = trace(
    request(1, "navigate", "https://portal.example/"),
    ("BROWSER_OBSERVATION", {"action_id": "a1"}),
    request(2, "form_fill", "https://portal.example/form"),
    request(3, "form_submit", "https://portal.example/form"),
    ("BROWSER_OBSERVATION", {"action_id": "a3"}),
    ("ACTION_SUCCEEDED", {"action_id": "a3"}),
)


def fired(t: list[dict[str, Any]]) -> set[str]:
    return {f.rule_id for f in rules.evaluate(t)}


# ------------------------------------------------------------------- rules


def test_an_ordinary_run_fires_nothing() -> None:
    assert rules.evaluate(NORMAL) == []
    assert rules.score_ppm([]) == 0


def test_a_loop_is_noticed_and_the_events_are_named() -> None:
    t = trace(*[request(i, "navigate", "https://portal.example/same") for i in range(5)])
    (finding,) = [f for f in rules.evaluate(t) if f.rule_id == "ANO-LOOP"]
    assert len(finding.evidence_event_ids) == 5
    assert "5 times" in finding.explanation


def test_three_repeats_are_not_yet_a_loop() -> None:
    t = trace(*[request(i, "navigate", "https://portal.example/same") for i in range(3)])
    assert "ANO-LOOP" not in fired(t)


def test_a_burst_of_failures_on_one_target_is_a_retry_burst() -> None:
    steps: list[tuple[str, dict[str, Any]]] = []
    for i in range(3):
        steps.append(request(i, "form_submit", "https://portal.example/pay"))
        steps.append(
            ("ACTION_FAILED", {"action_id": f"a{i}", "error_code": "X", "retryable": True})
        )
    assert "ANO-RETRY-BURST" in fired(trace(*steps))


def test_a_high_failure_share_is_an_error_rate() -> None:
    steps: list[tuple[str, dict[str, Any]]] = []
    for i in range(4):
        steps.append(request(i, "navigate", f"https://portal.example/{i}"))
        steps.append(
            ("ACTION_FAILED", {"action_id": f"a{i}", "error_code": "X", "retryable": False})
        )
    assert "ANO-ERROR-RATE" in fired(trace(*steps))


def test_a_huge_number_of_actions_is_flagged_as_volume() -> None:
    t = trace(*[request(i, "navigate", f"https://portal.example/{i}") for i in range(51)])
    assert "ANO-VOLUME" in fired(t)


def test_state_changes_without_ever_looking_are_flagged() -> None:
    t = trace(*[request(i, "form_submit", f"https://portal.example/{i}") for i in range(3)])
    assert "ANO-WRITES-WITHOUT-READING" in fired(t)
    looked = trace(
        *[request(i, "form_submit", f"https://portal.example/{i}") for i in range(3)],
        ("BROWSER_OBSERVATION", {"action_id": "a0"}),
    )
    assert "ANO-WRITES-WITHOUT-READING" not in fired(looked)


def test_repeated_unknown_outcomes_are_flagged() -> None:
    t = trace(
        request(1),
        ("OUTCOME_UNKNOWN", {"action_id": "a1"}),
        request(2),
        ("OUTCOME_UNKNOWN", {"action_id": "a2"}),
    )
    assert "ANO-UNKNOWN-OUTCOMES" in fired(t)


def test_the_score_is_the_sum_of_weights_capped_not_a_probability() -> None:
    t = trace(*[request(i, "form_submit", "https://portal.example/same") for i in range(60)])
    findings = rules.evaluate(t)
    assert rules.score_ppm(findings) == min(1_000_000, sum(f.weight_ppm for f in findings))
    assert rules.score_ppm(findings) <= 1_000_000
    assert rules.payload_for(findings)["score_kind"] == "RULE_SUM"


def test_the_payload_carries_identifiers_and_numbers_only() -> None:
    """R-ANO-10: no model, no pickle, nothing executable."""
    payload = rules.payload_for(rules.evaluate(trace(*[request(i) for i in range(5)])))
    assert set(payload) == {
        "model_id", "model_version", "feature_schema_id", "score_ppm", "reason_codes", "score_kind",
    }  # fmt: skip
    assert isinstance(payload["score_ppm"], int)
    assert all(isinstance(r, str) for r in payload["reason_codes"])
    assert len(json.dumps(payload)) < 400
    assert not list((REPO / "security").rglob("*.pkl"))
    assert not list((REPO / "security").rglob("*.onnx"))


# ------------------------------------------- R-ANO-05: no policy outcomes as input

POLICY_EVENTS = (
    ("ACTION_AUTHORIZED", {"action_id": "a1", "reason_codes": ["ALLOWED_BY_POLICY"]}),
    ("ACTION_BLOCKED", {"action_id": "a2", "reason_codes": ["DOMAIN_NOT_ALLOWED"]}),
    ("POLICY_VIOLATION_DETECTED", {"action_id": "a2", "reason_codes": ["OVER_ACTION_LIMIT"]}),
    ("HUMAN_APPROVAL_REQUESTED", {"action_id": "a2"}),
)


def test_adding_policy_decisions_to_a_trace_changes_no_finding() -> None:
    base = trace(*[request(i, "navigate", "https://portal.example/same") for i in range(5)])
    noisy = trace(
        *[request(i, "navigate", "https://portal.example/same") for i in range(5)], *POLICY_EVENTS
    )
    assert rules.evaluate(base) == [f for f in rules.evaluate(noisy)] or [
        (f.rule_id, f.weight_ppm) for f in rules.evaluate(base)
    ] == [(f.rule_id, f.weight_ppm) for f in rules.evaluate(noisy)]


def test_a_blocked_action_does_not_make_a_run_look_more_anomalous() -> None:
    """The policy channel already said it. Saying it again here would be circular."""
    base = NORMAL
    with_blocks = trace(
        *[(e["event_type"], e["payload"]) for e in NORMAL],
        *[
            ("ACTION_BLOCKED", {"action_id": f"x{i}", "reason_codes": ["DOMAIN_NOT_ALLOWED"]})
            for i in range(10)
        ],
    )
    assert rules.score_ppm(rules.evaluate(base)) == rules.score_ppm(rules.evaluate(with_blocks))


def test_the_feature_extractor_cannot_see_policy_event_types() -> None:
    assert not (
        rules.FEATURE_EVENT_TYPES
        & {
            "ACTION_AUTHORIZED",
            "ACTION_BLOCKED",
            "POLICY_VIOLATION_DETECTED",
            "HUMAN_APPROVAL_REQUESTED",
            "HUMAN_APPROVAL_GRANTED",
            "HUMAN_APPROVAL_DENIED",
            "ACTION_DISPATCHED",
        }
    )


def test_the_rules_source_never_names_a_policy_outcome() -> None:
    text = (REPO / "security" / "anomaly" / "rules.py").read_text(encoding="utf-8")
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith(("#",)))
    # The module's docstring explains the rule, so look only at executable lines.
    tree = ast.parse(text)
    strings = [
        n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]
    used = {s for s in strings if s.isupper() and "_" in s}
    for name in (
        "ACTION_AUTHORIZED",
        "ACTION_BLOCKED",
        "POLICY_VIOLATION_DETECTED",
        "ACTION_DISPATCHED",
    ):
        assert name not in used, name
    # `reason_codes` is only ever the name of our own output field, never something read.
    assert code.count("reason_codes") == 1


# ------------------------------------------------- R-ANO-11: failure is contained


class _BrokenTrace:
    def trace(self) -> list[dict[str, Any]]:
        raise RuntimeError("the ledger could not be read")


class _BrokenEmit:
    def trace(self) -> list[dict[str, Any]]:
        return NORMAL

    def emit_advisory(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("could not record")


def test_a_failure_in_the_anomaly_module_is_swallowed_and_nothing_else_changes() -> None:
    assert rules.run_anomaly(_BrokenTrace()) is None
    assert rules.run_anomaly(_BrokenEmit()) is None  # no exception reaches the caller


def test_the_anomaly_package_cannot_reach_signing_verification_or_authorization() -> None:
    forbidden = ("policy", "services", "signer", "adapters")
    for path in (REPO / "security" / "anomaly").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                assert name.split(".")[0] not in forbidden, f"{path.name} imports {name}"


# ------------------------------------------------------------ replay drift


def run_of(*actions: tuple[str, str], outcome: str = "COMPLETED") -> list[dict[str, Any]]:
    steps = [
        ("ACTION_REQUESTED", {"action_id": f"a{i}", "action_type": k, "target": t})
        for i, (k, t) in enumerate(actions)
    ]
    steps.append(("RUN_FINISHED", {"outcome": outcome}))
    return trace(*steps)


A = ("navigate", "https://portal.example/vendor/42")
B = ("form_fill", "https://portal.example/vendor/42")
C = ("form_submit", "https://portal.example/vendor/42/bank")


def test_the_same_run_twice_has_no_drift() -> None:
    d = drift.compare(run_of(A, B, C), run_of(A, B, C))
    assert not d.drifted and d.score_ppm == 0 and d.describe() == []


def test_params_and_ids_do_not_count_as_drift() -> None:
    first = run_of(A, B)
    second = run_of(A, B)
    second[0]["payload"]["action_id"] = "different-id"
    second[0]["payload"]["params_digest"] = "ff" * 32
    assert not drift.compare(first, second).drifted


def test_an_added_and_a_removed_action_are_both_reported() -> None:
    d = drift.compare(run_of(A, B), run_of(A, C))
    assert d.added == ((C[0], "portal.example/vendor/42/bank"),)
    assert d.removed == ((B[0], "portal.example/vendor/42"),)
    assert {"DRIFT-ACTIONS-ADDED", "DRIFT-ACTIONS-REMOVED"} <= set(d.reasons)
    assert any(line.startswith("added:") for line in d.describe())


def test_the_same_actions_in_another_order_is_its_own_finding() -> None:
    d = drift.compare(run_of(A, B, C), run_of(A, C, B))
    assert d.reasons == ("DRIFT-REORDERED",)
    assert d.reordered


def test_a_new_host_is_called_out() -> None:
    d = drift.compare(run_of(A), run_of(A, ("navigate", "https://elsewhere.example/x")))
    assert d.hosts_added == ("elsewhere.example",)
    assert "DRIFT-HOSTS-CHANGED" in d.reasons


def test_a_changed_outcome_is_reported() -> None:
    d = drift.compare(run_of(A, outcome="COMPLETED"), run_of(A, outcome="COMPLETED_WITH_BLOCKS"))
    assert d.reasons == ("DRIFT-OUTCOME-CHANGED",)
    assert "COMPLETED -> COMPLETED_WITH_BLOCKS" in d.describe()[0]


def test_drift_is_recorded_in_the_same_shape_as_the_rules_baseline() -> None:
    payload = drift.compare(run_of(A, B), run_of(A, C)).payload()
    assert payload["model_id"] == "abb-replay-drift"
    assert set(payload) == {
        "model_id", "model_version", "feature_schema_id", "score_ppm", "reason_codes", "score_kind",
    }  # fmt: skip
    assert 0 < payload["score_ppm"] <= 1_000_000


def _receipt(path: Path, events: list[dict[str, Any]]) -> Path:
    nodes = []
    for e in events:
        body = {
            "event_id": e["event_id"],
            "sequence": e["sequence"],
            "event_type": e["event_type"],
            "payload": e["payload"],
        }
        nodes.append({"canonical_b64": base64.b64encode(json.dumps(body).encode()).decode()})
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("receipt.json", json.dumps({"events": nodes}))
    return path


def _cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(REPO / "tools" / "replay_drift.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_tool_reports_no_drift_and_drift_and_refuses_a_non_receipt(tmp_path: Path) -> None:
    one = _receipt(tmp_path / "one.abbreceipt", run_of(A, B))
    same = _receipt(tmp_path / "same.abbreceipt", run_of(A, B))
    other = _receipt(tmp_path / "other.abbreceipt", run_of(A, C))
    ok = _cli(str(one), str(same))
    assert ok.returncode == 0 and "no drift" in ok.stdout
    changed = _cli(str(one), str(other))
    assert changed.returncode == 0  # advisory: drift is a finding, not a failure
    assert "added:" in changed.stdout and "not a probability" in changed.stdout
    junk = tmp_path / "junk.abbreceipt"
    junk.write_text("not a zip")
    bad = _cli(str(one), str(junk))
    assert bad.returncode == 65
    assert "Traceback" not in bad.stderr


@pytest.mark.parametrize("name", ["rules", "drift"])
def test_the_modules_say_they_are_advisory(name: str) -> None:
    text = (REPO / "security" / "anomaly" / f"{name}.py").read_text(encoding="utf-8").lower()
    assert "advisory" in text or "signal" in text
