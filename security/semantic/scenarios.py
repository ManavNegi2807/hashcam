"""Known-good and known-bad traces for every invariant (`R-SEM-02`).

Each scenario says which invariant it is for, what the answer must be, and which
events must be named. The tests run all of them; adding an invariant without a
scenario of each kind is a gap the tests point at.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .invariants import Status, Trace


class TraceBuilder:
    """A tiny way to write a trace: events get ids e1, e2, ... in order."""

    def __init__(self) -> None:
        self.events: Trace = []

    def add(self, event_type: str, **payload: Any) -> TraceBuilder:
        n = len(self.events) + 1
        self.events.append(
            {"event_id": f"e{n}", "sequence": n, "event_type": event_type, "payload": payload}
        )
        return self

    def request(self, action_id: str, action_type: str, target: str) -> TraceBuilder:
        return self.add(
            "ACTION_REQUESTED", action_id=action_id, action_type=action_type, target=target
        )


@dataclass(frozen=True)
class Scenario:
    invariant_id: str
    name: str
    trace: Trace
    expect: Status
    expect_evidence: tuple[str, ...] = ()


def _b() -> TraceBuilder:
    return TraceBuilder()


SCENARIOS: tuple[Scenario, ...] = (
    # --- INV-DISPATCH-NEEDS-AUTH
    Scenario(
        "INV-DISPATCH-NEEDS-AUTH",
        "good: authorized then dispatched",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_AUTHORIZED", action_id="a1")
        .add("ACTION_DISPATCHED", action_id="a1")
        .events,
        "PASS",
    ),
    Scenario(
        "INV-DISPATCH-NEEDS-AUTH",
        "bad: dispatched with no authorization",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .events,
        "FAIL",
        ("e2",),
    ),
    Scenario(
        "INV-DISPATCH-NEEDS-AUTH",
        "bad: authorization came after the dispatch",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .add("ACTION_AUTHORIZED", action_id="a1")
        .events,
        "FAIL",
        ("e2",),
    ),
    Scenario(
        "INV-DISPATCH-NEEDS-AUTH",
        "bad: authorized a different action",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_AUTHORIZED", action_id="other")
        .add("ACTION_DISPATCHED", action_id="a1")
        .events,
        "FAIL",
        ("e3",),
    ),
    Scenario("INV-DISPATCH-NEEDS-AUTH", "unknown: nothing observed", [], "UNKNOWN"),
    # --- INV-BANK-CHANGE-NEEDS-APPROVAL
    Scenario(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        "good: bank change dispatched after a grant",
        _b()
        .request("b1", "form_submit", "https://portal.example/vendor/42/bank")
        .add("HUMAN_APPROVAL_GRANTED", action_id="b1")
        .add("ACTION_DISPATCHED", action_id="b1")
        .events,
        "PASS",
    ),
    Scenario(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        "good: bank change requested but never dispatched",
        _b().request("b1", "form_submit", "https://portal.example/vendor/42/bank").events,
        "PASS",
    ),
    Scenario(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        "bad: bank change dispatched with no grant",
        _b()
        .request("b1", "form_submit", "https://portal.example/vendor/42/bank")
        .add("ACTION_DISPATCHED", action_id="b1")
        .events,
        "FAIL",
        ("e2",),
    ),
    Scenario(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        "bad: the grant was for another action",
        _b()
        .request("b1", "form_submit", "https://portal.example/vendor/42/bank")
        .add("HUMAN_APPROVAL_GRANTED", action_id="other")
        .add("ACTION_DISPATCHED", action_id="b1")
        .events,
        "FAIL",
        ("e3",),
    ),
    Scenario(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        "unknown: a dispatch for an action never seen requested",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="ghost")
        .events,
        "UNKNOWN",
        ("e2",),
    ),
    Scenario("INV-BANK-CHANGE-NEEDS-APPROVAL", "unknown: nothing observed", [], "UNKNOWN"),
    # --- INV-STAYS-ON-ONE-HOST
    Scenario(
        "INV-STAYS-ON-ONE-HOST",
        "good: everything on the first host",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .request("a2", "form_submit", "https://portal.example/y")
        .add("ACTION_DISPATCHED", action_id="a2")
        .events,
        "PASS",
    ),
    Scenario(
        "INV-STAYS-ON-ONE-HOST",
        "good: an off-host request that was blocked is not a violation",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .request("a2", "navigate", "https://evil.example/collect")
        .add("ACTION_BLOCKED", action_id="a2")
        .events,
        "PASS",
    ),
    Scenario(
        "INV-STAYS-ON-ONE-HOST",
        "bad: dispatched to another host",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .request("a2", "navigate", "https://evil.example/collect")
        .add("ACTION_DISPATCHED", action_id="a2")
        .events,
        "FAIL",
        ("e4",),
    ),
    Scenario(
        "INV-STAYS-ON-ONE-HOST",
        "bad: a lookalike host is a different host",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .request("a2", "navigate", "https://portal.example.evil.test/x")
        .add("ACTION_DISPATCHED", action_id="a2")
        .events,
        "FAIL",
        ("e3",),
    ),
    Scenario(
        "INV-STAYS-ON-ONE-HOST",
        "unknown: the first target is not a web address",
        _b().request("a1", "form_fill", "#vendor-form").events,
        "UNKNOWN",
        ("e1",),
    ),
    Scenario("INV-STAYS-ON-ONE-HOST", "unknown: nothing observed", [], "UNKNOWN"),
    # --- INV-NAVIGATION-OBSERVED
    Scenario(
        "INV-NAVIGATION-OBSERVED",
        "good: navigated and observed",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .add("BROWSER_OBSERVATION", action_id="a1")
        .events,
        "PASS",
    ),
    Scenario(
        "INV-NAVIGATION-OBSERVED",
        "unknown: navigated but never observed (not a pass)",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("ACTION_DISPATCHED", action_id="a1")
        .events,
        "UNKNOWN",
        ("e2",),
    ),
    Scenario(
        "INV-NAVIGATION-OBSERVED",
        "unknown: the observation came before the dispatch",
        _b()
        .request("a1", "navigate", "https://portal.example/x")
        .add("BROWSER_OBSERVATION", action_id="a1")
        .add("ACTION_DISPATCHED", action_id="a1")
        .events,
        "UNKNOWN",
        ("e3",),
    ),
    Scenario("INV-NAVIGATION-OBSERVED", "unknown: nothing observed", [], "UNKNOWN"),
)
