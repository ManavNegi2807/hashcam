"""The semantic monitor must read the ledger, not the worker's private copy.

Regression for a bug found by an end-to-end test: a normal run, with a human
approval relayed by the control plane, was reported as a semantic FAIL because
the monitor was fed the gateway's own list of events, which does not contain
the `HUMAN_APPROVAL_GRANTED` the control plane committed.
"""

from __future__ import annotations

from typing import Any

from adapters.base import Provenance
from policy.engine import Policy
from security.semantic import monitor
from services.worker.gateway import Gateway

PROVENANCE = Provenance("replay", "0.1.0", "x", "REPLAY", "STEP_GATED")


class LedgerSink:
    """A sink that can also read the ledger back, including events it did not write."""

    def __init__(self) -> None:
        self.written: list[dict[str, Any]] = []
        self.ledger: list[dict[str, Any]] = []

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        n = len(self.ledger) + 1
        self.ledger.append(
            {
                "event_id": f"e{n}",
                "sequence": n,
                "event_type": kwargs["event_type"],
                "payload": kwargs["payload"],
            }
        )
        return {"event_id": f"e{n}", "sequence": n, "leaf_hash": "00" * 32}

    def inject_control_plane_event(self, event_type: str, payload: dict[str, Any]) -> None:
        n = len(self.ledger) + 1
        self.ledger.append(
            {"event_id": f"e{n}", "sequence": n, "event_type": event_type, "payload": payload}
        )

    def fetch_events(self) -> list[dict[str, Any]]:
        return list(self.ledger)


class WriteOnlySink:
    def __init__(self) -> None:
        self.n = 0

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        self.n += 1
        return {"event_id": f"e{self.n}", "sequence": self.n, "leaf_hash": "00" * 32}


def _gateway(sink: Any) -> Gateway:
    return Gateway(
        sink=sink,
        policy=Policy.load("default", 1),
        provenance=PROVENANCE,
        in_scope_actions=["navigate", "form_submit"],
    )


def test_the_trace_includes_events_the_control_plane_committed() -> None:
    sink = LedgerSink()
    gateway = _gateway(sink)
    gateway.run_started(task="t", requested_coverage="STEP_GATED")
    sink.inject_control_plane_event("HUMAN_APPROVAL_GRANTED", {"action_id": "b-2"})
    types = [e["event_type"] for e in gateway.trace()]
    assert types == ["RUN_STARTED", "HUMAN_APPROVAL_GRANTED"]


def test_a_bank_change_with_a_relayed_grant_is_not_a_false_semantic_failure() -> None:
    sink = LedgerSink()
    gateway = _gateway(sink)
    target = "https://portal.example/vendor/42/bank"
    sink.inject_control_plane_event(
        "ACTION_REQUESTED", {"action_id": "b-2", "action_type": "form_submit", "target": target}
    )
    sink.inject_control_plane_event("ACTION_AUTHORIZED", {"action_id": "b-2"})
    sink.inject_control_plane_event("HUMAN_APPROVAL_GRANTED", {"action_id": "b-2"})
    sink.inject_control_plane_event("ACTION_DISPATCHED", {"action_id": "b-2"})
    findings = {f.invariant_id: f.status for f in monitor.evaluate(gateway.trace())}
    assert findings["INV-BANK-CHANGE-NEEDS-APPROVAL"] == "PASS"


def test_a_sink_that_cannot_read_falls_back_to_the_local_copy() -> None:
    gateway = _gateway(WriteOnlySink())
    gateway.run_started(task="t", requested_coverage="STEP_GATED")
    assert [e["event_type"] for e in gateway.trace()] == ["RUN_STARTED"]
