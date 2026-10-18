"""Turn a receipt summary (`services.dashboard.server.summarize`) into nodes and edges.

Pure and deterministic: the same summary always gives the same graph. Every id is namespaced with
the run id so graphs of different runs never collide inside one database.
"""

from __future__ import annotations

from typing import Any

# What the last event about an action says happened to it (later events win).
_STATUS = {
    "ACTION_REQUESTED": "requested",
    "ACTION_DISPATCHED": "dispatched",
    "ACTION_SUCCEEDED": "succeeded",
    "ACTION_FAILED": "failed",
    "ACTION_BLOCKED": "blocked",
    "OUTCOME_UNKNOWN": "unknown",
}
LABELS = ("Run", "Action", "Policy", "Approval", "Mandate", "Call")
RELATIONS = ("REQUESTED", "NEXT", "DECIDED_BY", "APPROVED_BY", "GOVERNED_BY", "BILLED")


def _text(value: Any, limit: int = 120) -> str:
    return value[:limit] if isinstance(value, str) else ""


def build(summary: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    run = summary.get("run", {})
    run_id = _text(run.get("run_id"), 80) or "run"
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def node(label: str, key: str, **props: Any) -> str:
        node_id = f"{run_id}:{label.lower()}:{key}"
        nodes.setdefault(node_id, {"id": node_id, "label": label, "name": key, **props})
        return node_id

    def edge(src: str, dst: str, relation: str) -> None:
        item = {"src": src, "dst": dst, "type": relation}
        if item not in edges:
            edges.append(item)

    root = node(
        "Run",
        run_id[:8],
        adapter=_text(run.get("adapter_name")),
        coverage=_text(run.get("observed_coverage") or run.get("declared_coverage")),
        outcome="",
        witnesses=int(summary.get("witnesses", 0)),
        anchors=int(summary.get("anchors", 0)),
    )

    previous = ""
    for event in summary.get("events", []):
        kind = str(event.get("event_type", ""))
        payload = event.get("payload", {}) or {}
        action_key = _text(payload.get("action_id"), 60)

        if kind == "RUN_FINISHED":
            nodes[root]["outcome"] = _text(payload.get("outcome"), 40)
        if not action_key:
            continue
        action = node("Action", action_key, action_type="", target="", status="requested")
        if kind == "ACTION_REQUESTED":
            nodes[action]["action_type"] = _text(payload.get("action_type"), 40)
            nodes[action]["target"] = _text(payload.get("target"), 200)
            amount = payload.get("amount_minor_units")
            if isinstance(amount, int) and not isinstance(amount, bool):
                nodes[action]["amount_minor_units"] = amount
            edge(root, action, "REQUESTED")
            if previous:
                edge(previous, action, "NEXT")
            previous = action
        if kind in _STATUS:
            nodes[action]["status"] = _STATUS[kind]
        if kind == "ACTION_AUTHORIZED":
            decision = _text(payload.get("decision"), 30)
            policy_name = (
                f"{_text(payload.get('policy_id'), 60)} v{_text(payload.get('policy_version'), 10)}"
            )
            edge(action, node("Policy", policy_name), "DECIDED_BY")
            nodes[action]["decision"] = decision
            if decision == "REQUIRE_APPROVAL" and nodes[action]["status"] == "requested":
                nodes[action]["status"] = "needs approval"
        if kind == "API_CALL_OBSERVED":
            usage = payload.get("usage", {}) or {}
            cents = usage.get("cents")
            call = node(
                "Call",
                f"{_text(payload.get('host'), 80) or 'provider'}#{event.get('sequence')}",
                cents=cents if isinstance(cents, (int, float)) else -1,
            )
            edge(action, call, "BILLED")

    for approval in summary.get("approvals", []):
        action = f"{run_id}:action:{_text(approval.get('action_id'), 60)}"
        decision = _text(approval.get("decision"), 30)
        signed = node("Approval", _text(approval.get("approval_id"), 12), decision=decision)
        if action in nodes:
            edge(action, signed, "APPROVED_BY")
            if nodes[action]["status"] in ("needs approval", "requested"):
                nodes[action]["status"] = "approved" if decision == "APPROVE" else "denied"

    mandate = summary.get("mandate")
    if mandate:
        edge(root, node("Mandate", _text(mandate.get("mandate_id"), 12)), "GOVERNED_BY")

    return {"nodes": list(nodes.values()), "edges": edges}
