"""Run the invariants and turn findings into ledger events (`R-SEM-06`, `R-SEM-07`).

The monitor reads a trace and reports. It never decides what an agent may do:
the only thing a finding can lead to is an *escalation the policy named in
advance*, and the set of escalations has no way to say "allow".
"""

from __future__ import annotations

from typing import Any

from .invariants import INVARIANTS, Finding, Trace

#: What a policy may ask for when an invariant fails. None of these grants
#: anything; "ALLOW" is deliberately not here and `escalations` rejects it.
ALLOWED_ESCALATIONS = frozenset({"NOTIFY", "REQUIRE_APPROVAL_FOR_NEXT", "STOP_RUN"})


def evaluate(trace: Trace) -> list[Finding]:
    """Every invariant, in a fixed order, against one trace."""
    return [invariant.evaluate(trace) for invariant in INVARIANTS]


def events_for(findings: list[Finding]) -> list[tuple[str, dict[str, Any]]]:
    """The ledger events for these findings: one check per invariant, plus a
    violation record for each `FAIL`."""
    out: list[tuple[str, dict[str, Any]]] = []
    for finding in findings:
        out.append(
            (
                "SEMANTIC_INVARIANT_CHECKED",
                {
                    "invariant_id": finding.invariant_id,
                    "invariant_version": str(finding.invariant_version),
                    "result": finding.status,
                    "evidence_event_ids": list(finding.evidence_event_ids),
                },
            )
        )
        if finding.status == "FAIL":
            out.append(
                (
                    "SEMANTIC_VIOLATION_DETECTED",
                    {
                        "invariant_id": finding.invariant_id,
                        "invariant_version": str(finding.invariant_version),
                        "severity": finding.severity,
                        "evidence_event_ids": list(finding.evidence_event_ids),
                        "status": "OPEN",
                    },
                )
            )
    return out


def escalations(findings: list[Finding], mapping: dict[str, str]) -> list[tuple[str, str]]:
    """The escalations a policy asked for, for the invariants that failed.

    `mapping` is policy-defined: invariant id -> escalation name. A value outside
    `ALLOWED_ESCALATIONS` is a configuration error, not something to honor.
    """
    unknown = sorted(set(mapping.values()) - ALLOWED_ESCALATIONS)
    if unknown:
        raise ValueError(f"not an escalation (a finding can never grant anything): {unknown}")
    return [
        (finding.invariant_id, mapping[finding.invariant_id])
        for finding in findings
        if finding.status == "FAIL" and finding.invariant_id in mapping
    ]


def run_monitor(gateway: Any) -> list[Finding]:
    """Check the gateway's own trace and record the results before the run ends."""
    findings = evaluate(gateway.trace())
    for number, (event_type, payload) in enumerate(events_for(findings)):
        gateway.emit_advisory(event_type, payload, idempotency_key=f"semantic-{number}")
    return findings
