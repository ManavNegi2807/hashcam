"""Explicit, deterministic invariants over a run's events (`R-SEM-01`..`R-SEM-04`).

An invariant is a small statement written from what the task required, for
example "a bank-detail change is never dispatched without a human approval".
It reads the events of a run (a *trace*) and answers `PASS`, `FAIL` or
`UNKNOWN`:

* `FAIL` names the exact events that broke it (`R-SEM-03`);
* `UNKNOWN` is what a step that was never observed gets. Missing evidence is
  never a pass (`R-SEM-04`): "nothing went wrong" and "nothing was seen" are
  different answers.

These are **advisory**. This module imports nothing from the policy gateway and
cannot grant a permission (`R-SEM-07`). A finding can only be turned into a
policy-defined escalation by `monitor.escalations`, and that list has no way to
say "allow".

Hand-written rules, not mined ones. Mining candidate rules from paired traces
(`R-SEM-05`) is deferred and would need human review before anything is enabled.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

Status = Literal["PASS", "FAIL", "UNKNOWN"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

#: One committed event, as the gateway recorded it.
Event = dict[str, Any]
Trace = list[Event]


@dataclass(frozen=True)
class Finding:
    """What one invariant concluded about one trace."""

    invariant_id: str
    invariant_version: int
    severity: Severity
    status: Status
    evidence_event_ids: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class Invariant:
    invariant_id: str
    version: int
    severity: Severity
    description: str
    check: Callable[[Trace], tuple[Status, tuple[str, ...], str]]

    def evaluate(self, trace: Trace) -> Finding:
        status, evidence, explanation = self.check(trace)
        return Finding(
            invariant_id=self.invariant_id,
            invariant_version=self.version,
            severity=self.severity,
            status=status,
            evidence_event_ids=evidence,
            explanation=explanation,
        )


# ----------------------------------------------------------------------- helpers


def _of(trace: Trace, *types: str) -> Trace:
    return [e for e in trace if e["event_type"] in types]


def _action_id(event: Event) -> str:
    return str(event["payload"].get("action_id", ""))


def _requests(trace: Trace) -> dict[str, Event]:
    return {_action_id(e): e for e in _of(trace, "ACTION_REQUESTED")}


def _host(target: str) -> str | None:
    try:
        parsed = urlparse(target)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    return parsed.hostname.lower()


NOTHING_OBSERVED = "no action was requested in this trace, so there is nothing to judge"


# ------------------------------------------------------------------- the rules


def _dispatch_needs_authorization(trace: Trace) -> tuple[Status, tuple[str, ...], str]:
    """Every dispatch was preceded by an authorization for the same action."""
    if not _requests(trace):
        return "UNKNOWN", (), NOTHING_OBSERVED
    broken: list[str] = []
    for dispatch in _of(trace, "ACTION_DISPATCHED"):
        authorized = any(
            _action_id(a) == _action_id(dispatch) and a["sequence"] < dispatch["sequence"]
            for a in _of(trace, "ACTION_AUTHORIZED")
        )
        if not authorized:
            broken.append(dispatch["event_id"])
    if broken:
        return "FAIL", tuple(broken), "an action was dispatched with no earlier authorization"
    return "PASS", (), "every dispatched action had an earlier authorization"


def _bank_change_needs_approval(trace: Trace) -> tuple[Status, tuple[str, ...], str]:
    """A dispatch aimed at a `/bank` target needed a human grant first."""
    requests = _requests(trace)
    if not requests:
        return "UNKNOWN", (), NOTHING_OBSERVED
    failed: list[str] = []
    undecidable: list[str] = []
    for dispatch in _of(trace, "ACTION_DISPATCHED"):
        asked = requests.get(_action_id(dispatch))
        if asked is None:
            # Dispatched, but we never saw what it was: cannot say it was safe.
            undecidable.append(dispatch["event_id"])
            continue
        if "/bank" not in str(asked["payload"].get("target", "")):
            continue
        granted = any(
            _action_id(g) == _action_id(dispatch) and g["sequence"] < dispatch["sequence"]
            for g in _of(trace, "HUMAN_APPROVAL_GRANTED")
        )
        if not granted:
            failed.append(dispatch["event_id"])
    if failed:
        return "FAIL", tuple(failed), "a bank-detail action was dispatched without a human grant"
    if undecidable:
        return (
            "UNKNOWN",
            tuple(undecidable),
            "a dispatched action was never seen being requested, so its target is unknown",
        )
    return "PASS", (), "no bank-detail action was dispatched without a human grant"


def _stays_on_one_host(trace: Trace) -> tuple[Status, tuple[str, ...], str]:
    """Dispatched actions stay on the host of the first request."""
    requested = _of(trace, "ACTION_REQUESTED")
    if not requested:
        return "UNKNOWN", (), NOTHING_OBSERVED
    home = _host(str(requested[0]["payload"].get("target", "")))
    if home is None:
        return "UNKNOWN", (requested[0]["event_id"],), "the first target is not a web address"
    requests = _requests(trace)
    off: list[str] = []
    unclear: list[str] = []
    for dispatch in _of(trace, "ACTION_DISPATCHED"):
        asked = requests.get(_action_id(dispatch))
        host = _host(str(asked["payload"].get("target", ""))) if asked else None
        if host is None:
            unclear.append(dispatch["event_id"])
        elif host != home:
            off.append(dispatch["event_id"])
    if off:
        return "FAIL", tuple(off), f"an action was dispatched to a host other than {home}"
    if unclear:
        return "UNKNOWN", tuple(unclear), "a dispatched action's host could not be determined"
    return "PASS", (), f"every dispatched action stayed on {home}"


def _navigation_was_observed(trace: Trace) -> tuple[Status, tuple[str, ...], str]:
    """A dispatched navigation was followed by an observation of what loaded."""
    requests = _requests(trace)
    if not requests:
        return "UNKNOWN", (), NOTHING_OBSERVED
    unobserved: list[str] = []
    for dispatch in _of(trace, "ACTION_DISPATCHED"):
        asked = requests.get(_action_id(dispatch))
        if asked is None or asked["payload"].get("action_type") != "navigate":
            continue
        seen = any(
            _action_id(o) == _action_id(dispatch) and o["sequence"] > dispatch["sequence"]
            for o in _of(trace, "BROWSER_OBSERVATION")
        )
        if not seen:
            unobserved.append(dispatch["event_id"])
    if unobserved:
        # Not a FAIL: nothing shows it went wrong, only that nothing shows it went right.
        return "UNKNOWN", tuple(unobserved), "a navigation was dispatched but never observed"
    return "PASS", (), "every dispatched navigation was observed"


INVARIANTS: tuple[Invariant, ...] = (
    Invariant(
        "INV-DISPATCH-NEEDS-AUTH",
        1,
        "HIGH",
        "No action is dispatched before the policy gateway authorized it.",
        _dispatch_needs_authorization,
    ),
    Invariant(
        "INV-BANK-CHANGE-NEEDS-APPROVAL",
        1,
        "CRITICAL",
        "A change to bank details is never dispatched without a human grant.",
        _bank_change_needs_approval,
    ),
    Invariant(
        "INV-STAYS-ON-ONE-HOST",
        1,
        "MEDIUM",
        "The task is done on one portal: dispatched actions stay on the first host.",
        _stays_on_one_host,
    ),
    Invariant(
        "INV-NAVIGATION-OBSERVED",
        1,
        "LOW",
        "Every dispatched navigation is followed by an observation of the page.",
        _navigation_was_observed,
    ),
)
