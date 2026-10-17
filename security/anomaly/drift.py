"""Replay drift: how a rerun differs from an earlier run (`R-ANO-02`, `D-19`).

Run the same task twice and compare what the agent did. A difference is not
wrongdoing: pages change and agents vary. It is worth a look, so it is reported
as an advisory signal, in the same record shape as the rules baseline.

Two actions are "the same" when they have the same type and the same host and
path. Parameters, ids and timing are ignored: they differ on every run.
"""

from __future__ import annotations

import base64
import json
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pathsafe

MODEL_ID = "abb-replay-drift"
MODEL_VERSION = "1"
FEATURE_SCHEMA_ID = "abb-drift-v1"

Trace = list[dict[str, Any]]

WEIGHTS = {
    "DRIFT-ACTIONS-ADDED": 250_000,
    "DRIFT-ACTIONS-REMOVED": 250_000,
    "DRIFT-REORDERED": 150_000,
    "DRIFT-HOSTS-CHANGED": 350_000,
    "DRIFT-OUTCOME-CHANGED": 300_000,
}


def _identity(event: dict[str, Any]) -> tuple[str, str]:
    payload = event["payload"]
    parsed = urlparse(str(payload.get("target", "")))
    place = (parsed.hostname or str(payload.get("target", ""))) + parsed.path
    return str(payload.get("action_type", "")), place


def _actions(trace: Trace) -> list[tuple[str, str]]:
    return [_identity(e) for e in trace if e["event_type"] == "ACTION_REQUESTED"]


def _hosts(trace: Trace) -> set[str]:
    out: set[str] = set()
    for e in trace:
        if e["event_type"] == "ACTION_REQUESTED":
            host = urlparse(str(e["payload"].get("target", ""))).hostname
            if host:
                out.add(host)
    return out


def _outcome(trace: Trace) -> str | None:
    for e in reversed(trace):
        if e["event_type"] == "RUN_FINISHED":
            return str(e["payload"].get("outcome"))
    return None


@dataclass(frozen=True)
class Drift:
    added: tuple[tuple[str, str], ...] = ()
    removed: tuple[tuple[str, str], ...] = ()
    reordered: bool = False
    hosts_added: tuple[str, ...] = ()
    hosts_removed: tuple[str, ...] = ()
    outcome_before: str | None = None
    outcome_after: str | None = None
    reasons: tuple[str, ...] = field(default=())

    @property
    def drifted(self) -> bool:
        return bool(self.reasons)

    @property
    def score_ppm(self) -> int:
        return min(1_000_000, sum(WEIGHTS[r] for r in self.reasons))

    def payload(self) -> dict[str, Any]:
        return {
            "model_id": MODEL_ID,
            "model_version": MODEL_VERSION,
            "feature_schema_id": FEATURE_SCHEMA_ID,
            "score_ppm": self.score_ppm,
            "reason_codes": sorted(self.reasons),
            "score_kind": "RULE_SUM",
        }

    def describe(self) -> list[str]:
        lines: list[str] = []
        for kind, place in self.added:
            lines.append(f"added:    {kind} {place}")
        for kind, place in self.removed:
            lines.append(f"removed:  {kind} {place}")
        if self.reordered:
            lines.append("the same actions happened in a different order")
        for host in self.hosts_added:
            lines.append(f"new host: {host}")
        for host in self.hosts_removed:
            lines.append(f"no longer contacted: {host}")
        if "DRIFT-OUTCOME-CHANGED" in self.reasons:
            lines.append(f"outcome:  {self.outcome_before} -> {self.outcome_after}")
        return lines


def compare(before: Trace, after: Trace) -> Drift:
    """Differences between two runs of the same task. Advisory."""
    a, b = _actions(before), _actions(after)
    ca, cb = Counter(a), Counter(b)
    added = tuple(sorted((cb - ca).elements()))
    removed = tuple(sorted((ca - cb).elements()))
    reordered = not added and not removed and a != b
    hosts_added = tuple(sorted(_hosts(after) - _hosts(before)))
    hosts_removed = tuple(sorted(_hosts(before) - _hosts(after)))
    outcome_before, outcome_after = _outcome(before), _outcome(after)

    reasons: list[str] = []
    if added:
        reasons.append("DRIFT-ACTIONS-ADDED")
    if removed:
        reasons.append("DRIFT-ACTIONS-REMOVED")
    if reordered:
        reasons.append("DRIFT-REORDERED")
    if hosts_added or hosts_removed:
        reasons.append("DRIFT-HOSTS-CHANGED")
    if outcome_before != outcome_after:
        reasons.append("DRIFT-OUTCOME-CHANGED")
    return Drift(
        added=added,
        removed=removed,
        reordered=reordered,
        hosts_added=hosts_added,
        hosts_removed=hosts_removed,
        outcome_before=outcome_before,
        outcome_after=outcome_after,
        reasons=tuple(reasons),
    )


def trace_from_receipt(path: Path) -> Trace:
    """The events of a receipt, decoded for comparison. Reads; verifies nothing."""
    with zipfile.ZipFile(pathsafe.extended(path)) as archive:
        document = json.loads(archive.read("receipt.json").decode("utf-8"))
    trace: Trace = []
    for item in document["events"]:
        event = json.loads(base64.b64decode(item["canonical_b64"]))
        trace.append(
            {
                "event_id": event["event_id"],
                "sequence": event["sequence"],
                "event_type": event["event_type"],
                "payload": event.get("payload", {}),
            }
        )
    return trace
