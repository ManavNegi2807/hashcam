"""A rules baseline for odd behavior (`R-ANO-01`..`R-ANO-05`, `R-ANO-09`..`R-ANO-11`).

Readable rules over what an agent *did*, before any model (`R-ANO-03`). Every rule
says in plain words why it fired and which events it is about.

Three properties are enforced here, and tested:

* **No policy labels as inputs** (`R-ANO-05`). The extractor reads only what the
  agent proposed and what came back: requests, observations, outcomes. It never
  reads an authorization, a block, a violation or a reason code. Otherwise "the
  policy blocked it" would be fed back in as evidence of oddness, and the anomaly
  channel would just repeat the policy channel.
* **A score is a rule score, not a probability** (`R-ANO-09`). It is the sum of the
  weights of the rules that fired, capped. Nothing here is calibrated.
* **Failure here changes nothing else** (`R-ANO-11`). `run_anomaly` swallows its own
  errors and records nothing; it cannot reach the signer, the verifier or a
  decision, because it imports none of them.

No trained model exists, and none is embedded anywhere (`R-ANO-10`): a receipt
carries identifiers and a number.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

MODEL_ID = "abb-anomaly-rules"
MODEL_VERSION = "1"
FEATURE_SCHEMA_ID = "abb-features-v1"

#: The only event types a feature may come from. Policy events are absent on purpose.
FEATURE_EVENT_TYPES = frozenset(
    {
        "ACTION_REQUESTED",
        "BROWSER_OBSERVATION",
        "API_CALL_OBSERVED",
        "ACTION_SUCCEEDED",
        "ACTION_FAILED",
        "OUTCOME_UNKNOWN",
    }
)

Trace = list[dict[str, Any]]

#: Thresholds, in one place so a reader can see them. Chosen by judgment, not fitted.
THRESHOLDS = {
    "loop_repeats": 4,
    "retry_failures": 3,
    "error_rate_min_requests": 4,
    "error_rate": 0.5,
    "volume": 50,
    "writes_without_reading": 3,
    "unknown_outcomes": 2,
}
WRITE_TYPES = frozenset({"form_fill", "form_submit", "api_call", "download"})


@dataclass(frozen=True)
class Finding:
    rule_id: str
    weight_ppm: int
    evidence_event_ids: tuple[str, ...]
    explanation: str


@dataclass(frozen=True)
class Features:
    requests: tuple[dict[str, Any], ...]
    observations: int
    failures: tuple[dict[str, Any], ...]
    unknown_outcomes: tuple[dict[str, Any], ...]


def extract(trace: Trace) -> Features:
    """Features from allowed event types only (`R-ANO-05`)."""
    allowed = [e for e in trace if e["event_type"] in FEATURE_EVENT_TYPES]
    return Features(
        requests=tuple(e for e in allowed if e["event_type"] == "ACTION_REQUESTED"),
        observations=sum(1 for e in allowed if e["event_type"] == "BROWSER_OBSERVATION"),
        failures=tuple(e for e in allowed if e["event_type"] == "ACTION_FAILED"),
        unknown_outcomes=tuple(e for e in allowed if e["event_type"] == "OUTCOME_UNKNOWN"),
    )


def _key(event: dict[str, Any]) -> tuple[str, str]:
    payload = event["payload"]
    return str(payload.get("action_type", "")), str(payload.get("target", ""))


def _loop(f: Features) -> Finding | None:
    counts = Counter(_key(e) for e in f.requests)
    (kind, target), n = counts.most_common(1)[0] if counts else (("", ""), 0)
    if n >= THRESHOLDS["loop_repeats"]:
        ids = tuple(e["event_id"] for e in f.requests if _key(e) == (kind, target))
        return Finding(
            "ANO-LOOP", 350_000, ids, f"the same {kind} on {target} was proposed {n} times"
        )
    return None


def _retry_burst(f: Features) -> Finding | None:
    asked = {str(e["payload"].get("action_id")): e for e in f.requests}
    per_target: dict[tuple[str, str], list[str]] = {}
    for failure in f.failures:
        request = asked.get(str(failure["payload"].get("action_id")))
        if request is not None:
            per_target.setdefault(_key(request), []).append(failure["event_id"])
    for (kind, target), ids in per_target.items():
        if len(ids) >= THRESHOLDS["retry_failures"]:
            return Finding(
                "ANO-RETRY-BURST",
                300_000,
                tuple(ids),
                f"{len(ids)} failed attempts at {kind} on {target}",
            )
    return None


def _error_rate(f: Features) -> Finding | None:
    total = len(f.requests)
    if (
        total >= THRESHOLDS["error_rate_min_requests"]
        and len(f.failures) / total > THRESHOLDS["error_rate"]
    ):
        return Finding(
            "ANO-ERROR-RATE",
            250_000,
            tuple(e["event_id"] for e in f.failures),
            f"{len(f.failures)} of {total} proposed actions failed",
        )
    return None


def _volume(f: Features) -> Finding | None:
    if len(f.requests) > THRESHOLDS["volume"]:
        return Finding(
            "ANO-VOLUME",
            200_000,
            (),
            f"{len(f.requests)} actions in one run (more than {THRESHOLDS['volume']})",
        )
    return None


def _writes_without_reading(f: Features) -> Finding | None:
    writes = [e for e in f.requests if e["payload"].get("action_type") in WRITE_TYPES]
    if len(writes) >= THRESHOLDS["writes_without_reading"] and f.observations == 0:
        return Finding(
            "ANO-WRITES-WITHOUT-READING",
            300_000,
            tuple(e["event_id"] for e in writes),
            f"{len(writes)} state-changing actions and nothing was ever observed",
        )
    return None


def _unknown_outcomes(f: Features) -> Finding | None:
    if len(f.unknown_outcomes) >= THRESHOLDS["unknown_outcomes"]:
        return Finding(
            "ANO-UNKNOWN-OUTCOMES",
            200_000,
            tuple(e["event_id"] for e in f.unknown_outcomes),
            f"{len(f.unknown_outcomes)} actions ended with an unknown outcome",
        )
    return None


RULES: tuple[Callable[[Features], Finding | None], ...] = (
    _loop,
    _retry_burst,
    _error_rate,
    _volume,
    _writes_without_reading,
    _unknown_outcomes,
)


def evaluate(trace: Trace) -> list[Finding]:
    features = extract(trace)
    return [finding for rule in RULES if (finding := rule(features)) is not None]


def score_ppm(findings: list[Finding]) -> int:
    """The sum of the weights that fired, capped at a million. Not a probability."""
    return min(1_000_000, sum(f.weight_ppm for f in findings))


def payload_for(findings: list[Finding]) -> dict[str, Any]:
    """The `ML_ANALYSIS_COMPLETED` payload: identifiers and a number, nothing executable."""
    return {
        "model_id": MODEL_ID,
        "model_version": MODEL_VERSION,
        "feature_schema_id": FEATURE_SCHEMA_ID,
        "score_ppm": score_ppm(findings),
        "reason_codes": sorted(f.rule_id for f in findings),
        "score_kind": "RULE_SUM",
    }


def run_anomaly(gateway: Any) -> list[Finding] | None:
    """Evaluate the run's ledger trace and record the result. Never raises.

    If anything here goes wrong the run carries on exactly as it would have:
    cryptographic checking and authorization do not depend on this (`R-ANO-11`).
    """
    try:
        findings = evaluate(gateway.trace())
        gateway.emit_advisory(
            "ML_ANALYSIS_COMPLETED", payload_for(findings), idempotency_key="anomaly-rules"
        )
    except Exception:
        return None
    return findings
