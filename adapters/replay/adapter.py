"""The ReplayAdapter: the default, zero-cost, deterministic path.

`R-ADP-04` and `R-COV-02`. It replays a committed scenario file: no network, no
clock, no randomness, so the same scenario produces the same actions and the
same observations every time. Its output is always labelled `mode = REPLAY`,
because it is a simulation and a receipt must say so.

It drives the gateway; it never records anything itself.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pathsafe
from adapters.base import AdapterResult, AdapterStep, Provenance
from policy.engine import Action, Decision
from services.worker.gateway import Gateway

SCENARIOS = Path(__file__).resolve().parent / "scenarios"

ADAPTER_NAME = "replay"
ADAPTER_VERSION = "0.1.0"

#: What a replay run can be gated on. Anything else is out of scope, and the
#: gateway refuses it rather than quietly widening the claim.
IN_SCOPE_ACTIONS = ["navigate", "form_fill", "form_submit", "download", "api_call"]


def load_scenario(name: str, *, directory: Path | None = None) -> dict[str, Any]:
    path = (directory or SCENARIOS) / f"{name}.json"
    # Read through pathsafe: a deep checkout on Windows otherwise fails here
    # with a file that `iterdir` can see and `open` cannot.
    scenario: dict[str, Any] = json.loads(pathsafe.read_text(path))
    return scenario


class ReplayAdapter:
    """Replays one scenario through a gateway."""

    def __init__(
        self,
        scenario: dict[str, Any],
        *,
        execution_id: str = "replay-1",
        approver: Callable[[Gateway, Action], Decision] | None = None,
    ) -> None:
        self.scenario = scenario
        self.execution_id = execution_id
        # Stands in for a human at their own device. With none attached, an
        # action that needs approval simply waits, which is the safe default.
        self.approver = approver

    def provenance(self, observed_coverage: str) -> Provenance:
        return Provenance(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            execution_id=self.execution_id,
            # Always REPLAY: this is a simulation (R-COV-02).
            mode="REPLAY",
            observed_coverage=observed_coverage,  # type: ignore[arg-type]
        )

    def run(self, gateway: Gateway) -> AdapterResult:
        """Walk the scenario. Returns the normalised result of `DESIGN.md` 13.1."""
        steps: list[AdapterStep] = []
        errors: list[dict[str, Any]] = []

        for raw in self.scenario["steps"]:
            action = Action(
                action_id=str(raw["action_id"]),
                action_type=str(raw["action_type"]),
                target=str(raw["target"]),
                amount_minor_units=raw.get("amount_minor_units"),
                params=dict(raw.get("params", {})),
            )
            step = AdapterStep(
                action_id=action.action_id,
                action_type=action.action_type,
                target=action.target,
                params=action.params,
            )

            decision = gateway.request(action)
            if decision.outcome == "REQUIRE_APPROVAL" and self.approver is not None:
                decision = self.approver(gateway, action)
            if not decision.allows_dispatch:
                step.status = "BLOCKED" if decision.outcome == "DENY" else "AWAITING_APPROVAL"
                errors.append(
                    {
                        "action_id": action.action_id,
                        "outcome": decision.outcome,
                        "reason_codes": list(decision.reason_codes),
                    }
                )
                steps.append(step)
                continue

            gateway.dispatch(action)
            evidence: list[str] = []
            observation = raw.get("observation")
            if observation:
                committed = gateway.observe(
                    action,
                    observation_kind=str(observation["observation_kind"]),
                    url=str(observation["url"]),
                    text=str(observation["text"]),
                )
                evidence.append(committed.event_id)
                capture = observation.get("capture")
                if capture:
                    captured = gateway.capture_artifact(
                        action,
                        str(capture["content"]).encode("utf-8"),
                        media_type=str(capture["media_type"]),
                        capture_method=str(capture["capture_method"]),
                    )
                    evidence.append(captured.event_id)
                step.observations.append(dict(observation))
            gateway.succeeded(action, evidence=evidence)
            step.status = "SUCCEEDED"
            steps.append(step)

        return AdapterResult(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            execution_id=self.execution_id,
            requested_coverage=self.scenario.get("requested_coverage", "STEP_GATED"),
            # What the adapter can actually evidence. A replay run is gated by
            # construction: every action goes through the gateway above.
            observed_coverage="STEP_GATED",
            # Fixed times: a replay is deterministic, and these are claims
            # either way (PROTOCOL.md 10.4).
            started_at=1_760_000_000_000,
            finished_at=1_760_000_000_000,
            status="COMPLETED" if not errors else "COMPLETED_WITH_BLOCKS",
            steps=steps,
            artifacts=[],
            errors=errors,
            external_usage={},
            provenance=self.provenance("STEP_GATED").to_payload(),
        )
