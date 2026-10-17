"""The adapter contract.

`DESIGN.md` 13.1 and `R-ADP-02`, `R-ADP-03`: every adapter returns the same
shape, and that shape keeps three kinds of statement apart (`PROTOCOL.md` 5.1):

* `reported_by_adapter` — the adapter or a provider said so;
* `observed_by_local_gateway` — the local gateway saw it happen;
* `verified_by_black_box` — we recomputed it ourselves.

An adapter never writes to the ledger. It proposes actions to the gateway,
which decides and records. That is what makes `STEP_GATED` mean anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Mode = Literal["REPLAY", "LIVE_LOCAL", "LIVE_EXTERNAL"]
Coverage = Literal["TASK_LEVEL", "STEP_OBSERVED", "STEP_GATED"]


@dataclass(frozen=True)
class Provenance:
    """Who produced an observation, and under what claim."""

    adapter_name: str
    adapter_version: str
    execution_id: str
    mode: Mode
    observed_coverage: Coverage

    def to_payload(self) -> dict[str, str]:
        return {
            "adapter_name": self.adapter_name,
            "adapter_version": self.adapter_version,
            "execution_id": self.execution_id,
            "mode": self.mode,
            "observed_coverage": self.observed_coverage,
        }


@dataclass
class AdapterStep:
    """One step an adapter took, as it reports it."""

    action_id: str
    action_type: str
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    status: str = "PENDING"
    observations: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class AdapterResult:
    """The normalised result of `DESIGN.md` 13.1. All twelve fields."""

    adapter_name: str
    adapter_version: str
    execution_id: str
    requested_coverage: Coverage
    observed_coverage: Coverage
    started_at: int
    finished_at: int
    status: str
    steps: list[AdapterStep] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    external_usage: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def summary(self) -> str:
        blocked = sum(1 for step in self.steps if step.status == "BLOCKED")
        done = sum(1 for step in self.steps if step.status == "SUCCEEDED")
        return (
            f"{self.adapter_name} {self.adapter_version}: {done} dispatched, "
            f"{blocked} blocked, coverage {self.observed_coverage}"
        )
