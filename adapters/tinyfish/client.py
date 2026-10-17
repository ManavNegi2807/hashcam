"""What the adapter needs from TinyFish, and a scripted stand-in for tests.

`TinyFishClient` is the seam. `http_client.HttpTinyFishClient` is the real one,
written from the provider's published API and checked against the service in the
capability spike (`docs/TINYFISH_SPIKE.md`). `FakeTinyFishClient` plays back a
script and never touches the network: it exists so the parts that are ours (opt-in,
budget, error handling, what gets recorded) can be tested exactly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class QuotaExhausted(Exception):
    """The provider says the account has nothing left."""


class ProviderTimeout(Exception):
    """No answer in time. The remote action may or may not have happened.

    `cents` is what the steps seen so far cost, so a timed-out run is still counted."""

    def __init__(self, message: str = "", cents: int = 0) -> None:
        super().__init__(message)
        self.cents = cents


class BadResponse(Exception):
    """The provider's answer failed our shape checks."""


class RateLimited(Exception):
    """HTTP 429. Not retried here: the caller decides, after `retry_after` seconds."""

    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__("rate limited")
        self.retry_after = retry_after


class AuthFailure(Exception):
    """The key is missing, wrong or not allowed. Nothing about the key is in the message."""


class NotSupported(Exception):
    """An operation this client does not implement (so it is never guessed at)."""


class RunFailed(Exception):
    """The provider ran the task and reports it failed. A failed run can still cost steps."""

    def __init__(self, code: str, message: str, cents: int = 0) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.cents = cents


@dataclass(frozen=True)
class Usage:
    """What the provider says a call cost. `cents` is integer; `raw` is kept as returned."""

    cents: int
    raw: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class Reply:
    execution_id: str
    steps: tuple[dict[str, str], ...]
    result: str
    usage: Usage


class TinyFishClient(Protocol):
    """The seam. A real client goes here."""

    host: str

    def estimate_cents(self, kind: str, task: str) -> int | None:
        """An upper bound on the cost in whole cents, rounded up, else `None`."""
        ...

    def remaining_cents(self) -> int | None:
        """Credits left if the provider exposes them, else `None`."""
        ...

    def run(self, kind: str, task: str, url: str) -> dict[str, Any]:
        """Perform the operation, starting at `url`, and return the provider's answer.

        May raise `QuotaExhausted`, `ProviderTimeout`, `RateLimited`, `AuthFailure`,
        `NotSupported`, `RunFailed` or `BadResponse`.
        """
        ...


def parse_reply(raw: Any) -> Reply:
    """Check the provider's answer. Anything off is `BadResponse`, never guessed at."""
    if not isinstance(raw, dict):
        raise BadResponse("the answer is not an object")
    execution_id = raw.get("execution_id")
    result = raw.get("result")
    steps = raw.get("steps")
    usage = raw.get("usage")
    if not isinstance(execution_id, str) or not execution_id:
        raise BadResponse("no execution id")
    if not isinstance(result, str):
        raise BadResponse("no result text")
    if not isinstance(steps, list):
        raise BadResponse("steps is not a list")
    clean_steps = []
    for step in steps:
        if not isinstance(step, dict) or not all(
            isinstance(step.get(k), str) for k in ("kind", "url", "text")
        ):
            raise BadResponse("a step is malformed")
        clean_steps.append({k: str(step[k]) for k in ("kind", "url", "text")})
    if not isinstance(usage, dict) or not all(
        isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in usage.values()
    ):
        raise BadResponse("usage is missing or not whole non-negative numbers")
    if not isinstance(usage.get("cents"), int):
        raise BadResponse("usage has no cents")
    return Reply(
        execution_id=execution_id,
        steps=tuple(clean_steps),
        result=result,
        usage=Usage(cents=int(usage["cents"]), raw={k: int(v) for k, v in usage.items()}),
    )


@dataclass
class FakeTinyFishClient:
    """Plays back a script. Each `run` pops the next outcome."""

    host: str = "api.tinyfish.test"
    script: list[Any] = field(default_factory=list)
    estimate: int | None = None
    remaining: int | None = None
    calls: list[tuple[str, str]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)

    def estimate_cents(self, kind: str, task: str) -> int | None:
        return self.estimate

    def remaining_cents(self) -> int | None:
        return self.remaining

    def run(self, kind: str, task: str, url: str) -> dict[str, Any]:
        self.calls.append((kind, task))
        self.urls.append(url)
        if not self.script:
            raise AssertionError("the fake has no more scripted outcomes")
        outcome = self.script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        answer: dict[str, Any] = outcome
        return answer


def good_answer(cents: int = 40, steps: int = 2, execution_id: str = "exec-1") -> dict[str, Any]:
    return {
        "execution_id": execution_id,
        "result": "done",
        "steps": [
            {"kind": "navigated", "url": f"https://portal.example/{i}", "text": f"page {i}"}
            for i in range(steps)
        ],
        "usage": {"cents": cents, "steps_billed": steps},
    }
