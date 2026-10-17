"""The optional TinyFish adapter (`R-TFY-01`..`R-TFY-07`, `R-COV-04`, `R-COV-06`, `D-14`).

What this adapter is: a careful wrapper around *someone else's agent*. The remote
agent decides and acts on its own; we can gate the **request we send it** and record
what it **tells us** it did. We cannot gate its individual steps before they happen,
so the most this adapter may ever claim is `STEP_OBSERVED`, and what it records of
those steps is labelled `reported_by_adapter`: the provider's word, not ours
(`PROTOCOL.md` 5.1). The coverage stays at that level until a spike has shown
otherwise, and the verifier refuses `STEP_GATED` for a `LIVE_EXTERNAL` run that has
no capability evidence.

What it will not do:

* run without an explicit opt-in (`R-TFY-01`);
* make a call that would spend into the reserve, or any call once the ceiling is
  reached, judged by the provider's own metering (`R-TFY-03`..`R-TFY-05`);
* retry a refused, failed or timed-out call by another, paid route. There is no
  fallback path in this file to be found;
* retry blindly after a timeout: a remote action may have happened, so the outcome
  is recorded as unknown (`ERROR_HANDLING.md` 2).

The client is injected. `http_client.HttpTinyFishClient` talks to the real service;
tests use a scripted fake or a local fake HTTP server that follows the documented API.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from adapters.base import Coverage, Provenance
from adapters.tinyfish.budget import Budget, BudgetError, BudgetReserveReached
from adapters.tinyfish.client import (
    AuthFailure,
    BadResponse,
    NotSupported,
    ProviderTimeout,
    QuotaExhausted,
    RateLimited,
    RunFailed,
    TinyFishClient,
    parse_reply,
)
from policy.engine import Action

ADAPTER_NAME = "tinyfish"
ADAPTER_VERSION = "0.1.0"
IN_SCOPE_ACTIONS = ["api_call"]

#: Never higher than this, until a spike proves pre-dispatch gating (`R-COV-04`).
CEILING_COVERAGE: Coverage = "STEP_OBSERVED"
COVERAGE_REASON = (
    "the provider's agent acts on its own: the request sent to it is gated and the steps it "
    "reports are recorded as the provider's claims, but its individual steps were not "
    "gated before they happened"
)


class OptInRequired(Exception):
    """TinyFish was not explicitly switched on for this run."""


@dataclass(frozen=True)
class Outcome:
    # SUCCEEDED, BLOCKED, QUOTA_EXHAUSTED, RESERVE_REACHED, OUTCOME_UNKNOWN or BAD_RESPONSE
    status: str
    detail: str = ""
    execution_id: str | None = None


class TinyFishAdapter:
    def __init__(
        self,
        gateway: Any,
        client: TinyFishClient,
        budget: Budget,
        *,
        opt_in: bool = False,
        execution_id: str = "tinyfish-1",
        clock_ms: Any = None,
    ) -> None:
        self.gateway = gateway
        self.client = client
        self.budget = budget
        self.opt_in = opt_in
        self.execution_id = execution_id
        self._clock = clock_ms or (lambda: 0)
        self._counter = 0

    def provenance(self) -> Provenance:
        return Provenance(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            execution_id=self.execution_id,
            mode="LIVE_EXTERNAL",
            observed_coverage=CEILING_COVERAGE,
        )

    def _id(self) -> str:
        self._counter += 1
        return f"tf-{self._counter}"

    # -------------------------------------------------------------- operations

    def search_fetch(self, task: str, url: str) -> Outcome:
        """The lighter provider operation (search and fetch)."""
        return self._run("search_fetch", task, url)

    def search(self, task: str) -> Outcome:
        """Ranked web results for a question. One request; the results are the provider's."""
        return self._run("search", task, self._api_url("search"))

    def research(self, task: str) -> Outcome:
        """A written, cited report from a question (minutes long)."""
        return self._run("research", task, self._api_url("research"))

    def _api_url(self, kind: str) -> str:
        """Where this kind of task is sent. Policy is asked about that address."""
        api_url = getattr(self.client, "api_url", None)
        if callable(api_url):
            return str(api_url(kind))
        return f"https://{self.client.host}"

    def run_agent(self, task: str, url: str) -> Outcome:
        """The provider's autonomous web agent, starting at `url`."""
        return self._run("agent", task, url)

    def _run(self, kind: str, task: str, url: str) -> Outcome:
        if not self.opt_in:
            raise OptInRequired("TinyFish is optional and must be switched on for each run")

        action = Action(
            action_id=self._id(),
            action_type="api_call",
            # Policy judges where the agent is sent to start, since that is the part we
            # can decide. The call to the provider itself is recorded as API_CALL_OBSERVED.
            target=url,
            # Only a digest of the task is recorded: the text may be sensitive.
            params={
                "kind": kind,
                "task_digest": hashlib.sha256(task.encode()).hexdigest(),
                "via": self.client.host,
            },
        )

        # 1. Before anything is spent: reserve and credits.
        try:
            remaining = self.client.remaining_cents()
            if remaining is not None and remaining < self.budget.remaining_cents:
                # The provider's own number wins over ours when it is lower.
                self.budget.ceiling_cents = self.budget.spent_cents + remaining
            self.budget.check(self.client.estimate_cents(kind, task))
        except BudgetReserveReached:
            self.gateway.deny(action, "BUDGET_RESERVE_REACHED")
            return Outcome("RESERVE_REACHED", "optional calls stop at the reserve")
        except BudgetError as exc:
            self.gateway.deny(action, exc.code)
            return Outcome("QUOTA_EXHAUSTED", "the ceiling is reached; no call was made")

        # 2. The request we send is itself an action: policy decides.
        decision = self.gateway.request(action)
        if not decision.allows_dispatch:
            return Outcome("BLOCKED", ",".join(decision.reason_codes))
        self.gateway.dispatch(action)

        # 3. The call. Each failure mode is recorded as what it is, and none is retried.
        try:
            raw = self.client.run(kind, task, url)
        except QuotaExhausted:
            self.gateway.failed(action, error_code="PROVIDER_QUOTA_EXHAUSTED", retryable=False)
            return Outcome("QUOTA_EXHAUSTED", "the provider reports no quota; no fallback is tried")
        except ProviderTimeout as exc:
            self.budget.record(exc.cents)  # what the steps seen so far cost still counts
            self.gateway.outcome_unknown(
                action,
                reason="the provider did not answer in time; the remote action may have happened",
            )
            return Outcome(
                "OUTCOME_UNKNOWN", "not retried: the first attempt may have taken effect"
            )

        except RateLimited as exc:
            self.gateway.failed(action, error_code="PROVIDER_RATE_LIMITED", retryable=True)
            wait = f" (retry after {exc.retry_after:.0f}s)" if exc.retry_after else ""
            return Outcome("RATE_LIMITED", "the provider is rate limiting" + wait)
        except AuthFailure as exc:
            self.gateway.failed(action, error_code="PROVIDER_AUTH_FAILED", retryable=False)
            return Outcome("AUTH_FAILED", str(exc))
        except NotSupported as exc:
            self.gateway.failed(action, error_code="NOT_SUPPORTED", retryable=False)
            return Outcome("NOT_SUPPORTED", str(exc))
        except RunFailed as exc:
            # The provider ran it and says it failed. Steps already taken still cost money.
            self.budget.record(exc.cents)
            self.gateway.failed(action, error_code=f"PROVIDER_{exc.code}"[:64], retryable=False)
            return Outcome("RUN_FAILED", exc.message[:200])
        except BadResponse as exc:
            self.gateway.failed(action, error_code="ADAPTER_BAD_RESPONSE", retryable=False)
            return Outcome("BAD_RESPONSE", str(exc))

        try:
            reply = parse_reply(raw)
        except BadResponse as exc:
            self.gateway.failed(action, error_code="ADAPTER_BAD_RESPONSE", retryable=False)
            return Outcome("BAD_RESPONSE", str(exc))

        # 4. What it cost, as the provider metered it, then what it says it did.
        self.budget.record(reply.usage.cents)
        observed = self.gateway.observe_api_call(
            action,
            method="POST",
            host=url.split("//", 1)[-1].split("/", 1)[0].split("?", 1)[0] or self.client.host,
            status_code=200,
            body_digest=hashlib.sha256(repr(sorted(reply.usage.raw.items())).encode()).hexdigest(),
            extra={
                "provider_execution_id": reply.execution_id,
                "usage": dict(reply.usage.raw),
                "usage_observed_at": int(self._clock()),
            },
        )
        evidence = [observed.event_id]
        for step in reply.steps:
            reported = self.gateway.report_observation(
                action, observation_kind=step["kind"], url=step["url"], text=step["text"]
            )
            evidence.append(reported.event_id)
        self.gateway.succeeded(action, evidence=evidence)
        return Outcome("SUCCEEDED", reply.result, reply.execution_id)
