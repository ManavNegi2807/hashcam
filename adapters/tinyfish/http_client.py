"""The real TinyFish client, over HTTPS, written from the provider's published API.

What it does, and what it does not:

* Three operations are live: **agent** (`POST /v1/automation/run-async`, then poll
  `GET /v1/runs/{id}`), **search** (`GET https://api.search.tinyfish.ai`, ranked results)
  and **research** (`POST /v1/automation/run-research-async`, then poll
  `GET /v1/research-run/{id}`; a written, cited report, usually 5 to 20 minutes).
  Anything else raises `NotSupported`: nothing is guessed.
* The API key is read from the environment variable `TINYFISH_API_KEY` that the
  user sets. It is never printed, logged, stored or placed in an error message,
  and it is sent only in the `X-API-Key` header.
* Every run carries hard caps (`max_steps`, `max_duration_seconds`). If our own
  deadline passes first, the run is cancelled and the outcome is *unknown*.
* Cost: the run response has **no usage field**. Cost is derived as
  `num_of_steps x the per-step rate` from `GET /v1/wallet`, cross-checked with the
  wallet drop around the run; the larger of the two is used. The balance alone is
  not trusted: it once rose after a run (a credit), which would read as negative
  spend. Both numbers are kept in `usage` as integers.
* No retries. A 429 is raised as `RateLimited` and left to the caller.

Standard library only (no new dependency). Plain `http://` is accepted only for a
loopback base URL, so tests can use a local fake server.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from adapters.tinyfish.client import (
    AuthFailure,
    BadResponse,
    NotSupported,
    ProviderTimeout,
    QuotaExhausted,
    RateLimited,
    RunFailed,
)

DEFAULT_BASE_URL = "https://agent.tinyfish.ai"
DEFAULT_SEARCH_URL = "https://api.search.tinyfish.ai"
MAX_RESULTS_SHOWN = 8
KEY_ENV = "TINYFISH_API_KEY"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}
_TERMINAL = {"COMPLETED", "FAILED", "CANCELLED"}
_BILLING_CODES = {"BILLING_FAILURE", "BILLING_REJECTED"}
#: Failed looks at a run in a row before giving up on it.
MAX_POLL_FAILURES = 5


def _cents(dollars: Any, rounding: str) -> int:
    try:
        value = Decimal(str(dollars)) * 100
    except InvalidOperation as exc:
        raise BadResponse("a money value is not a decimal string") from exc
    return int(value.to_integral_value(rounding=rounding))


class HttpTinyFishClient:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        *,
        max_steps: int = 5,
        send_step_cap: bool = True,
        max_duration_seconds: int = 60,
        poll_seconds: float = 1.0,
        progress: Callable[[str], None] | None = None,
        deadline_seconds: float = 90.0,
        request_timeout: float = 20.0,
        search_url: str = DEFAULT_SEARCH_URL,
        research_deadline_seconds: float = 1500.0,
        research_poll_seconds: float = 5.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and not (
            parsed.scheme == "http" and parsed.hostname in _LOOPBACK
        ):
            raise ValueError("the TinyFish base URL must be https (http only for loopback)")
        search = urlparse(search_url)
        if search.scheme != "https" and not (
            search.scheme == "http" and search.hostname in _LOOPBACK
        ):
            raise ValueError("the search URL must be https (http only for loopback)")
        if not 1 <= max_steps <= 500:
            raise ValueError("max_steps must be 1..500")
        self._base = base_url.rstrip("/")
        self.host = parsed.netloc
        self.max_steps = max_steps
        self._send_step_cap = send_step_cap
        self.max_duration_seconds = max_duration_seconds
        self._poll = poll_seconds
        self._progress = progress
        self._deadline = deadline_seconds
        self._request_timeout = request_timeout
        self._sleep = sleep
        self._clock = clock
        self._step_rate: Decimal | None = None  # dollars per step, from the wallet
        self._rates: dict[str, Decimal] = {}  # every meter on the wallet's rate card
        self._search_base = search_url.rstrip("/")
        self._search_host = search.netloc
        self._research_deadline = research_deadline_seconds
        self._research_poll = research_poll_seconds

    def __repr__(self) -> str:  # never shows the key
        return f"HttpTinyFishClient(host={self.host!r})"

    # -- transport -------------------------------------------------------------

    def _call(
        self, method: str, path: str, body: dict[str, Any] | None = None, base: str | None = None
    ) -> Any:
        key = os.environ.get(KEY_ENV, "")
        if not key:
            raise AuthFailure(f"{KEY_ENV} is not set")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            (base if base is not None else self._base) + path,
            data=data,
            method=method,
            headers={
                "X-API-Key": key,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._request_timeout) as resp:  # noqa: S310
                raw = resp.read(4_000_000)
        except urllib.error.HTTPError as exc:
            self._raise_for_status(exc)
            raise  # unreachable; keeps type checkers calm
        except TimeoutError as exc:
            raise ProviderTimeout("the provider did not answer in time") from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ProviderTimeout("the provider did not answer in time") from exc
            raise BadResponse("the provider could not be reached") from exc
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise BadResponse("the answer is not JSON") from exc

    @staticmethod
    def _raise_for_status(exc: urllib.error.HTTPError) -> None:
        code = ""
        try:
            payload = json.loads(exc.read(100_000))
            err = payload.get("error", payload) if isinstance(payload, dict) else {}
            code = str(err.get("code", "")) if isinstance(err, dict) else ""
        except (ValueError, OSError):
            pass
        if exc.code in (401, 403):
            detail = f"HTTP {exc.code} {code}".strip()
            raise AuthFailure(f"the provider refused the request ({detail})") from exc
        if exc.code == 429:
            retry = exc.headers.get("Retry-After") if exc.headers else None
            try:
                wait = float(retry) if retry else None
            except ValueError:
                wait = None
            raise RateLimited(wait) from exc
        if exc.code == 402 or code in _BILLING_CODES:
            raise QuotaExhausted(code or "payment required") from exc
        raise BadResponse(f"the provider answered HTTP {exc.code} {code}".strip()) from exc

    # -- money -----------------------------------------------------------------

    def _wallet(self) -> dict[str, Any]:
        wallet = self._call("GET", "/v1/wallet")
        if not isinstance(wallet, dict) or "available_balance" not in wallet:
            raise BadResponse("the wallet answer has no balance")
        rates = wallet.get("rates")
        if isinstance(rates, dict):
            for meter in rates.get("meters") or []:
                label = str(meter.get("label", "")).lower() if isinstance(meter, dict) else ""
                if isinstance(meter, dict):
                    try:
                        self._rates[label] = Decimal(str(meter["unit_amount"]))
                    except (InvalidOperation, KeyError):
                        pass
                if isinstance(meter, dict) and (meter.get("per") == "step" or "step" in label):
                    try:
                        self._step_rate = Decimal(str(meter["unit_amount"]))
                    except (InvalidOperation, KeyError):
                        pass
        return wallet

    def remaining_cents(self) -> int | None:
        try:
            return _cents(self._wallet()["available_balance"], ROUND_FLOOR)
        except (AuthFailure, BadResponse, ProviderTimeout, RateLimited):
            return None

    def estimate_cents(self, kind: str, task: str) -> int | None:
        """An upper bound in whole cents, rounded up. Agent: the step cap times the step rate."
        Search and research: the per-use rate on the wallet's rate card (the card says 0 today)."""
        if kind in ("search", "research"):
            if not self._rates:
                try:
                    self._wallet()
                except (AuthFailure, BadResponse, ProviderTimeout, RateLimited):
                    return None
            rate = next((r for label, r in self._rates.items() if kind in label), None)
            return None if rate is None else _cents(rate, ROUND_CEILING)
        if kind != "agent":
            return None
        if self._step_rate is None:
            try:
                self._wallet()
            except (AuthFailure, BadResponse, ProviderTimeout, RateLimited):
                return None
        if self._step_rate is None:
            return None
        return _cents(self._step_rate * self.max_steps, ROUND_CEILING)

    # -- the run ---------------------------------------------------------------

    def api_url(self, kind: str) -> str:
        """Where a task of this kind is sent: what policy is asked about for search and research."""
        if kind == "search":
            return self._search_base
        if kind == "research":
            return self._base + "/v1/automation/run-research-async"
        return self._base

    def run(self, kind: str, task: str, url: str) -> dict[str, Any]:
        if kind == "search":
            return self._search(task)
        if kind == "research":
            return self._research(task)
        if kind != "agent":
            raise NotSupported("this operation is not implemented against the live API")
        before = self._wallet_cents_or_none()
        started = self._call(
            "POST",
            "/v1/automation/run-async",
            {
                "url": url,
                "goal": task,
                "browser_profile": "lite",
                "agent_config": self._agent_config(),
            },
        )
        run_id = started.get("run_id") if isinstance(started, dict) else None
        if not isinstance(run_id, str) or not run_id:
            err = started.get("error") if isinstance(started, dict) else None
            code = (
                str(err.get("code", "CREATE_FAILED")) if isinstance(err, dict) else "CREATE_FAILED"
            )
            if code in _BILLING_CODES:
                raise QuotaExhausted(code)
            raise RunFailed(code, "the provider did not start the run")

        started = self._clock()
        deadline = started + self._deadline
        run: Any = {}
        failures = 0
        done_steps = 0
        while True:
            try:
                run = self._call("GET", f"/v1/runs/{run_id}")
                if not isinstance(run, dict):
                    raise BadResponse("the run answer is not an object")
                failures = 0
            except (ProviderTimeout, BadResponse, RateLimited) as exc:
                # Looking at a run's progress changes nothing, so a failed look is tried
                # again. Only the request that starts the run is never repeated.
                failures += 1
                self._say(
                    f"checking progress failed ({type(exc).__name__}), "
                    f"try {failures} of {MAX_POLL_FAILURES}"
                )
                if failures >= MAX_POLL_FAILURES or self._clock() >= deadline:
                    self._cancel(run_id)
                    raise ProviderTimeout(
                        "progress checks kept failing; the run was asked to cancel",
                        self._usage(done_steps, before)["cents"],
                    ) from exc
                pause = exc.retry_after if isinstance(exc, RateLimited) else None
                self._sleep(min(pause or self._poll, 10.0))
                continue
            if run.get("status") in _TERMINAL:
                break
            seen = run.get("num_of_steps")
            done_steps = seen if isinstance(seen, int) and not isinstance(seen, bool) else 0
            seconds = int(self._clock() - started)
            self._say(
                f"TinyFish says {run.get('status')}, {done_steps} step(s) so far ({seconds} s)"
            )
            if self._clock() >= deadline:
                self._say(
                    f"No finish after {seconds} s and {done_steps} step(s): asking TinyFish "
                    "to cancel. The outcome is recorded as unknown, not retried."
                )
                self._cancel(run_id)
                raise ProviderTimeout(
                    "our deadline passed; the run was asked to cancel",
                    self._usage(done_steps, before)["cents"],
                )
            self._sleep(self._poll)

        steps_n = run.get("num_of_steps")
        steps_n = steps_n if isinstance(steps_n, int) and not isinstance(steps_n, bool) else 0
        usage = self._usage(steps_n, before)
        status = run["status"]
        if status != "COMPLETED":
            err = run.get("error")
            code = str(err.get("code", status)) if isinstance(err, dict) else str(status)
            message = str(err.get("message", "")) if isinstance(err, dict) else ""
            raise RunFailed(code, message or f"the run ended as {status}", usage["cents"])

        result = run.get("result")
        if isinstance(result, dict) and isinstance(result.get("result"), str):
            result_text = result["result"]
        elif isinstance(result, str):
            result_text = result
        else:
            result_text = json.dumps(result, sort_keys=True)[:2000]
        return {
            "execution_id": run_id,
            "result": result_text,
            "steps": self._steps(run.get("steps"), url),
            "usage": usage,
        }

    # -- search: ranked results, one request, no run to wait for

    def _search(self, query: str) -> dict[str, Any]:
        data = self._call("GET", "?" + urlencode({"query": query[:500]}), base=self._search_base)
        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list):
            raise BadResponse("the search answer has no results list")
        items: list[dict[str, str]] = []
        for entry in results[:MAX_RESULTS_SHOWN]:
            if not isinstance(entry, dict):
                continue
            title = str(entry.get("title", "")).strip()
            link = str(entry.get("url", "")).strip()
            snippet = " ".join(str(entry.get("snippet", "")).split())
            if title and link.startswith(("http://", "https://")):
                items.append({"title": title, "url": link, "snippet": snippet})
        if not items:
            text = "The search found no results for this question."
        else:
            lines = ["**Top web results**", ""]
            for item in items:
                clean = "".join(c for c in item["title"] if c not in "[]()")
                lines.append(
                    f"- [{clean}]({quote(item['url'], safe=':/?&=%#~+@,;')}) \u2014 "
                    f"{item['snippet']}"
                )
            text = chr(10).join(lines)
        digest = hashlib.sha256(query.encode("utf-8")).hexdigest()[:16]
        return {
            "execution_id": "search-" + digest,  # a search has no run id; this is ours
            "result": text,
            "steps": [
                {
                    "kind": "search_result",
                    "url": i["url"],
                    "text": f"{i['title']} \u2014 {i['snippet']}"[:500],
                }
                for i in items
            ],
            "usage": {"cents": 0, "results": len(items)},
        }

    # -- research: a written, cited report from a question (an async job, minutes long)

    def _research(self, query: str) -> dict[str, Any]:
        before = self._wallet_cents_or_none()
        try:
            started = self._call(
                "POST", "/v1/automation/run-research-async", {"query": query[:2000], "mode": "deep"}
            )
        except AuthFailure as exc:
            raise AuthFailure(
                f"{exc} Research may not be switched on for this TinyFish account."
            ) from exc
        run_id = started.get("research_run_id") if isinstance(started, dict) else None
        if not isinstance(run_id, str) or not run_id:
            err = started.get("error") if isinstance(started, dict) else None
            code = (
                str(err.get("code", "CREATE_FAILED")) if isinstance(err, dict) else "CREATE_FAILED"
            )
            raise RunFailed(code, "the provider did not start the research")
        started_at = self._clock()
        deadline = started_at + self._research_deadline
        failures = 0
        run: Any = {}
        while True:
            try:
                run = self._call("GET", f"/v1/research-run/{run_id}")
                if not isinstance(run, dict):
                    raise BadResponse("the research answer is not an object")
                failures = 0
            except (ProviderTimeout, BadResponse, RateLimited) as exc:
                failures += 1
                self._say(
                    f"checking progress failed ({type(exc).__name__}), "
                    f"try {failures} of {MAX_POLL_FAILURES}"
                )
                if failures >= MAX_POLL_FAILURES or self._clock() >= deadline:
                    self._cancel_research(run_id)
                    raise ProviderTimeout(
                        "progress checks kept failing; the research was asked to cancel"
                    ) from exc
                self._sleep(self._research_poll)
                continue
            status = run.get("status")
            if status in ("COMPLETED", "FAILED", "CANCELLED", "TIMED_OUT"):
                break
            seconds = int(self._clock() - started_at)
            self._say(
                f"TinyFish says {status} ({seconds // 60} min {seconds % 60} s). "
                "Research usually takes 5 to 20 minutes."
            )
            if self._clock() >= deadline:
                self._say(
                    "Our time limit passed: asking TinyFish to cancel. "
                    "The outcome is recorded as unknown."
                )
                self._cancel_research(run_id)
                raise ProviderTimeout("our deadline passed; the research was asked to cancel")
            self._sleep(self._research_poll)
        usage = {"cents": 0, "steps_billed": 0, "wallet_drop_cents": 0}
        after = self._wallet_cents_or_none()
        if before is not None and after is not None and before > after:
            usage["cents"] = usage["wallet_drop_cents"] = before - after
        if status != "COMPLETED":
            err = run.get("error")
            code = str(err.get("code", status)) if isinstance(err, dict) else str(status)
            message = str(err.get("message", "")) if isinstance(err, dict) else ""
            raise RunFailed(code, message or f"the research ended as {status}", usage["cents"])
        deep = run.get("deep_result")
        report = deep.get("result") if isinstance(deep, dict) else None
        if not isinstance(report, str) or not report.strip():
            raise BadResponse("the research finished without a report")
        raw_citations = deep.get("citations") if isinstance(deep, dict) else None
        citations = raw_citations if isinstance(raw_citations, list) else []
        cited = [
            c for c in citations if isinstance(c, str) and c.startswith(("http://", "https://"))
        ]
        return {
            "execution_id": run_id,
            "result": report,
            "steps": [{"kind": "citation", "url": c, "text": "cited source"} for c in cited[:50]],
            "usage": usage,
        }

    def _cancel_research(self, run_id: str) -> None:
        try:
            self._call("POST", f"/v1/research-run/{run_id}/cancel", {})
        except (AuthFailure, BadResponse, ProviderTimeout, RateLimited):
            pass  # best effort; the outcome is recorded as unknown either way

    def _agent_config(self) -> dict[str, int]:
        """`max_steps` needs beta access (the docs say a request that includes it without
        beta returns 403). Without it the cap is the duration and our own deadline, and
        `max_steps` is then only the *assumed* worst case used for the estimate."""
        config = {"max_duration_seconds": self.max_duration_seconds}
        if self._send_step_cap:
            config["max_steps"] = self.max_steps
        return config

    def _say(self, message: str) -> None:
        if self._progress is not None:
            self._progress(message)

    def _wallet_cents_or_none(self) -> int | None:
        try:
            return _cents(self._wallet()["available_balance"], ROUND_FLOOR)
        except (BadResponse, ProviderTimeout, RateLimited):
            return None

    def _usage(self, steps: int, before: int | None) -> dict[str, int]:
        by_steps = (
            _cents(self._step_rate * steps, ROUND_CEILING) if self._step_rate is not None else 0
        )
        drop = 0
        after = self._wallet_cents_or_none()
        if before is not None and after is not None and before > after:
            drop = before - after
        cents = max(by_steps, drop)
        if self._step_rate is None and after is None:
            cents = max(cents, 1)  # unknown is not free
        return {
            "cents": cents,
            "steps_billed": steps,
            "cents_by_steps": by_steps,
            "wallet_drop_cents": drop,
        }

    @staticmethod
    def _steps(raw: Any, start_url: str) -> list[dict[str, str]]:
        """The provider's step records carry an action text, not a page URL, so the
        start URL is given and the text says so. Nothing is invented."""
        out: list[dict[str, str]] = []
        if not isinstance(raw, list):
            return out
        for item in raw:
            action = item.get("action") if isinstance(item, dict) else None
            if isinstance(action, str):
                out.append(
                    {
                        "kind": "provider_step",
                        "url": start_url,
                        "text": f"[step page URL not reported; start URL shown] {action}"[:500],
                    }
                )
        return out

    def _cancel(self, run_id: str) -> None:
        try:
            self._call("POST", f"/v1/runs/{run_id}/cancel", {})
        except (AuthFailure, BadResponse, ProviderTimeout, RateLimited):
            pass  # best effort; the outcome is recorded as unknown either way
