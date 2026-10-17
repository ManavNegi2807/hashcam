"""The real TinyFish client, tested against a local fake that follows the *documented* API.

This proves our client handles the documented shapes and errors. It does **not**
prove anything about the real service: that is `docs/TINYFISH_SPIKE.md` (two live
runs through a connector) plus any run the user makes with their own key.
The key used here is a dummy value; no real key is read or needed.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from adapters.tinyfish.client import (
    AuthFailure,
    BadResponse,
    NotSupported,
    ProviderTimeout,
    QuotaExhausted,
    RateLimited,
    RunFailed,
)
from adapters.tinyfish.http_client import KEY_ENV, HttpTinyFishClient

DUMMY_KEY = "dummy-key-for-tests-only"
START = "https://example.com"


class Fake:
    """Scripted server state."""

    def __init__(self) -> None:
        self.balance = ["15.000"]  # popped per wallet read; the last value repeats
        self.rate = "0.016"
        self.statuses = ["RUNNING", "COMPLETED"]
        self.steps = 3
        self.run_error: Any = None
        self.fail_http: dict[str, tuple[int, dict[str, Any]]] = {}
        self.requests: list[tuple[str, str, dict[str, Any] | None, str | None]] = []
        self.cancelled = False
        self.research_statuses = ["RUNNING", "COMPLETED"]
        self.research_cancelled = False
        self.search_results: Any = [
            {
                "position": 1,
                "site_name": "example.org",
                "title": "POCO phones [India] (list)",
                "snippet": "Prices from Rs. 9,999.",
                "url": "https://example.org/poco?x=1&y=2",
            },
            {"position": 2, "title": "No link", "snippet": "x", "url": "javascript:alert(1)"},
        ]
        self.fail_times: dict[str, int] = {}  # path -> how many requests to fail with HTTP 500

    def wallet(self) -> dict[str, Any]:
        bal = self.balance.pop(0) if len(self.balance) > 1 else self.balance[0]
        return {
            "available_balance": bal,
            "currency": "USD",
            "as_of": "2026-10-17T00:00:00Z",
            "rates": {
                "meters": [
                    {
                        "label": "Agent steps",
                        "unit_amount": self.rate,
                        "currency": "USD",
                        "per": "step",
                    },
                    {
                        "label": "Browser",
                        "unit_amount": "0.002",
                        "currency": "USD",
                        "per": "minute",
                    },
                    {
                        "label": "TinyFish Search",
                        "unit_amount": "0",
                        "currency": "USD",
                        "per": "query",
                    },
                    {
                        "label": "TinyFish Research",
                        "unit_amount": "0",
                        "currency": "USD",
                        "per": "run",
                    },
                ],
                "as_of": "2026-10-17T00:00:00Z",
            },
        }


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch) -> Iterator[Fake]:
    monkeypatch.setenv(KEY_ENV, DUMMY_KEY)
    fake = Fake()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: Any) -> None:
            pass

        def _send(
            self, code: int, body: dict[str, Any], headers: dict[str, str] | None = None
        ) -> None:
            raw = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(raw)

        def _handle(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length)) if length else None
            fake.requests.append((method, self.path, body, self.headers.get("X-API-Key")))
            if self.headers.get("X-API-Key") != DUMMY_KEY:
                return self._send(401, {"error": {"code": "INVALID_API_KEY"}})
            if fake.fail_times.get(self.path, 0) > 0:
                fake.fail_times[self.path] -= 1
                return self._send(500, {"error": {"code": "INTERNAL"}})
            if self.path in fake.fail_http:
                code, payload = fake.fail_http[self.path]
                return self._send(code, payload, {"Retry-After": "7"} if code == 429 else None)
            if method == "GET" and self.path.startswith("/?query="):
                return self._send(
                    200,
                    {"query": "q", "results": fake.search_results, "total_results": 2, "page": 0},
                )
            if method == "POST" and self.path == "/v1/automation/run-research-async":
                return self._send(200, {"research_run_id": "rr-1", "error": None})
            if method == "POST" and self.path == "/v1/research-run/rr-1/cancel":
                fake.research_cancelled = True
                return self._send(
                    200, {"research_run_id": "rr-1", "status": "CANCELLED", "cancelled": True}
                )
            if method == "GET" and self.path == "/v1/research-run/rr-1":
                status = (
                    fake.research_statuses.pop(0)
                    if len(fake.research_statuses) > 1
                    else fake.research_statuses[0]
                )
                done = status == "COMPLETED"
                return self._send(
                    200,
                    {
                        "research_run_id": "rr-1",
                        "status": status,
                        "deep_result": {
                            "result": "# Report" + chr(10) + "- fact one",
                            "citations": ["https://a.example/x", "ftp://bad"],
                        }
                        if done
                        else None,
                        "error": {"code": "TIMEOUT", "message": "too slow"}
                        if status == "TIMED_OUT"
                        else None,
                    },
                )
            if method == "GET" and self.path == "/v1/wallet":
                return self._send(200, fake.wallet())
            if method == "POST" and self.path == "/v1/automation/run-async":
                return self._send(200, {"run_id": "run-1", "error": None})
            if method == "POST" and self.path == "/v1/runs/run-1/cancel":
                fake.cancelled = True
                return self._send(200, {"run_id": "run-1", "status": "CANCELLED"})
            if method == "GET" and self.path == "/v1/runs/run-1":
                status = fake.statuses.pop(0) if len(fake.statuses) > 1 else fake.statuses[0]
                run: dict[str, Any] = {
                    "run_id": "run-1",
                    "status": status,
                    "num_of_steps": fake.steps if status in ("COMPLETED", "FAILED") else None,
                    "result": {"result": "Example Domain"} if status == "COMPLETED" else None,
                    "error": fake.run_error if status == "FAILED" else None,
                    "steps": [{"action": f"did thing {i}"} for i in range(fake.steps)],
                }
                return self._send(200, run)
            return self._send(404, {"error": {"code": "NOT_FOUND"}})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    fake.base = f"http://127.0.0.1:{httpd.server_port}"  # type: ignore[attr-defined]
    yield fake
    httpd.shutdown()


def client(fake: Any, **kw: Any) -> HttpTinyFishClient:
    kw.setdefault("sleep", lambda s: None)
    kw.setdefault("poll_seconds", 0)
    return HttpTinyFishClient(fake.base, **kw)


def test_a_documented_run_is_started_polled_and_costed_by_steps(server: Fake) -> None:
    server.balance = ["15.000", "14.952"]
    answer = client(server, max_steps=5, max_duration_seconds=60).run(
        "agent", "get the title", START
    )
    assert answer["execution_id"] == "run-1"
    assert answer["result"] == "Example Domain"
    assert answer["usage"] == {
        "cents": 5,  # 3 steps x $0.016 = 4.8 cents, rounded up; wallet drop 4.8 -> 5 floor diff 5
        "steps_billed": 3,
        "cents_by_steps": 5,
        "wallet_drop_cents": 5,
    }
    start = next(r for r in server.requests if r[1] == "/v1/automation/run-async")
    assert start[2] == {
        "url": START,
        "goal": "get the title",
        "browser_profile": "lite",
        "agent_config": {"max_steps": 5, "max_duration_seconds": 60},
    }


def test_the_larger_of_steps_cost_and_wallet_drop_is_used(server: Fake) -> None:
    server.balance = ["15.000", "14.000"]  # the wallet fell a lot more than 3 steps
    assert client(server).run("agent", "g", START)["usage"]["cents"] == 100


def test_a_balance_rise_is_never_read_as_negative_spend(server: Fake) -> None:
    server.balance = ["15.000", "15.904"]  # a credit landed during the run (seen once, live)
    usage = client(server).run("agent", "g", START)["usage"]
    assert usage["wallet_drop_cents"] == 0
    assert usage["cents"] == usage["cents_by_steps"] == 5


def test_the_estimate_is_the_step_cap_times_the_rate_rounded_up(server: Fake) -> None:
    assert client(server, max_steps=5).estimate_cents("agent", "g") == 8  # 5 x 1.6 = 8.0
    assert client(server, max_steps=3).estimate_cents("agent", "g") == 5  # 4.8 -> 5
    assert client(server).estimate_cents("search_fetch", "g") is None


def test_remaining_credit_comes_from_the_wallet(server: Fake) -> None:
    server.balance = ["14.856"]
    assert client(server).remaining_cents() == 1485  # rounded down


def test_the_key_goes_only_in_the_header_and_not_in_the_repr_or_errors(server: Fake) -> None:
    c = client(server)
    c.run("agent", "g", START)
    assert all(req[3] == DUMMY_KEY for req in server.requests)
    assert all(DUMMY_KEY not in json.dumps(req[2]) for req in server.requests)
    assert DUMMY_KEY not in repr(c)


def test_a_missing_key_fails_closed_without_a_request(
    server: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV)
    with pytest.raises(AuthFailure) as err:
        client(server).run("agent", "g", START)
    assert KEY_ENV in str(err.value)
    assert server.requests == []


def test_a_wrong_key_is_an_auth_failure_that_does_not_echo_it(
    server: Fake, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(KEY_ENV, "wrong-key-value")
    with pytest.raises(AuthFailure) as err:
        client(server).run("agent", "g", START)
    assert "wrong-key-value" not in str(err.value)


def test_429_is_raised_with_retry_after_and_not_retried(server: Fake) -> None:
    server.fail_http["/v1/automation/run-async"] = (429, {"error": {"code": "RATE_LIMIT_EXCEEDED"}})
    with pytest.raises(RateLimited) as err:
        client(server).run("agent", "g", START)
    assert err.value.retry_after == 7.0
    assert sum(1 for r in server.requests if r[1] == "/v1/automation/run-async") == 1


@pytest.mark.parametrize("code", ["BILLING_FAILURE", "BILLING_REJECTED"])
def test_billing_errors_mean_quota_exhausted(server: Fake, code: str) -> None:
    server.fail_http["/v1/automation/run-async"] = (400, {"error": {"code": code}})
    with pytest.raises(QuotaExhausted):
        client(server).run("agent", "g", START)


def test_a_failed_run_carries_the_provider_code_and_its_steps_cost(server: Fake) -> None:
    server.statuses = ["FAILED"]
    server.run_error = {"code": "SITE_BLOCKED", "message": "blocked"}
    with pytest.raises(RunFailed) as err:
        client(server).run("agent", "g", START)
    assert err.value.code == "SITE_BLOCKED"
    assert err.value.cents == 5  # failed runs are still charged for their steps


def test_our_deadline_cancels_the_run_and_the_outcome_is_unknown(server: Fake) -> None:
    server.statuses = ["RUNNING"]
    ticks = iter(range(0, 1000, 40))
    with pytest.raises(ProviderTimeout):
        client(server, deadline_seconds=90, clock=lambda: float(next(ticks))).run(
            "agent", "g", START
        )
    assert server.cancelled


def test_search_fetch_is_not_implemented_and_makes_no_request(server: Fake) -> None:
    with pytest.raises(NotSupported):
        client(server).run("search_fetch", "g", START)
    assert server.requests == []


def test_plain_http_is_refused_for_a_non_loopback_base_url() -> None:
    with pytest.raises(ValueError):
        HttpTinyFishClient("http://api.tinyfish.example")


def test_the_step_text_is_marked_as_not_having_a_page_url(server: Fake) -> None:
    steps = client(server).run("agent", "g", START)["steps"]
    assert len(steps) == 3
    assert all("step page URL not reported" in s["text"] for s in steps)


def test_end_to_end_through_the_adapter_records_metering_and_caps_coverage(server: Fake) -> None:
    from adapters.base import Provenance
    from adapters.playwright.adapter import MemorySink
    from adapters.tinyfish.adapter import IN_SCOPE_ACTIONS, TinyFishAdapter
    from adapters.tinyfish.budget import Budget
    from policy.engine import Policy
    from services.worker.gateway import Gateway

    policy = Policy(
        {
            "policy_id": "external",
            "version": 1,
            "allowed_action_types": ["api_call"],
            "action_types_needing_target": ["api_call"],
            "allowed_hosts": ["example.com"],
            "max_actions": 10,
        }
    )
    sink = MemorySink()
    prov = Provenance("tinyfish", "0.1.0", "t", "LIVE_EXTERNAL", "STEP_OBSERVED")
    gateway = Gateway(sink=sink, policy=policy, provenance=prov, in_scope_actions=IN_SCOPE_ACTIONS)
    http = client(server)
    budget = Budget()
    outcome = TinyFishAdapter(gateway, http, budget, opt_in=True, clock_ms=lambda: 1).run_agent(
        "get the title", START
    )
    assert outcome.status == "SUCCEEDED"
    assert budget.spent_cents == 5
    metered = [e for e in sink.events if e["event_type"] == "API_CALL_OBSERVED"]
    assert metered and metered[0]["payload"]["usage"]["steps_billed"] == 3
    assert metered[0]["payload"]["provider_execution_id"] == "run-1"

    blocked = TinyFishAdapter(gateway, http, budget, opt_in=True, clock_ms=lambda: 1).run_agent(
        "x", "https://evil.example/"
    )
    assert blocked.status == "BLOCKED"


def test_without_the_step_cap_only_the_duration_is_sent(server: Fake) -> None:
    client(server, send_step_cap=False, max_duration_seconds=60).run("agent", "g", START)
    start = next(r for r in server.requests if r[1] == "/v1/automation/run-async")
    assert start[2] is not None
    assert start[2]["agent_config"] == {"max_duration_seconds": 60}


def test_a_403_names_the_provider_code_so_the_cause_is_visible(server: Fake) -> None:
    server.fail_http["/v1/automation/run-async"] = (403, {"error": {"code": "FORBIDDEN"}})
    with pytest.raises(AuthFailure) as err:
        client(server).run("agent", "g", START)
    assert "HTTP 403 FORBIDDEN" in str(err.value)
    assert DUMMY_KEY not in str(err.value)


def test_a_failed_progress_check_is_tried_again_and_the_answer_is_not_lost(server: Fake) -> None:
    """A real run lost its answer when one status check failed; the run had in fact finished."""
    server.fail_times["/v1/runs/run-1"] = 2
    answer = client(server).run("agent", "g", START)
    assert answer["result"] == "Example Domain"
    assert answer["usage"]["steps_billed"] == 3


def test_progress_checks_that_keep_failing_end_as_unknown_with_the_cost_so_far(
    server: Fake,
) -> None:
    server.fail_times["/v1/runs/run-1"] = 99
    with pytest.raises(ProviderTimeout) as err:
        client(server).run("agent", "g", START)
    assert server.cancelled  # we asked TinyFish to stop; nothing is retried blindly
    assert isinstance(err.value.cents, int)
    polls = [r for r in server.requests if r[1] == "/v1/runs/run-1"]
    assert len(polls) == 5  # exactly the limit, then it stops


# ---- search and research ----------------------------------------------------------------


def test_search_returns_ranked_links_as_a_readable_list_and_costs_nothing(server: Fake) -> None:
    answer = client(server, search_url=server.base).run("search", "poco prices", "")
    assert answer["usage"] == {"cents": 0, "results": 1}
    assert answer["result"].startswith("**Top web results**")
    # Brackets in a title cannot break the link; a result without a web link is dropped.
    assert "[POCO phones India list](https://example.org/poco?x=1&y=2)" in answer["result"]
    assert "javascript" not in answer["result"]
    assert answer["steps"] == [
        {
            "kind": "search_result",
            "url": "https://example.org/poco?x=1&y=2",
            "text": "POCO phones [India] (list) \u2014 Prices from Rs. 9,999.",
        }
    ]
    assert answer["execution_id"].startswith("search-")


def test_a_search_answer_without_a_results_list_is_a_bad_response(server: Fake) -> None:
    server.search_results = None
    with pytest.raises(BadResponse):
        client(server, search_url=server.base).run("search", "q", "")


def test_research_waits_for_the_report_and_returns_it_with_its_sources(server: Fake) -> None:
    server.balance = ["15.000", "15.000"]
    answer = client(server, research_poll_seconds=0).run("research", "what is x", "")
    assert answer["execution_id"] == "rr-1"
    assert answer["result"].startswith("# Report")
    assert answer["steps"] == [
        {"kind": "citation", "url": "https://a.example/x", "text": "cited source"}
    ]
    assert answer["usage"]["cents"] == 0
    sent = next(r for r in server.requests if r[1] == "/v1/automation/run-research-async")
    assert sent[2] == {"query": "what is x", "mode": "deep"}


def test_research_that_ended_badly_is_a_failed_run_with_the_provider_code(server: Fake) -> None:
    server.research_statuses = ["TIMED_OUT"]
    with pytest.raises(RunFailed) as err:
        client(server, research_poll_seconds=0).run("research", "q", "")
    assert err.value.code == "TIMEOUT"


def test_research_not_switched_on_says_so_without_the_key(server: Fake) -> None:
    server.fail_http["/v1/automation/run-research-async"] = (403, {"error": {"code": "FORBIDDEN"}})
    with pytest.raises(AuthFailure) as err:
        client(server).run("research", "q", "")
    assert "Research may not be switched on" in str(err.value)
    assert DUMMY_KEY not in str(err.value)


def test_research_past_our_time_limit_is_cancelled_and_left_unknown(server: Fake) -> None:
    server.research_statuses = ["RUNNING"]
    ticks = iter(range(0, 100000, 400))
    with pytest.raises(ProviderTimeout):
        client(
            server,
            research_deadline_seconds=1000,
            research_poll_seconds=0,
            clock=lambda: float(next(ticks)),
        ).run("research", "q", "")
    assert server.research_cancelled


def test_search_and_research_estimates_come_from_the_rate_card(server: Fake) -> None:
    assert client(server).estimate_cents("search", "q") == 0
    assert client(server).estimate_cents("research", "q") == 0


def test_the_address_policy_is_asked_about_is_the_providers_own_api(server: Fake) -> None:
    c = client(server, search_url=server.base)
    assert c.api_url("search") == server.base
    assert c.api_url("research").endswith("/v1/automation/run-research-async")
