"""A local Playwright adapter with one chokepoint (`R-ADP-01`, `R-COV-03`, `R-COV-07`, `D-14`).

The coverage claim this adapter may make is only as good as its chokepoint, so
the design is the chokepoint:

* **Every request the browser makes goes through one route handler on the
  browser *context*, not a page.** A popup, a new tab, an iframe, a fetch from
  page script, a redirect hop, a beacon, a form with `target=_blank` and a
  WebSocket are all requests of that context, so they all land here. Nothing is
  allowed because it looked harmless.
* **Before anything is sent**, the handler records `ACTION_REQUESTED`, checks
  SSRF rules, asks the gateway, and only on an allow records `ACTION_DISPATCHED`
  and lets the request out. A block aborts the request. The adapter performs the
  fetch itself and hands the answer to the browser, so a redirect is returned as
  a redirect and its next hop is gated again.
* **Service workers are blocked** for the context: a worker's own fetches would
  not pass through the page's routes.

Whether the adapter may *claim* `STEP_GATED` is not assumed. `self_test` runs a
battery of bypass attempts against a local probe site and measures what got
through (`probe_site.py`). Any leak, and the declared coverage is
`STEP_OBSERVED`, with the report's digest recorded as the evidence.

Honest limits, stated rather than hidden:

* only HTTP(S) and WebSocket traffic is gated. Other transports (WebRTC, for
  one) are not covered, and the coverage reason says so;
* DNS rebinding: the SSRF check resolves a name, then the fetch resolves it
  again. A name that answers differently the second time is a time-of-check gap
  this adapter does not close. `UNVERIFIED` against a live rebinding server.
* client-side-only DOM actions that send nothing are out of scope.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

from adapters.base import Coverage, Provenance
from adapters.playwright.probe_site import PROBES, ProbeSite
from policy.engine import Action, Policy

ADAPTER_NAME = "playwright"
ADAPTER_VERSION = "0.1.0"

#: What this adapter gates. Everything it gates is a network effect or a form fill.
IN_SCOPE_ACTIONS = ["navigate", "form_fill", "form_submit", "download", "api_call"]

#: Browser flags. Chromium's own "local network access" check stops a page from
#: reaching loopback addresses, which would make the probe site (on loopback)
#: look gated even with no gateway at all, while telling us nothing about a real
#: internet destination, which that check does not cover. So it is switched off:
#: the self-test must measure *this adapter's* gating, not an accident of where
#: the probe site happens to live.
LAUNCH_ARGS = ["--disable-features=LocalNetworkAccessChecks"]

NON_HTTP_NOTE = (
    "only HTTP(S) and WebSocket traffic passes the gateway; other transports "
    "(for example WebRTC) and client-side-only DOM actions are not covered"
)


def ssrf_reason(url: str, trusted_origins: frozenset[str]) -> str | None:
    """`SSRF_BLOCKED` when the target is a private, loopback or link-local address.

    Checked on IP literals and on what a name resolves to. A trusted origin (the
    probe site, an explicitly allowed local app) is exempt, exactly and only.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return "SSRF_BLOCKED"
    if parsed.scheme not in {"http", "https", "ws", "wss"} or not parsed.hostname:
        return "SSRF_BLOCKED"
    origin = f"{parsed.scheme.replace('ws', 'http')}://{parsed.netloc}"
    if origin in trusted_origins:
        return None
    host = parsed.hostname
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, parsed.port or 80, proto=socket.IPPROTO_TCP)
        except OSError:
            return None  # cannot resolve: the fetch will fail, and nothing is sent
        addresses = [ipaddress.ip_address(info[4][0]) for info in infos]
    for address in addresses:
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_unspecified
            or address.is_multicast
        ):
            return "SSRF_BLOCKED"
    return None


class MemorySink:
    """Collects events in memory: for the self-test, which must not touch the run's ledger."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        n = len(self.events) + 1
        self.events.append(
            {
                "event_id": f"m{n}",
                "sequence": n,
                "event_type": kwargs["event_type"],
                "payload": kwargs["payload"],
                "source": kwargs.get("source"),
            }
        )
        return {"event_id": f"m{n}", "sequence": n, "leaf_hash": "00" * 32}

    def fetch_events(self) -> list[dict[str, Any]]:
        return list(self.events)


def probe_policy() -> Policy:
    """What the self-test enforces: the probe site's own host and nothing else."""
    return Policy(
        {
            "policy_id": "probe",
            "version": 1,
            "allowed_action_types": IN_SCOPE_ACTIONS,
            "action_types_needing_target": ["navigate", "form_submit", "download", "api_call"],
            "allowed_hosts": ["127.0.0.1"],
            "max_actions": 10_000,
        }
    )


@dataclass(frozen=True)
class SelfTestReport:
    results: dict[str, str]  # probe name -> "GATED" | "LEAKED"
    detail: dict[str, str]

    @property
    def all_gated(self) -> bool:
        return all(v == "GATED" for v in self.results.values())

    def digest(self) -> str:
        """A digest of the report, recorded as the coverage evidence."""
        text = json.dumps(self.results, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(text.encode()).hexdigest()


class PlaywrightAdapter:
    """Drives a local Chromium, with every request passing the gateway first."""

    def __init__(
        self,
        gateway: Any,
        *,
        trusted_origins: frozenset[str] = frozenset(),
        gate_websockets: bool = True,
        execution_id: str = "playwright-1",
        browser: Any = None,
        approver: Any = None,
    ) -> None:
        self.gateway = gateway
        self.trusted_origins = trusted_origins
        # Turning this off simulates an adapter with a hole, so a test can show the
        # self-test notices and the coverage claim drops (never for production use).
        self._gate_websockets = gate_websockets
        # Asked when policy says an action needs a person's signed approval. It returns the
        # gateway's decision after the signature is relayed; with none, such an action is
        # blocked, as before.
        self._approver = approver
        self.execution_id = execution_id
        self._browser = browser
        self._owns_browser = browser is None
        self._playwright: Any = None
        self._context: Any = None
        self._counter = 0

    # ------------------------------------------------------------- lifecycle

    def provenance(self, observed_coverage: Coverage) -> Provenance:
        return Provenance(
            adapter_name=ADAPTER_NAME,
            adapter_version=ADAPTER_VERSION,
            execution_id=self.execution_id,
            mode="LIVE_LOCAL",
            observed_coverage=observed_coverage,
        )

    def start(self) -> PlaywrightAdapter:
        from playwright.sync_api import sync_playwright

        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(args=LAUNCH_ARGS)
        # Service workers would make their own requests outside the page's routes.
        self._context = self._browser.new_context(service_workers="block")
        self._context.route("**/*", self._on_request)
        if self._gate_websockets:
            self._context.route_web_socket("**/*", self._on_websocket)
        return self

    def stop(self) -> None:
        if self._context is not None:
            self._context.close()
            self._context = None
        if self._owns_browser and self._browser is not None:
            self._browser.close()
            self._browser = None
        if self._playwright is not None:
            self._playwright.stop()
            self._playwright = None

    def __enter__(self) -> PlaywrightAdapter:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # --------------------------------------------------------- the chokepoint

    def _next_id(self) -> str:
        self._counter += 1
        return f"pw-{self._counter}"

    @staticmethod
    def _kind(request: Any) -> str:
        if request.resource_type == "document" or request.is_navigation_request():
            return "form_submit" if request.method.upper() == "POST" else "navigate"
        return "api_call"

    def _admit(self, kind: str, url: str, params: dict[str, Any]) -> Action | None:
        """The one decision point. Returns the action if it may be dispatched, else `None`."""
        action = Action(action_id=self._next_id(), action_type=kind, target=url, params=params)
        reason = ssrf_reason(url, self.trusted_origins)
        if reason is not None:
            self.gateway.deny(action, reason)
            return None
        decision = self.gateway.request(action)
        if decision.outcome == "REQUIRE_APPROVAL" and self._approver is not None:
            decision = self._approver(self.gateway, action)
        if not decision.allows_dispatch:
            return None  # blocked, or waiting for an approval that is not there
        self.gateway.dispatch(action)
        return action

    #: How many redirect hops one request may follow before it is stopped.
    MAX_REDIRECTS = 10

    def _on_request(self, route: Any, request: Any) -> None:
        """Gate the request, then every redirect hop it leads to.

        Redirects are followed *here*, not by the browser. The browser does not
        send a redirect hop back through the route handler, so letting it follow
        one would be an unguarded request. A bypass probe found exactly that hole
        in an earlier version of this handler. The page therefore receives the
        final answer for the URL it asked for, and its own `location` keeps the
        original URL: a known difference from a normal browser.
        """
        kind = self._kind(request)
        url = request.url
        method = request.method
        params = {"method": method, "resource_type": request.resource_type}
        action = self._admit(kind, url, params)
        if action is None:
            route.abort("blockedbyclient")
            return

        hops = 0
        fetch_args: dict[str, Any] = {"max_redirects": 0}
        while True:
            try:
                response = route.fetch(**fetch_args)
                body = response.body()
            except Exception:
                self.gateway.failed(action, error_code="FETCH_FAILED", retryable=False)
                route.abort("failed")
                return
            location = response.headers.get("location")
            if response.status not in (301, 302, 303, 307, 308) or not location:
                break
            hops += 1
            if hops > self.MAX_REDIRECTS:
                self.gateway.failed(action, error_code="TOO_MANY_REDIRECTS", retryable=False)
                route.abort("failed")
                return
            # This hop is finished; the next one is a new action of its own.
            self.gateway.succeeded(action, evidence=[])
            url = urljoin(url, location)
            if response.status == 303 or (response.status in (301, 302) and method != "GET"):
                method = "GET"
                fetch_args = {"url": url, "method": "GET", "max_redirects": 0}
            else:
                fetch_args = {"url": url, "max_redirects": 0}
            action = self._admit(kind, url, {**params, "redirected": True})
            if action is None:
                route.abort("blockedbyclient")
                return

        content_type = response.headers.get("content-type", "")
        if content_type.startswith(("text/", "application/json")):
            text = body.decode("utf-8", "replace")
        else:
            text = f"<{content_type or 'unknown type'}, {len(body)} bytes>"
        seen = self.gateway.observe(
            action, observation_kind=f"http_{response.status}", url=url, text=text
        )
        self.gateway.succeeded(action, evidence=[seen.event_id])
        route.fulfill(response=response)

    async def _on_websocket(self, ws: Any) -> None:
        """Gate a WebSocket. This one handler is `async` on purpose.

        Playwright awaits WebSocket handlers on its own event loop, so a blocking
        call into the sync API from here (such as `ws.close()`) deadlocks. The
        gateway call below is a short blocking HTTP request, which is acceptable
        on that loop; the close goes through the implementation object, which is
        a private Playwright API. That is why the version is pinned (see
        `requirements-dev.txt`) and why a Playwright upgrade must rerun the bypass
        tests before anything is called `STEP_GATED`.
        """
        # Policy judges hosts of web addresses, so a ws:// target is judged as its http:// twin.
        target = ws.url.replace("ws", "http", 1)
        action = self._admit(
            "api_call", target, {"method": "WEBSOCKET", "resource_type": "websocket"}
        )
        if action is None:
            await ws._impl_obj.close(code=1008, reason="blocked by the gateway")
            return
        ws.connect_to_server()

    # -------------------------------------------------------- what an agent does

    def new_page(self) -> Any:
        return self._context.new_page()

    def goto(self, page: Any, url: str) -> str:
        """Navigate. Returns `OK`, `BLOCKED`, `FAILED`, `TIMEOUT` or `INTERRUPTED`.

        None of them is an exception for the agent: the ledger records what happened.
        """
        try:
            page.goto(url, wait_until="load", timeout=15_000)
        except Exception as exc:
            text = str(exc)
            if "ERR_BLOCKED_BY_CLIENT" in text or "blockedbyclient" in text.lower():
                return "BLOCKED"
            if "net::ERR_" in text:
                return "FAILED"
            if "Timeout" in text:
                return "TIMEOUT"
            if "interrupted by another navigation" in text:
                return "INTERRUPTED"
            raise
        return "OK"

    def fill(self, page: Any, selector: str, value: str) -> bool:
        """A form fill is a state change in the page, so it passes the gateway too."""
        action = self._admit("form_fill", page.url, {"selector": selector})
        if action is None:
            return False
        page.fill(selector, value)
        self.gateway.succeeded(action, evidence=[])
        return True

    # ------------------------------------------------------------ the self-test

    def self_test(self) -> SelfTestReport:
        """Run every bypass probe and measure what got through.

        Uses its own throwaway gateway and ledger so the run's record is not
        cluttered, and the same configuration as this adapter, so a hole here is
        a hole in the real one.
        """
        from services.worker.gateway import Gateway

        results: dict[str, str] = {}
        detail: dict[str, str] = {}
        with ProbeSite() as site:
            for name in PROBES:
                sink = MemorySink()
                gateway = Gateway(
                    sink=sink,
                    policy=probe_policy(),
                    provenance=self.provenance("STEP_GATED"),
                    in_scope_actions=IN_SCOPE_ACTIONS,
                )
                # Test the same class, so a subclass with a hole is measured, not assumed.
                trial = type(self)(
                    gateway,
                    trusted_origins=frozenset({site.origin}),
                    gate_websockets=self._gate_websockets,
                    browser=self._browser,
                )
                with trial:
                    mark = site.mark()
                    page = trial.new_page()
                    trial.goto(page, f"{site.origin}/probe/{name}")
                    # A probe that never finishes is judged on what leaked, not on timing.
                    with contextlib.suppress(Exception):
                        page.wait_for_function("window.__done === true", timeout=4_000)
                    page.wait_for_timeout(400)  # let a late popup or worker request land
                leaked = site.leaked_since(mark)
                off_host = [
                    e["payload"]["action_id"]
                    for e in sink.events
                    if e["event_type"] == "ACTION_DISPATCHED"
                    and not _dispatched_to(sink, e, "127.0.0.1")
                ]
                if leaked or off_host:
                    results[name] = "LEAKED"
                    detail[name] = (
                        f"{len(leaked)} request(s) reached the forbidden name; "
                        f"{len(off_host)} off-host dispatch(es)"
                    )
                else:
                    results[name] = "GATED"
                    detail[name] = "no request reached the forbidden name"
        return SelfTestReport(results=results, detail=detail)

    def coverage_after(self, report: SelfTestReport) -> tuple[Coverage, str]:
        """The coverage this adapter may declare, and the plain-words reason."""
        if report.all_gated:
            return (
                "STEP_GATED",
                f"{len(report.results)} bypass probes were all stopped at the gateway; "
                f"{NON_HTTP_NOTE}",
            )
        leaked = ", ".join(sorted(k for k, v in report.results.items() if v != "GATED"))
        return (
            "STEP_OBSERVED",
            f"these bypass probes got through, so actions are observed, not gated: {leaked}",
        )


def _dispatched_to(sink: MemorySink, dispatch: dict[str, Any], host: str) -> bool:
    action_id = dispatch["payload"]["action_id"]
    for event in sink.events:
        if event["event_type"] == "ACTION_REQUESTED" and event["payload"]["action_id"] == action_id:
            return (urlparse(str(event["payload"]["target"])).hostname or "") == host
    return False
