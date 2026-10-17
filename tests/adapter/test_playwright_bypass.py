"""Bypass tests for the Playwright adapter (`R-TST-04`; the release gate "Playwright bypass tests").

Each probe is a page that tries to reach a forbidden place by a different route.
The probe site records, on its own side, every request that arrives under the
forbidden name. A single such request is a bypass.

Three configurations, so each protection is shown to work *alone*:

* both layers on (SSRF rules and policy), the real configuration;
* policy alone (the SSRF layer told to trust the forbidden name);
* SSRF alone (policy told that the forbidden host is allowed).

And a negative control: an adapter with a deliberate hole, which the battery must
catch, otherwise "everything was blocked" would prove nothing about the battery.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from adapters.playwright.adapter import (  # noqa: E402
    IN_SCOPE_ACTIONS,
    NON_HTTP_NOTE,
    PlaywrightAdapter,
)
from adapters.playwright.probe_site import PROBES, ProbeSite  # noqa: E402
from policy.engine import Policy  # noqa: E402
from tests.adapter.test_playwright_gating import (  # noqa: E402
    browser,  # noqa: F401  (a pytest fixture, imported so this module can use it)
    make,
    reasons,
)


def run_probe(browser: Any, site: ProbeSite, name: str, **kwargs: Any) -> tuple[Any, Any]:
    adapter, sink, _ = make(browser, site, **kwargs)
    with adapter:
        mark = site.mark()
        page = adapter.new_page()
        adapter.goto(page, f"{site.origin}/probe/{name}")
        # A probe that never finishes is judged on what leaked, not on timing.
        with contextlib.suppress(Exception):
            page.wait_for_function("window.__done === true", timeout=4_000)
        page.wait_for_timeout(400)
        leaked = site.leaked_since(mark)
    return leaked, sink


def policy_allowing(*hosts: str) -> Policy:
    return Policy(
        {
            "policy_id": "wide",
            "version": 1,
            "allowed_action_types": IN_SCOPE_ACTIONS,
            "action_types_needing_target": ["navigate", "form_submit", "download", "api_call"],
            "allowed_hosts": list(hosts),
            "max_actions": 100_000,
        }
    )


@pytest.fixture(scope="module")
def probe_site() -> Any:
    with ProbeSite() as running:
        yield running


def test_there_is_a_probe_for_each_route_we_know_of() -> None:
    expected = {
        "fetch", "xhr", "beacon", "img", "script", "iframe", "websocket", "popup", "tab",
        "formblank", "serviceworker", "redirect", "redirect_private", "download",
    }  # fmt: skip
    assert set(PROBES) == expected


@pytest.mark.parametrize("name", PROBES)
def test_both_layers_on_nothing_reaches_the_forbidden_name(
    browser: Any,
    probe_site: ProbeSite,
    name: str,
) -> None:
    leaked, _ = run_probe(browser, probe_site, name)
    assert leaked == [], [(h.host, h.path) for h in leaked]


@pytest.mark.parametrize("name", [p for p in PROBES if p not in {"serviceworker"}])
def test_policy_alone_stops_each_probe(browser: Any, probe_site: ProbeSite, name: str) -> None:
    """SSRF rules told to trust the forbidden name: only the host policy stands in the way."""
    trusted = {probe_site.origin, probe_site.forbidden_origin}
    leaked, sink = run_probe(browser, probe_site, name, trusted=trusted)
    assert leaked == [], [(h.host, h.path) for h in leaked]
    if name != "redirect_private":  # 127.0.0.2 is not a trusted origin: SSRF still applies
        assert "DOMAIN_NOT_ALLOWED" in reasons(sink)


@pytest.mark.parametrize("name", [p for p in PROBES if p not in {"serviceworker"}])
def test_ssrf_rules_alone_stop_each_probe(browser: Any, probe_site: ProbeSite, name: str) -> None:
    """Policy told the forbidden host is fine: only the SSRF rules stand in the way."""
    leaked, sink = run_probe(
        browser, probe_site, name, policy=policy_allowing("127.0.0.1", "localhost", "127.0.0.2")
    )
    assert leaked == [], [(h.host, h.path) for h in leaked]
    assert "SSRF_BLOCKED" in reasons(sink)


def test_a_service_worker_cannot_be_installed(browser: Any, probe_site: ProbeSite) -> None:
    """With workers blocked, registration does nothing: no registration, no worker.

    A control with workers allowed shows the page really would get one otherwise,
    so the assertion above is about the adapter and not about the page.
    """
    probe = """async () => {
        await navigator.serviceWorker.register('/sw.js');
        await new Promise(r => setTimeout(r, 800));
        const regs = await navigator.serviceWorker.getRegistrations();
        return {registrations: regs.length, controlled: !!navigator.serviceWorker.controller};
    }"""
    adapter, _, _ = make(browser, probe_site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, probe_site.origin + "/")
        outcome = page.evaluate(probe)
        assert outcome == {"registrations": 0, "controlled": False}
        assert adapter._context.service_workers == []

    control = browser.new_context(service_workers="allow")
    try:
        page = control.new_page()
        page.goto(probe_site.origin + "/")
        assert page.evaluate(probe)["registrations"] == 1
    finally:
        control.close()


def test_a_popup_opens_but_its_requests_are_gated_like_any_other(
    browser: Any,
    probe_site: ProbeSite,
) -> None:
    adapter, sink, _ = make(browser, probe_site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, probe_site.origin + "/")
        with page.context.expect_page() as popup_info:
            page.evaluate("window.open('/api/data')")
        popup = popup_info.value
        popup.wait_for_load_state()
    paths = [
        r["target"].rsplit("/", 1)[-1]
        for r in sink.events
        and [e["payload"] for e in sink.events if e["event_type"] == "ACTION_REQUESTED"]
    ]
    assert "data" in paths  # the popup's own request went through the gateway


# ----------------------------------------------------------- the self-test


def test_the_self_test_finds_every_probe_gated_and_allows_step_gated(browser: Any) -> None:
    adapter, _, _ = make(browser, ProbeSite().start(), spy=False)
    with adapter:
        report = adapter.self_test()
        coverage, reason = adapter.coverage_after(report)
    assert report.all_gated, report.detail
    assert set(report.results) == set(PROBES)
    assert coverage == "STEP_GATED"
    assert NON_HTTP_NOTE in reason  # the claim carries its limits
    assert len(report.digest()) == 64


class _UngatedAdapter(PlaywrightAdapter):
    """A deliberately broken adapter: lets every request through unchecked."""

    def _on_request(self, route: Any, request: Any) -> None:
        route.continue_()


def test_an_adapter_with_a_hole_is_caught_and_cannot_claim_step_gated(browser: Any) -> None:
    site = ProbeSite().start()
    try:
        adapter, _, _ = make(browser, site, spy=False)
        broken = _UngatedAdapter(
            adapter.gateway,
            trusted_origins=adapter.trusted_origins,
            browser=browser,
        )
        with broken:
            report = broken.self_test()
            coverage, reason = broken.coverage_after(report)
    finally:
        site.stop()
    leaked = {k for k, v in report.results.items() if v == "LEAKED"}
    assert {"fetch", "xhr", "img", "script", "iframe", "redirect"} <= leaked, report.results
    assert coverage == "STEP_OBSERVED"
    assert "got through" in reason


def test_an_adapter_that_does_not_gate_websockets_is_caught(browser: Any) -> None:
    site = ProbeSite().start()
    try:
        adapter, _, _ = make(browser, site, spy=False, gate_websockets=False)
        with adapter:
            report = adapter.self_test()
            coverage, _ = adapter.coverage_after(report)
    finally:
        site.stop()
    assert report.results["websocket"] == "LEAKED"
    assert coverage == "STEP_OBSERVED"
    # The other routes are still stopped: the report says exactly what is open.
    assert report.results["fetch"] == "GATED"


def test_the_digest_changes_when_what_got_through_changes(browser: Any) -> None:
    site = ProbeSite().start()
    try:
        good, _, _ = make(browser, site, spy=False)
        leaky, _, _ = make(browser, site, spy=False, gate_websockets=False)
        with good:
            digest_good = good.self_test().digest()
        with leaky:
            digest_leaky = leaky.self_test().digest()
    finally:
        site.stop()
    assert digest_good != digest_leaky
