"""The Playwright adapter's gateway: every in-scope action is requested, decided and
only then dispatched (`R-ADP-01`, `R-COV-03`, `R-COV-07`, `R-TST-04`).

No database is needed: the adapter writes to an in-memory ledger. What is
measured on the *server side* (the probe site's own request log) is what proves a
request really was held back, not the adapter's account of itself.

Needs Playwright and its Chromium; without them the tests skip with a reason.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

os.environ.setdefault(
    "PLAYWRIGHT_BROWSERS_PATH",
    os.environ.get("ABB_PLAYWRIGHT_BROWSERS", str(Path.home() / "AppData/Local/ms-playwright")),
)

from adapters.base import Provenance  # noqa: E402
from adapters.playwright.adapter import (  # noqa: E402
    IN_SCOPE_ACTIONS,
    LAUNCH_ARGS,
    MemorySink,
    PlaywrightAdapter,
    probe_policy,
    ssrf_reason,
)
from adapters.playwright.probe_site import ProbeSite  # noqa: E402
from policy.engine import Policy  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402

PROVENANCE = Provenance("playwright", "0.1.0", "t", "LIVE_LOCAL", "STEP_GATED")


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            instance = p.chromium.launch(args=LAUNCH_ARGS)
        except Exception as exc:
            pytest.skip(f"Chromium is not available: {str(exc).splitlines()[0]}")
        yield instance
        instance.close()


@pytest.fixture
def site() -> Iterator[ProbeSite]:
    with ProbeSite() as running:
        yield running


def make(
    browser: Any,
    site: ProbeSite,
    *,
    policy: Policy | None = None,
    trusted: set[str] | None = None,
    spy: bool = True,
    **options: Any,
) -> tuple[PlaywrightAdapter, MemorySink, list[tuple[str, str, int]]]:
    """An adapter over an in-memory ledger. `timeline` records, for each event, how many
    requests the server had seen when it happened."""
    sink = MemorySink()
    timeline: list[tuple[str, str, int]] = []
    if spy:
        original = sink.emit

        def spying(**kwargs: Any) -> dict[str, Any]:
            payload = kwargs["payload"]
            target = str(payload.get("target", ""))
            timeline.append((kwargs["event_type"], target, len(site.hits)))
            return original(**kwargs)

        sink.emit = spying  # type: ignore[method-assign]
    gateway = Gateway(
        sink=sink,
        policy=policy or probe_policy(),
        provenance=PROVENANCE,
        in_scope_actions=IN_SCOPE_ACTIONS,
    )
    adapter = PlaywrightAdapter(
        gateway,
        trusted_origins=frozenset(trusted if trusted is not None else {site.origin}),
        browser=browser,
        **options,
    )
    return adapter, sink, timeline


def types(sink: MemorySink) -> list[str]:
    return [e["event_type"] for e in sink.events]


def reasons(sink: MemorySink) -> list[str]:
    return [
        code
        for e in sink.events
        if e["event_type"] == "ACTION_BLOCKED"
        for code in e["payload"]["reason_codes"]
    ]


def requested(sink: MemorySink) -> list[dict[str, Any]]:
    return [e["payload"] for e in sink.events if e["event_type"] == "ACTION_REQUESTED"]


# ------------------------------------------------------------------ the rule


def test_a_navigation_is_requested_and_authorized_before_the_server_sees_anything(
    browser: Any, site: ProbeSite
) -> None:
    adapter, sink, timeline = make(browser, site)
    with adapter:
        page = adapter.new_page()
        assert adapter.goto(page, site.origin + "/") == "OK"
    order = types(sink)
    assert order[:3] == ["ACTION_REQUESTED", "ACTION_AUTHORIZED", "ACTION_DISPATCHED"]
    # The server had seen no request at all when the request and the decision were
    # recorded; it saw the page only after the dispatch.
    seen_at = {kind: count for kind, _, count in timeline}
    assert seen_at["ACTION_REQUESTED"] == 0
    assert seen_at["ACTION_AUTHORIZED"] == 0
    assert seen_at["ACTION_DISPATCHED"] == 0
    assert len(site.hits) == 1


def test_every_dispatch_has_an_earlier_authorization(browser: Any, site: ProbeSite) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/form")
        adapter.fill(page, "#email", "a@portal.example")
        page.click("#go")
        page.wait_for_load_state()
    authorized: set[str] = set()
    for event in sink.events:
        if event["event_type"] == "ACTION_AUTHORIZED":
            authorized.add(event["payload"]["action_id"])
        if event["event_type"] == "ACTION_DISPATCHED":
            assert event["payload"]["action_id"] in authorized, event


def test_a_form_submit_is_its_own_gated_action(browser: Any, site: ProbeSite) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/form")
        page.click("#go")
        page.wait_for_load_state()
    kinds = [r["action_type"] for r in requested(sink)]
    assert "form_submit" in kinds
    assert any(h.method == "POST" and h.path == "/submit" for h in site.hits)


def test_a_fetch_from_page_script_is_an_api_call_through_the_gateway(
    browser: Any, site: ProbeSite
) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/")
        answer = page.evaluate("fetch('/api/data').then(r => r.json())")
    assert answer == {"ok": True}
    assert "api_call" in [r["action_type"] for r in requested(sink)]


def test_a_form_fill_passes_the_gateway_and_a_denied_one_changes_nothing(
    browser: Any, site: ProbeSite
) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/form")
        assert adapter.fill(page, "#email", "x@portal.example") is True
        assert page.input_value("#email") == "x@portal.example"
    assert "form_fill" in [r["action_type"] for r in requested(sink)]

    # Same page, but a policy that does not allow form_fill at all.
    strict = Policy(
        {
            "policy_id": "nofill",
            "version": 1,
            "allowed_action_types": ["navigate", "api_call", "form_submit"],
            "action_types_needing_target": ["navigate", "api_call", "form_submit"],
            "allowed_hosts": ["127.0.0.1"],
            "max_actions": 1000,
        }
    )
    adapter2, sink2, _ = make(browser, site, policy=strict)
    with adapter2:
        page = adapter2.new_page()
        adapter2.goto(page, site.origin + "/form")
        assert adapter2.fill(page, "#email", "x@portal.example") is False
        assert page.input_value("#email") == ""
    assert "ACTION_TYPE_NOT_ALLOWED" in reasons(sink2)


def test_an_action_that_needs_approval_is_not_sent_without_one(
    browser: Any, site: ProbeSite
) -> None:
    gated = Policy(
        {
            "policy_id": "needs-approval",
            "version": 1,
            "allowed_action_types": IN_SCOPE_ACTIONS,
            "action_types_needing_target": ["navigate", "form_submit", "download", "api_call"],
            "allowed_hosts": ["127.0.0.1"],
            "max_actions": 1000,
            "approval_required": {"target_contains": ["/form"]},
        }
    )
    adapter, sink, _ = make(browser, site, policy=gated)
    with adapter:
        page = adapter.new_page()
        assert adapter.goto(page, site.origin + "/form") == "BLOCKED"
    assert "HUMAN_APPROVAL_REQUESTED" in types(sink)
    assert not any(h.path == "/form" for h in site.hits)


def test_the_policy_alone_keeps_the_agent_off_a_host_that_is_not_allowed(
    browser: Any, site: ProbeSite
) -> None:
    """With the SSRF layer told to trust the name, policy is still a wall of its own."""
    adapter, sink, _ = make(browser, site, trusted={site.origin, site.forbidden_origin})
    with adapter:
        page = adapter.new_page()
        assert adapter.goto(page, site.forbidden_origin + "/secret/x") == "BLOCKED"
    assert "DOMAIN_NOT_ALLOWED" in reasons(sink)
    assert [h for h in site.hits if h.host != "127.0.0.1"] == []


# ---------------------------------------------------------------- redirects


def test_a_redirect_to_an_allowed_page_works_and_each_hop_is_a_gated_action(
    browser: Any, site: ProbeSite
) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/redirect?to=/api/data")
        body = page.inner_text("body")
    assert '"ok": true' in body
    targets = [urlparse(r["target"]).path for r in requested(sink)]
    assert targets == ["/redirect", "/api/data"]
    dispatched = [e for e in sink.events if e["event_type"] == "ACTION_DISPATCHED"]
    assert len(dispatched) == 2


def test_a_redirect_hop_to_a_forbidden_name_is_stopped_at_that_hop(
    browser: Any, site: ProbeSite
) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        target = site.forbidden_origin + "/secret/chain"
        adapter.goto(page, f"{site.origin}/redirect?to={target}")
    assert [h for h in site.hits if h.host != "127.0.0.1"] == []
    assert "SSRF_BLOCKED" in reasons(sink)


def test_a_redirect_loop_stops_and_is_recorded_as_failed(browser: Any, site: ProbeSite) -> None:
    adapter, sink, _ = make(browser, site)
    with adapter:
        page = adapter.new_page()
        adapter.goto(page, site.origin + "/loop")
    failed = [e["payload"]["error_code"] for e in sink.events if e["event_type"] == "ACTION_FAILED"]
    assert "TOO_MANY_REDIRECTS" in failed
    assert len(site.hits) <= adapter.MAX_REDIRECTS + 2


# --------------------------------------------------------------------- SSRF


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/admin",
        "http://192.168.1.10/",
        "http://172.16.0.1/",
        "http://[::1]:8080/",
        "http://[fd00::1]/",
        "http://0.0.0.0/",
        "http://127.0.0.2:80/",
        "http://localhost:9999/",
        "ftp://example.test/",
        "file:///etc/passwd",
    ],
)
def test_private_loopback_link_local_and_odd_schemes_are_blocked(url: str) -> None:
    assert ssrf_reason(url, frozenset()) == "SSRF_BLOCKED"


def test_a_trusted_origin_is_exempt_exactly_and_only() -> None:
    trusted = frozenset({"http://127.0.0.1:5000"})
    assert ssrf_reason("http://127.0.0.1:5000/x", trusted) is None
    assert ssrf_reason("http://127.0.0.1:5001/x", trusted) == "SSRF_BLOCKED"
    assert ssrf_reason("http://localhost:5000/x", trusted) == "SSRF_BLOCKED"


def test_a_public_literal_address_passes_the_ssrf_check() -> None:
    assert ssrf_reason("http://93.184.216.34/", frozenset()) is None


def test_a_name_that_resolves_to_a_private_address_is_blocked() -> None:
    """The check follows the name, not just the text of the URL (`localhost` is loopback)."""
    assert ssrf_reason("http://localhost/", frozenset()) == "SSRF_BLOCKED"
