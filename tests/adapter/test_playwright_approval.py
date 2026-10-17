"""Submitting a form waits for a person's approval, in a real browser.

The rule: reading is free; a `form_submit` is held until the approver says yes. What proves it
is the *server's own* request log: a POST must not reach the site unless the approval granted it.
(The approver here is a plain function that returns the gateway's decision; the signing itself,
through `abb approve` and the receipt, is covered by `tests/ui/test_guarded_run.py`, and a run on
the real public site `httpbin.org` was done by hand and is described in `docs/DEMO.md`.)

Needs Playwright and its Chromium; without them the tests skip with a reason.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

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
)
from adapters.playwright.probe_site import ProbeSite  # noqa: E402
from policy.engine import Decision, Policy  # noqa: E402
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


def policy_for_submit_approval() -> Policy:
    return Policy(
        {
            "policy_id": "submit-needs-approval",
            "version": 1,
            "allowed_action_types": IN_SCOPE_ACTIONS,
            "action_types_needing_target": ["navigate", "form_submit", "download", "api_call"],
            "allowed_hosts": ["127.0.0.1"],
            "max_actions": 100,
            "approval_required": {"action_types": ["form_submit"]},
        }
    )


class Relay:
    """Stands in for the control plane that checks and records a signed approval."""

    def __init__(self, decision: str) -> None:
        self.decision = decision

    def submit(self, **_: Any) -> dict[str, str]:
        return {"decision": self.decision}


def decision(outcome: str, policy: Policy) -> Decision:
    return Decision(
        outcome=outcome,  # type: ignore[arg-type]
        reason_codes=("APPROVAL_GRANTED",) if outcome == "ALLOW" else ("APPROVAL_DENIED",),
        policy_id=policy.policy_id,
        policy_version=policy.version,
        input_digest="",
    )


def run_submit(
    browser: Any, site: ProbeSite, answer: str | None
) -> tuple[list[str], list[str], list[str]]:
    """Open the form, fill it, press Save. `answer` is what the approver says (None: no approver).

    Returns the methods and paths the SERVER saw, the questions the approver was asked, and the
    event types the ledger recorded."""
    policy = policy_for_submit_approval()
    sink = MemorySink()
    gateway = Gateway(
        sink=sink,
        policy=policy,
        provenance=PROVENANCE,
        in_scope_actions=IN_SCOPE_ACTIONS,
        approvals=Relay("GRANTED" if answer == "ALLOW" else "DENIED"),
    )
    asked: list[str] = []

    def approver(gw: Gateway, action: Any) -> Decision:
        asked.append(f"{action.action_type} {action.target}")
        assert answer is not None
        # The gateway authorizes only through its own approval path, never on an approver's say-so.
        return gw.submit_approval(action, statement_b64="stmt", key_id="key", signature="sig")

    adapter = PlaywrightAdapter(
        gateway,
        trusted_origins=frozenset({site.origin}),
        browser=browser,
        approver=approver if answer is not None else None,
    )
    with adapter:
        page = adapter.new_page()
        assert adapter.goto(page, site.origin + "/form") == "OK"
        assert adapter.fill(page, "#email", "a@portal.example")
        page.click("#go", no_wait_after=True)
        page.wait_for_timeout(1500)
    seen = [f"{h.method} {h.path}" for h in site.hits]
    return seen, asked, [e["event_type"] for e in sink.events]


def test_reading_is_free_and_nobody_is_asked_to_open_a_page(browser: Any, site: ProbeSite) -> None:
    seen, asked, _ = run_submit(browser, site, "ALLOW")
    assert "GET /form" in seen  # the page was opened
    # Only the submit was held for a decision; opening the page needed none.
    assert all("/form" not in question for question in asked)


def test_a_granted_approval_lets_the_form_reach_the_site(browser: Any, site: ProbeSite) -> None:
    seen, asked, types = run_submit(browser, site, "ALLOW")
    assert asked == [f"form_submit {site.origin}/submit"]
    assert "POST /submit" in seen
    assert "ACTION_DISPATCHED" in types


def test_a_denial_means_the_form_never_reaches_the_site(browser: Any, site: ProbeSite) -> None:
    seen, asked, _ = run_submit(browser, site, "DENY")
    assert asked == [f"form_submit {site.origin}/submit"]
    assert "POST /submit" not in seen  # the server's own log: nothing was sent


def test_with_no_approver_at_all_the_form_is_blocked_as_before(
    browser: Any, site: ProbeSite
) -> None:
    seen, asked, _ = run_submit(browser, site, None)
    assert asked == []
    assert "POST /submit" not in seen


def test_no_answer_leaves_the_form_unsent(browser: Any, site: ProbeSite) -> None:
    """The approver gives up (no signature arrives): the request is still waiting for approval,
    which is not a yes, so the site never sees it."""
    policy = policy_for_submit_approval()
    sink = MemorySink()
    gateway = Gateway(
        sink=sink, policy=policy, provenance=PROVENANCE, in_scope_actions=IN_SCOPE_ACTIONS
    )

    def silent(gw: Gateway, action: Any) -> Decision:
        return Decision(
            outcome="REQUIRE_APPROVAL",
            reason_codes=("APPROVAL_NOT_RECEIVED",),
            policy_id=policy.policy_id,
            policy_version=policy.version,
            input_digest="",
        )

    adapter = PlaywrightAdapter(
        gateway, trusted_origins=frozenset({site.origin}), browser=browser, approver=silent
    )
    with adapter:
        page = adapter.new_page()
        assert adapter.goto(page, site.origin + "/form") == "OK"
        adapter.fill(page, "#email", "a@portal.example")
        page.click("#go", no_wait_after=True)
        page.wait_for_timeout(1500)
    assert "POST /submit" not in [f"{h.method} {h.path}" for h in site.hits]
