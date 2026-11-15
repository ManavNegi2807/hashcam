"""The HashCam Console has the same motion layer as the public site.

* The server hands out the two motion files, and `site/` carries byte-identical copies.
* The console loads clean (no console error, no failed request), shifts nothing, and animates only
  compositor properties, with the telemetry core where the old REC circle was.
* "The path of every action" is five cards joined by rails with a travelling pulse; a refused request
  stops at the gateway. "Events per session" is a flat stacked bar chart whose numbers add up.
* With prefers-reduced-motion everything is shown at once and nothing runs.

The browser tests need the same stack as `test_console.py` (the recorder, `abb`, PostgreSQL).
"""

# ruff: noqa: E501, F811  (E501: page-side JavaScript in strings; F811: the imported fixture is used by name)

from __future__ import annotations

import re
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from services.dashboard.server import Config, serve
from tests.ui.test_console import NEEDS_STACK, stack  # noqa: F401 - the fixture
from tests.ui.test_motion import COMPOSITOR, WATCH, Watch

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

REPO = Path(__file__).resolve().parents[2]
NO_ONBOARDING = "localStorage.setItem('hc-onboarded', '1')"


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture(scope="module")
def bare() -> Iterator[str]:
    """The console's static files with no recorder and no verifier behind them."""
    work = Path(tempfile.mkdtemp(prefix="console-static-"))
    server = serve(Config(receipts=work, keys=None, abb="abb"), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def fetch(url: str) -> tuple[int, str, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=20) as response:  # noqa: S310 - loopback
            return response.status, response.headers.get("Content-Type", ""), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers.get("Content-Type", ""), exc.read()


# ---------------------------------------------------------------- the files


def test_the_server_hands_out_the_motion_files_and_the_site_has_the_same_copies(bare: str) -> None:
    for name, kind in (("motion.css", "text/css"), ("motion.js", "text/javascript")):
        status, content_type, body = fetch(f"{bare}/{name}")
        assert status == 200 and content_type.startswith(kind), (name, status, content_type)
        assert body == (REPO / "ui" / name).read_bytes()
        assert (REPO / "site" / name).read_bytes() == body, f"site/{name} is not the ui/ copy"
    status, _, _ = fetch(f"{bare}/vendor/not-a-file.js")
    assert status == 404
    page = fetch(f"{bare}/console")[2].decode("utf-8")
    assert 'href="/motion.css"' in page and 'src="/motion.js"' in page
    # The font is fetched early (so swapping it in shifts nothing).
    with urllib.request.urlopen(f"{bare}/console", timeout=20) as response:  # noqa: S310
        assert "rel=preload" in response.headers.get("Link", "")


# ---------------------------------------------------------------- the page, in a real browser


def open_console(browser: Any, stack: dict[str, Any], **kw: Any) -> tuple[Any, Watch]:
    page = browser.new_page(**{"viewport": {"width": 1280, "height": 800}, **kw})
    page.set_default_timeout(20_000)
    watch = Watch(page, stack["base"])
    page.add_init_script(WATCH)
    page.add_init_script(NO_ONBOARDING)
    page.goto(stack["base"] + "/console")
    return page, watch


def scroll_through(page: Any) -> None:
    height = page.evaluate("document.documentElement.scrollHeight")
    for _ in range(int(height / 380) + 1):
        page.mouse.wheel(0, 380)
        page.wait_for_timeout(120)
    page.wait_for_timeout(900)


@NEEDS_STACK
def test_the_console_loads_clean_shifts_nothing_and_animates_only_the_compositor(
    browser: Any, stack: dict[str, Any]
) -> None:
    page, watch = open_console(browser, stack)
    page.wait_for_timeout(1500)
    assert page.locator(".synth-sun").count() == 0, "the retro REC circle is gone"
    expect(page.locator("#core.hero-core")).to_be_visible()
    scroll_through(page)
    page.evaluate("window.scrollTo(0, 0)")
    for selector in (".panel", ".card", ".btn"):
        target = page.locator(selector).first
        target.scroll_into_view_if_needed()
        target.hover()
        page.wait_for_timeout(350)
    seen = page.evaluate("window.__m")
    watch.assert_clean()
    assert seen["errs"] == [], seen["errs"]
    assert seen["shifts"] == 0, f"layout shifted by {seen['shifts']}: {seen['shiftList']}"
    offenders = {where: prop for where, prop in seen["props"].items() if prop not in COMPOSITOR}
    assert offenders == {}, offenders
    assert seen["props"], "the audit saw no motion"
    page.close()


@NEEDS_STACK
def test_the_path_of_every_action_is_five_cards_and_a_pulse_and_a_refusal_stops(
    browser: Any, stack: dict[str, Any]
) -> None:
    page, watch = open_console(browser, stack)
    page.locator("#iso").scroll_into_view_if_needed()
    assert page.locator("#iso .pipe-node").count() == 5
    assert page.locator("#iso .pipe-rail").count() == 4
    titles = page.locator("#iso .pn-title").all_inner_texts()
    assert titles == ["AI agent", "Policy gateway", "Ledger", "Separate signer", "Receipt"]
    assert "SHA-256" in page.locator("#iso .pipe-node").nth(2).inner_text()
    # A pulse travels a rail (transform only) ...
    page.wait_for_timeout(1200)
    moved = page.evaluate(
        "[...new Set([...document.querySelectorAll('#iso .pipe-pk')].flatMap(n => n.getAnimations()"
        ".flatMap(a => a.effect.getKeyframes().flatMap(k => Object.keys(k)))))]"
    )
    assert set(moved) - {"offset", "computedOffset", "easing", "composite"} == {"transform"}, moved
    # ... and every third request is refused at the gateway: DENY lights, the node turns to a stop.
    gateway = page.locator("#iso .pipe-node").nth(1)
    expect(gateway).to_have_class(re.compile(r"\bstop\b"), timeout=14_000)
    expect(gateway.locator(".pn-chip.bad")).to_have_class(re.compile(r"\bhit\b"))
    watch.assert_clean()
    page.close()


@NEEDS_STACK
def test_events_per_session_are_flat_stacked_bars_whose_numbers_add_up(
    browser: Any, stack: dict[str, Any]
) -> None:
    page, watch = open_console(browser, stack)
    page.locator("#bars").scroll_into_view_if_needed()
    expect(page.locator("#bars .eb-row").first).to_be_visible(timeout=20_000)
    rows = page.locator("#bars .eb-row")
    assert rows.count() >= 1
    assert (
        page.evaluate("getComputedStyle(document.querySelector('#bars .eb')).transform") == "none"
    )
    assert page.locator("#bars .cube").count() == 0, "no 3D blocks"
    row_totals = [int(n) for n in page.locator("#bars .eb-n").all_inner_texts()]
    legend = [int(n) for n in page.locator("#bars .eb-legend b").all_inner_texts()]
    assert len(legend) == 4 and sum(legend) == sum(row_totals), (legend, row_totals)
    for i in range(rows.count()):
        parts = [
            int(re.search(r": (\d+)$", t).group(1))  # type: ignore[union-attr]
            for t in rows.nth(i).locator(".eb-seg").evaluate_all("els => els.map(e => e.title)")
        ]
        assert sum(parts) == row_totals[i], (i, parts, row_totals)
    watch.assert_clean()
    page.close()


@NEEDS_STACK
def test_reduced_motion_shows_the_console_still(browser: Any, stack: dict[str, Any]) -> None:
    page, watch = open_console(browser, stack, reduced_motion="reduce")
    scroll_through(page)
    assert page.evaluate("document.getAnimations().length") == 0
    assert page.evaluate(
        "[...document.querySelectorAll('[data-reveal]')].every(n => getComputedStyle(n).opacity === '1')"
    )
    assert page.locator("#iso .pipe-node.on").count() == 5, (
        "every card shown, none waiting for a pulse"
    )
    expect(page.locator("#cartoon .flow-state")).to_have_text("AUTHORIZED")
    watch.assert_clean()
    page.close()
