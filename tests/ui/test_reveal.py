# ruff: noqa: E501
"""Every page of the site actually shows its content.

A panel marked `data-reveal` starts at opacity 0 and only appears when the page's script starts the
reveal. If a page forgets to, the page looks empty even though every button still works, so tests that
only click buttons pass. These tests look at what a person sees: after scrolling through the page, no
visible panel may still be see-through.

Needs only a browser.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site

sync_api = pytest.importorskip("playwright.sync_api")

PAGES = sorted(p.name for p in SITE.glob("*.html"))

# Every element that starts see-through, once it is on screen: its opacity, and how many there are.
SCAN = """() => {
  const els = [...document.querySelectorAll('[data-reveal]')].filter((e) => e.getClientRects().length);
  return { count: els.length, see_through: els.filter((e) => Number(getComputedStyle(e).opacity) < 0.98).map((e) => e.className || e.tagName) };
}"""


@pytest.fixture(scope="module")
def origin() -> Iterator[str]:
    with serve_site() as base:
        yield base


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def scroll_through(page: Any) -> None:
    height = page.evaluate("document.documentElement.scrollHeight")
    for y in range(0, height + 800, 400):
        page.evaluate(f"window.scrollTo({{ top: {y}, behavior: 'instant' }})")
        page.wait_for_timeout(250)
    page.wait_for_timeout(900)


def test_there_are_pages_to_check() -> None:
    assert {"index.html", "sandbox.html", "range.html", "about.html"} <= set(PAGES)


@pytest.mark.parametrize("name", PAGES)
@pytest.mark.parametrize("how", ["http", "file"])
def test_no_panel_is_left_invisible_after_scrolling_through_the_page(
    browser: Any, origin: str, name: str, how: str
) -> None:
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(f"{origin}/{name}" if how == "http" else (SITE / name).as_uri())
    page.wait_for_timeout(1200)
    scroll_through(page)
    found = page.evaluate(SCAN)
    assert found["see_through"] == [], (name, how, found)
    page.close()


def test_the_sandbox_has_panels_and_they_all_appear(browser: Any, origin: str) -> None:
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto(f"{origin}/sandbox.html")
    page.wait_for_timeout(1200)
    scroll_through(page)
    found = page.evaluate(SCAN)
    assert found["count"] >= 6, found  # flights, escrow, gate, key, radar, ledger, rules
    assert found["see_through"] == []
    page.close()


@pytest.mark.parametrize("name", PAGES)
def test_under_reduced_motion_everything_is_shown_at_once(
    browser: Any, origin: str, name: str
) -> None:
    page = browser.new_page(viewport={"width": 1280, "height": 800}, reduced_motion="reduce")
    page.goto(f"{origin}/{name}")
    page.wait_for_timeout(800)
    found = page.evaluate(SCAN)
    assert found["see_through"] == [], (name, found)
    page.close()
