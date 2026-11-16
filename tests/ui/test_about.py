"""The About page of the website, and the About section of the console.

* The website's About page is plain (no script, no inline style), loads clean from http and from file://,
  shifts nothing, fits a phone, and every link on it goes somewhere that exists.
* Its status table keeps the honest labels: what is built, planned, or not possible.
* Every page of the site has an About link in its nav, and the page marks itself as the current one.
* The console has an About section reachable from its nav.

Needs only a browser.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tests.ui.test_motion import WATCH, Watch

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

REPO = SITE.parent


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


def open_about(browser: Any, origin: str, how: str = "http", **kw: Any) -> tuple[Any, Watch]:
    page = browser.new_page(**{"viewport": {"width": 1280, "height": 900}, **kw})
    watch = Watch(page, origin)
    page.add_init_script(WATCH)
    page.goto(f"{origin}/about.html" if how == "http" else (SITE / "about.html").as_uri())
    return page, watch


def test_the_about_page_is_plain() -> None:
    html = (SITE / "about.html").read_text(encoding="utf-8")
    assert not re.search(r"<script", html, re.IGNORECASE), "no script at all"
    assert not re.search(r"<style", html, re.IGNORECASE)
    assert not re.search(r"\sstyle\s*=", html, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE)
    assert not re.search(r'(?:src|href)="https?:', html), "no link off the site"
    assert '<link rel="icon"' in html and 'href="brand.css"' in html


def test_every_site_page_links_to_about() -> None:
    for name in ("index.html", "sandbox.html", "range.html", "about.html"):
        html = (SITE / name).read_text(encoding="utf-8")
        assert html.count('href="about.html"') == 1, name
    html = (SITE / "about.html").read_text(encoding="utf-8")
    assert 'href="about.html" aria-current="page"' in html
    assert html.count('aria-current="page"') == 1


@pytest.mark.parametrize("how", ["http", "file"])
def test_the_about_page_loads_clean_and_shifts_nothing(browser: Any, origin: str, how: str) -> None:
    page, watch = open_about(browser, origin, how)
    page.wait_for_timeout(1200)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(600)
    seen = page.evaluate("window.__m")
    assert seen["shifts"] <= (0.001 if how == "http" else 0.01), seen["shiftList"]
    assert page.locator("h1").inner_text() == "A flight recorder for AI agents."
    assert page.locator(".ab-grid .card").count() == 7
    watch.assert_clean()
    page.close()


def test_the_about_page_fits_a_phone(browser: Any, origin: str) -> None:
    page, watch = open_about(browser, origin, viewport={"width": 375, "height": 800})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    expect(page.locator(".ab-table")).to_be_visible()
    watch.assert_clean()
    page.close()


def test_the_status_table_keeps_its_honest_labels(browser: Any, origin: str) -> None:
    page, _ = open_about(browser, origin)
    rows = page.locator(".ab-table tbody tr")
    got = {
        rows.nth(i).locator("th").inner_text(): rows.nth(i).locator(".ab-tag").inner_text()
        for i in range(rows.count())
    }
    assert got == {
        "Receipt checker (this site)": "BUILT",
        "Gatekeeper Sandbox": "BUILT",
        "Range": "BUILT",
        "Pro: licence, your name and logo, audit pack, CSV, compare runs": "BUILT",
        "Policy Studio (free) and exporting a policy (Pro)": "BUILT",
        "Pro: more levels, command-line scorer, verify widget": "PLANNED",
        "Browser extension": "BUILT",
        "MCP proxy (Claude Code, Cursor)": "PLANNED",
        "Watching an agent on someone else's machine": "NOT POSSIBLE",
    }
    assert "not enforced" in rows.nth(2).inner_text()
    page.close()


def test_every_link_on_the_about_page_goes_somewhere_real(browser: Any, origin: str) -> None:
    page, _ = open_about(browser, origin)
    targets = page.evaluate(
        "[...document.querySelectorAll('main a, header a')].map(a => a.getAttribute('href'))"
    )
    assert len(targets) >= 12
    for target in sorted(set(targets)):
        name, _, fragment = target.partition("#")
        assert (SITE / name).is_file(), target
        if fragment:
            html = (SITE / name).read_text(encoding="utf-8")
            assert f'id="{fragment}"' in html, target
    page.close()


def test_the_about_page_makes_no_claim_the_site_does_not_keep(browser: Any, origin: str) -> None:
    """The page says nothing is uploaded and no other site is contacted: check while it is used."""
    page, watch = open_about(browser, origin)
    sent: list[str] = []
    page.on("request", lambda r: sent.append(r.method) if r.method != "GET" else None)
    page.locator("a", has_text="Open the Range").click()
    page.wait_for_url("**/range.html")
    assert sent == [] and watch.outside == []
    page.close()


# ---------------------------------------------------------------- the console


def test_the_console_has_an_about_section_in_its_nav() -> None:
    html = (REPO / "ui" / "console.html").read_text(encoding="utf-8")
    assert '<a href="#about">About</a>' in html
    assert html.count('id="about"') == 1
    section = html.split('id="about"', 1)[1].split("</section>", 1)[0]
    assert "PLANNED" in section and "uploaded" in section
    assert not re.search(r'(?:src|href)="https?:', section)
