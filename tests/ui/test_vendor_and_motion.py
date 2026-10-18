"""The font and the animation library: served from this computer, checked, and harmless.

Both files in `ui/vendor/` are third-party downloads. These tests pin them to the hashes recorded in
`ui/vendor/README.md`, check that the pages load nothing from another site, that the content
security policy stays strict, and that the animations are decoration only: they run normally and
do nothing at all when the person has asked their system for reduced motion.
"""

from __future__ import annotations

import hashlib
import http.client
import re
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from services.dashboard.server import UI_DIR, Config, serve


@pytest.fixture()
def port(tmp_path: Path) -> Iterator[int]:
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb"), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def fetch(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read()
    headers = {k.lower(): v for k, v in response.getheaders()}
    conn.close()
    return response.status, headers, body


VENDOR_FILES = [
    "motion.js",
    "plus-jakarta-sans.woff2",
    "gsap.min.js",
    "ScrollTrigger.min.js",
    "lenis.min.js",
    "lenis.css",
]


def recorded_hashes() -> dict[str, str]:
    text = (UI_DIR / "vendor" / "README.md").read_text(encoding="utf-8")
    found: dict[str, str] = {}
    for name in VENDOR_FILES:
        match = re.search(rf"\| {re.escape(name)} \|.*\| ([0-9a-f]{{64}}) \|", text)
        assert match, f"no recorded hash for {name}"
        found[name] = match.group(1)
    return found


@pytest.mark.parametrize("name", VENDOR_FILES)
def test_the_vendor_files_are_exactly_the_ones_that_were_checked(name: str) -> None:
    data = (UI_DIR / "vendor" / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == recorded_hashes()[name]


def test_the_vendor_licences_are_shipped_with_the_files() -> None:
    assert "MIT" in (UI_DIR / "vendor" / "LICENSE-motion.md").read_text(encoding="utf-8")
    assert "Open Font License" in (UI_DIR / "vendor" / "OFL-plus-jakarta-sans.txt").read_text(
        encoding="utf-8"
    )


def test_the_vendor_files_are_served_with_the_right_types(port: int) -> None:
    status, headers, body = fetch(port, "/vendor/plus-jakarta-sans.woff2")
    assert (status, headers["content-type"]) == (200, "font/woff2")
    assert body[:4] == b"wOF2"
    status, headers, body = fetch(port, "/vendor/motion.js")
    assert (status, headers["content-type"].split(";")[0]) == (200, "text/javascript")
    assert b"Motion" in body[:2000]
    assert fetch(port, "/fx.js")[0] == 200


def test_only_the_listed_vendor_files_can_be_fetched(port: int) -> None:
    for path in ("/vendor/README.md", "/vendor/../server.py", "/vendor/", "/vendor/nothing.js"):
        assert fetch(port, path)[0] == 404


def test_the_policy_allows_fonts_from_this_computer_and_nothing_loosened(port: int) -> None:
    csp = fetch(port, "/")[1]["content-security-policy"]
    assert "font-src 'self'" in csp
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert "http:" not in csp.replace("'self'", "") and "https:" not in csp


@pytest.mark.parametrize("page", ["index.html", "run.html", "style.css", "chat.css"])
def test_no_page_or_stylesheet_loads_anything_from_another_site(page: str) -> None:
    text = (UI_DIR / page).read_text(encoding="utf-8")
    external = re.findall(
        r"""(?:src|href)=["']https?://|url\(\s*["']?https?://|@import\s+["']?https?:""", text
    )
    assert external == []


@pytest.mark.parametrize(
    "script", ["motion.js", "gsap.min.js", "ScrollTrigger.min.js", "lenis.min.js"]
)
def test_the_third_party_script_makes_no_network_or_eval_calls(script: str) -> None:
    source = (UI_DIR / "vendor" / script).read_text(encoding="utf-8")
    for forbidden in (
        "XMLHttpRequest",
        "fetch(",
        "WebSocket",
        "sendBeacon",
        "eval(",
        "new Function",
    ):
        assert forbidden not in source, forbidden


# ---- in a real browser ------------------------------------------------------------------------


def _playwright() -> object:
    return pytest.importorskip("playwright.sync_api")


def test_animations_run_by_default_and_never_hide_content(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page()
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1500)
        facts = page.evaluate(
            """() => ({
                motion: typeof window.Motion,
                ready: fx.ready(),
                font: document.fonts.check('16px "Plus Jakarta Sans"'),
                family: getComputedStyle(document.body).fontFamily.split(',')[0],
                heroOpacity: getComputedStyle(document.querySelector('#hero h1')).opacity,
            })"""
        )
        browser.close()
    assert failures == []
    assert facts["motion"] == "object"
    assert facts["ready"] is True
    assert facts["font"] is True  # the font really loaded from this computer
    assert "Plus Jakarta Sans" in facts["family"]
    assert float(facts["heroOpacity"]) == 1.0  # the animation ended fully visible


def test_with_reduced_motion_nothing_animates_and_everything_is_visible(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(reduced_motion="reduce")
        page.goto(f"http://127.0.0.1:{port}/run")
        # Read straight away: with no animation there is no moment of being half-visible.
        facts = page.evaluate(
            """() => ({
                ready: fx.ready(),
                heroOpacity: getComputedStyle(document.querySelector('#hero h1')).opacity,
                transform: getComputedStyle(document.querySelector('#hero h1')).transform,
            })"""
        )
        browser.close()
    assert facts["ready"] is False
    assert float(facts["heroOpacity"]) == 1.0
    assert facts["transform"] in ("none", "matrix(1, 0, 0, 1, 0, 0)")


def test_the_page_still_works_if_the_animation_library_is_missing(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page()
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.route("**/vendor/motion.js", lambda route: route.abort())
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1000)
        visible = page.evaluate("getComputedStyle(document.querySelector('#hero h1')).opacity")
        browser.close()
    assert failures == []  # fx quietly does nothing
    assert float(visible) == 1.0


def test_scroll_effects_run_and_the_whole_page_stays_readable(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 500})
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.goto(f"http://127.0.0.1:{port}/")
        page.wait_for_timeout(1200)
        page.evaluate(
            "document.querySelector('.content').style.minHeight = '3000px';"
            "window.ScrollTrigger.refresh()"
        )
        page.mouse.wheel(0, 600)
        page.wait_for_timeout(1500)
        facts = page.evaluate(
            """() => ({
                libs: [typeof window.gsap, typeof window.ScrollTrigger, typeof window.Lenis],
                lenis: document.documentElement.classList.contains('lenis'),
                scrolled: window.scrollY,
                bar: getComputedStyle(document.getElementById('scrollbar')).transform,
                notice: getComputedStyle(document.querySelector('.notice')).opacity,
            })"""
        )
        browser.close()
    assert failures == []
    assert facts["libs"] == ["object", "function", "function"]
    assert facts["lenis"] is True
    assert facts["scrolled"] > 0
    fill = float(facts["bar"].split("(")[1].split(",")[0])
    assert 0 < fill < 1  # the bar follows how far down the page you are
    assert float(facts["notice"]) == 1.0  # revealed, never left hidden


def test_with_reduced_motion_the_page_scrolls_normally_with_no_effects(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(reduced_motion="reduce")
        page.goto(f"http://127.0.0.1:{port}/")
        page.wait_for_timeout(500)
        facts = page.evaluate(
            """() => ({
                lenis: document.documentElement.classList.contains('lenis'),
                notice: getComputedStyle(document.querySelector('.notice')).opacity,
            })"""
        )
        browser.close()
    assert facts["lenis"] is False
    assert float(facts["notice"]) == 1.0


def test_the_page_still_works_if_the_scroll_libraries_are_missing(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page()
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        for name in ("gsap.min.js", "ScrollTrigger.min.js", "lenis.min.js"):
            page.route(f"**/vendor/{name}", lambda route: route.abort())
        page.goto(f"http://127.0.0.1:{port}/")
        page.wait_for_timeout(800)
        notice = page.evaluate("getComputedStyle(document.querySelector('.notice')).opacity")
        browser.close()
    assert failures == []
    assert float(notice) == 1.0


# ---- icons, logos and the other effects, on BOTH pages ------------------------------------------

PAGES = [("/", "h1", "Hascham audit view"), ("/run", "#hero h1", "What should the agent do?")]


@pytest.mark.parametrize(("path", "title", "text"), PAGES)
def test_logo_icons_and_title_effects_run_and_leave_everything_readable(
    port: int, path: str, title: str, text: str
) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 800})
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.goto(f"http://127.0.0.1:{port}{path}")
        page.wait_for_timeout(2500)
        facts = page.evaluate(
            """(title) => ({
                label: document.querySelector(title).getAttribute('aria-label'),
                shown: document.querySelector(title).textContent.replace(/\s+/g, ' ').trim(),
                letters: document.querySelectorAll('.fxchar').length,
                letterOpacity: getComputedStyle(document.querySelector('.fxchar')).opacity,
                logoDash: getComputedStyle(document.querySelector('.logo path')).strokeDasharray,
                icons: document.querySelectorAll('.ico').length,
                hidden: [...document.querySelectorAll('.ico')].every(
                    (i) => i.getAttribute('aria-hidden') === 'true'),
            })""",
            title,
        )
        browser.close()
    assert failures == []
    assert facts["label"] == text  # screen readers get the whole title
    assert facts["shown"] == text  # and the visible text is unchanged
    assert facts["letters"] >= 10
    assert float(facts["letterOpacity"]) == 1.0
    assert facts["logoDash"] == "none"  # the logo finished drawing and is fully visible
    assert facts["icons"] >= 5 and facts["hidden"] is True


@pytest.mark.parametrize(("path", "title", "text"), PAGES)
def test_with_reduced_motion_titles_and_logos_are_untouched(
    port: int, path: str, title: str, text: str
) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(reduced_motion="reduce")
        page.goto(f"http://127.0.0.1:{port}{path}")
        page.wait_for_timeout(500)
        facts = page.evaluate(
            """(title) => ({
                letters: document.querySelectorAll('.fxchar').length,
                text: document.querySelector(title).textContent.replace(/\s+/g, ' ').trim(),
                dash: getComputedStyle(document.querySelector('.logo path')).strokeDasharray,
            })""",
            title,
        )
        browser.close()
    assert facts["letters"] == 0
    assert facts["text"] == text
    assert facts["dash"] == "none"


@pytest.mark.parametrize(("path", "title", "text"), PAGES)
def test_pages_work_if_gsap_is_missing(port: int, path: str, title: str, text: str) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page()
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.route("**/vendor/gsap.min.js", lambda route: route.abort())
        page.goto(f"http://127.0.0.1:{port}{path}")
        page.wait_for_timeout(800)
        shown = page.evaluate(
            "(t) => document.querySelector(t).textContent.replace(/\s+/g, ' ').trim()", title
        )
        browser.close()
    assert failures == []
    assert shown == text
