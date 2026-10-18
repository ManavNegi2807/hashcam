"""The sidebar list of what the console can do: one click picks a task type."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from services.dashboard.server import Config, serve

MODES = ["search", "research", "agent", "guarded", "endpoint", "pay", "realsite"]


@pytest.fixture()
def port(tmp_path: Path) -> Iterator[int]:
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb"), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _playwright() -> object:
    return pytest.importorskip("playwright.sync_api")


def test_each_task_type_is_listed_in_the_sidebar_and_a_click_picks_it(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        failures: list[str] = []
        page.on("pageerror", lambda e: failures.append(str(e)))
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1500)
        listed = page.evaluate(
            "[...document.querySelectorAll('#modes-nav .modebtn')].map(b => b.dataset.mode)"
        )
        start = page.evaluate(
            "document.querySelector('#modes-nav [aria-current=true]').dataset.mode"
        )
        page.click("#modes-nav [data-mode=pay]")
        after = page.evaluate(
            """() => ({
                checked: document.querySelector('input[name=mode]:checked').value,
                current: document.querySelector('#modes-nav [aria-current=true]').dataset.mode,
                focused: document.activeElement.id,
                label: document.getElementById('task-run-label').textContent,
            })"""
        )
        page.click("#modes-nav [data-mode=endpoint]")
        second = page.evaluate("document.querySelector('input[name=mode]:checked').value")
        browser.close()
    assert failures == []
    assert listed == MODES
    assert start == "search"  # the page opens on Search, and the list says so
    assert after["checked"] == "pay" and after["current"] == "pay"
    assert after["focused"] == "task-goal"  # ready to type
    assert after["label"] == "Pay (test money)"
    assert second == "endpoint"


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_sidebar_list_is_readable_and_has_no_accessibility_violations(
    port: int, scheme: str
) -> None:
    sync_api = _playwright()
    axe_module = pytest.importorskip("axe_playwright_python.sync_playwright")
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(color_scheme=scheme, viewport={"width": 1280, "height": 900})
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(2500)  # let the entrance animations finish
        results = axe_module.Axe().run(page)
        violations = [(v["id"], v["impact"]) for v in results.response["violations"]]
        browser.close()
    assert violations == [], violations


def test_with_reduced_motion_the_list_still_works(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(reduced_motion="reduce")
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(600)
        page.click("#modes-nav [data-mode=realsite]")
        picked = page.evaluate("document.querySelector('input[name=mode]:checked').value")
        browser.close()
    assert picked == "realsite"


def test_on_a_wide_screen_the_card_grid_is_out_of_sight_and_a_caption_says_what_is_picked(
    port: int,
) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1500)
        first = page.evaluate(
            """() => ({
                grid: document.getElementById('modes').getBoundingClientRect().height,
                caption: document.getElementById('mode-caption').textContent,
            })"""
        )
        page.click("#modes-nav [data-mode=endpoint]")
        caption = page.evaluate("document.getElementById('mode-caption').textContent")
        browser.close()
    assert first["grid"] <= 2  # the cards take no room
    assert first["caption"].startswith("Search") and "ranked web results" in first["caption"]
    assert caption.startswith("Endpoint review") and "analyst signs" in caption


def test_the_hidden_grid_opens_for_the_keyboard_and_still_works(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1000)
        page.focus("input[name=mode][value=search]")
        opened = page.evaluate("document.getElementById('modes').getBoundingClientRect().height")
        page.keyboard.press("ArrowRight")  # radios move with the arrow keys
        picked = page.evaluate("document.querySelector('input[name=mode]:checked').value")
        current = page.evaluate(
            "document.querySelector('#modes-nav [aria-current=true]').dataset.mode"
        )
        browser.close()
    assert opened > 50  # focus brings the grid back into view
    assert picked == "research" and current == "research"


def test_on_a_phone_the_grid_stays_because_the_sidebar_list_is_hidden(port: int) -> None:
    sync_api = _playwright()
    with sync_api.sync_playwright() as p:  # type: ignore[attr-defined]
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 390, "height": 800})
        page.goto(f"http://127.0.0.1:{port}/run")
        page.wait_for_timeout(1000)
        facts = page.evaluate(
            """() => ({
                grid: document.getElementById('modes').getBoundingClientRect().height,
                nav: getComputedStyle(document.getElementById('modes-nav')).display,
                overflow: document.documentElement.scrollWidth > innerWidth,
            })"""
        )
        browser.close()
    assert facts["grid"] > 100 and facts["nav"] == "none" and facts["overflow"] is False
