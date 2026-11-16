"""The free "Verify this receipt" widget (site/widget/verify.js).

Another website includes one script tag. The tests serve a host page from a DIFFERENT origin (another port) and
check that the widget:

* shows VALID, INVALID, INCOMPLETE and UNREADABLE for the genuine, edited and key-less samples and a junk file;
* fetches nothing but its own script and verifier.wasm from the HashCam site, sends nothing, and loads the
  verifier only when a file is dropped;
* works under a strict host Content Security Policy that has exactly the lines the About page documents, and fails
  with an honest message (never a made-up verdict) when a line is missing;
* cannot be broken by the host page's styles, does not touch the host page, and never puts text from a receipt into
  the page as markup.

Needs only a browser.
"""

# ruff: noqa: E501

from __future__ import annotations

import http.server
import json
import re
import threading
import urllib.request
import zipfile
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

GENUINE = SITE / "samples" / "genuine.abbreceipt"
EDITED = SITE / "samples" / "edited.abbreceipt"
KEYS = SITE / "samples" / "sample.keys.json"


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


class HostHandler(http.server.SimpleHTTPRequestHandler):
    """A host page on another origin; `?csp=...`-style pages get their own Content Security Policy header."""

    policies: dict[str, str] = {}  # noqa: RUF012

    def end_headers(self) -> None:
        policy = self.policies.get(self.path.split("?")[0])
        if policy:
            self.send_header("Content-Security-Policy", policy)
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def host(origin: str, tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """Host pages served from their own port: the page's origin is not HashCam's."""
    folder = tmp_path_factory.mktemp("host")
    tag = f'<script src="{origin}/widget/verify.js" async></script>'
    page = (
        '<!doctype html><meta charset="utf-8"><title>Host</title><h1 id="mine">My site</h1>{body}'
    )
    pages = {
        "plain.html": page.format(body=f'<div id="one" data-hashcam-verify></div>{tag}'),
        "two.html": page.format(
            body=f'<div id="a" data-hashcam-verify></div><div id="b" data-hashcam-verify></div>{tag}{tag}'
        ),
        "bare.html": page.format(body=f"<p id='before'>before</p>{tag}<p id='after'>after</p>"),
        "strict.html": page.format(body=f"<div data-hashcam-verify></div>{tag}"),
        "no-wasm.html": page.format(body=f"<div data-hashcam-verify></div>{tag}"),
        "no-connect.html": page.format(body=f"<div data-hashcam-verify></div>{tag}"),
        "hostile.html": page.format(
            body="<style>input, p, a, b, div div { display: none !important; color: red !important; font-size: 1px !important; } "
            "#mine { font-size: 40px; }</style><div data-hashcam-verify></div>" + tag
        ),
    }
    for name, html in pages.items():
        (folder / name).write_text(html, encoding="utf-8")
    base = "default-src 'none'; style-src 'none'; frame-ancestors 'none'"
    HostHandler.policies = {
        "/strict.html": f"{base}; script-src 'self' {origin} 'wasm-unsafe-eval'; connect-src {origin}",
        "/no-wasm.html": f"{base}; script-src 'self' {origin}; connect-src {origin}",
        "/no-connect.html": f"{base}; script-src 'self' {origin} 'wasm-unsafe-eval'",
    }
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), partial(HostHandler, directory=str(folder))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{server.server_address[1]}", "folder": folder}
    server.shutdown()


def open_host(browser: Any, host: dict[str, Any], name: str) -> tuple[Any, list[str], list[str]]:
    page = browser.new_page()
    page.set_default_timeout(20_000)
    errors: list[str] = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    requests: list[str] = []
    page.on("request", lambda r: requests.append(f"{r.method} {r.url}"))
    page.goto(f"{host['url']}/{name}")
    expect(page.locator("[data-hashcam-verify] .title").first).to_be_visible()
    return page, requests, errors


def drop(
    page: Any, files: list[Path], selector: str = "[data-hashcam-verify] input[type=file]"
) -> None:
    page.set_input_files(selector, [str(f) for f in files])


OUT = "[data-hashcam-verify] .out"


# ---------------------------------------------------------------- the verdicts


@pytest.mark.parametrize(
    ("files", "word", "says"),
    [
        (
            [GENUINE, KEYS],
            "VALID",
            "has not changed since it was signed. That does not mean the agent was honest.",
        ),
        (
            [GENUINE],
            "INCOMPLETE",
            "Part of this receipt could not be checked. Drop its .keys.json too.",
        ),
        ([EDITED, KEYS], "INVALID", "Do not trust it."),
    ],
)
def test_the_widget_shows_the_real_verifiers_verdict(
    browser: Any, host: dict[str, Any], files: list[Path], word: str, says: str
) -> None:
    page, _, errors = open_host(browser, host, "plain.html")
    drop(page, files)
    expect(page.locator(f"{OUT} b")).to_have_text(word)
    assert says in page.locator(OUT).inner_text()
    link = page.locator("[data-hashcam-verify] .foot a")
    assert page.locator("[data-hashcam-verify] .foot").inner_text() == "Checked with HashCam"
    assert (
        link.get_attribute("rel") == "noopener noreferrer"
        and link.get_attribute("target") == "_blank"
    )
    assert errors == [], errors
    page.close()


def test_a_file_that_is_not_a_receipt_is_unreadable_and_other_drops_are_refused(
    browser: Any, host: dict[str, Any], tmp_path: Path
) -> None:
    page, _, _ = open_host(browser, host, "plain.html")
    junk = tmp_path / "junk.abbreceipt"
    junk.write_bytes(b"this is not a receipt" * 20)
    drop(page, [junk])
    expect(page.locator(f"{OUT} b")).to_have_text("UNREADABLE")
    drop(page, [KEYS])
    expect(page.locator(OUT)).to_have_text("Drop the .abbreceipt file.")
    many = []
    for i in range(5):
        f = tmp_path / f"r{i}.abbreceipt"
        f.write_bytes(b"x")
        many.append(f)
    drop(page, many)
    expect(page.locator(OUT)).to_contain_text("Too much to check")
    big = tmp_path / "big.abbreceipt"
    big.write_bytes(b"x" * (9 * 1048576))
    drop(page, [big])
    expect(page.locator(OUT)).to_contain_text("Too much to check")
    page.close()


# ---------------------------------------------------------------- what it fetches and sends


def test_the_widget_loads_only_its_own_files_lazily_and_sends_nothing(
    browser: Any, host: dict[str, Any], origin: str
) -> None:
    page, requests, _ = open_host(browser, host, "plain.html")
    page.wait_for_timeout(500)
    away = [r for r in requests if not r.startswith(f"GET {host['url']}") and "favicon" not in r]
    assert away == [f"GET {origin}/widget/verify.js"], (
        "before anything is dropped, only the script itself was fetched"
    )
    drop(page, [GENUINE, KEYS])
    expect(page.locator(f"{OUT} b")).to_have_text("VALID")
    drop(page, [EDITED, KEYS])
    expect(page.locator(f"{OUT} b")).to_have_text("INVALID")
    away = [r for r in requests if not r.startswith(f"GET {host['url']}") and "favicon" not in r]
    assert away == [f"GET {origin}/widget/verify.js", f"GET {origin}/verifier.wasm"], away
    assert [r for r in requests if not r.startswith("GET ")] == [], (
        "no POST or other request: nothing is sent"
    )
    page.close()


def test_the_verifier_and_the_widget_may_be_loaded_by_other_sites_and_nothing_else_may(
    origin: str,
) -> None:
    def headers(path: str) -> Any:
        with urllib.request.urlopen(f"{origin}{path}") as response:  # noqa: S310 (local test server)
            return response.headers

    for path in ("/widget/verify.js", "/verifier.wasm"):
        h = headers(path)
        assert (
            h["Cross-Origin-Resource-Policy"] == "cross-origin"
            and h["Access-Control-Allow-Origin"] == "*"
        ), path
        assert h["X-Content-Type-Options"] == "nosniff"
    for path in ("/range.html", "/pro.html", "/sandbox.js", "/lockedpdf.js", "/about.html"):
        h = headers(path)
        assert (
            h["Cross-Origin-Resource-Policy"] == "same-origin"
            and h["Access-Control-Allow-Origin"] is None
        ), path
    config = json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))
    sources = [rule["source"] for rule in config["headers"]]
    assert sources == ["/(.*)", "/((?!widget/|verifier\\.wasm).*)", "/(widget/.*|verifier\\.wasm)"]
    assert all(h["key"] != "Cross-Origin-Resource-Policy" for h in config["headers"][0]["headers"])


# ---------------------------------------------------------------- the host page's Content Security Policy


def test_the_widget_works_under_a_strict_host_policy_with_exactly_the_documented_lines(
    browser: Any, host: dict[str, Any]
) -> None:
    page, _, errors = open_host(browser, host, "strict.html")
    # styled although the host forbids every inline style: the stylesheet is constructed, not injected
    assert (
        page.locator("[data-hashcam-verify] .box").evaluate(
            "e => getComputedStyle(e).borderTopWidth"
        )
        == "1px"
    )
    drop(page, [GENUINE, KEYS])
    expect(page.locator(f"{OUT} b")).to_have_text("VALID")
    assert errors == [], errors
    page.close()


@pytest.mark.parametrize("name", ["no-wasm.html", "no-connect.html"])
def test_a_missing_policy_line_gives_an_honest_message_never_a_verdict(
    browser: Any, host: dict[str, Any], name: str
) -> None:
    page, _, _ = open_host(browser, host, name)
    drop(page, [GENUINE, KEYS])
    expect(page.locator(OUT)).to_have_text(
        "Could not check: the verifier did not load here, so nothing was checked."
    )
    assert page.locator(f"{OUT} b").count() == 0, (
        "no VALID, INVALID, INCOMPLETE or UNREADABLE is shown"
    )
    page.close()


def test_the_about_page_documents_the_snippet_and_the_policy_the_tests_use(origin: str) -> None:
    html = (SITE / "about.html").read_text(encoding="utf-8")
    assert "&lt;div data-hashcam-verify&gt;&lt;/div&gt;" in html
    assert (
        "&lt;script src=&quot;https://hashcam.vercel.app/widget/verify.js&quot; async&gt;&lt;/script&gt;"
        in html
    )
    assert (
        "script-src https://hashcam.vercel.app 'wasm-unsafe-eval'; connect-src https://hashcam.vercel.app"
        in html
    )
    assert not re.search(r"<script", html, re.IGNORECASE) and not re.search(
        r'(?:src|href)="https?:', html
    )
    source = (SITE / "widget" / "verify.js").read_text(encoding="utf-8")
    assert (
        "script-src https://hashcam.vercel.app 'wasm-unsafe-eval'; connect-src https://hashcam.vercel.app"
        in source
    )


# ---------------------------------------------------------------- isolation


def test_the_host_pages_styles_cannot_break_the_widget_and_it_leaves_the_host_alone(
    browser: Any, host: dict[str, Any]
) -> None:
    page = browser.new_page()
    page.goto(f"{host['url']}/hostile.html")
    expect(page.locator("[data-hashcam-verify] .title")).to_be_visible()
    box = page.locator("[data-hashcam-verify] input[type=file]").bounding_box()
    assert box is not None and box["width"] > 20 and box["height"] > 10, (
        "the host's `input { display: none !important }` does not reach in"
    )
    assert (
        page.locator("[data-hashcam-verify] .hint").evaluate("e => getComputedStyle(e).fontSize")
        == "13px"
    )
    assert page.locator("#mine").evaluate("e => getComputedStyle(e).fontSize") == "40px", (
        "the widget does not restyle the host"
    )
    assert page.evaluate("document.querySelectorAll('style').length") == 1, (
        "the widget added no <style> to the host page"
    )
    assert page.evaluate("document.head.children.length") <= 3
    page.close()


def test_two_placeholders_make_two_widgets_and_including_the_script_twice_does_not_double_them(
    browser: Any, host: dict[str, Any]
) -> None:
    page, _, _ = open_host(browser, host, "two.html")
    page.wait_for_timeout(300)
    assert (
        page.locator("[data-hashcam-verify]").count() == 2
        and page.locator("[data-hashcam-verify] .box").count() == 2
    )
    drop(page, [GENUINE, KEYS], "#a input[type=file]")
    expect(page.locator("#a .out b")).to_have_text("VALID")
    assert page.locator("#b .out").inner_text() == "", "the other widget is unaffected"
    page.close()


def test_without_a_placeholder_the_widget_appears_right_after_the_script(
    browser: Any, host: dict[str, Any]
) -> None:
    page = browser.new_page()
    page.goto(f"{host['url']}/bare.html")
    expect(page.locator("[data-hashcam-verify] .title")).to_be_visible()
    order = page.evaluate(
        "[...document.body.children].map(e => e.id || e.tagName + (e.hasAttribute('data-hashcam-verify') ? '[w]' : ''))"
    )
    assert order.index("before") < order.index("DIV[w]") < order.index("after"), order
    page.close()


def test_text_from_a_receipt_never_becomes_markup_on_the_host_page(
    browser: Any, host: dict[str, Any], tmp_path: Path
) -> None:
    hostile = tmp_path / "hostile.abbreceipt"
    payload = "<img src=x onerror=window.__pwned=1><script>window.__pwned=1</script>"
    with zipfile.ZipFile(hostile, "w") as z:
        z.writestr(
            "receipt.json",
            json.dumps({"events": [{"canonical_b64": payload, "note": payload}], "title": payload}),
        )
    page, _, errors = open_host(browser, host, "plain.html")
    drop(page, [hostile])
    expect(page.locator(f"{OUT} b")).to_have_text(re.compile(r"INVALID|UNREADABLE|INCOMPLETE"))
    page.wait_for_timeout(500)
    assert page.evaluate("window.__pwned") is None
    assert (
        page.locator("[data-hashcam-verify] img").count() == 0
        and page.locator("[data-hashcam-verify] script").count() == 0
    )
    assert "onerror" not in page.locator("[data-hashcam-verify] .box").evaluate("e => e.outerHTML")
    assert errors == [], errors
    page.close()


# ---------------------------------------------------------------- the file itself


def test_the_widget_file_is_small_plain_and_makes_one_request() -> None:
    source = (SITE / "widget" / "verify.js").read_text(encoding="utf-8")
    assert len(source.encode("utf-8")) < 12000, "small enough to embed"
    code = "\n".join(line for line in source.splitlines() if not line.lstrip().startswith("//"))
    assert not re.search(
        r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function|importScripts|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|document\.cookie",
        code,
    )
    assert code.count("fetch(") == 1 and 'fetch(ORIGIN + "/verifier.wasm"' in code
    assert 'credentials: "omit"' in code and "attachShadow" in code and "CSSStyleSheet" in code
    assert not re.search(r"(?i)pricing|\bprice|subscri|billing|stripe|invoice|checkout\b", code)
