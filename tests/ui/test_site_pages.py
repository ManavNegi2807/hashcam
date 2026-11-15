"""The home page and the Gatekeeper Sandbox, served as Vercel serves them and opened from disk.

* Every relative link and anchor resolves; no inline script, style or event handler (the site's
  content security policy forbids them).
* Both pages load from http (with the Vercel headers) and from file:// with no console error, no
  failed request and no request to any other host, and fit a phone-width screen.
* The telemetry panels and the live view read as plain sentences, with raw records closed.
* The sandbox: each test flight, the held gate and the two signature outcomes, the escrow numbers,
  the radar's four explainers, tamper (links turn crimson from the edited event on), restore,
  and the exported receipt, which checks itself offline and notices an edit.

Needs only a browser (no recorder, no database).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

PAGES = ["index.html", "sandbox.html"]
EMERALD = "rgb(16, 185, 129)"
CRIMSON = "rgb(239, 68, 68)"


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


def address(origin: str, name: str, how: str) -> str:
    return f"{origin}/{name}" if how == "http" else (SITE / name).as_uri()


class Watch:
    """What went wrong on a page: console errors, failed requests, requests to other places."""

    def __init__(self, page: Any, origin: str) -> None:
        self.errors: list[str] = []
        self.failed: list[str] = []
        self.outside: list[str] = []
        page.on("pageerror", lambda e: self.errors.append(str(e)))
        page.on("console", lambda m: self.errors.append(m.text) if m.type == "error" else None)
        page.on("requestfailed", lambda r: self.failed.append(r.url))
        page.on(
            "request",
            lambda r: self.outside.append(r.url)
            if not r.url.startswith((origin, "file:", "data:", "blob:"))
            else None,
        )

    def assert_clean(self) -> None:
        assert self.errors == [] and self.failed == [] and self.outside == [], (
            self.errors,
            self.failed,
            self.outside,
        )


@pytest.fixture(params=["http", "file"])
def how(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def open_page(browser: Any, origin: str, name: str, how: str, **kw: Any) -> tuple[Any, Watch]:
    page = browser.new_page(**kw)
    page.set_default_timeout(20_000)
    watch = Watch(page, origin)
    page.goto(address(origin, name, how))
    return page, watch


# ---------------------------------------------------------------- the files themselves


class Refs(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.refs: list[tuple[str, str, str]] = []
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if values.get("id"):
            self.ids.add(str(values["id"]))
        for attr in ("href", "src", "action"):
            if values.get(attr):
                self.refs.append((tag, attr, str(values[attr])))


def refs_of(name: str) -> Refs:
    parser = Refs()
    parser.feed((SITE / name).read_text(encoding="utf-8"))
    return parser


@pytest.mark.parametrize("name", PAGES)
def test_every_relative_link_and_anchor_resolves(name: str) -> None:
    page = refs_of(name)
    assert page.refs, name
    for tag, attr, value in page.refs:
        if tag == "link" and value.startswith("data:image/"):
            continue  # an inline image (the favicon), not a link to anywhere
        if value.startswith(("http://", "https://")):
            assert (tag, attr) == ("a", "href"), f"{name}: only a link may leave the site: {value}"
            continue
        assert not value.startswith(("//", "javascript:", "data:")), (name, value)
        target, _, fragment = value.partition("#")
        target = target.split("?", 1)[0]
        if target:
            assert (SITE / target).exists(), f"{name}: {value} does not exist"
        if fragment:
            ids = page.ids if not target or target == name else refs_of(target).ids
            assert fragment in ids, f"{name}: #{fragment} is not on {target or name}"


@pytest.mark.parametrize("name", PAGES)
def test_the_pages_use_no_inline_script_style_or_handler(name: str) -> None:
    html = (SITE / name).read_text(encoding="utf-8")
    assert not re.search(r"<style", html, re.IGNORECASE)
    assert not re.search(r"\sstyle\s*=", html, re.IGNORECASE)
    assert not re.search(r"<script(?![^>]*\ssrc=)", html, re.IGNORECASE)
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE)
    assert "javascript:" not in html


@pytest.mark.parametrize("name", PAGES)
def test_the_pages_link_nowhere_outside_the_site(name: str) -> None:
    """No GitHub link or button, and no other outbound link either."""
    for tag, attr, value in refs_of(name).refs:
        assert not value.startswith(("http://", "https://", "//")), (name, tag, attr, value)
    assert "github.com/ManavNegi2807" not in " ".join(v for _, _, v in refs_of(name).refs)
    html = (SITE / name).read_text(encoding="utf-8")
    assert ">GitHub<" not in html and "Get it on GitHub" not in html


def test_the_navigation_keeps_its_links() -> None:
    home = (SITE / "index.html").read_text(encoding="utf-8")
    for label in ("Attach", "Live", "Receipts", "How it works", "Sandbox"):
        assert re.search(rf"<a [^>]*>{label}</a>", home), label
    assert 'class="status-pill"' in home and "ZERO SAAS • PLAIN HTML • OFFLINE VERIFIABLE" in home
    assert 'href="sandbox.html"' in home


def test_the_radar_sweep_is_defined() -> None:
    assert "@keyframes radarSweep" in (SITE / "sandbox.css").read_text(encoding="utf-8")


# ---------------------------------------------------------------- loading


@pytest.mark.parametrize("name", PAGES)
def test_the_pages_load_clean_and_fit_a_phone(
    browser: Any, origin: str, name: str, how: str
) -> None:
    page, watch = open_page(browser, origin, name, how, viewport={"width": 375, "height": 812})
    if name == "sandbox.html":
        expect(page.locator(".flight").first).to_be_enabled()
    else:
        expect(page.locator("#busPlain .lede")).to_be_visible()
    page.wait_for_timeout(800)
    overflow = page.evaluate("document.documentElement.scrollWidth - window.innerWidth")
    assert overflow <= 1, f"{name} scrolls sideways by {overflow}px on a phone"
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- plain words on the home page


BUS_STOPS = [
    (0, ["fingerprint", "Session opened", 'Asked to run "Provision Sandbox GPU"']),
    (
        1,
        [
            "fixed rule",
            "Held for a person to sign",
            "$35.00 is more than the $10.00 the agent may spend alone.",
        ],
    ),
    (2, ["money is fake", "$35.00", "refused, even if someone approves"]),
    (3, ["A person approved it", "chain intact, 5 events"]),
]


def test_the_telemetry_bus_reads_in_plain_words(browser: Any, origin: str, how: str) -> None:
    page, watch = open_page(browser, origin, "index.html", how)
    expect(page.locator("#busPlain .lede")).to_be_visible()
    for stop, phrases in BUS_STOPS:
        page.locator(f"#busSvg .bus-node[data-i='{stop}']").click()
        expect(page.locator("#busPlain")).to_contain_text(phrases[0])
        text = page.inner_text("#busPlain")
        for phrase in phrases:
            assert phrase in text, (stop, phrase, text)
        assert "{" not in text and '"type"' not in text, "raw JSON is showing"
        assert page.evaluate(
            "[...document.querySelectorAll('#busPlain details.tech')].every(d => !d.open)"
        )
    # The raw record is one click away, with nothing sensitive in it.
    page.locator("#busSvg .bus-node[data-i='1']").click()
    page.locator("#busPlain details.tech summary").first.click()
    expect(page.locator("#busPlain .tech-text").first).to_contain_text('"type": "POLICY_DECISION"')
    watch.assert_clean()
    page.close()


def test_the_live_sample_reads_as_sentences(browser: Any, origin: str, how: str) -> None:
    page, watch = open_page(browser, origin, "index.html", how)
    roll = page.locator("#liveRoll")
    expect(roll).to_contain_text("Opened shop.example/checkout")
    text = roll.inner_text()
    for sentence in (
        "Typed a password on shop.example/login",
        "Sent a form to shop.example/order",
        "Stopped from opening bank.example/transfer",
        "Wants to download a file from shop.example/invoice.pdf",
    ):
        assert sentence in text, sentence
    for code in ("form_submit", "COMMITTED", "NOT_SENT", "navigate"):
        assert code not in text, code
    password = page.locator("#liveRoll .says-li", has_text="Typed a password")
    expect(password.locator(".tech-withheld")).to_have_count(1)
    expect(password.locator(".tech-text")).to_have_count(0)
    assert page.evaluate(
        "[...document.querySelectorAll('#liveRoll details.tech')].every(d => !d.open)"
    )
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- the sandbox


def fly(page: Any, name: str) -> None:
    page.get_by_role("button", name=name).click()


def start(browser: Any, origin: str, how: str, **kw: Any) -> tuple[Any, Watch]:
    page, watch = open_page(browser, origin, "sandbox.html", how, **kw)
    expect(page.locator(".flight").first).to_be_enabled()
    return page, watch


def test_the_four_test_flights(browser: Any, origin: str, how: str) -> None:
    page, watch = start(browser, origin, how)
    ledger = page.locator("#ledger")

    fly(page, "Read Repo Docs ($0.00)")
    expect(ledger).to_contain_text("Allowed: no money moves.")
    expect(page.locator("#chainStatus")).to_contain_text("Record intact")

    fly(page, "Sync External Webhook")
    expect(ledger).to_contain_text("Denied: hooks.partner-sync.example is not on the allow-list.")
    keys = page.locator("#why .badge .k")
    assert keys.all_inner_texts() == [
        "RULE_ID",
        "TRIGGER_REASON",
        "DOMAIN_CHECK",
        "DETERMINISTIC_OUTCOME",
    ]
    expect(page.locator("#why .badge[data-k='RULE_ID'] .v")).to_have_text("R1 · DOMAIN_NOT_ALLOWED")

    # $35.00 is more than the agent may spend alone: the gate latches and the agent is frozen.
    fly(page, "Provision Sandbox GPU ($35.00)")
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    expect(page.locator("#mHeld")).to_have_text("$35.00")
    expect(page.locator("#mSpent")).to_have_text("$0.00")
    expect(page.locator("#mLeft")).to_have_text("$65.00")  # spent + held + left = the cap
    expect(page.get_by_role("button", name="Bulk Token Purchase ($250.00)")).to_be_disabled()
    expect(page.locator("#exportBtn")).to_be_disabled()
    expect(page.locator("#why .badge[data-k='RULE_ID'] .v")).to_have_text(
        "R5 · HUMAN_SIGNOFF_REQUIRED"
    )

    page.get_by_role("button", name="Sign & Authorize Gate").click()
    expect(page.locator("#mSpent")).to_have_text("$35.00")
    expect(page.locator("#mHeld")).to_have_text("$0.00")
    expect(page.locator("#mLeft")).to_have_text("$65.00")
    expect(ledger).to_contain_text("A person approved it, signed with key")
    expect(page.locator("#chainStatus")).to_contain_text("1 signed decision valid")

    fly(page, "Bulk Token Purchase ($250.00)")
    expect(ledger).to_contain_text("Denied: $250.00 is more than the $65.00 left in escrow.")
    expect(page.locator("#why .badge[data-k='RULE_ID'] .v")).to_have_text("R2 · OVER_BUDGET")
    expect(page.locator("#mSpent")).to_have_text("$35.00")
    assert "ACTION_REQUESTED" not in ledger.inner_text()  # codes are not what people read
    watch.assert_clean()
    page.close()


def test_rejecting_halts_the_session(browser: Any, origin: str, how: str) -> None:
    page, watch = start(browser, origin, how)
    fly(page, "Provision Sandbox GPU ($35.00)")
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    page.get_by_role("button", name="Reject & Halt").click()
    expect(page.locator("#gate")).to_have_attribute("data-state", "halted")
    expect(page.locator("#ledger")).to_contain_text("A person rejected it")
    expect(page.locator("#ledger")).to_contain_text(
        "Session halted: a person rejected the held action."
    )
    expect(page.get_by_role("button", name="Read Repo Docs ($0.00)")).to_be_disabled()
    expect(page.locator("#mSpent")).to_have_text("$0.00")
    watch.assert_clean()
    page.close()


def expect_colour(page: Any, indexes: range, colour: str) -> None:
    """The ledger's left edge fades between colours, so wait for it rather than read it once."""
    for i in indexes:
        expect(page.locator("#ledger .ev").nth(i)).to_have_css("border-left-color", colour)


def test_tampering_breaks_every_link_after_the_edit(browser: Any, origin: str, how: str) -> None:
    page, watch = start(browser, origin, how)
    fly(page, "Read Repo Docs ($0.00)")
    fly(page, "Sync External Webhook")
    expect(page.locator("#ledger .ev")).to_have_count(6)
    expect(page.locator("#chainStatus")).to_contain_text("Record intact: 6 events")

    page.get_by_role("button", name="Simulate Tamper").click()
    areas = page.locator(".ev-json")
    expect(areas).to_have_count(6)
    original = areas.nth(1).input_value()
    assert '"amount_cents": 0' in original
    areas.nth(1).fill(original.replace('"amount_cents": 0', '"amount_cents": 9999'))
    expect(page.locator("#chainStatus")).to_contain_text("Record broken at event #1")
    expect(page.locator("#chainStatus")).to_contain_text("5 of 6 events no longer check out")
    expect_colour(page, range(0, 1), EMERALD)  # what came before the edit still holds
    expect_colour(page, range(1, 6), CRIMSON)  # the edit and everything after
    expect(page.locator("#ledger .ev").nth(1).locator(".ev-note")).to_contain_text(
        "no longer matches its fingerprint"
    )
    expect(page.get_by_role("button", name="Export Verified Receipt (.html)")).to_be_disabled()

    page.get_by_role("button", name="Restore Original").click()
    expect(page.locator("#chainStatus")).to_contain_text("Record intact: 6 events")
    expect_colour(page, range(6), EMERALD)

    # Text that is not even a record breaks the chain from that event on.
    areas.nth(3).fill("{ not a record")
    expect(page.locator("#chainStatus")).to_contain_text("Record broken at event #3")
    expect_colour(page, range(2, 3), EMERALD)
    expect_colour(page, range(3, 4), CRIMSON)
    page.get_by_role("button", name="Restore Original").click()
    expect(page.locator("#chainStatus")).to_contain_text("Record intact: 6 events")
    watch.assert_clean()
    page.close()


def test_the_exported_receipt_checks_itself_offline(
    browser: Any, origin: str, how: str, tmp_path: Path
) -> None:
    page, watch = start(browser, origin, how)
    fly(page, "Provision Sandbox GPU ($35.00)")
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    page.get_by_role("button", name="Sign & Authorize Gate").click()
    expect(page.locator("#mSpent")).to_have_text("$35.00")
    export = page.get_by_role("button", name="Export Verified Receipt (.html)")
    expect(export).to_be_enabled()
    with page.expect_download() as download:
        export.click()
    saved = tmp_path / download.value.suggested_filename
    download.value.save_as(saved)
    assert re.fullmatch(r"hashcam-sandbox-receipt-[0-9a-f]{8}\.html", saved.name), saved.name
    html = saved.read_text(encoding="utf-8")
    assert not re.search(r"(src|href)=\"https?://", html), "the receipt must not load anything"
    watch.assert_clean()
    page.close()

    # Opened straight from disk, on its own: it checks itself and notices an edit.
    receipt, receipt_watch = open_page(browser, origin, "index.html", "file")
    receipt.goto(saved.as_uri())
    banner = receipt.locator("#banner")
    expect(banner).to_contain_text("Record intact: 5 events, all linked · 1 signed decision valid")
    expect(receipt.locator("#rows li.ok")).to_have_count(5)
    assert "ACTION_REQUESTED" not in receipt.inner_text("#rows")
    receipt.locator("summary").click()  # the raw record is behind an opener
    raw = receipt.locator("#edit").input_value()
    assert '"amount_cents": 3500' in raw
    receipt.fill("#edit", raw.replace('"amount_cents": 3500', '"amount_cents": 3400', 1))
    receipt.click("#verify")
    expect(banner).to_contain_text("Record broken")
    assert receipt.locator("#rows li.bad").count() >= 1
    receipt.click("#reset")
    expect(banner).to_contain_text("Record intact")
    # The helper opened index.html first; only the receipt's own errors matter here.
    assert [e for e in receipt_watch.errors if "receipt" in e.lower()] == []
    receipt.close()


# ------------------------------------------------------------ the Merkle tree (why tampering fails)


def pill_gap(page: Any) -> tuple[float, dict[str, float], dict[str, float]]:
    """Pixels of clear space between the signature pill and the root node, and both boxes."""
    seal = page.locator("#merkle .mk-seal").bounding_box()
    root = page.locator("#merkle .mk-node.lv3").bounding_box()
    assert seal and root
    return root["y"] - (seal["y"] + seal["height"]), seal, root


@pytest.mark.parametrize("width", [1280, 768, 375])
def test_the_signature_pill_never_overlaps_the_root_node(
    browser: Any, origin: str, width: int
) -> None:
    page, watch = open_page(
        browser, origin, "index.html", "http", viewport={"width": width, "height": 900}
    )
    page.locator("#merkle").scroll_into_view_if_needed()
    seal_box = page.locator("#merkle .mk-seal")
    expect(seal_box).to_contain_text("Ed25519(root)")
    gap, _, _ = pill_gap(page)
    assert gap >= 8, f"valid state: only {gap}px between the pill and the root at {width}px"

    # Tamper with an event: the pill changes to the longer "no longer matches: INVALID" text.
    page.locator("#merkle .mk-editors input").nth(2).fill("TAMPERED")
    expect(seal_box).to_have_class(re.compile("broken"))
    expect(seal_box).to_contain_text("INVALID")
    page.wait_for_timeout(900)  # let the climb animation settle
    gap, seal, _ = pill_gap(page)
    assert gap >= 8, f"tampered state: only {gap}px between the pill and the root at {width}px"
    stage = page.locator("#merkle .mk-stage").bounding_box()
    assert stage
    assert (
        seal["x"] >= stage["x"] - 1 and seal["x"] + seal["width"] <= stage["x"] + stage["width"] + 1
    )

    # Rotating the tree (arrow keys, as a visitor would) must not bring them together either.
    page.locator("#merkle .mk-stage").focus()
    for key in ("ArrowUp", "ArrowUp", "ArrowUp", "ArrowRight", "ArrowRight"):
        page.keyboard.press(key)
    gap, _, _ = pill_gap(page)
    assert gap >= 8, f"after rotating: only {gap}px between the pill and the root at {width}px"
    watch.assert_clean()
    page.close()


# ------------------------------------------------------- every button, desktop and phone

DEVICES = {
    "desktop": {"viewport": {"width": 1280, "height": 800}},
    "phone": {
        "viewport": {"width": 390, "height": 844},
        "is_mobile": True,
        "has_touch": True,
    },
}


def device_page(browser: Any, origin: str, device: str, name: str) -> tuple[Any, Any, Watch]:
    context = browser.new_context(
        **DEVICES[device], permissions=["clipboard-read", "clipboard-write"]
    )
    page = context.new_page()
    page.set_default_timeout(20_000)
    watch = Watch(page, origin)
    page.goto(f"{origin}/{name}")
    return context, page, watch


@pytest.mark.parametrize("device", list(DEVICES))
def test_every_button_on_the_home_page_works(browser: Any, origin: str, device: str) -> None:
    context, page, watch = device_page(browser, origin, device, "index.html")
    expect(page.locator("#busPlain .lede")).to_be_visible()

    # The navigation: each link moves to its section.
    for label, anchor in (
        ("Attach", "attach"), ("Live", "live"), ("Receipts", "receipt"), ("How it works", "how"),
    ):  # fmt: skip
        page.locator("header nav").get_by_role("link", name=label).click()
        expect(page).to_have_url(re.compile(f"#{anchor}$"))
    page.get_by_role("link", name="See how it works").click()
    expect(page).to_have_url(re.compile("#how$"))

    # The four stops of the telemetry bus, by click and by keyboard.
    for stop, phrases in BUS_STOPS:
        page.locator(f"#busSvg .bus-node[data-i='{stop}']").click()
        expect(page.locator("#busPlain")).to_contain_text(phrases[0])
    page.locator("#busSvg .bus-node[data-i='0']").focus()
    page.keyboard.press("Enter")
    expect(page.locator("#busTitle")).to_have_text("1. SHA-256 Chain")

    # The quickstart tabs; each copy button puts exactly the code shown on the clipboard.
    for index in range(3):
        page.locator(f"#qt{index}").click()
        panel = page.locator(f"#qp{index}")
        expect(panel).to_be_visible()
        copy = panel.locator(".copy")
        shown = copy.locator("xpath=..").locator("code").text_content()
        copy.click()
        expect(copy).to_have_text("Copied ✓")
        clipboard = page.evaluate("navigator.clipboard.readText()")
        assert clipboard.splitlines() == shown.splitlines()  # CRLF on Windows, LF elsewhere

    # Both sample receipts, and the drop zone with its files.
    page.get_by_role("button", name="Genuine sample").click()
    expect(page.locator("#stamp")).to_have_text("VALID")
    page.get_by_role("button", name="Same sample, one event edited").click()
    expect(page.locator("#stamp")).to_have_text("INVALID")
    page.set_input_files(
        "#files", [str(SITE / "samples/genuine.abbreceipt"), str(SITE / "samples/sample.keys.json")]
    )
    expect(page.locator("#stamp")).to_have_text("VALID")

    # The Merkle tree: editing an event breaks the signature pill, and putting it back mends it.
    editor = page.locator("#merkle .mk-editors input").nth(2)
    original = editor.input_value()
    editor.fill("TAMPERED")
    expect(page.locator("#merkle .mk-seal")).to_contain_text("INVALID")
    editor.fill(original)
    expect(page.locator("#merkle .mk-seal")).to_contain_text("Ed25519(root)")
    assert page.evaluate("document.documentElement.scrollWidth - window.innerWidth") <= 1

    # The sandbox buttons lead to the sandbox.
    page.get_by_role("link", name="Launch the Gatekeeper Sandbox").click()
    expect(page).to_have_url(re.compile("sandbox.html$"))
    watch.assert_clean()
    context.close()


def test_the_connect_form_reports_an_unreachable_recorder(browser: Any, origin: str) -> None:
    """The one control that reaches out: with no recorder running it says so, plainly."""
    context, page, _ = device_page(browser, origin, "desktop", "index.html")
    page.fill("#viewerKey", "not-a-real-key")
    page.fill("#viewerPort", "1999")  # nothing listens there
    page.get_by_role("button", name="Connect").click()
    expect(page.locator("#liveState")).to_contain_text("Could not reach your recorder")
    page.get_by_role("button", name="Disconnect").click()
    expect(page.locator("#liveState")).to_contain_text("Not connected")
    context.close()


@pytest.mark.parametrize("device", list(DEVICES))
def test_every_sandbox_button_works(browser: Any, origin: str, device: str, tmp_path: Path) -> None:
    context, page, watch = device_page(browser, origin, device, "sandbox.html")
    expect(page.locator(".flight").first).to_be_enabled()
    fly(page, "Read Repo Docs ($0.00)")
    expect(page.locator("#ledger")).to_contain_text("Allowed: no money moves.")
    fly(page, "Sync External Webhook")
    expect(page.locator("#ledger")).to_contain_text("Denied: hooks.partner-sync.example")
    fly(page, "Provision Sandbox GPU ($35.00)")
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    page.get_by_role("button", name="Sign & Authorize Gate").click()
    expect(page.locator("#mSpent")).to_have_text("$35.00")
    fly(page, "Bulk Token Purchase ($250.00)")
    expect(page.locator("#ledger")).to_contain_text("Denied: $250.00 is more than the $65.00")

    page.get_by_role("button", name="Simulate Tamper").click()
    first = page.locator(".ev-json").nth(1)
    first.fill(first.input_value().replace('"amount_cents": 0', '"amount_cents": 7'))
    expect(page.locator("#chainStatus")).to_contain_text("Record broken at event #1")
    page.get_by_role("button", name="Restore Original").click()
    expect(page.locator("#chainStatus")).to_contain_text("Record intact")
    page.get_by_role("button", name="Simulate Tamper").click()  # back out of tamper mode
    with page.expect_download() as download:
        page.get_by_role("button", name="Export Verified Receipt (.html)").click()
    assert download.value.suggested_filename.startswith("hashcam-sandbox-receipt-")

    page.get_by_role("button", name="Reset session").click()
    expect(page.locator("#mSpent")).to_have_text("$0.00")
    fly(page, "Provision Sandbox GPU ($35.00)")
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    page.get_by_role("button", name="Reject & Halt").click()
    expect(page.locator("#gate")).to_have_attribute("data-state", "halted")
    assert page.evaluate("document.documentElement.scrollWidth - window.innerWidth") <= 1
    watch.assert_clean()
    context.close()


def test_the_atom_survives_a_collapsed_panel(browser: Any, origin: str) -> None:
    """A hidden or collapsed side panel has a tiny canvas; a negative radius used to throw."""
    page, watch = open_page(browser, origin, "index.html", "http")
    result = page.evaluate(
        """() => {
            const canvas = document.createElement("canvas");
            canvas.style.width = "10px";
            canvas.style.height = "10px";
            document.body.append(canvas);
            const state = () => ({ agent: "Agent", trust: 100, counts: {}, waiting: 1 });
            const atom = HCFX.glowAtom(canvas, state);
            try { atom.redraw(); return "drew"; } catch (e) { return e.name + ": " + e.message; }
        }"""
    )
    assert result == "drew", result
    watch.assert_clean()
    page.close()
