"""The site's motion: no library, one easing, compositor-only, no layout shift, still when asked.

* No animation library or CDN: the site animates with the browser's own Web Animations API.
* A tour of each page (home from disk and over http, the sandbox approved and rejected) has no console
  error, shifts nothing (layout-shift is 0), and animates only transform, opacity, stroke-dashoffset
  (and the individual `scale`/`translate`/`rotate` properties): never a width, height, colour or filter.
* Digests (SHA-256, the Merkle root, the run's id) scramble through hex for about 320ms and lock,
  left to right, into the real value, including when an event is edited and when a receipt is checked.
* The hero's telemetry core, the cursor-following card light, the tactile buttons, the sliding tab
  underline, the staggered entrances and "A risky step, from start to seal" all work.
* With prefers-reduced-motion, everything is shown at once and nothing runs.

Needs only a browser (no recorder, no database).
"""

# ruff: noqa: E501  (the page-side JavaScript in the strings below is easier to read on long lines)

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from itertools import pairwise
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

EASE = "cubic-bezier(0.16, 1, 0.3, 1)"
# The only things allowed to animate: none of them repaints or reflows a frame.
COMPOSITOR = {"transform", "opacity", "strokeDashoffset", "scale", "translate", "rotate"}
STEPS = [
    "The agent asks to submit an order form.",
    "The gateway checks the rules: spending money needs a person.",
    "You hold your finger on the passkey. Only then is your key used.",
    "The step is sealed into a receipt anyone can check offline.",
]
LEAVES = [
    "RUN_STARTED",
    "PAGE shop.test",
    "SECRET password",
    "SUBMIT form",
    "APPROVED",
    "DISPATCHED",
    "PAGE /thanks",
    "RUN_FINISHED",
]


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


@pytest.fixture(params=["http", "file"])
def how(request: pytest.FixtureRequest) -> str:
    return str(request.param)


# Records every property any animation or transition touches, and every layout shift.
WATCH = """
window.__m = { props: {}, shifts: 0, shiftList: [], errs: [] };
const SKIP = ["offset", "computedOffset", "easing", "composite"];
const label = (t) => {
  if (!t) return "?";
  const c = typeof t.className === "string" ? t.className : (t.className && t.className.baseVal) || "";
  return t.tagName + (t.id ? "#" + t.id : "") + (c ? "." + c.trim().split(/\\s+/).join(".") : "");
};
const scan = () => {
  try {
    for (const a of document.getAnimations()) {
      const eff = a.effect;
      const where = label(eff && eff.target) + ((eff && eff.pseudoElement) || "");
      const names = a.constructor.name === "CSSTransition" ? [a.transitionProperty] : [];
      if (eff && !names.length) for (const kf of eff.getKeyframes()) for (const k of Object.keys(kf)) if (!SKIP.includes(k)) names.push(k);
      for (const n of new Set(names)) window.__m.props[n + " @ " + where] = n;
    }
  } catch (e) { window.__m.errs.push(String(e)); }
  requestAnimationFrame(scan);
};
requestAnimationFrame(scan);
try {
  new PerformanceObserver((list) => {
    for (const e of list.getEntries()) if (!e.hadRecentInput) {
      window.__m.shifts += e.value;
      window.__m.shiftList.push([Math.round(e.startTime), e.value, (e.sources || []).map((s) => label(s.node))]);
    }
  }).observe({ type: "layout-shift", buffered: true });
} catch (e) { window.__m.errs.push(String(e)); }
"""


class Watch:
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


def open_page(
    browser: Any, origin: str, name: str, how: str = "http", init: str = "", **kw: Any
) -> tuple[Any, Watch]:
    page = browser.new_page(**{"viewport": {"width": 1280, "height": 800}, **kw})
    page.set_default_timeout(20_000)
    watch = Watch(page, origin)
    page.add_init_script(WATCH)
    if init:
        page.add_init_script(init)
    page.goto(f"{origin}/{name}" if how == "http" else (SITE / name).as_uri())
    return page, watch


def scroll_through(page: Any) -> None:
    height = page.evaluate("document.documentElement.scrollHeight")
    for _ in range(int(height / 380) + 1):
        page.mouse.wheel(0, 380)
        page.wait_for_timeout(120)
    page.wait_for_timeout(900)


# ---------------------------------------------------------------- the files


def test_no_animation_library_and_no_cdn() -> None:
    for name in ("index.html", "sandbox.html"):
        html = (SITE / name).read_text(encoding="utf-8")
        assert "gsap" not in html.lower(), name
        assert not re.search(r'<(?:script|link)[^>]+(?:src|href)="https?:', html), name
        assert 'href="motion.css"' in html and 'src="motion.js"' in html, name
    for script in ("site.js", "showcase.js", "sandbox.js", "motion.js", "chain.js"):
        assert "gsap" not in (SITE / script).read_text(encoding="utf-8").lower(), script
    assert not list((SITE / "vendor").glob("*gsap*"))


# ---------------------------------------------------------------- a tour of each page


def tour_home(page: Any) -> None:
    scroll_through(page)
    page.evaluate("window.scrollTo(0, 0)")
    for selector in (".panel", ".card", "#launchSandbox", ".qs-tab", ".copy"):
        target = page.locator(selector).first
        if target.count():
            target.scroll_into_view_if_needed()
            target.hover()
            page.wait_for_timeout(350)
    page.locator("#busSvg .bus-node[data-i='2']").click()
    page.locator(".qs-tab").nth(1).click()
    page.locator("#sampleValid").scroll_into_view_if_needed()
    page.locator("#sampleValid").click()
    page.wait_for_timeout(1200)
    page.locator("#sampleInvalid").click()
    page.wait_for_timeout(1200)
    editor = page.locator("#merkle .mk-editors input").nth(2)
    editor.scroll_into_view_if_needed()
    editor.fill("TAMPERED")
    page.wait_for_timeout(900)
    editor.fill("SECRET password")
    page.wait_for_timeout(900)


def tour_sandbox(page: Any, reject: bool) -> None:
    scroll_through(page)
    page.evaluate("window.scrollTo(0, 0)")
    page.get_by_role("button", name="Read Repo Docs ($0.00)").click()
    page.wait_for_timeout(500)
    page.get_by_role("button", name="Provision Sandbox GPU ($35.00)").click()
    expect(page.locator("#gate")).to_have_attribute("data-state", "held")
    page.wait_for_timeout(1200)
    if reject:
        page.get_by_role("button", name="Reject & Halt").click()
        page.wait_for_timeout(1200)
        return
    page.get_by_role("button", name="Sign & Authorize Gate").click()
    page.wait_for_timeout(1200)
    page.get_by_role("button", name="Simulate Tamper").click()
    area = page.locator(".ev-json").nth(1)
    area.fill(area.input_value().replace('"amount_cents": 0', '"amount_cents": 9999'))
    page.wait_for_timeout(900)
    page.get_by_role("button", name="Restore Original").click()
    page.wait_for_timeout(900)


@pytest.mark.parametrize(
    ("name", "scenario"),
    [("index.html", "home"), ("sandbox.html", "approve"), ("sandbox.html", "reject")],
)
def test_a_tour_is_clean_shifts_nothing_and_animates_only_the_compositor(
    browser: Any, origin: str, how: str, name: str, scenario: str
) -> None:
    page, watch = open_page(browser, origin, name, how)
    if scenario == "home":
        tour_home(page)
    else:
        tour_sandbox(page, reject=scenario == "reject")
    seen = page.evaluate("window.__m")
    watch.assert_clean()
    assert seen["errs"] == [], seen["errs"]
    # Over http (as deployed) the font is preloaded by a response header and nothing shifts. From a
    # file:// page there is no header, so the one-off swap to the page font may nudge the header
    # text by a hair (the page still moves nothing else).
    limit = 0 if how == "http" else 0.001
    assert seen["shifts"] <= limit, f"layout shifted by {seen['shifts']}: {seen['shiftList']}"
    offenders = {where: prop for where, prop in seen["props"].items() if prop not in COMPOSITOR}
    assert offenders == {}, offenders
    assert seen["props"], "nothing animated at all: the audit did not see the motion"
    page.close()


# ---------------------------------------------------------------- reduced motion


def test_reduced_motion_shows_everything_still(browser: Any, origin: str, how: str) -> None:
    page, watch = open_page(browser, origin, "index.html", how, reduced_motion="reduce")
    scroll_through(page)
    assert page.evaluate("document.getAnimations().length") == 0
    assert page.evaluate(
        "[...document.querySelectorAll('[data-reveal]')].every(n => getComputedStyle(n).opacity === '1'"
        " && getComputedStyle(n).transform === 'none')"
    )
    # The risky-step flow is already in its final state, with no Replay to press.
    expect(page.locator(".flow-state")).to_have_text("AUTHORIZED")
    expect(page.locator(".flow-hash")).to_contain_text("sha256 ")
    expect(page.locator(".flow-replay")).to_be_hidden()
    # A digest is set at once, never scrambled.
    page.locator("#merkle .mk-editors input").nth(2).fill("TAMPERED")
    root = page.locator("#merkle .mk-node.lv3 code")
    want = merkle_root([*LEAVES[:2], "TAMPERED", *LEAVES[3:]])[:8]
    expect(root).to_have_text(want, timeout=2000)
    for _ in range(5):
        assert root.inner_text() == want
        page.wait_for_timeout(40)
    assert page.evaluate("document.getAnimations().length") == 0
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- 3. the hex scramble


def merkle_root(leaves: list[str]) -> str:
    level = [hashlib.sha256(t.encode()).hexdigest() for t in leaves]
    while len(level) > 1:
        level = [
            hashlib.sha256((level[i] + level[i + 1]).encode()).hexdigest()
            for i in range(0, len(level), 2)
        ]
    return level[0]


def test_a_digest_scrambles_for_about_320ms_then_locks_left_to_right(
    browser: Any, origin: str
) -> None:
    page, watch = open_page(browser, origin, "index.html")
    final = hashlib.sha256(b"HashCam").hexdigest()
    run = page.evaluate(
        """async (final) => {
          const node = document.createElement("code");
          document.body.append(node);
          const frames = [];
          let took = null;
          const t0 = performance.now();
          const sample = (now) => { frames.push([now - t0, node.textContent]); if (took === null) requestAnimationFrame(sample); };
          requestAnimationFrame(sample);
          await window.HCMotion.settle(node, final);
          took = performance.now() - t0;
          node.remove();
          return { took, frames };
        }""",
        final,
    )
    # About 320ms (a frame or two over on a slow machine), never instant and never long.
    assert 300 <= run["took"] <= 520, run["took"]
    frames = run["frames"]
    assert len(frames) >= 3, "the scramble was not drawn frame by frame"
    for _, text in frames:
        assert len(text) == len(final) and re.fullmatch(r"[0-9a-f]+", text), text
    # It locks left to right: what the scramble has passed is already the real digest, and what it
    # has not reached is still random. (Each sample may lag the one before it by a frame.)
    for (t_before, _), (_, text) in pairwise(frames):
        locked = int(min(1.0, max(t_before, 0) / 320) * len(final)) - 2
        assert text[: max(0, locked)] == final[: max(0, locked)], (t_before, text)
    mid = [text for t, text in frames if 60 < t < 250]
    assert mid, "no frame landed mid-scramble"
    assert any(text[40:] != final[40:] for text in mid), mid
    # Characters that are not hex digits are left alone.
    kept = page.evaluate(
        """async () => {
          const node = document.createElement("code");
          document.body.append(node);
          const seen = [];
          const p = window.HCMotion.settle(node, "run 3cea…9527 - e0");
          for (let i = 0; i < 4; i++) { await new Promise(r => requestAnimationFrame(r)); seen.push(node.textContent); }
          await p;
          node.remove();
          return seen;
        }"""
    )
    for text in kept:
        assert text[3] == " " and text[8] == "…" and text[13] == " " and text[14] == "-", text
    watch.assert_clean()
    page.close()


def test_editing_an_event_scrambles_the_hashes_into_their_real_values(
    browser: Any, origin: str
) -> None:
    page, watch = open_page(browser, origin, "index.html")
    page.locator("#merkle").scroll_into_view_if_needed()
    root = page.locator("#merkle .mk-node.lv3 code")
    expect(root).to_have_text(merkle_root(LEAVES)[:8])
    page.locator("#merkle .mk-editors input").nth(2).fill("TAMPERED")
    edited = [*LEAVES[:2], "TAMPERED", *LEAVES[3:]]
    # Mid-way it is still hex, still eight characters, and not yet the answer ...
    page.wait_for_timeout(110)
    assert re.fullmatch(r"[0-9a-f]{8}", root.inner_text())
    # ... and then it is exactly SHA-256 of the edited events, with the signature pill broken.
    expect(root).to_have_text(merkle_root(edited)[:8], timeout=2000)
    expect(page.locator("#merkle .mk-seal")).to_contain_text("INVALID")
    leaf = page.locator("#merkle .mk-node.lv0 code").nth(2)
    expect(leaf).to_have_text(hashlib.sha256(b"TAMPERED").hexdigest()[:8])
    page.locator("#merkle .mk-editors input").nth(2).fill("SECRET password")
    expect(root).to_have_text(merkle_root(LEAVES)[:8], timeout=2000)
    expect(page.locator("#merkle .mk-seal")).to_contain_text("Ed25519(root) ✓")
    watch.assert_clean()
    page.close()


def test_checking_a_receipt_scrambles_the_run_digest_into_place(
    browser: Any, origin: str, how: str
) -> None:
    page, watch = open_page(browser, origin, "index.html", how)
    page.locator("#sampleValid").scroll_into_view_if_needed()
    page.locator("#sampleValid").click()
    digest = page.locator("#runDigest")
    expect(digest).to_have_text(re.compile(r"^run [0-9a-f]{8,}$"), timeout=10_000)
    assert page.locator("#runDigest .hex").count() == 1
    page.wait_for_timeout(900)  # past the scramble: now it is the real id
    final = digest.inner_text()
    assert re.fullmatch(r"run [0-9a-f]{32}", final), final
    page.wait_for_timeout(500)
    assert digest.inner_text() == final, "it settled and stayed"
    page.locator("#sampleInvalid").click()
    expect(page.locator("#verdictPlain")).not_to_be_empty()
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- 2. the telemetry core


def test_the_hero_shows_a_telemetry_core_not_the_old_circle(browser: Any, origin: str) -> None:
    page, watch = open_page(browser, origin, "index.html")
    page.wait_for_timeout(1400)
    assert page.locator(".synth-sun").count() == 0, "the retro REC circle is gone"
    core = page.locator("#core.hero-core")
    expect(core).to_be_visible()
    assert page.evaluate("getComputedStyle(document.querySelector('#core')).position") == "absolute"
    assert page.evaluate("document.querySelector('.hero').getBoundingClientRect().height") < 700
    # Hairline rings turning in opposite directions, data-bus arcs, a breathing REC glow.
    names = page.evaluate(
        "[...document.querySelectorAll('#core *')].flatMap(n => n.getAnimations().map(a => a.animationName))"
    )
    assert {"coreCW", "coreCCW", "coreBus", "recBreath"} <= set(names), names
    assert page.locator("#core .core-turn").count() == 2
    assert page.locator("#core .core-arc").count() == 3
    expect(page.locator("#core .core-rec-text")).to_have_text("REC")
    # Dark glass: a translucent panel with a hairline edge. No live blur (it would be recomputed
    # every frame the grid rolls behind it).
    glass = page.evaluate(
        "(() => { const s = getComputedStyle(document.querySelector('#core'));"
        " return [s.backdropFilter, s.backgroundImage, s.borderTopWidth]; })()"
    )
    assert glass[0] == "none" and "rgba" in glass[1] and glass[2] == "1px", glass
    # Only transform, opacity and stroke-dashoffset move.
    moved = page.evaluate(
        "[...new Set([...document.querySelectorAll('#core, #core *')].flatMap(n => n.getAnimations()"
        ".flatMap(a => a.effect.getKeyframes().flatMap(k => Object.keys(k)))))]"
    )
    assert set(moved) - {"offset", "computedOffset", "easing", "composite"} <= COMPOSITOR, moved
    # A radial spotlight follows the mouse over the perspective grid.
    page.mouse.move(300, 240)
    page.mouse.move(420, 330)
    page.wait_for_timeout(500)
    got = page.evaluate(
        "(() => { const s = document.querySelector('.hero').style;"
        " return [s.getPropertyValue('--mouse-x'), s.getPropertyValue('--mouse-y')]; })()"
    )
    assert got[0].endswith("px") and got[1].endswith("px"), got
    assert abs(float(got[0][:-2]) - 420) < 2 and abs(float(got[1][:-2]) - (330 - 63)) < 4, got
    expect(page.locator(".synth-spot")).to_have_css("opacity", "1")
    assert "matrix" in page.evaluate(
        "getComputedStyle(document.querySelector('.synth-spot')).transform"
    )
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- 4. cards, buttons, tabs


def test_cards_light_their_border_where_the_pointer_is(browser: Any, origin: str) -> None:
    page, watch = open_page(browser, origin, "index.html")
    scroll_through(page)
    card = page.locator("#attach .card").first
    card.scroll_into_view_if_needed()
    page.wait_for_timeout(300)
    box = card.bounding_box()
    assert box is not None
    page.mouse.move(box["x"] + 40, box["y"] + 30)
    page.mouse.move(box["x"] + 90, box["y"] + 60)
    page.wait_for_timeout(700)
    x = card.evaluate("n => n.style.getPropertyValue('--mouse-x')")
    y = card.evaluate("n => n.style.getPropertyValue('--mouse-y')")
    assert abs(float(x[:-2]) - 90) < 3 and abs(float(y[:-2]) - 60) < 3, (x, y)
    light = card.evaluate(
        "n => { const s = getComputedStyle(n, '::after'); return [s.opacity, s.maskComposite || s.webkitMaskComposite, s.backgroundImage]; }"
    )
    assert light[0] == "1", light
    assert "radial-gradient" in light[2], light
    watch.assert_clean()
    page.close()


def test_buttons_have_weight(browser: Any, origin: str) -> None:
    page, watch = open_page(browser, origin, "index.html")
    button = page.locator("#launchSandbox")
    assert (
        page.evaluate("getComputedStyle(document.querySelector('#launchSandbox')).transform")
        == "none"
    )
    button.hover()
    expect(button).to_have_css("transform", "matrix(1, 0, 0, 1, 0, -1)")
    page.mouse.down()
    expect(button).to_have_css("transform", "matrix(0.985, 0, 0, 0.985, 0, 0)")
    page.mouse.move(2, 400)  # let go away from the link, so nothing is followed
    page.mouse.up()
    assert page.url.endswith("index.html")
    watch.assert_clean()
    page.close()


def test_the_tab_underline_slides_to_the_selected_tab(browser: Any, origin: str) -> None:
    page, watch = open_page(browser, origin, "index.html")
    page.locator(".qs-tabs").scroll_into_view_if_needed()
    bar = page.locator(".qs-tabs .tab-ind")
    expect(bar).to_have_count(1)
    for index in (1, 2, 0):
        tab = page.locator(".qs-tab").nth(index)
        tab.click()
        page.wait_for_timeout(1000)
        t, b = tab.bounding_box(), bar.bounding_box()
        assert t is not None and b is not None
        assert abs(t["x"] - b["x"]) < 2 and abs(t["width"] - b["width"]) < 2, (index, t, b)
    assert bar.evaluate("n => getComputedStyle(n).transitionTimingFunction") == EASE
    watch.assert_clean()
    page.close()


# ---------------------------------------------------------------- 1. entrances and the easing


RECORD_REVEALS = """
window.__rv = [];
const animate = Element.prototype.animate;
Element.prototype.animate = function (keyframes, options) {
  if (this.hasAttribute && this.hasAttribute("data-reveal")) {
    window.__rv.push({ delay: options.delay, easing: options.easing, from: keyframes[0].transform, opacity: keyframes[0].opacity });
  }
  return animate.call(this, keyframes, options);
};
"""


def test_cards_rise_in_with_a_sixty_millisecond_stagger(browser: Any, origin: str) -> None:
    page, watch = open_page(browser, origin, "index.html", init=RECORD_REVEALS)
    below = page.locator("#attach [data-reveal]")
    assert below.count() >= 2
    assert below.first.evaluate("n => getComputedStyle(n).opacity") == "0"
    assert below.first.evaluate("n => n.classList.contains('in')") is False
    page.evaluate("window.__rv.length = 0")
    page.locator("#attach").scroll_into_view_if_needed()
    for _ in range(80):  # (wait_for_function would need eval, which the page's policy forbids)
        if page.evaluate("window.__rv.length") >= 2:
            break
        page.wait_for_timeout(100)
    timings = page.evaluate("window.__rv")
    delays = sorted({t["delay"] for t in timings})
    assert delays[0] == 0 and 60 in delays, delays
    assert all(t["easing"] == EASE for t in timings), timings
    assert all(
        t["from"] == "translateY(14px) scale(0.985)" and str(t["opacity"]) == "0" for t in timings
    )
    expect(below.first).to_have_css("opacity", "1", timeout=5000)
    expect(below.first).to_have_css("transform", "none", timeout=5000)
    watch.assert_clean()
    page.close()


def test_every_transition_uses_the_expo_out_curve(browser: Any, origin: str) -> None:
    pairs_of = (
        "n => { const s = getComputedStyle(n);"
        " const t = s.transitionTimingFunction.split(/, (?=[a-z])/), d = s.transitionDuration.split(', ');"
        " return d.map((dur, i) => [parseFloat(dur), t[i % t.length]]); }"
    )
    for name, selectors in (
        (
            "index.html",
            [".btn", ".panel", ".card", ".qs-tab", ".stage-list li", ".story-step", ".tab-ind"],
        ),
        ("sandbox.html", [".flight", ".jaw", ".meter-liquid", ".meter-hold", ".panel"]),
    ):
        page, _ = open_page(browser, origin, name)
        for selector in selectors:
            pairs = page.locator(selector).first.evaluate(pairs_of)
            for duration, timing in pairs:
                if duration > 0:  # a colour that switches at once has no curve to check
                    assert timing == EASE, (name, selector, pairs)
        page.close()


# ---------------------------------------------------------------- 5. a risky step, from start to seal


def test_a_risky_step_runs_from_start_to_seal(browser: Any, origin: str, how: str) -> None:
    page, watch = open_page(browser, origin, "index.html", how)
    flow = page.locator("#cartoon")
    flow.scroll_into_view_if_needed()
    state = page.locator("#cartoon .flow-state")
    # Idle until it is on screen, then the packet pulses ride the rails ...
    page.wait_for_timeout(1000)
    packets = page.evaluate(
        "[...document.querySelectorAll('#cartoon .flow-packet')].flatMap(n => n.getAnimations())"
        ".length"
    )
    assert packets >= 1, "a packet pulse is travelling a rail"
    # ... the passkey hold fills a ring, then the seal snaps in ...
    expect(state).to_have_text("HELD", timeout=8000)
    ring = page.locator("#cartoon .flow-ring")
    assert ring.evaluate("n => n.getAnimations().length") == 1
    expect(state).to_have_text("AUTHORIZED", timeout=8000)
    assert ring.evaluate("n => getComputedStyle(n).strokeDashoffset") == "0px"
    page.wait_for_timeout(800)
    assert (
        float(page.locator("#cartoon .flow-seal").evaluate("n => getComputedStyle(n).opacity"))
        == 1.0
    )
    # ... and the receipt carries the real SHA-256 of the story, scrambled into place.
    want = hashlib.sha256(" ".join(STEPS).encode()).hexdigest()[:16]
    expect(page.locator("#cartoon .flow-hash")).to_have_text("sha256 " + want, timeout=4000)
    expect(page.locator("#cartoon .flow-node.ok")).to_have_count(2)
    expect(page.locator("#cartoon .flow-steps li.on")).to_have_text(STEPS[3])
    # Replay runs it again from the start.
    page.get_by_role("button", name="Replay").click()
    expect(page.locator("#cartoon .flow-node.ok")).to_have_count(0)
    expect(state).to_have_text("HELD", timeout=8000)
    expect(state).to_have_text("AUTHORIZED", timeout=8000)
    expect(page.locator("#cartoon .flow-hash")).to_have_text("sha256 " + want, timeout=4000)
    watch.assert_clean()
    page.close()
