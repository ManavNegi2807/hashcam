"""The audit dashboard in a real browser (`R-UI-01`..`R-UI-05`, `R-SVC-01`).

What matters most here is what the page refuses to do: show `UNKNOWN` or
`NOT_INDEPENDENT` as green, rely on color alone, render receipt content as
markup, or decide validity itself. Accessibility is checked with axe in both
color schemes.

Needs Playwright and its Chromium (`python -m playwright install chromium`),
and for the live tests a PostgreSQL (`ABB_TEST_DSN`). Missing pieces skip with a
reason; they never pass silently.
"""

from __future__ import annotations

import json
import os
import re
import sys
import threading
import urllib.error
import urllib.request
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

UI = REPO / "ui"


# ------------------------------------------------------------------ static checks


def test_the_page_never_computes_validity_itself() -> None:
    """R-SVC-01, R-UI-04: the verdict comes from `abb verify`, nothing else."""
    source = (UI / "app.js").read_text(encoding="utf-8").lower()
    for forbidden in ("crypto.subtle", "sha256", "sha-256", "ed25519", "digest(", "merkle"):
        assert forbidden not in source, f"app.js mentions {forbidden}"
    # It does not derive an overall result: every overall comes from the report.
    assert "report.overall" in source
    assert not re.search(r"\.overall\s*=[^=]", source), "app.js assigns an overall result"
    assert not re.search(r"dimensions\[[^\]]+\]\s*=[^=]", source), "app.js writes a status"


def test_receipt_content_is_never_inserted_as_markup() -> None:
    source = (UI / "app.js").read_text(encoding="utf-8")
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert forbidden not in source, f"app.js uses {forbidden}"


def test_the_page_loads_nothing_from_elsewhere() -> None:
    html = (UI / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"(?:src|href)=\"https?://", html)
    assert "<script>" not in html  # no inline script: the CSP forbids it too


def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) / 255 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)


def _ratio(a: str, b: str) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def _tokens(block: str) -> dict[str, str]:
    return dict(re.findall(r"--([a-z-]+):\s*(#[0-9a-fA-F]{6})", block))


def test_every_color_pair_meets_4_5_to_1_in_both_schemes() -> None:
    css = (UI / "style.css").read_text(encoding="utf-8")
    light_block = css.split("@media (prefers-color-scheme: dark)")[0]
    dark_block = css.split("@media (prefers-color-scheme: dark)")[1].split("}\n}")[0]
    pairs = [
        ("text", "bg"),
        ("text", "surface"),
        ("muted", "surface"),
        ("muted", "bg"),
        ("accent", "surface"),
        ("ok-fg", "ok-bg"),
        ("fail-fg", "fail-bg"),
        ("unknown-fg", "unknown-bg"),
        ("notind-fg", "notind-bg"),
        ("na-fg", "na-bg"),
        ("ok-fg", "surface"),
        ("fail-fg", "surface"),
        ("unknown-fg", "surface"),
        ("notind-fg", "surface"),
        ("na-fg", "surface"),
    ]
    for name, tokens in (("light", _tokens(light_block)), ("dark", _tokens(dark_block))):
        for fg, bg in pairs:
            assert fg in tokens and bg in tokens, (name, fg, bg)
            assert _ratio(tokens[fg], tokens[bg]) >= 4.5, (name, fg, bg, tokens[fg], tokens[bg])


def test_unknown_and_not_independent_have_their_own_colors_never_the_pass_color() -> None:
    css = (UI / "style.css").read_text(encoding="utf-8")
    for block in (css.split("@media (prefers-color-scheme: dark)")[0],):
        t = _tokens(block)
        ok = (t["ok-fg"], t["ok-bg"])
        for other in ("unknown", "notind", "na", "fail"):
            assert (t[f"{other}-fg"], t[f"{other}-bg"]) != ok


# --------------------------------------------------------------------- the server


def _server(receipts: Path, keys: Path | None, abb: str) -> Iterator[str]:
    from services.dashboard.server import Config, serve

    httpd = serve(Config(receipts=receipts, keys=keys, abb=abb), 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.fixture
def bare_server(tmp_path: Path) -> Iterator[str]:
    """A server over an empty folder: enough for static and saved-report tests."""
    yield from _server(tmp_path, None, "abb")


def _get(url: str) -> tuple[int, dict[str, str], bytes]:
    try:
        with urllib.request.urlopen(url, timeout=10) as response:  # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_the_server_sends_a_strict_content_security_policy(bare_server: str) -> None:
    status, headers, _ = _get(bare_server + "/")
    assert status == 200
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_the_server_is_read_only_and_will_not_leave_its_folder(bare_server: str) -> None:
    for name in ("../../etc/passwd", "..%2f..%2fsecret.abbreceipt", "x.txt", "a/b.abbreceipt"):
        status, _, _ = _get(f"{bare_server}/api/verify?name={name}")
        assert status == 404, name
    request = urllib.request.Request(bare_server + "/api/receipts", data=b"{}", method="POST")  # noqa: S310
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(request, timeout=10)  # noqa: S310
    assert raised.value.code == 405


def test_the_server_listens_on_loopback_only(bare_server: str) -> None:
    assert bare_server.startswith("http://127.0.0.1:")


# ---------------------------------------------------------------- the browser


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        try:
            instance = p.chromium.launch()
        except Exception as exc:
            pytest.skip(f"Chromium is not available: {str(exc).splitlines()[0]}")
        yield instance
        instance.close()


def _page(browser: Any, **options: Any) -> Any:
    context = browser.new_context(**options)
    return context.new_page()


def _saved_report(**overrides: Any) -> dict[str, Any]:
    dims = {
        "evidence_integrity": "PASS",
        "checkpoint_signatures": "PASS",
        "consistency": "PASS",
        "global_log_inclusion": "PASS",
        "artifact_manifest_integrity": "NOT_APPLICABLE",
        "artifact_availability": "UNKNOWN",
        "witness_quorum": "NOT_INDEPENDENT",
        "anchor_match": "NOT_INDEPENDENT",
        "observation_coverage": "PASS",
        "policy_assessment": "PASS",
        "mandate_compliance": "NOT_APPLICABLE",
        "semantic_assessment": "UNKNOWN",
        "prompt_security_assessment": "FAIL",
        "behavior_anomaly_assessment": "UNKNOWN",
        "ml_assessment": "UNKNOWN",
        "execution_outcome": "PASS",
    }
    reqs = {k: "informational" for k in dims}
    for k in (
        "evidence_integrity",
        "checkpoint_signatures",
        "consistency",
        "global_log_inclusion",
        "observation_coverage",
        "policy_assessment",
        "artifact_manifest_integrity",
    ):
        reqs[k] = "required"
    for k in ("witness_quorum", "anchor_match", "artifact_availability", "mandate_compliance"):
        reqs[k] = "optional"
    report = {
        "overall": "PARTIAL",
        "run_id": "00000000-0000-4000-8000-000000000001",
        "profile": "LOCAL_ONLY",
        "declared_coverage": "STEP_GATED",
        "dimensions": dims,
        "requirements": reqs,
        "details": [],
    }
    report.update(overrides)
    return report


def _open_report(page: Any, base: str, tmp: Path, report: dict[str, Any]) -> None:
    page.goto(base + "/")
    path = tmp / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    page.set_input_files("#report-file", str(path))
    page.wait_for_selector("#overall:not([hidden])")


def test_unknown_and_not_independent_are_never_green_and_never_color_alone(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, _saved_report())
    rows = page.locator("#dims-table tbody tr")
    assert rows.count() == 16
    colors: dict[str, set[str]] = {}
    for i in range(rows.count()):
        chip = rows.nth(i).locator(".chip")
        text = chip.inner_text().strip()
        cls = chip.get_attribute("class")
        assert text, "a status must be written out, not only colored"
        assert chip.locator("svg").count() == 1, f"{text} has no icon"
        colors.setdefault(text, set()).add(chip.evaluate("e => getComputedStyle(e).color"))
        if text in {"UNKNOWN", "NOT INDEPENDENT", "FAIL", "NOT APPLICABLE"}:
            assert " ok" not in f" {cls}", f"{text} carries the pass class"
    green = colors["PASS"]
    for status in ("UNKNOWN", "NOT INDEPENDENT", "FAIL", "NOT APPLICABLE"):
        assert colors[status].isdisjoint(green), f"{status} shares the PASS color"
    page.context.close()


def test_the_overall_banner_shows_the_reports_word_and_its_limits(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, _saved_report(overall="VALID"))
    banner = page.locator("#overall-body").inner_text()
    assert "VALID" in banner
    assert "not say the task was safe" in banner
    assert "has not re-verified" in banner  # a saved report is labelled as such
    page.context.close()


@pytest.mark.parametrize(
    "overall", ["PARTIAL", "INCOMPLETE", "INVALID", "UNSUPPORTED", "UNREADABLE"]
)
def test_only_valid_gets_the_pass_styling(
    browser: Any, bare_server: str, tmp_path: Path, overall: str
) -> None:
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, _saved_report(overall=overall))
    assert "ok" not in page.locator("#overall-body .banner").get_attribute("class").split()
    page.context.close()


def test_receipt_text_is_shown_as_text_and_cannot_run(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    hostile = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>'
    report = _saved_report(
        overall="INVALID",
        details=[{"dimension": "evidence_integrity", "message": hostile, "locator": hostile}],
        run_id=hostile,
    )
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, report)
    page.wait_for_timeout(200)
    assert page.evaluate("window.__pwned") is None
    assert page.locator("#findings-list img, #findings-list script").count() == 0
    assert hostile in page.locator("#findings-list").inner_text()
    page.context.close()


def test_a_file_that_is_not_a_report_is_refused_plainly(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    page.goto(bare_server + "/")
    path = tmp_path / "nope.json"
    path.write_text('{"hello": "world"}', encoding="utf-8")
    page.set_input_files("#report-file", str(path))
    page.wait_for_function(
        "document.getElementById('status').textContent.includes('not a verifier')"
    )
    assert page.locator("#overall").is_hidden()
    page.context.close()


def test_the_five_channels_are_shown_separately(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, _saved_report())
    titles = page.locator("#channels-body h3").all_inner_texts()
    assert titles == [
        "Policy",
        "Semantic",
        "Prompt security",
        "Behavior anomaly",
        "Evidence integrity",
    ]
    page.context.close()


def test_the_limits_of_what_the_page_proves_are_on_screen(browser: Any, bare_server: str) -> None:
    page = _page(browser)
    page.goto(bare_server + "/")
    text = page.locator(".notice").inner_text()
    for phrase in (
        "does not mean the task was safe",
        "does not show which person held that key",
        "does not prove a page was truthful",
        "not proof of an attack",
        "never passes",
    ):
        assert phrase in text, phrase
    page.context.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_axe_finds_no_violations(
    browser: Any, bare_server: str, tmp_path: Path, scheme: str
) -> None:
    axe_module = pytest.importorskip("axe_playwright_python.sync_playwright")
    page = _page(browser, color_scheme=scheme)
    _open_report(
        page,
        bare_server,
        tmp_path,
        _saved_report(
            details=[{"dimension": "prompt_security_assessment", "message": "a finding"}]
        ),
    )
    results = axe_module.Axe().run(page)
    violations = [(v["id"], v["impact"], v["help"]) for v in results.response["violations"]]
    assert violations == [], violations
    page.context.close()


def test_keyboard_users_can_skip_to_the_results_and_see_where_focus_is(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    _open_report(page, bare_server, tmp_path, _saved_report())
    page.reload()
    page.keyboard.press("Tab")
    assert page.evaluate("document.activeElement.className") == "skip"
    page.keyboard.press("Enter")
    assert page.evaluate("document.activeElement.id") == "main"
    # Every control that can take focus shows it.
    page.focus("#receipt")
    assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") != "none"
    page.focus("#verify")
    assert page.evaluate("getComputedStyle(document.activeElement).outlineWidth") != "0px"
    page.context.close()


def test_touch_targets_are_at_least_44_pixels(browser: Any, bare_server: str) -> None:
    page = _page(browser)
    page.goto(bare_server + "/")
    for selector in ("#receipt", "#verify", "label.file"):
        box = page.locator(selector).bounding_box()
        assert box is not None and box["height"] >= 44, (selector, box)
    page.context.close()


def test_reduced_motion_turns_transitions_off(browser: Any, bare_server: str) -> None:
    page = _page(browser, reduced_motion="reduce")
    page.goto(bare_server + "/")
    assert page.evaluate(
        "getComputedStyle(document.getElementById('verify')).transitionDuration"
    ) in {
        "0s",
        "0s, 0s",
    }
    page.context.close()


def test_a_phone_width_has_no_sideways_scroll_of_the_page(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser, viewport={"width": 375, "height": 800})
    _open_report(page, bare_server, tmp_path, _saved_report())
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
    page.context.close()


def test_the_page_makes_no_request_to_any_other_origin(
    browser: Any, bare_server: str, tmp_path: Path
) -> None:
    page = _page(browser)
    seen: list[str] = []
    page.on("request", lambda r: seen.append(r.url))
    _open_report(page, bare_server, tmp_path, _saved_report())
    assert seen and all(u.startswith(bare_server) or u.startswith("data:") for u in seen), seen
    page.context.close()


# ----------------------------------------------------------- live, with a real run


@pytest.fixture(scope="module")
def live(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    pytest.importorskip("psycopg")
    if not os.environ.get("ABB_TEST_DSN"):
        pytest.skip("set ABB_TEST_DSN to run the dashboard against real receipts")

    from tests.tamper import test_approvals_mandate as env
    from tests.tamper.test_tamper_suite import read_receipt, write_receipt

    # Reuse the approvals module's stack fixture by calling its generator directly.
    manager = env.ctx.__wrapped__(tmp_path_factory)  # type: ignore[attr-defined]
    context = next(manager)
    try:
        good = env.produce(context, "bank_change_approval", approve="GRANTED")
        folder = tmp_path_factory.mktemp("receipts")
        (folder / "good.abbreceipt").write_bytes(good["receipt"].read_bytes())

        import base64

        document = read_receipt(good["receipt"])
        for event in document["events"]:
            canonical = base64.b64decode(event["canonical_b64"])
            if b"BROWSER_OBSERVATION" in canonical:
                at = canonical.find(b'"text_digest":"') + len(b'"text_digest":"')
                flipped = bytearray(canonical)
                flipped[at] = ord("0") if chr(flipped[at]) != "0" else ord("1")
                event["canonical_b64"] = base64.b64encode(bytes(flipped)).decode("ascii")
                break
        write_receipt(document, folder / "tampered.abbreceipt", keep_artifacts_from=good["receipt"])
        yield {"folder": folder, "keys": good["keys"], "abb": good["abb"]}
    finally:
        try:
            next(manager)
        except StopIteration:
            pass


def test_a_real_receipt_verifies_in_the_page(browser: Any, live: dict[str, Any]) -> None:
    gen = _server(live["folder"], live["keys"], live["abb"])
    base = next(gen)
    try:
        page = _page(browser)
        page.goto(base + "/")
        page.select_option("#receipt", "good.abbreceipt")
        page.click("#verify")
        page.wait_for_selector("#overall:not([hidden])")
        assert "VALID" in page.locator("#overall-body .big").inner_text()
        assert "ok" in page.locator("#overall-body .banner").get_attribute("class").split()
        assert page.locator("#dims-table tbody tr").count() == 16
        assert page.locator("#events-table tbody tr").count() > 10
        # The approval panel keeps the limit attached to the signature.
        assert "not which person held it" in page.locator("#run-body").inner_text()
        page.context.close()
    finally:
        _drain(gen)


def test_a_tampered_receipt_shows_invalid_and_names_the_failing_check(
    browser: Any, live: dict[str, Any]
) -> None:
    gen = _server(live["folder"], live["keys"], live["abb"])
    base = next(gen)
    try:
        page = _page(browser)
        page.goto(base + "/")
        page.select_option("#receipt", "tampered.abbreceipt")
        page.click("#verify")
        page.wait_for_selector("#overall:not([hidden])")
        assert "INVALID" in page.locator("#overall-body .big").inner_text()
        findings = page.locator("#findings-list").inner_text()
        assert "Evidence integrity" in findings
        assert "ok" not in page.locator("#overall-body .banner").get_attribute("class").split()
        page.context.close()
    finally:
        _drain(gen)


def test_without_a_key_manifest_the_page_says_signatures_were_not_judged(
    browser: Any, live: dict[str, Any]
) -> None:
    gen = _server(live["folder"], None, live["abb"])
    base = next(gen)
    try:
        page = _page(browser)
        page.goto(base + "/")
        page.select_option("#receipt", "good.abbreceipt")
        page.click("#verify")
        page.wait_for_selector("#overall:not([hidden])")
        assert "No key manifest" in page.locator("#overall-body").inner_text()
        assert "VALID" != page.locator("#overall-body .big").inner_text().strip()
        page.context.close()
    finally:
        _drain(gen)


def test_the_servers_verdict_is_the_clis_verdict_with_nothing_added(live: dict[str, Any]) -> None:
    import subprocess

    gen = _server(live["folder"], live["keys"], live["abb"])
    base = next(gen)
    try:
        _, _, body = _get(base + "/api/verify?name=good.abbreceipt")
        served = json.loads(body)
        direct = json.loads(
            subprocess.run(  # noqa: S603
                [
                    live["abb"],
                    "verify",
                    str(live["folder"] / "good.abbreceipt"),
                    "--keys",
                    str(live["keys"]),
                    "--profile",
                    "LOCAL_ONLY",
                    "--json",
                ],
                capture_output=True,
                check=False,
            ).stdout
        )
        for extra in ("exit_code", "keys_supplied"):
            served.pop(extra)
        assert served == direct
    finally:
        _drain(gen)


def _drain(gen: Iterator[str]) -> None:
    try:
        next(gen)
    except StopIteration:
        pass
