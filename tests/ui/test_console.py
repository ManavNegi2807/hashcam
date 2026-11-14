"""The HashCam Console: receipt viewer, domino verdict, live view, guards, reduced motion.

Receipts are made by the real recorder (signer, ledger, `abb verify`); the tampered one has one
edited event. The page is driven in a real Chromium. Needs `ABB_BIN`, `ABB_SIGNER_BIN` and
`ABB_TEST_DSN`; the layout-independent checks run without them.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from services.dashboard.console import RecorderLink
from services.dashboard.server import Config, serve

REPO = Path(__file__).resolve().parents[2]
NEEDS_STACK = pytest.mark.skipif(
    not (
        os.environ.get("ABB_BIN")
        and os.environ.get("ABB_SIGNER_BIN")
        and os.environ.get("ABB_TEST_DSN")
    ),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)


# ---------------------------------------------------------------- shared files


def test_the_extension_uses_the_same_theme_and_animations_as_the_console() -> None:
    for name in ("theme.css", "fx3d.js"):
        assert (REPO / "ui" / name).read_bytes() == (REPO / "extension" / name).read_bytes(), name


def test_verdict_colours_are_reserved_and_unknown_is_never_green() -> None:
    theme = (REPO / "ui" / "theme.css").read_text(encoding="utf-8")
    assert "--hc-valid: #3DDC97" in theme
    assert "--hc-unknown: #B9A7FF" in theme
    for line in theme.splitlines():
        if "UNKNOWN" in line and "{" in line:
            assert "--hc-valid" not in line


# ---------------------------------------------------------------- fixtures


@pytest.fixture(scope="module")
def stack() -> Iterator[dict[str, Any]]:
    if not (
        os.environ.get("ABB_BIN")
        and os.environ.get("ABB_SIGNER_BIN")
        and os.environ.get("ABB_TEST_DSN")
    ):
        pytest.skip("needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN")
    from services.recorder.server import serve as serve_recorder
    from services.recorder.session import Recorder
    from tests.recorder.test_recorder_service import edit_one_event

    work = Path(tempfile.mkdtemp(prefix="console-test-"))
    recorder = Recorder.start(
        admin_dsn=os.environ["ABB_TEST_DSN"], work=work, receipts=work / "receipts"
    )
    token = secrets.token_urlsafe(16)
    token_file = work / "token"
    token_file.write_text(token, encoding="utf-8")
    rec_server = serve_recorder(recorder, token, 0)
    threading.Thread(target=rec_server.serve_forever, daemon=True).start()

    # One sealed session (VALID), one copy with an edited event (INVALID), one session left open.
    sealed = recorder.start_session(
        task="Buy one notebook on shop.test", agent="Test agent", passport={"hosts": ["shop.test"]}
    )
    recorder.report(sealed, {"kind": "navigate", "url": "https://shop.test/"})
    recorder.report(sealed, {"kind": "navigate", "url": "https://bank.test/"})  # blocked
    name = recorder.stop(sealed, killed=False)["receipt"]
    valid = work / "receipts" / name
    invalid = work / "receipts" / ("tampered-" + name)
    edit_one_event(valid, invalid)
    open_session = recorder.start_session(
        task="Read docs on shop.test", agent="Live agent", passport={"hosts": ["shop.test"]}
    )
    recorder.report(open_session, {"kind": "navigate", "url": "https://shop.test/docs"})

    config = Config(
        receipts=work / "receipts",
        keys=None,
        abb=os.environ["ABB_BIN"],
        recorder=RecorderLink(f"http://127.0.0.1:{rec_server.server_address[1]}", token_file),
    )
    server = serve(config, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {
        "base": f"http://127.0.0.1:{server.server_address[1]}",
        "valid": valid,
        "invalid": invalid,
        "keys": valid.with_name(valid.name + ".keys.json"),
        "open_id": open_session.session_id,
        "work": work,
    }
    server.shutdown()
    rec_server.shutdown()
    recorder.close()


def post(base: str, path: str, body: Any, headers: dict[str, str] | None = None) -> tuple[int, Any]:
    request = urllib.request.Request(  # noqa: S310 - loopback test server
        base + path,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def get(base: str, path: str) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(base + path, timeout=30) as response:  # noqa: S310
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def upload_body(receipt: Path, keys: Path | None) -> dict[str, str]:
    return {
        "receipt_b64": base64.b64encode(receipt.read_bytes()).decode(),
        "keys_json": keys.read_text(encoding="utf-8") if keys else "",
    }


# ---------------------------------------------------------------- the server side


@NEEDS_STACK
def test_inspect_returns_the_verifiers_own_verdict(stack: dict[str, Any]) -> None:
    status, answer = post(stack["base"], "/api/inspect", upload_body(stack["valid"], stack["keys"]))
    assert status == 200
    assert answer["verdict"]["overall"] == "VALID"
    assert answer["summary"]["events"]
    status, answer = post(
        stack["base"], "/api/inspect", upload_body(stack["invalid"], stack["keys"])
    )
    assert answer["verdict"]["overall"] == "INVALID"
    assert answer["verdict"]["dimensions"]["evidence_integrity"] == "FAIL"


@NEEDS_STACK
def test_without_keys_signatures_are_never_passed(stack: dict[str, Any]) -> None:
    _, answer = post(stack["base"], "/api/inspect", upload_body(stack["valid"], None))
    assert answer["verdict"]["overall"] != "VALID"


@NEEDS_STACK
def test_inspect_refuses_a_foreign_origin_and_junk(stack: dict[str, Any]) -> None:
    status, _ = post(
        stack["base"],
        "/api/inspect",
        upload_body(stack["valid"], None),
        {"Origin": "https://evil.example"},
    )
    assert status == 403
    status, answer = post(
        stack["base"], "/api/inspect", {"receipt_b64": base64.b64encode(b"hello").decode()}
    )
    assert status == 400 and "not a .abbreceipt" in answer["error"]


@NEEDS_STACK
def test_live_view_reads_the_recorder_without_exposing_the_token(stack: dict[str, Any]) -> None:
    status, answer = get(stack["base"], "/api/live/sessions")
    assert status == 200
    agents = {s["agent"]: s for s in answer["sessions"]}
    assert agents["Live agent"]["state"] == "recording"
    assert agents["Test agent"]["counts"]["blocked"] == 1
    status, view = get(stack["base"], f"/api/live/session?id={stack['open_id']}")
    assert status == 200 and view["agent"] == "Live agent"
    token = (stack["work"] / "token").read_text(encoding="utf-8")
    assert token not in json.dumps(answer) and token not in json.dumps(view)
    assert get(stack["base"], "/api/live/session?id=../../etc")[0] == 404


# ---------------------------------------------------------------- the page, in a real browser


@NEEDS_STACK
@pytest.mark.parametrize("reduced", [False, True], ids=["motion", "reduced-motion"])
def test_receipt_viewer_and_domino_verdict(stack: dict[str, Any], reduced: bool) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(
            viewport={"width": 1280, "height": 900},
            reduced_motion="reduce" if reduced else "no-preference",
        )
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.add_init_script("localStorage.setItem('hc-onboarded', '1')")
        page.goto(stack["base"] + "/console")

        # VALID: every tile before the first FAIL falls; the stamp is the verifier's word.
        page.set_input_files("#files", [str(stack["valid"]), str(stack["keys"])])
        page.wait_for_selector("#receiptOut:not([hidden])", timeout=120_000)
        assert page.inner_text("#stamp") == "VALID"
        check_dominoes(page, reduced)
        assert page.locator("#eventRoll li").count() > 3
        assert page.locator("#graph svg").count() == 1

        # INVALID: the edited receipt.
        page.set_input_files("#files", [str(stack["invalid"]), str(stack["keys"])])
        # The page's own CSP forbids eval, so wait with Playwright's assertion, not a JS string.
        sync_api.expect(page.locator("#stamp")).to_have_text("INVALID", timeout=120_000)
        check_dominoes(page, reduced)
        assert "evidence_integrity" in page.inner_text("#dominoes")

        if reduced:
            assert page.locator(".hero.still").count() == 1  # the synthwave hero is drawn still
        page.screenshot(
            path=str(stack["work"] / f"console-{'still' if reduced else 'motion'}.png"),
            full_page=True,
        )
        assert errors == []
        browser.close()


def check_dominoes(page: Any, reduced: bool) -> None:
    statuses = page.eval_on_selector_all(
        "#dominoes .domino", "els => els.map(e => e.className.match(/d-(\\w+)/)[1])"
    )
    assert statuses, "no dominoes drawn"
    fail_at = statuses.index("FAIL") if "FAIL" in statuses else len(statuses)
    if not reduced:
        page.wait_for_timeout(300 + 120 * len(statuses))
    fallen = page.eval_on_selector_all(
        "#dominoes .domino",
        "els => els.map(e => e.classList.contains('fallen')"
        " || getComputedStyle(e).transform !== 'none')",
    )
    assert fallen[:fail_at] == [True] * fail_at, statuses
    assert not any(fallen[fail_at + 1 :]), "tiles after a FAIL must stay standing"
    # The same facts in text, for screen readers and for anyone not watching the animation.
    assert page.locator("#dominoes .dims li").count() == len(statuses)
