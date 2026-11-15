# ruff: noqa: E501
"""The extension's locked session report, its watermark, glass cards and tab animation.

The report modules (session-report.js, lockedpdf.js, report-art.js) call no extension APIs,
so they are loaded here as plain modules from a local server and run in a real browser, as shipped.
The PDF is then opened with an independent library: it must refuse every wrong password and open
with the right one. (The whole panel inside a real Chrome is covered by
tests/recorder/test_extension_e2e.py.)

Needs only a browser (and pypdf for the PDF checks).
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import re
import threading
from collections.abc import Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

REPO = Path(__file__).resolve().parents[2]
EXT = REPO / "extension"


class Quiet(http.server.SimpleHTTPRequestHandler):
    extensions_map = {  # noqa: RUF012
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
    }

    def log_message(self, format: str, *args: Any) -> None:
        pass


@pytest.fixture(scope="module")
def origin() -> Iterator[str]:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(EXT)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


def event(n: int, kind: str, status: str, **more: Any) -> dict[str, Any]:
    return {"n": n, "kind": kind, "status": status, "reasons": [], **more}


def view(**more: Any) -> dict[str, Any]:
    return {
        "session_id": "s1",
        "agent": "Browser agent",
        "task": "Buy one notebook on shop.test",
        "sensitive": False,
        "state": "sealed",
        "started": 1_700_000_000,
        "receipt": "run-1.abbreceipt",
        "passport": {"hosts": ["shop.test"]},
        "verdict": {"overall": "VALID", "dimensions": {}},
        "timeline": [
            event(1, "SESSION", "RECORDING", reasons=["passport: shop.test"]),
            event(2, "navigate", "ALLOWED", target="https://shop.test/cart"),
            event(
                3, "secret", "COMMITTED", field_kind="password", target="https://shop.test/login"
            ),
            event(4, "form_submit", "APPROVED", target="https://shop.test/pay?token=SECRETVALUE99"),
            event(
                5,
                "navigate",
                "BLOCKED",
                target="https://bank.example/home",
                reasons=["DOMAIN_NOT_ALLOWED"],
                drift={"host": "bank.example"},
            ),
            event(6, "SEALED", "VALID"),
        ],
        **more,
    }


SHA = hashlib.sha256(b"a receipt").hexdigest()


def make(
    browser: Any, origin: str, tmp_path: Path, data: dict[str, Any], sha: str = SHA
) -> tuple[Path, str]:
    pypdf = pytest.importorskip("pypdf")
    del pypdf
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto(f"{origin}/manifest.json")
    got = page.evaluate(
        "async ([v, sha]) => { const m = await import('/session-report.js'); const { bytes, password } = await m.makeSessionReport(v, sha);"
        " let s = ''; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode(...bytes.subarray(i, i + 8192));"
        " return { b64: btoa(s), password }; }",
        [data, sha],
    )
    page.close()
    assert errors == [], errors
    out = tmp_path / "session.pdf"
    out.write_bytes(base64.b64decode(got["b64"]))
    return out, got["password"]


def read(pdf: Path, password: str) -> str:
    import pypdf

    opened = pypdf.PdfReader(str(pdf))
    assert opened.decrypt(password) != 0
    return " ".join(" ".join(p.extract_text() for p in opened.pages).split())


def test_the_report_opens_only_with_its_password_and_tells_the_story(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    import pypdf

    pdf, password = make(browser, origin, tmp_path, view())
    assert re.fullmatch(r"(?:[2-9A-HJKMNP-Z]{5}-){4}[2-9A-HJKMNP-Z]{5}", password)
    raw = pdf.read_bytes()
    assert b"/AESV3" in raw and b"/R 6" in raw and raw.count(b"/DCTDecode") == 2
    for word in (b"VALID", b"bank.example", b"Browser agent", b"shop.test", password.encode()):
        assert word not in raw, word
    for wrong in ("", "password", password.lower(), password[:-1], password + "A"):
        assert pypdf.PdfReader(str(pdf)).decrypt(wrong) == 0, wrong
    text = read(pdf, password)
    for part in (
        "HashCam Recorder Agent session report",
        "RESULT VALID",
        "Session of Browser agent",
        "Its task: Buy one notebook on shop.test",
        "What your agent did well",
        "Opened shop.test/cart",
        "PROTECTED",
        "What went wrong",
        "Stopped from opening bank.example/home",
        "HEADS-UP",
        "bank.example is not one of the sites the task mentions",
        "What to do next",
        "Look at each blocked step",
        "It went to sites the task does not mention",
        "How this was checked",
        "The offline verifier says VALID",
        f"SHA-256 {SHA}",
        "locked with AES-256",
    ):
        assert part in text, part
    assert "SECRETVALUE99" not in text and "token=" not in text, (
        "a URL's query string is never shown"
    )
    assert "Do not rely on this record" not in text


def test_a_sensitive_agent_gets_a_report_that_leaves_its_details_out(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    pdf, password = make(browser, origin, tmp_path, view(sensitive=True))
    text = read(pdf, password)
    assert "The task is withheld: this agent is marked sensitive." in text
    assert "Buy one notebook" not in text
    assert "shop.test/cart" not in text and "bank.example/home" not in text, "paths are left out"
    assert "Opened shop.test" in text, "the host is still said"
    assert "marked sensitive: its task, its paths and its raw records are left out" in text


def test_a_record_that_is_not_valid_says_not_to_rely_on_it(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    pdf, password = make(
        browser, origin, tmp_path, view(verdict={"overall": "INVALID", "dimensions": {}}), sha=""
    )
    text = read(pdf, password)
    assert "RESULT INVALID" in text and "Do not rely on this record" in text
    assert "SHA-256" not in text, "no fingerprint is made up when the receipt could not be read"


def test_a_secret_in_the_task_is_masked(browser: Any, origin: str, tmp_path: Path) -> None:
    pdf, password = make(
        browser, origin, tmp_path, view(task="Use key sk_live_ABCDEFGH12345678 on shop.test")
    )
    text = read(pdf, password)
    assert "sk_live_ABCDEFGH12345678" not in text and "Its task: Use key" in text


def test_a_long_session_says_and_n_more_instead_of_filling_the_file(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    long = view()
    long["timeline"] = [
        event(i, "navigate", "ALLOWED", target=f"https://shop.test/page-{i}") for i in range(2, 130)
    ]
    pdf, password = make(browser, origin, tmp_path, long)
    text = read(pdf, password)
    assert "and 88 more" in text and "page-129" not in text and "Page 1 of" in text


def test_every_report_gets_its_own_password(browser: Any, origin: str, tmp_path: Path) -> None:
    seen = {make(browser, origin, tmp_path, view())[1] for _ in range(3)}
    assert len(seen) == 3


# ---------------------------------------------------------------- the files


def test_the_extension_keeps_the_shared_pdf_module_byte_for_byte() -> None:
    source = (REPO / "ui" / "lockedpdf.js").read_text(encoding="utf-8")
    assert (EXT / "lockedpdf.js").read_text(encoding="utf-8") == source
    assert not re.search(r"^import ", source, re.MULTILINE), "the shared module imports nothing"
    # The site's classic copy has the same code.
    classic = (REPO / "site" / "lockedpdf.js").read_text(encoding="utf-8")
    assert "window.HCLockedPdf = { newPassword, hash2B, buildLockedPdf }" in classic
    assert not re.search(r"^export ", classic, re.MULTILINE)


def test_the_panel_has_the_report_button_the_watermark_and_the_tab_animation() -> None:
    html = (EXT / "sidepanel.html").read_text(encoding="utf-8")
    assert '<link rel="stylesheet" href="brand.css">' in html
    js = (EXT / "panel.js").read_text(encoding="utf-8")
    assert 'import { makeSessionReport } from "./session-report.js"' in js
    assert "Locked report (.pdf)" in js and 'id: "reportKey"' in js
    assert "textContent = password" in js and "localStorage" not in js.split("saveReport")[1][:1800]
    css = (EXT / "panel.css").read_text(encoding="utf-8")
    assert ".tabs button::after" in css and "scaleX(1)" in css
    assert "prefers-reduced-motion" in css.split(".tabs button::after")[1][:900]
    assert "backdrop-filter: blur(2px)" in css, "glass cards"
    brand = (EXT / "brand.css").read_text(encoding="utf-8")
    assert "body::before" in brand and 'url("data:image/webp;base64,' in brand
    assert "pointer-events: none" in brand and "z-index: -1" in brand


def test_no_script_is_added_that_the_extensions_policy_would_refuse() -> None:
    manifest = json.loads((EXT / "manifest.json").read_text(encoding="utf-8"))
    policy = json.dumps(manifest.get("content_security_policy", {}))
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
    for name in ("session-report.js", "lockedpdf.js", "report-art.js"):
        source = (EXT / name).read_text(encoding="utf-8")
        assert not re.search(r"\beval\(|new Function|innerHTML|document\.write", source), name
        assert "chrome." not in source, (
            f"{name} stays free of extension APIs so it can be tested alone"
        )
