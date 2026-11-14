"""The public HashCam site (site/), served with the same headers Vercel serves it with.

* The in-browser verifier (WebAssembly) gives exactly the verdict `abb verify --json` gives for
  the same receipt and keys: genuine, edited, and without keys.
* The live view reads a real local recorder with the read-only viewer key, from the site's own
  origin, under the site's content security policy.

Needs `site/verifier.wasm` (python tools/build_site.py), `ABB_BIN`, `ABB_SIGNER_BIN` and
`ABB_TEST_DSN`.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import tempfile
import threading
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, SiteHandler

pytestmark = pytest.mark.skipif(
    not (
        os.environ.get("ABB_BIN")
        and os.environ.get("ABB_SIGNER_BIN")
        and os.environ.get("ABB_TEST_DSN")
        and (SITE / "verifier.wasm").exists()
    ),
    reason="needs site/verifier.wasm, ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)
sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def world() -> Iterator[dict[str, Any]]:
    from services.recorder.server import serve
    from services.recorder.session import Recorder

    site = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{site.server_address[1]}"

    work = Path(tempfile.mkdtemp(prefix="site-test-"))
    recorder = Recorder.start(
        admin_dsn=os.environ["ABB_TEST_DSN"], work=work, receipts=work / "receipts"
    )
    session = recorder.start_session(
        task="Read docs on shop.test", agent="Site test agent", passport={"hosts": ["shop.test"]}
    )
    recorder.report(session, {"kind": "navigate", "url": "https://shop.test/docs"})
    viewer = secrets.token_urlsafe(16)
    rec = serve(recorder, secrets.token_urlsafe(16), 0, viewer_token=viewer, web_origins=(origin,))
    threading.Thread(target=rec.serve_forever, daemon=True).start()
    yield {"origin": origin, "viewer": viewer, "port": rec.server_address[1]}
    rec.shutdown()
    recorder.close()
    site.shutdown()


def cli(receipt: Path, keys: Path | None) -> dict[str, Any]:
    argv = [os.environ["ABB_BIN"], "verify", str(receipt), "--json", "--profile", "LOCAL_ONLY"]
    if keys:
        argv += ["--keys", str(keys)]
    done = subprocess.run(argv, capture_output=True, check=False)  # noqa: S603 - fixed argv
    result: dict[str, Any] = json.loads(done.stdout)
    return result


def page_verdict(page: Any) -> tuple[str, dict[str, str]]:
    names = page.eval_on_selector_all(
        "#dominoes .dims li span:first-child", "e => e.map(x => x.textContent)"
    )
    stats = page.eval_on_selector_all(
        "#dominoes .dims li span:last-child", "e => e.map(x => x.textContent)"
    )
    return page.inner_text("#stamp"), dict(zip(names, stats, strict=True))


@pytest.mark.parametrize(
    ("button", "receipt", "keys"),
    [
        ("#sampleValid", "genuine.abbreceipt", True),
        ("#sampleInvalid", "edited.abbreceipt", True),
        (None, "genuine.abbreceipt", False),
    ],
    ids=["genuine", "edited", "no-keys"],
)
def test_the_browser_verifier_matches_abb_verify(
    world: dict[str, Any], button: str | None, receipt: str, keys: bool
) -> None:
    samples = SITE / "samples"
    expected = cli(samples / receipt, samples / "sample.keys.json" if keys else None)
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(reduced_motion="reduce")
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(world["origin"] + "/")
        if button:
            page.click(button)
        else:
            page.set_input_files("#files", [str(samples / receipt)])
        sync_api.expect(page.locator("#stamp")).to_have_text(expected["overall"], timeout=60_000)
        overall, dims = page_verdict(page)
        assert overall == expected["overall"]
        assert dims == expected["dimensions"]
        assert errors == []
        browser.close()


def test_the_live_view_reads_the_local_recorder_with_the_viewer_key(world: dict[str, Any]) -> None:
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.goto(world["origin"] + "/")
        assert "sample" in page.inner_text("#liveState").lower()
        page.fill("#viewerPort", str(world["port"]))
        page.fill("#viewerKey", world["viewer"])
        page.click("#connect button[type=submit]")
        sync_api.expect(page.locator("#liveState")).to_contain_text(
            "Connected to your recorder", timeout=30_000
        )
        sync_api.expect(page.locator("#sessionList")).to_contain_text("Site test agent")
        sync_api.expect(page.locator("#coreTitle")).to_contain_text("Site test agent")
        assert page.locator("#sampleNote").is_hidden()
        assert page.locator("#viewerKey").input_value() == ""  # the key is not left in the field
        assert errors == []
        browser.close()


def test_a_wrong_viewer_key_shows_an_error_and_keeps_the_sample(world: dict[str, Any]) -> None:
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(world["origin"] + "/")
        page.fill("#viewerPort", str(world["port"]))
        page.fill("#viewerKey", "wrong-key")
        page.click("#connect button[type=submit]")
        sync_api.expect(page.locator("#liveState")).to_contain_text(
            "Could not reach your recorder", timeout=30_000
        )
        assert page.locator("#sampleNote").is_visible()
        browser.close()
