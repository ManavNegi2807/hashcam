"""The HashCam website's read-only access to the local recorder.

The site may READ sessions with the separate viewer key, from its own origin only, and can never
start, report, approve or stop anything. The extension's pairing token is unchanged.

Needs `ABB_BIN`, `ABB_SIGNER_BIN` and `ABB_TEST_DSN`.
"""

from __future__ import annotations

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

from services.recorder.server import serve
from services.recorder.session import Recorder

pytestmark = pytest.mark.skipif(
    not (
        os.environ.get("ABB_BIN")
        and os.environ.get("ABB_SIGNER_BIN")
        and os.environ.get("ABB_TEST_DSN")
    ),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)

SITE = "https://hashcam.example"
TOKEN = secrets.token_urlsafe(16)
VIEWER = secrets.token_urlsafe(16)


@pytest.fixture(scope="module")
def base() -> Iterator[dict[str, Any]]:
    work = Path(tempfile.mkdtemp(prefix="viewer-test-"))
    recorder = Recorder.start(
        admin_dsn=os.environ["ABB_TEST_DSN"], work=work, receipts=work / "receipts"
    )
    session = recorder.start_session(
        task="Read docs on shop.test", agent="Agent", passport={"hosts": ["shop.test"]}
    )
    quiet = recorder.start_session(
        task="Check the statement on bank.test",
        agent="Bank agent",
        passport={"hosts": ["bank.test"]},
        sensitive=True,
    )
    # A page address that carries a token in its query string.
    recorder.report(
        session, {"kind": "navigate", "url": "https://shop.test/orders/7?token=SECRET123"}
    )
    recorder.report(
        quiet, {"kind": "navigate", "url": "https://bank.test/accounts/42?token=SECRET123"}
    )
    server = serve(recorder, TOKEN, 0, viewer_token=VIEWER, web_origins=(SITE,))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {
        "url": f"http://127.0.0.1:{server.server_address[1]}",
        "sid": session.session_id,
        "quiet": quiet.session_id,
    }
    server.shutdown()
    recorder.close()


def call(
    base: dict[str, Any],
    path: str,
    *,
    method: str = "GET",
    origin: str | None = SITE,
    key: str = VIEWER,
    extra: dict[str, str] | None = None,
) -> tuple[int, dict[str, str], Any]:
    headers = {"X-HashCam-Token": key, **(extra or {})}
    if origin:
        headers["Origin"] = origin
    data = b"{}" if method == "POST" else None
    request = urllib.request.Request(  # noqa: S310 - loopback test server
        base["url"] + path, data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            raw = response.read()
            return response.status, dict(response.headers), json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        return exc.code, dict(exc.headers), json.loads(raw) if raw else None


def test_the_site_reads_sessions_with_the_viewer_key(base: dict[str, Any]) -> None:
    status, headers, body = call(base, "/sessions")
    assert status == 200
    assert headers["Access-Control-Allow-Origin"] == SITE
    assert body["sessions"][0]["agent"] == "Agent"
    status, _, view = call(base, f"/sessions/{base['sid']}")
    assert status == 200 and view["state"] == "recording"


def test_the_site_can_never_change_anything(base: dict[str, Any]) -> None:
    for path in (
        "/sessions",
        f"/sessions/{base['sid']}/events",
        f"/sessions/{base['sid']}/stop",
        f"/sessions/{base['sid']}/decide",
        "/passkey/challenge",
    ):
        status, _, body = call(base, path, method="POST")
        assert status == 403, path
        assert "only read" in body["error"]
    # Not even with the full pairing token: a web origin is read-only, full stop.
    status, _, _ = call(base, f"/sessions/{base['sid']}/stop", method="POST", key=TOKEN)
    assert status == 403


def test_the_site_needs_the_viewer_key_not_the_pairing_token(base: dict[str, Any]) -> None:
    assert call(base, "/sessions", key="wrong")[0] == 403
    assert call(base, "/sessions", key=TOKEN)[0] == 403


def test_other_sites_are_refused(base: dict[str, Any]) -> None:
    status, headers, _ = call(base, "/sessions", origin="https://evil.example")
    assert status == 403
    assert "Access-Control-Allow-Origin" not in headers


def test_the_viewer_key_does_not_work_for_the_extension_routes(base: dict[str, Any]) -> None:
    # Without a web origin the full pairing token is required.
    assert call(base, "/sessions", origin=None, key=VIEWER)[0] == 403
    assert call(base, "/sessions", origin=None, key=TOKEN)[0] == 200


def test_preflight_allows_reads_from_the_site_only(base: dict[str, Any]) -> None:
    ask = {
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "x-hashcam-token",
        "Access-Control-Request-Private-Network": "true",
    }
    status, headers, _ = call(base, "/sessions", method="OPTIONS", extra=ask)
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == SITE
    assert headers["Access-Control-Allow-Private-Network"] == "true"
    assert headers["Access-Control-Allow-Methods"] == "GET"
    assert (
        call(base, "/sessions", method="OPTIONS", origin="https://evil.example", extra=ask)[0]
        == 403
    )
    post = {**ask, "Access-Control-Request-Method": "POST"}
    assert call(base, f"/sessions/{base['sid']}/stop", method="OPTIONS", extra=post)[0] == 403


def test_the_site_never_sees_a_query_string(base: dict[str, Any]) -> None:
    status, _, view = call(base, f"/sessions/{base['sid']}")
    assert status == 200
    targets = [e["target"] for e in view["timeline"] if e["kind"] == "navigate"]
    assert targets == ["https://shop.test/orders/7"]
    assert "SECRET123" not in json.dumps(view)


def test_a_sensitive_agent_shows_the_site_only_what_it_needs(base: dict[str, Any]) -> None:
    status, _, view = call(base, f"/sessions/{base['quiet']}")
    assert status == 200 and view["sensitive"] is True
    assert view["task"] == "Withheld: this agent is marked sensitive."
    assert view["passport"]["hosts"] == ["(hidden)"]
    targets = [e["target"] for e in view["timeline"] if e["kind"] == "navigate"]
    assert targets == ["https://bank.test"]
    text = json.dumps(view)
    assert "SECRET123" not in text and "accounts" not in text and "statement" not in text
    _, _, listing = call(base, "/sessions")
    row = next(r for r in listing["sessions"] if r["session_id"] == base["quiet"])
    assert row["sensitive"] is True and "statement" not in json.dumps(row)
    # No screenshots of a sensitive agent's pages for the site, even if one is asked for by number.
    assert call(base, f"/sessions/{base['quiet']}/snapshot/0")[0] == 403


def test_the_local_extension_still_sees_the_whole_session(base: dict[str, Any]) -> None:
    # The person's own tools are not cut down: only the website's viewer is.
    status, _, view = call(base, f"/sessions/{base['quiet']}", origin=None, key=TOKEN)
    assert status == 200
    assert view["task"] == "Check the statement on bank.test" and view["sensitive"] is True
    assert any("accounts/42?token=SECRET123" in e["target"] for e in view["timeline"])


EXTENSION = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
PREFLIGHT = {
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "x-hashcam-token,content-type",
    "Access-Control-Request-Private-Network": "true",
}


def test_the_extension_gets_a_proper_cors_answer(base: dict[str, Any]) -> None:
    """Some browsers check CORS for an extension too; a flat 403 cuts it off from the recorder."""
    status, headers, _ = call(
        base, "/sessions", method="OPTIONS", origin=EXTENSION, extra=PREFLIGHT
    )
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == EXTENSION
    assert "X-HashCam-Token" in headers["Access-Control-Allow-Headers"]
    assert "POST" in headers["Access-Control-Allow-Methods"]
    assert headers["Access-Control-Allow-Private-Network"] == "true"
    # With the pairing token it can read the answer; without, it can read the refusal.
    status, headers, body = call(base, "/status", origin=EXTENSION, key=TOKEN)
    assert status == 200 and headers["Access-Control-Allow-Origin"] == EXTENSION
    status, headers, body = call(base, "/status", origin=EXTENSION, key="wrong")
    assert status == 403 and headers["Access-Control-Allow-Origin"] == EXTENSION
    assert "pair the extension" in body["error"]


def test_no_other_web_page_gets_that_answer(base: dict[str, Any]) -> None:
    for origin in ("https://evil.example", "http://127.0.0.1:9999"):
        status, headers, _ = call(base, "/status", origin=origin, key=TOKEN)
        assert status == 403 and "Access-Control-Allow-Origin" not in headers, origin
        status, headers, _ = call(
            base, "/sessions", method="OPTIONS", origin=origin, extra=PREFLIGHT
        )
        assert status == 403 and "Access-Control-Allow-Origin" not in headers, origin
    # The token is still required from the extension's own origin, on every route.
    assert call(base, "/sessions", origin=EXTENSION, key="wrong")[0] == 403
