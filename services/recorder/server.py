"""The recorder's HTTP API, for the browser extension (and, read-only, the HashCam website).

Served on 127.0.0.1. Every request needs a loopback `Host` and a token in `X-HashCam-Token`.

* The extension (a `chrome-extension://` origin, or no origin for local tools) uses the pairing
  token and may do everything.
* A web page may call only if its origin is on the `web_origins` list given at start (the public
  HashCam site), only the read-only routes (status, sessions, one session, a snapshot), and only
  with the separate **viewer token**. It can look; it cannot start, report, approve or stop. What
  it sees is cut down by `public.py`: no query strings, and nothing sensitive for a session marked
  sensitive.
* Any other origin is refused: a page the agent opens cannot drive this API.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from services.recorder.public import public_row, public_view
from services.recorder.session import Recorder, RecorderError

MAX_BODY = 8_000_000
_LOOPBACK = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")
_VIEWER_ROUTE = re.compile(
    r"^/(status|sessions|sessions/[0-9a-f]{12}|sessions/[0-9a-f]{12}/snapshot/\d+)$"
)


def make_handler(
    recorder: Recorder,
    token: str,
    viewer_token: str | None = None,
    web_origins: tuple[str, ...] = (),
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "HashCamRecorder"
        sys_version = ""
        cors_origin: str | None = None

        def log_message(self, *_: Any) -> None:  # nothing about requests is logged
            return

        # ------------------------------------------------------------ plumbing

        def _send(self, status: int, body: Any, content_type: str = "application/json") -> None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self._cors_headers()
            self.end_headers()
            self.wfile.write(data)

        def _cors_headers(self) -> None:
            if self.cors_origin:
                self.send_header("Access-Control-Allow-Origin", self.cors_origin)
                self.send_header("Vary", "Origin")

        def do_OPTIONS(self) -> None:
            origin = self.headers.get("Origin")
            path = self.path.split("?", 1)[0]
            if (
                origin in web_origins
                and _LOOPBACK.match(self.headers.get("Host", ""))
                and self.headers.get("Access-Control-Request-Method") == "GET"
                and _VIEWER_ROUTE.match(path)
            ):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET")
                self.send_header("Access-Control-Allow-Headers", "X-HashCam-Token")
                # Chrome's Private Network Access: a public page may reach this computer only
                # if this answer says so.
                self.send_header("Access-Control-Allow-Private-Network", "true")
                self.send_header("Access-Control-Max-Age", "600")
                self.send_header("Vary", "Origin")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def _guard(self, method: str) -> str | None:
            if not _LOOPBACK.match(self.headers.get("Host", "")):
                return "loopback only"
            origin = self.headers.get("Origin")
            given = self.headers.get("X-HashCam-Token", "").encode()
            if origin is not None and origin in web_origins:
                # The website: read-only routes, viewer token only.
                self.cors_origin = origin
                path = self.path.split("?", 1)[0]
                if method != "GET" or not _VIEWER_ROUTE.match(path):
                    return "the website may only read sessions"
                if not viewer_token or not secrets.compare_digest(given, viewer_token.encode()):
                    return "paste the viewer key from the recorder first"
                return None
            if origin is not None and not origin.startswith("chrome-extension://"):
                return "this API answers the HashCam extension only"
            if not secrets.compare_digest(given, token.encode()):
                return "pair the extension first"
            return None

        def _body(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise RecorderError("the request is too large", 413)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise RecorderError("the body must be JSON") from None
            if not isinstance(body, dict):
                raise RecorderError("the body must be a JSON object")
            return body

        def _handle(self, method: str) -> None:
            problem = self._guard(method)
            if problem:
                self._send(403, {"error": problem})
                return
            try:
                self._send(200, *self._route(method))
            except RecorderError as exc:
                self._send(exc.status, {"error": str(exc)})
            except Exception:
                self._send(500, {"error": "the recorder hit an internal error"})

        def do_GET(self) -> None:
            self._handle("GET")

        def do_POST(self) -> None:
            self._handle("POST")

        # -------------------------------------------------------------- routes

        def _route(self, method: str) -> tuple[Any, ...]:
            path = self.path.split("?", 1)[0]
            parts = [p for p in path.split("/") if p]
            if method == "GET" and path == "/status":
                return (
                    {
                        "ok": True,
                        "passkey": recorder.credential is not None,
                        "sessions": len(recorder.sessions),
                    },
                )
            if method == "GET" and path == "/sessions":
                finish = public_row if self.cors_origin else (lambda row: row)
                return (
                    {
                        "sessions": [
                            finish(
                                {
                                    k: view[k]
                                    for k in (
                                        "session_id",
                                        "agent",
                                        "task",
                                        "sensitive",
                                        "state",
                                        "started",
                                        "trust",
                                    )
                                }
                                | {
                                    "counts": _counts(view["timeline"]),
                                    "waiting": len(view["waiting"]),
                                }
                            )
                            for view in (recorder.view(s) for s in list(recorder.sessions.values()))
                        ]
                    },
                )
            if method == "POST" and path == "/passkey/challenge":
                body = self._body()
                return (
                    {
                        "challenge": recorder.passkey_challenge(
                            str(body.get("purpose", "")),
                            decision=str(body.get("decision", "")),
                            digest=str(body.get("summary_digest", "")),
                        )
                    },
                )
            if method == "POST" and path == "/passkey/register":
                origin = self.headers.get("Origin") or ""
                if not origin.startswith("chrome-extension://"):
                    raise RecorderError("a passkey can be registered from the extension only")
                recorder.passkey_register(self._body(), origin)
                return ({"ok": True},)
            if method == "POST" and path == "/sessions":
                body = self._body()
                session = recorder.start_session(
                    task=body.get("task", ""),
                    agent=body.get("agent", ""),
                    passport=body.get("passport") or {},
                    sensitive=bool(body.get("sensitive")),
                )
                return (recorder.view(session),)
            if method == "POST" and path == "/verify":
                return (self._verify_upload(self._body()),)
            if len(parts) >= 2 and parts[0] == "sessions":
                session = recorder.get(parts[1])
                tail = "/".join(parts[2:])
                if method == "GET" and tail == "":
                    view = recorder.view(session)
                    return (public_view(view) if self.cors_origin else view,)
                if method == "GET" and tail.startswith("snapshot/") and tail[9:].isdigit():
                    if self.cors_origin and session.sensitive:
                        raise RecorderError("screenshots are hidden for a sensitive agent", 403)
                    data = session.snapshots.get(int(tail[9:]))
                    if data is None:
                        raise RecorderError("no such snapshot", 404)
                    return (data, "image/png")
                if method == "GET" and tail in ("receipt", "receipt-keys"):
                    if not session.receipt:
                        raise RecorderError("the session is not sealed yet", 409)
                    name = session.receipt + (".keys.json" if tail == "receipt-keys" else "")
                    return (
                        (recorder.receipts / name).read_bytes(),
                        "application/json" if tail == "receipt-keys" else "application/zip",
                    )
                if method == "POST" and tail == "events":
                    return (recorder.report(session, self._body()),)
                if method == "POST" and tail == "observe":
                    return (recorder.observe(session, self._body()),)
                if method == "POST" and tail == "decide":
                    return (recorder.decide(session, self._body()),)
                if method == "POST" and tail == "stop":
                    body = self._body()
                    return (recorder.stop(session, killed=bool(body.get("killed"))),)
            raise RecorderError("not found", 404)

        @staticmethod
        def _verify_upload(body: dict[str, Any]) -> dict[str, Any]:
            """Verify a receipt the person dropped onto the verify page, with `abb verify`."""
            try:
                data = base64.b64decode(str(body.get("receipt_b64", "")), validate=True)
                keys = body.get("keys_json")
            except ValueError:
                raise RecorderError("the receipt is not base64") from None
            if not data.startswith(b"PK"):
                raise RecorderError("that is not a .abbreceipt file")
            with tempfile.TemporaryDirectory(prefix="hashcam-verify-") as tmp:
                path = Path(tmp) / "dropped.abbreceipt"
                path.write_bytes(data)
                if isinstance(keys, str) and keys:
                    json.loads(keys)  # must at least be JSON
                    (Path(tmp) / "dropped.abbreceipt.keys.json").write_text(keys, encoding="utf-8")
                return recorder.verify(path)

    return Handler


def _counts(timeline: list[dict[str, Any]]) -> dict[str, int]:
    """How many events ended in each outcome, for the console's 3D overview."""
    counts = {"allowed": 0, "approved": 0, "blocked": 0, "tripwire": 0}
    for e in timeline:
        if e["kind"] in ("SESSION", "SEALED"):
            continue
        if e.get("tripwire"):
            counts["tripwire"] += 1
        if e["status"] in ("ALLOWED", "COMMITTED"):
            counts["allowed"] += 1
        elif e["status"] == "APPROVED":
            counts["approved"] += 1
        elif e["status"] in ("BLOCKED", "DENIED", "TIMED_OUT", "NOT_SENT"):
            counts["blocked"] += 1
    return counts


def serve(
    recorder: Recorder,
    token: str,
    port: int,
    *,
    viewer_token: str | None = None,
    web_origins: tuple[str, ...] = (),
) -> ThreadingHTTPServer:
    handler = make_handler(recorder, token, viewer_token, web_origins)
    return ThreadingHTTPServer(("127.0.0.1", port), handler)
