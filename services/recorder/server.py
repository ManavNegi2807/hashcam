"""The recorder's HTTP API, for the browser extension only.

Served on 127.0.0.1. Every request needs the pairing token in `X-HashCam-Token`, a loopback
`Host`, and either no `Origin` or a `chrome-extension://` one: a web page the agent opens cannot
drive this API, because it cannot read the token and its origin is refused.
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

from services.recorder.session import Recorder, RecorderError

MAX_BODY = 8_000_000
_LOOPBACK = re.compile(r"^(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")


def make_handler(recorder: Recorder, token: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "HashCamRecorder"
        sys_version = ""

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
            self.end_headers()
            self.wfile.write(data)

        def _guard(self) -> str | None:
            if not _LOOPBACK.match(self.headers.get("Host", "")):
                return "loopback only"
            origin = self.headers.get("Origin")
            if origin is not None and not origin.startswith("chrome-extension://"):
                return "this API answers the HashCam extension only"
            given = self.headers.get("X-HashCam-Token", "")
            if not secrets.compare_digest(given.encode(), token.encode()):
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
            problem = self._guard()
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
                )
                return (recorder.view(session),)
            if method == "POST" and path == "/verify":
                return (self._verify_upload(self._body()),)
            if len(parts) >= 2 and parts[0] == "sessions":
                session = recorder.get(parts[1])
                tail = "/".join(parts[2:])
                if method == "GET" and tail == "":
                    return (recorder.view(session),)
                if method == "GET" and tail.startswith("snapshot/") and tail[9:].isdigit():
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


def serve(recorder: Recorder, token: str, port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(recorder, token))
