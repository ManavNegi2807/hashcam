"""A local site that tries to get around the gateway (`R-TST-04`).

One server, two names. It is reached as `127.0.0.1` (the *allowed* origin) and as
`localhost` (the *forbidden* origin: same machine, different host name, so the
policy and the SSRF rules treat it as somewhere the agent may not go). Every
probe page, loaded from the allowed origin, tries to reach the forbidden one by a
different route: `fetch`, XHR, a beacon, an image, a script, an iframe, a
WebSocket, `window.open`, a link with `target=_blank`, a form with
`target=_blank`, a service worker, a redirect chain, a redirect to a private
address, and a download.

The server records the `Host` header of every request it receives. If a request
arrives for `localhost`, the gateway was bypassed: the browser reached a place it
should not have. That is the whole test, and it does not depend on trusting the
adapter's own records.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

#: Every probe, by name. The self-test and the bypass tests iterate this list.
PROBES = (
    "fetch",
    "xhr",
    "beacon",
    "img",
    "script",
    "iframe",
    "websocket",
    "popup",
    "tab",
    "formblank",
    "serviceworker",
    "redirect",
    "redirect_private",
    "download",
)

PAGE = (
    "<!doctype html><meta charset=utf-8><title>{title}</title><body><h1>{title}</h1>{body}</body>"
)

SERVICE_WORKER = """
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const forbidden = new URL(self.location.origin);
  forbidden.hostname = 'localhost';
  e.waitUntil(fetch(forbidden.origin + '/secret/serviceworker').catch(() => {}));
});
"""


def _probe_body(name: str) -> str:
    # `F` is the forbidden origin, worked out in the page from where it was loaded.
    prelude = (
        "<script>const F = location.origin.replace('127.0.0.1', 'localhost');"
        "const S = F + '/secret/{name}'; window.__done = false;</script>"
    ).replace("{name}", name)
    scripts = {
        "fetch": "fetch(S).catch(() => {}).finally(() => { window.__done = true; });",
        "xhr": (
            "const x = new XMLHttpRequest(); x.open('GET', S);"
            "x.onloadend = () => { window.__done = true; }; x.send();"
        ),
        "beacon": "navigator.sendBeacon(S, 'x'); window.__done = true;",
        "img": "const i = new Image(); i.onerror = i.onload = () => { window.__done = true; }; i.src = S;",
        "script": (
            "const s = document.createElement('script'); s.onerror = s.onload = "
            "() => { window.__done = true; }; s.src = S; document.head.appendChild(s);"
        ),
        "iframe": (
            "const f = document.createElement('iframe'); f.onload = f.onerror = "
            "() => { window.__done = true; }; f.src = S; document.body.appendChild(f);"
        ),
        "websocket": (
            "const w = new WebSocket(S.replace('http', 'ws'));"
            "w.onerror = w.onclose = () => { window.__done = true; };"
            "setTimeout(() => { window.__done = true; }, 600);"
        ),
        "popup": "window.open(S); window.__done = true;",
        "tab": (
            "const a = document.createElement('a'); a.href = S; a.target = '_blank';"
            "document.body.appendChild(a); a.click(); window.__done = true;"
        ),
        "formblank": (
            "const f = document.createElement('form'); f.method = 'POST'; f.action = S;"
            "f.target = '_blank'; document.body.appendChild(f); f.submit(); window.__done = true;"
        ),
        "serviceworker": (
            "navigator.serviceWorker.register('/sw.js').then(() => fetch('/'))"
            ".catch(() => {}).finally(() => { setTimeout(() => { window.__done = true; }, 500); });"
        ),
        "redirect": "location.href = '/redirect?to=' + encodeURIComponent(S);",
        "redirect_private": "location.href = '/redirect-private';",
        "download": (
            "const a = document.createElement('a'); a.href = F + '/secret/download.bin';"
            "a.download = 'x.bin'; document.body.appendChild(a); a.click(); window.__done = true;"
        ),
    }
    return prelude + f"<script>{scripts[name]}</script>"


@dataclass
class Hit:
    host: str
    path: str
    method: str
    upgrade: bool


@dataclass
class ProbeSite:
    """Start with `start()`, stop with `stop()`. Use as a context manager."""

    hits: list[Hit] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _second: ThreadingHTTPServer | None = None  # the same site on 127.0.0.2
    _lock: threading.Lock = field(default_factory=threading.Lock)

    # ------------------------------------------------------------- lifecycle

    def start(self) -> ProbeSite:
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                return

            def _record(self) -> None:
                host = (self.headers.get("Host") or "").split(":")[0]
                with site._lock:
                    site.hits.append(
                        Hit(
                            host=host,
                            path=self.path,
                            method=self.command,
                            upgrade=bool(self.headers.get("Upgrade")),
                        )
                    )

            def _send(
                self, status: int, body: bytes, ctype: str, extra: dict[str, str] | None = None
            ) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body)

            def _html(self, title: str, body: str) -> None:
                self._send(
                    200, PAGE.format(title=title, body=body).encode(), "text/html; charset=utf-8"
                )

            def do_GET(self) -> None:
                self._record()
                url = urlparse(self.path)
                path = url.path
                if path == "/":
                    self._html(
                        "Local portal",
                        '<p>Vendor 42</p><a id="next" href="/form">Edit contact</a>'
                        '<a id="api" href="/api/data">data</a>',
                    )
                elif path == "/form":
                    self._html(
                        "Contact form",
                        '<form id="f" method="POST" action="/submit">'
                        '<label for="email">Email</label><input id="email" name="email">'
                        '<button id="go" type="submit">Save</button></form>',
                    )
                elif path == "/api/data":
                    self._send(200, b'{"ok": true}', "application/json")
                elif path == "/sw.js":
                    self._send(200, SERVICE_WORKER.encode(), "text/javascript")
                elif path.startswith("/probe/"):
                    name = path.removeprefix("/probe/")
                    if name in PROBES:
                        self._html(f"probe {name}", _probe_body(name))
                    else:
                        self._send(404, b"no such probe", "text/plain")
                elif path == "/redirect":
                    target = parse_qs(url.query).get("to", ["/"])[0]
                    self._send(302, b"", "text/plain", {"Location": target})
                elif path == "/loop":
                    self._send(302, b"", "text/plain", {"Location": "/loop"})
                elif path == "/redirect-private":
                    # Another loopback address: private, and observable if it is reached.
                    port = (self.headers.get("Host") or "").split(":")[-1]
                    self._send(
                        302,
                        b"",
                        "text/plain",
                        {"Location": f"http://127.0.0.2:{port}/secret/private"},
                    )
                elif path.startswith("/secret/"):
                    ctype = "application/octet-stream" if path.endswith(".bin") else "text/plain"
                    extra = {"Content-Disposition": "attachment"} if path.endswith(".bin") else None
                    self._send(200, b"SECRET", ctype, extra)
                else:
                    self._send(404, b"not found", "text/plain")

            def do_POST(self) -> None:
                self._record()
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                self._html("Saved", "<p>Saved.</p>")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        # Same port, another loopback address. It is private, so a request that
        # reaches it is a bypass, and reaching it leaves a trace in `hits`.
        try:
            self._second = ThreadingHTTPServer(("127.0.0.2", self.port), Handler)
            threading.Thread(target=self._second.serve_forever, daemon=True).start()
        except OSError:
            self._second = None
        return self

    def stop(self) -> None:
        if self._second is not None:
            self._second.shutdown()
            self._second.server_close()
            self._second = None
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> ProbeSite:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---------------------------------------------------------------- names

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("the probe site is not running")
        return int(self._server.server_address[1])

    @property
    def origin(self) -> str:
        """The allowed origin."""
        return f"http://127.0.0.1:{self.port}"

    @property
    def forbidden_origin(self) -> str:
        """The same server under another name: somewhere the agent may not go."""
        return f"http://localhost:{self.port}"

    # --------------------------------------------------------------- reading

    def mark(self) -> int:
        with self._lock:
            return len(self.hits)

    def leaked_since(self, mark: int) -> list[Hit]:
        """Requests that reached the forbidden name after `mark`. Any is a bypass."""
        with self._lock:
            return [h for h in self.hits[mark:] if h.host != "127.0.0.1"]
