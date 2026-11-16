"""Serve site/ the way Vercel does: the same headers, including the strict content security policy.

Shared by the site tests so a page that needs an inline script, an inline style or a request to
another host fails here as it would on the web.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[2]
SITE = REPO / "site"


def vercel_headers(path: str = "/") -> dict[str, str]:
    """The headers vercel.json sends for one path: every matching rule, later rules last."""
    config = json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for rule in config["headers"]:
        if re.fullmatch(rule["source"], path):
            out.update({h["key"]: h["value"] for h in rule["headers"]})
    return out


class SiteHandler(SimpleHTTPRequestHandler):
    extensions_map: ClassVar[dict[str, str]] = {  # type: ignore[misc]
        **SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".js": "text/javascript",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(SITE), **kwargs)

    def end_headers(self) -> None:
        for key, value in vercel_headers(urlsplit(self.path).path).items():
            self.send_header(key, value)
        super().end_headers()

    def log_message(self, *_: Any) -> None:
        return


@contextmanager
def serve_site() -> Iterator[str]:
    """The site on a free local port; yields its origin."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
