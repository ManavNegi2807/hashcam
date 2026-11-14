"""Serve site/ the way Vercel does: the same headers, including the strict content security policy.

Shared by the site tests so a page that needs an inline script, an inline style or a request to
another host fails here as it would on the web.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, ClassVar

REPO = Path(__file__).resolve().parents[2]
SITE = REPO / "site"


def vercel_headers() -> dict[str, str]:
    config = json.loads((SITE / "vercel.json").read_text(encoding="utf-8"))
    return {h["key"]: h["value"] for h in config["headers"][0]["headers"]}


class SiteHandler(SimpleHTTPRequestHandler):
    extensions_map: ClassVar[dict[str, str]] = {  # type: ignore[misc]
        **SimpleHTTPRequestHandler.extensions_map,
        ".wasm": "application/wasm",
        ".js": "text/javascript",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(SITE), **kwargs)

    def end_headers(self) -> None:
        for key, value in vercel_headers().items():
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
