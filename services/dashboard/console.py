"""The HashCam Console's two server-side helpers.

* `inspect_upload`: a receipt the person dropped on the page is checked with the offline
  verifier (`abb verify`) and summarized for display. Nothing is stored; the verdict is the
  verifier's own, word for word.
* `RecorderLink`: read-only questions to the local recorder (`services/recorder`). The pairing
  token is read from its file here, on the server, so the page never holds it. Approving and
  the kill switch are deliberately NOT here: they need the person's passkey, which lives in
  the extension.
"""

from __future__ import annotations

import base64
import json
import re
import tempfile
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_UPLOAD = 30_000_000
MAX_SNAPSHOTS = 60
_SESSION_ID = re.compile(r"^[0-9a-f]{12}$")


class ConsoleError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def inspect_upload(config: Any, body: dict[str, Any]) -> dict[str, Any]:
    """Verify a dropped receipt and return what the receipt viewer shows."""
    from endpoint.alerts import alerts_from
    from services.dashboard.server import summarize, verify
    from services.graph.build import build as build_graph

    try:
        data = base64.b64decode(str(body.get("receipt_b64", "")), validate=True)
    except ValueError:
        raise ConsoleError("the receipt is not base64") from None
    if not data.startswith(b"PK"):
        raise ConsoleError("that is not a .abbreceipt file")
    keys = body.get("keys_json")
    with tempfile.TemporaryDirectory(prefix="hashcam-inspect-") as tmp:
        path = Path(tmp) / "dropped.abbreceipt"
        path.write_bytes(data)
        if isinstance(keys, str) and keys.strip():
            try:
                json.loads(keys)
            except ValueError:
                raise ConsoleError("the key manifest is not JSON") from None
            (Path(tmp) / "dropped.abbreceipt.keys.json").write_text(keys, encoding="utf-8")
        report = verify(config, path)
        try:
            summary = summarize(path)
        except (KeyError, ValueError, zipfile.BadZipFile):
            return {
                "verdict": report,
                "summary": None,
                "graph": None,
                "alerts": [],
                "snapshots": [],
            }
        return {
            "verdict": report,
            "summary": summary,
            "graph": {"source": "receipt", **build_graph(summary)},
            "alerts": alerts_from(path, summary),
            "snapshots": snapshots_of(path, summary),
        }


def snapshots_of(path: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Page screenshots sealed in the receipt, as data URLs, in event order."""
    shots = []
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        for event in summary["events"]:
            payload = event["payload"]
            if (
                event["event_type"] != "ARTIFACT_CAPTURED"
                or payload.get("media_type") != "image/png"
            ):
                continue
            name = f"artifacts/{payload.get('artifact_digest', '')}"
            if name not in names:
                continue  # an artifact the receipt does not carry: shown as missing, not faked
            raw = archive.read(name)
            if not raw.startswith(b"\x89PNG\r\n\x1a\n"):
                continue
            shots.append(
                {
                    "sequence": event["sequence"],
                    "digest": payload["artifact_digest"],
                    "src": "data:image/png;base64," + base64.b64encode(raw).decode("ascii"),
                }
            )
            if len(shots) >= MAX_SNAPSHOTS:
                break
    return shots


@dataclass(frozen=True)
class RecorderLink:
    """Read-only access to the local recorder on 127.0.0.1."""

    base_url: str
    token_file: Path

    def _token(self) -> str:
        try:
            return self.token_file.read_text(encoding="utf-8").strip()
        except OSError:
            raise ConsoleError("the recorder's pairing token file was not found", 503) from None

    def get(self, path: str) -> tuple[bytes, str]:
        request = urllib.request.Request(  # noqa: S310 - a loopback URL given on the command line
            self.base_url + path, headers={"X-HashCam-Token": self._token()}
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
                return response.read(), response.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as exc:
            raise ConsoleError("the recorder refused the request", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ConsoleError("the recorder is not running", 503) from None

    def sessions(self) -> Any:
        body, _ = self.get("/sessions")
        return json.loads(body)

    def session(self, session_id: str) -> Any:
        if not _SESSION_ID.match(session_id):
            raise ConsoleError("no such session", 404)
        body, _ = self.get(f"/sessions/{session_id}")
        return json.loads(body)

    def snapshot(self, session_id: str, n: str) -> tuple[bytes, str]:
        if not _SESSION_ID.match(session_id) or not n.isdigit():
            raise ConsoleError("no such snapshot", 404)
        return self.get(f"/sessions/{session_id}/snapshot/{int(n)}")
