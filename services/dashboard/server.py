"""A small local server for the audit dashboard (`R-UI-01`..`R-UI-05`).

It does two things and nothing else:

* serves the static files in `ui/`;
* answers three read-only questions about receipts in one directory: which
  exist, what the **offline verifier** says about one, and a display summary of
  what is inside it.

The verdict always comes from `abb verify --json`, passed through untouched. This
server and the page never compute validity, hash anything, or check a signature
(`R-SVC-01`, `R-UI-04`). It listens on 127.0.0.1 only, serves receipts only from
the directory it was started with, and sends no secrets because it holds none.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import zipfile
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import pathsafe
from services.dashboard.runner import Refused

UI_DIR = Path(__file__).resolve().parents[2] / "ui"
RECEIPT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.abbreceipt$")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/chat.css": ("chat.css", "text/css; charset=utf-8"),
    "/run": ("run.html", "text/html; charset=utf-8"),
    "/run.js": ("run.js", "text/javascript; charset=utf-8"),
    "/format.js": ("format.js", "text/javascript; charset=utf-8"),
}
SECURITY_HEADERS = {
    # Everything the page needs comes from this origin; nothing is inlined.
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
MAX_EVENTS_SHOWN = 500


@dataclass(frozen=True)
class Config:
    receipts: Path
    keys: Path | None
    abb: str
    profile: str = "LOCAL_ONLY"
    runner: Any = None  # a `runner.Runner`; `None` keeps the server strictly read-only


def list_receipts(config: Config) -> list[str]:
    names = [n for n in pathsafe.listdir(config.receipts) if RECEIPT_NAME.match(n)]
    return sorted(names)


def labels(config: Config, names: list[str]) -> dict[str, dict[str, Any]]:
    """A readable name per receipt: the task title the run console saved beside it, else
    nothing (the page then shows the date). `when` is the file's modified time in seconds.
    Display only; nothing here is evidence."""
    out: dict[str, dict[str, Any]] = {}
    for name in names:
        entry: dict[str, Any] = {
            "title": None,
            "when": None,
            "answer": None,
            "goal": None,
            "url": None,
        }
        try:
            entry["when"] = int(os.stat(pathsafe.extended(config.receipts / name)).st_mtime)
            meta = json.loads(pathsafe.read_text(config.receipts / (name + ".meta.json")))
            title = meta.get("title")
            if isinstance(title, str) and title.strip():
                entry["title"] = title.strip()[:80]
            goal = meta.get("goal")
            if isinstance(goal, str) and goal.strip():
                entry["goal"] = goal.strip()[:500]
            url = meta.get("url")
            if isinstance(url, str):
                entry["url"] = url[:300]
            answer = meta.get("answer")
            if isinstance(answer, str) and answer.strip():
                entry["answer"] = answer.strip()[:2000]
        except (OSError, ValueError):
            pass
        out[name] = entry
    return out


def resolve(config: Config, name: str) -> Path | None:
    """A receipt inside the served directory, or `None`. No path ever escapes it."""
    if not RECEIPT_NAME.match(name):
        return None
    path = (config.receipts / name).resolve()
    if path.parent != config.receipts.resolve() or not pathsafe.exists(path):
        return None
    return path


def verify(config: Config, path: Path) -> dict[str, Any]:
    """The offline verifier's own JSON, plus its exit code. Nothing is added to the verdict."""
    argv = [config.abb, "verify", str(path), "--profile", config.profile, "--json"]
    # A receipt made by the run console carries the key manifest of its own run beside it.
    sibling = path.with_name(path.name + ".keys.json")
    keys = sibling if pathsafe.exists(sibling) else config.keys
    if keys is not None:
        argv += ["--keys", str(keys)]
    done = subprocess.run(argv, capture_output=True, timeout=120, check=False)  # noqa: S603
    text = done.stdout.decode("utf-8", "replace").strip()
    if not text.startswith("{"):
        # Unreadable or refused container: say so, with the CLI's own words.
        return {
            "overall": "UNREADABLE",
            "exit_code": done.returncode,
            "message": done.stderr.decode("utf-8", "replace").strip()[:300],
        }
    report: dict[str, Any] = json.loads(text)
    report["exit_code"] = done.returncode
    report["keys_supplied"] = keys is not None
    return report


def summarize(path: Path) -> dict[str, Any]:
    """What is inside a receipt, for display. Nothing here is a verdict."""
    with zipfile.ZipFile(pathsafe.extended(path)) as archive:
        document = json.loads(archive.read("receipt.json").decode("utf-8"))
        artifact_files = [n for n in archive.namelist() if n.startswith("artifacts/")]

    events = []
    for item in document.get("events", [])[:MAX_EVENTS_SHOWN]:
        event = json.loads(base64.b64decode(item["canonical_b64"]))
        events.append(
            {
                "sequence": event["sequence"],
                "event_id": event["event_id"],
                "event_type": event["event_type"],
                "source": event.get("source"),
                "created_at": event.get("created_at"),
                "payload": event.get("payload", {}),
                "commitments": sorted(event.get("commitments", {})),
            }
        )

    approvals = []
    for record in document.get("approvals", []):
        statement = json.loads(base64.b64decode(record["statement_b64"]))
        approvals.append(
            {
                "approval_id": statement["approval_id"],
                "action_id": statement["action_id"],
                "decision": statement["decision"],
                "expires_at": statement["expires_at"],
                "key_id": record["key_id"],
            }
        )

    mandate = None
    if "mandate" in document:
        body = json.loads(base64.b64decode(document["mandate"]["document_b64"]))
        mandate = {
            k: body[k]
            for k in (
                "mandate_id",
                "subject",
                "allowed_hosts",
                "allowed_action_types",
                "max_actions",
                "max_spend_minor_units",
                "currency",
                "issuer_key_id",
            )
            if k in body
        }

    global_log = document.get("global_log", {})
    return {
        "run": document.get("run", {}),
        "policy": document.get("policy", {}),
        "events": events,
        "events_total": len(document.get("events", [])),
        "approvals": approvals,
        "mandate": mandate,
        "disclosures": len(document.get("disclosures", [])),
        "witnesses": len(document.get("witnesses", [])),
        "anchors": len(document.get("anchors", [])),
        "artifact_files": len(artifact_files),
        "checkpoints": len(document.get("checkpoints", [])),
        "global_log": {
            "position": global_log.get("position"),
            "tree_size": global_log.get("tree_size"),
            "checkpoints": len(global_log.get("checkpoints", [])),
        },
        "exporter": document.get("export", {}),
    }


def make_handler(config: Config) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "abb-dashboard"

        def log_message(self, format: str, *args: Any) -> None:
            return  # no access log: receipt names are not worth writing anywhere

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, value in SECURITY_HEADERS.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, status: int, value: Any) -> None:
            self._send(status, json.dumps(value).encode("utf-8"), "application/json")

        def do_GET(self) -> None:
            url = urlparse(self.path)
            if self._run_get(url):
                return
            try:
                if url.path in STATIC:
                    name, content_type = STATIC[url.path]
                    self._send(200, pathsafe.read_bytes(UI_DIR / name), content_type)
                elif url.path == "/api/receipts":
                    names = list_receipts(config)
                    self._json(200, {"receipts": names, "labels": labels(config, names)})
                elif url.path in {"/api/verify", "/api/receipt"}:
                    name = parse_qs(url.query).get("name", [""])[0]
                    path = resolve(config, name)
                    if path is None:
                        self._json(404, {"error": "no such receipt"})
                    elif url.path == "/api/verify":
                        self._json(200, verify(config, path))
                    else:
                        self._json(200, summarize(path))
                else:
                    self._json(404, {"error": "not found"})
            except (OSError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError):
                # Never a path, a trace or a message from inside the receipt.
                self._json(500, {"error": "could not read that receipt"})

        def _run_get(self, url: Any) -> bool:
            """The run console's two GET routes. False when they do not apply."""
            runner = config.runner
            if runner is None or url.path not in {"/api/run/info", "/api/run/status"}:
                return False
            try:
                runner.check_host(self.headers.get("Host"))
                if url.path == "/api/run/info":
                    self._json(200, runner.info())
                else:
                    job_id = parse_qs(url.query).get("id", [""])[0]
                    self._json(200, runner.status(job_id))
            except Refused as exc:
                self._json(exc.status, {"error": str(exc)})
            return True

        def do_POST(self) -> None:
            runner = config.runner
            route = urlparse(self.path).path
            if runner is None or route not in {"/api/run/start", "/api/run/approve"}:
                # Read what was sent first, so the client sees the 405 and not a reset.
                self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096))
                self._json(405, {"error": "read-only"})
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
                # Read the body before any refusal, so the client sees the answer, not a reset.
                raw = self.rfile.read(min(max(length, 0), 4096))
                runner.check_request(
                    self.headers.get("Host"),
                    self.headers.get("Origin"),
                    self.headers.get("X-ABB-Token"),
                )
                if not 0 < length <= 4096:
                    raise Refused("bad request size")
                body = json.loads(raw)
                if not isinstance(body, dict):
                    raise Refused("bad request")
                if route == "/api/run/approve":
                    done = runner.approve(
                        body.get("job"), body.get("decision"), body.get("summary_digest")
                    )
                    self._json(200, {"ok": True, **done})
                    return
                job = runner.start(
                    body.get("goal"),
                    body.get("url"),
                    body.get("confirm_cents"),
                    body.get("mode", "agent"),
                )
                self._json(202, {"job": job})
            except Refused as exc:
                self._json(exc.status, {"error": str(exc)})
            except (ValueError, UnicodeDecodeError):
                self._json(400, {"error": "bad request"})

        do_PUT = do_DELETE = do_PATCH = do_POST

    return Handler


def serve(config: Config, port: int) -> ThreadingHTTPServer:
    """Bind to 127.0.0.1 only. The caller runs `serve_forever()`."""
    return ThreadingHTTPServer(("127.0.0.1", port), make_handler(config))
