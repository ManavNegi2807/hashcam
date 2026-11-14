"""The one-click launcher (HashCam.bat -> tools/launcher.ps1): no terminal, nothing to type.

* The script is valid PowerShell.
* On spare ports and in temporary folders (never the real recorder or token): a cold start brings up
  the website, the recorder and the console and they work together (the console reads the
  recorder's sessions); a second run reuses them instead of starting duplicates; a recorder it
  cannot use (a stale one, left over from an earlier version) is reported with the click-only fix;
  Stop ends everything and leaves nothing listening.

Windows only (it is a PowerShell launcher). The start test needs ABB_BIN, ABB_SIGNER_BIN and the
test PostgreSQL on port 55432.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import REPO

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="a Windows PowerShell launcher")
SCRIPT = REPO / "tools" / "launcher.ps1"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def launcher(*args: str, timeout: int = 240) -> subprocess.CompletedProcess[str]:
    """Run the launcher with its output going to a file, not a pipe: the services it starts are
    long-lived and inherit its handles, so a pipe would never reach end-of-file."""
    argv = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(SCRIPT), *args]
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as out:
        done = subprocess.run(  # noqa: S603 - fixed argv
            argv, stdout=out, stderr=subprocess.STDOUT, timeout=timeout, check=False
        )
        out.seek(0)
        text = out.read()
    return subprocess.CompletedProcess(argv, done.returncode, text, "")


def status(url: str, headers: dict[str, str] | None = None) -> int:
    request = urllib.request.Request(url, headers=headers or {})  # noqa: S310 - loopback
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)


def test_the_launcher_is_valid_powershell() -> None:
    check = (
        "$e = $null; $t = $null; "
        "[void][System.Management.Automation.Language.Parser]"
        f"::ParseFile('{SCRIPT}', [ref]$t, [ref]$e); "
        "if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }"
    )
    argv = ["powershell", "-NoProfile", "-Command", check]
    done = subprocess.run(argv, capture_output=True, text=True, check=False)  # noqa: S603
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_batch_files_only_call_the_launcher() -> None:
    for name, flag in (
        ("HashCam.bat", ""),
        ("HashCam-Stop.bat", "-Stop"),
        ("HashCam-Extension-Setup.bat", "-ExtensionSetup"),
    ):
        text = (REPO / name).read_text(encoding="utf-8")
        assert r"%~dp0tools\launcher.ps1" in text, name
        assert flag in text, name
        assert "TINYFISH" not in text and "token" not in text.lower().replace("pairing token", "")


NEEDS_STACK = pytest.mark.skipif(
    not (os.environ.get("ABB_BIN") and os.environ.get("ABB_SIGNER_BIN") and listening(55432)),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and the test PostgreSQL on port 55432",
)


@pytest.fixture
def ports(tmp_path: Path) -> Iterator[dict[str, Any]]:
    p = {"web": free_port(), "console": free_port(), "recorder": free_port(), "dir": str(tmp_path)}
    yield p
    launcher(*flags(p, stop=True))  # whatever the test did, leave nothing running


def flags(p: dict[str, Any], *, stop: bool = False, recorder: int | None = None) -> list[str]:
    out = [
        "-Quiet",
        "-NoOpen",
        "-WebsitePort",
        str(p["web"]),
        "-ConsolePort",
        str(p["console"]),
        "-RecorderPort",
        str(recorder or p["recorder"]),
        "-DataDir",
        p["dir"],
        "-StateDir",
        p["dir"],
    ]
    return (["-Stop"] if stop else []) + out


@NEEDS_STACK
def test_one_click_start_reuse_and_stop(ports: dict[str, Any]) -> None:
    web, console, recorder = ports["web"], ports["console"], ports["recorder"]
    first = launcher(*flags(ports))
    assert first.returncode == 0, first.stdout + first.stderr
    for line in (f"Website: started (port {web})", f"Recorder: started (port {recorder})",
                 f"Console: started (port {console})"):  # fmt: skip
        assert line in first.stdout, first.stdout
    assert "Please note" not in first.stdout

    token = (Path(ports["dir"]) / "recorder-token").read_text(encoding="utf-8").strip()
    assert (Path(ports["dir"]) / "recorder-viewer-key").exists()
    assert status(f"http://127.0.0.1:{web}/") == 200
    assert status(f"http://127.0.0.1:{web}/sandbox.html") == 200
    assert status(f"http://127.0.0.1:{console}/console") == 200
    assert status(f"http://127.0.0.1:{recorder}/status", {"X-HashCam-Token": token}) == 200
    assert status(f"http://127.0.0.1:{recorder}/status", {"X-HashCam-Token": "wrong"}) == 403
    # The pairing token goes to the clipboard in normal mode, and is never written to any output.
    assert token not in first.stdout + first.stderr
    # The console reads the recorder's sessions itself: nothing was pasted anywhere.
    assert status(f"http://127.0.0.1:{console}/api/live/sessions") == 200

    pids = (Path(ports["dir"]) / "pids.txt").read_text(encoding="utf-8").split()
    second = launcher(*flags(ports))
    assert second.returncode == 0 and "Please note" not in second.stdout, second.stdout
    assert second.stdout.count("running (port") == 3, second.stdout
    assert (Path(ports["dir"]) / "pids.txt").read_text(
        encoding="utf-8"
    ).split() == pids  # no duplicates

    stopped = launcher(*flags(ports, stop=True))
    assert "Stopped" in stopped.stdout, stopped.stdout
    assert not any(listening(port) for port in (web, console, recorder))


@NEEDS_STACK
def test_a_recorder_it_cannot_use_is_reported_with_the_fix(ports: dict[str, Any]) -> None:
    """Something on the recorder's port that is not a usable recorder (a stale one)."""

    class Stale(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(404)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_: Any) -> None:
            return

    old = ThreadingHTTPServer(("127.0.0.1", ports["recorder"]), Stale)
    threading.Thread(target=old.serve_forever, daemon=True).start()
    try:
        done = launcher(*flags(ports))
        assert done.returncode == 0, done.stdout + done.stderr
        assert "cannot use it" in done.stdout, done.stdout
        assert "HashCam-Stop.bat" in done.stdout
        assert f"Website: started (port {ports['web']})" in done.stdout  # the rest still works
    finally:
        old.shutdown()
        old.server_close()


def test_stop_with_nothing_running_says_so(ports: dict[str, Any]) -> None:
    done = launcher(*flags(ports, stop=True))
    assert done.returncode == 0
    assert "Nothing of HashCam was running." in done.stdout, done.stdout
