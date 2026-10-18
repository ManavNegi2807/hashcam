"""A real, opt-in collector for the one computer it runs on. It watches only what it is told to.

What it can see, and what it never does:

* **Downloads**: new, finished files appearing in ONE folder you name. It records the file's name,
  size, the hour, and (on Windows, where the browser leaves it) the address the file came from. It
  never reads file contents and never records the folder path.
* **Program launches**: only script shells (`powershell.exe`, `cmd.exe`, ...) that START while it
  runs, with the program that started them. It does not record command lines or arguments, and it
  does not report ordinary programs at all.
* **Clicked links**: it does NOT read browser history. A link is collected only if it is written to
  a file you name (a chat or mail integration, or you), one per line.

Everything it records is appended to a JSON-lines file you can read first. Nothing leaves this
computer from here: the file is only analysed later by `tools/demo_endpoint.py`. Use it only on a
computer you are authorised to monitor. It is a demo collector, not an endpoint security product:
it can be switched off by anyone, and it sees nothing it was not pointed at.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from urllib.parse import urlparse

from endpoint.events import EndpointEvent
from endpoint.scoring import SHELLS

TEMPORARY = (".crdownload", ".part", ".partial", ".tmp", ".download", ".opdownload")
MAX_EVENTS = 500
MAX_CLICK_LINE = 2000


def parse_zone_identifier(text: str) -> str:
    """The address a file came from, out of a Windows `Zone.Identifier` stream, or ''."""
    found = {}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        found[key.strip().lower()] = value.strip()
    for field in ("hosturl", "referrerurl"):
        candidate = found.get(field, "")
        if urlparse(candidate).scheme in ("http", "https"):
            return candidate[:500]
    return ""


def origin_of(path: Path) -> str:
    """Where a downloaded file came from, if the system recorded it. Never raises."""
    try:
        with open(str(path) + ":Zone.Identifier", encoding="utf-8", errors="replace") as stream:
            return parse_zone_identifier(stream.read(4000))
    except OSError:
        return ""  # not Windows, not NTFS, or the browser left no mark


class DownloadWatcher:
    """New, finished files in one folder. Files already there when it starts are ignored."""

    def __init__(self, folder: Path, user: str, hour: Callable[[], int]) -> None:
        self._folder = folder
        self._user = user
        self._hour = hour
        self._sizes: dict[str, int] = {}
        self._reported: set[str] = set()
        self._known: set[str] = {e.name for e in os.scandir(folder) if e.is_file()}

    def poll(self) -> list[EndpointEvent]:
        events: list[EndpointEvent] = []
        for entry in os.scandir(self._folder):
            name = entry.name
            if not entry.is_file() or name in self._known or name in self._reported:
                continue
            if name.lower().endswith(TEMPORARY):
                continue
            size = entry.stat().st_size
            if self._sizes.get(name) != size:
                self._sizes[name] = size  # still growing (or first sight): wait one more poll
                continue
            self._reported.add(name)
            source = origin_of(Path(entry.path))
            events.append(
                EndpointEvent(
                    "file_download",
                    self._user,
                    self._hour(),
                    target=source or f"local-file:///{name}",
                    size_mb=size // (1024 * 1024),
                )
            )
        return events


def list_processes() -> dict[int, tuple[str, int]]:
    """pid -> (name, parent pid) for the processes running now. Names only, no arguments."""
    program = shutil.which("powershell" if os.name == "nt" else "ps")
    if program is None:
        return {}
    if os.name == "nt":
        script = (
            "Get-CimInstance Win32_Process | ForEach-Object "
            "{ '{0}|{1}|{2}' -f $_.ProcessId, $_.ParentProcessId, $_.Name }"
        )
        out = subprocess.run(  # noqa: S603 - fixed argv, full path resolved above
            [program, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout
        rows = [line.split("|", 2) for line in out.splitlines() if line.count("|") == 2]
    else:
        out = subprocess.run(  # noqa: S603 - fixed argv, full path resolved above
            [program, "-eo", "pid=,ppid=,comm="],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        ).stdout
        rows = [line.split(None, 2) for line in out.splitlines() if len(line.split(None, 2)) == 3]
    table: dict[int, tuple[str, int]] = {}
    for pid, ppid, name in rows:
        try:
            table[int(pid)] = (name.strip().lower(), int(ppid))
        except ValueError:
            continue
    return table


class ProcessWatcher:
    """Script shells that start while this runs, and which program started them."""

    def __init__(
        self,
        user: str,
        hour: Callable[[], int],
        lister: Callable[[], dict[int, tuple[str, int]]] = list_processes,
    ) -> None:
        self._user = user
        self._hour = hour
        self._lister = lister
        self._seen: set[int] = set(self._lister())

    def poll(self) -> list[EndpointEvent]:
        table = self._lister()
        events: list[EndpointEvent] = []
        for pid, (name, ppid) in table.items():
            if pid in self._seen:
                continue
            self._seen.add(pid)
            exe = name if name.endswith(".exe") else name + ".exe"
            if exe not in SHELLS:
                continue  # ordinary programs are not reported at all
            parent = table.get(ppid, ("", 0))[0]
            parent_exe = parent if parent.endswith(".exe") or not parent else parent + ".exe"
            events.append(
                EndpointEvent(
                    "process_launch", self._user, self._hour(), process=exe, parent=parent_exe
                )
            )
        return events


class ClickFileWatcher:
    """Links written, one per line, to a file you name. Only http and https lines count."""

    def __init__(self, path: Path, user: str, hour: Callable[[], int]) -> None:
        self._path = path
        self._user = user
        self._hour = hour
        self._offset = path.stat().st_size if path.exists() else 0

    def poll(self) -> list[EndpointEvent]:
        if not self._path.exists():
            return []
        size = self._path.stat().st_size
        if size < self._offset:
            self._offset = 0  # the file was replaced
        with open(self._path, encoding="utf-8", errors="replace") as stream:
            stream.seek(self._offset)
            chunk = stream.read(200_000)
            self._offset = stream.tell()
        events: list[EndpointEvent] = []
        for line in chunk.splitlines():
            link, _, where = line.strip()[:MAX_CLICK_LINE].partition(" ")
            if urlparse(link).scheme not in ("http", "https"):
                continue
            source = (
                where.strip().lower() if where.strip().lower() in {"chat", "email"} else "reported"
            )
            events.append(EndpointEvent("url_click", self._user, self._hour(), link, source=source))
        return events


def append_events(path: Path, events: list[EndpointEvent]) -> None:
    """One JSON object per line, readable by `tools/demo_endpoint.py --events-file`."""
    with open(path, "a", encoding="utf-8") as out:
        for event in events:
            out.write(json.dumps(asdict(event), sort_keys=True) + "\n")


def local_hour() -> int:
    return time.localtime().tm_hour
