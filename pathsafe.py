"""Reading project files on Windows, where paths are limited to 260 characters.

A checkout can easily sit deeper than that — ours does — and the failure is
nasty: `iterdir()` lists a file that `open()` then cannot find, because the
directory handle is fine and the full path is not.

Windows accepts an extended-length prefix (`\\\\?\\`) on absolute paths, which
lifts the limit without changing anything on the host. Every project data file
(policy documents, replay scenarios, migrations) is read through here so a deep
checkout does not quietly break the demo.

This is a filesystem concern only. Nothing here touches protocol bytes.
"""

from __future__ import annotations

import os
from pathlib import Path

EXTENDED_PREFIX = "\\\\?\\"


def extended(path: Path | str) -> str:
    """An absolute path safe to pass to `open()` on any platform."""
    text = os.path.abspath(os.fspath(path))
    if os.name == "nt" and not text.startswith(EXTENDED_PREFIX):
        # UNC paths take a different prefix; a plain drive path takes this one.
        if text.startswith("\\\\"):
            return EXTENDED_PREFIX + "UNC" + text[1:]
        return EXTENDED_PREFIX + text
    return text


def read_text(path: Path | str, *, encoding: str = "utf-8") -> str:
    """Read a text file, long path or not."""
    with open(extended(path), encoding=encoding) as handle:
        return handle.read()


def read_bytes(path: Path | str) -> bytes:
    """Read a binary file, long path or not."""
    with open(extended(path), "rb") as handle:
        return handle.read()


def write_text(path: Path | str, text: str, *, encoding: str = "utf-8") -> None:
    """Write a text file, long path or not."""
    with open(extended(path), "w", encoding=encoding) as handle:
        handle.write(text)


def write_bytes(path: Path | str, data: bytes) -> None:
    """Write a binary file, long path or not."""
    with open(extended(path), "wb") as handle:
        handle.write(data)


def makedirs(path: Path | str) -> None:
    """Create a directory tree, long path or not."""
    os.makedirs(extended(path), exist_ok=True)


def exists(path: Path | str) -> bool:
    """Whether a file exists, long path or not."""
    return os.path.exists(extended(path))


def remove(path: Path | str) -> None:
    """Remove a file if it is there."""
    try:
        os.remove(extended(path))
    except FileNotFoundError:
        pass


def read_migrations(directory: Path | str) -> str:
    """Every `*.sql` migration in order, as one script.

    Forward-only: the files are numbered, and a database built from empty runs
    them all. Reading through here keeps a deep Windows checkout working.
    """
    names = sorted(n for n in listdir(directory) if n.endswith(".sql"))
    return "\n".join(read_text(Path(directory) / name) for name in names)


def listdir(path: Path | str) -> list[str]:
    """List a directory, long path or not."""
    return os.listdir(extended(path))
