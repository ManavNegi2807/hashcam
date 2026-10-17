"""Cross-language gate: the `abb` CLI must agree with the frozen vectors.

Step 2 is built, so this no longer xfails. The Rust workspace runs the same
check as part of `cargo test`; this test exists so the Python suite also fails
if someone hands it a broken binary. It needs the compiled binary, which it
finds through `ABB_BIN` or on `PATH`; with neither it skips rather than
pretending the check ran.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def find_abb() -> str | None:
    from_env = os.environ.get("ABB_BIN")
    if from_env and Path(from_env).is_file():
        return from_env
    on_path = shutil.which("abb")
    if on_path:
        return on_path
    # The usual cargo layout, and the short target dir Windows needs.
    for candidate in (
        REPO / "core" / "target" / "debug" / "abb.exe",
        REPO / "core" / "target" / "debug" / "abb",
        REPO / "core" / "target" / "release" / "abb.exe",
        REPO / "core" / "target" / "release" / "abb",
    ):
        if candidate.is_file():
            return str(candidate)
    return None


@pytest.mark.requires_abb
def test_abb_vectors_check_passes() -> None:
    abb = find_abb()
    if abb is None:
        pytest.skip("abb binary not found; build it with `cargo build -p abb-cli` and set ABB_BIN")
    done = subprocess.run(  # noqa: S603
        [abb, "vectors", "check", "--dir", str(REPO / "vectors")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    assert "0 failed" in done.stdout
    assert "total: 190 passed, 0 failed" in done.stdout, done.stdout
