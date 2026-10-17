"""A Playwright run end to end: real browser, real ledger, offline verifier.

What this pins down is the link between a *measured* result and the receipt: the
declared coverage a receipt shows must be the one the run's own signed events
declared, and that in turn must be what the bypass self-test justified.

Slow (about a minute and a half per run) because it starts the whole stack and a
browser. Needs Chromium and a PostgreSQL; missing pieces skip with a reason.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _run_demo(*extra: str) -> subprocess.CompletedProcess[str]:
    dsn = os.environ.get("ABB_TEST_DSN")
    if not dsn:
        pytest.skip("set ABB_TEST_DSN to run the Playwright receipt tests")
    pytest.importorskip("playwright")
    env = dict(os.environ)
    env.setdefault(
        "PLAYWRIGHT_BROWSERS_PATH",
        os.environ.get("ABB_PLAYWRIGHT_BROWSERS", str(Path.home() / "AppData/Local/ms-playwright")),
    )
    done = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(REPO / "tools" / "demo_playwright.py"), "--dsn", dsn, *extra],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        cwd=str(REPO),
        timeout=600,
    )
    if "Chromium" in done.stderr and "Executable doesn't exist" in done.stderr:
        pytest.skip("Chromium is not installed")
    if "ABB_BIN" in done.stderr or ("abb-signer" in done.stderr and done.returncode != 0):
        pytest.skip("the abb binaries are not available (set ABB_BIN and ABB_SIGNER_BIN)")
    return done


def _receipt_coverage(out: str) -> str:
    match = re.search(r"declared coverage in the receipt: (\w+)", out)
    assert match, out
    return match.group(1)


def test_a_fully_gated_adapter_declares_step_gated_and_the_receipt_says_so() -> None:
    done = _run_demo()
    assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-800:]
    assert "-> declared coverage: STEP_GATED" in done.stdout
    assert "requests that reached the forbidden name: 0" in done.stdout
    assert "as expected: VALID" in done.stdout
    assert _receipt_coverage(done.stdout) == "STEP_GATED"


def test_an_adapter_with_a_hole_declares_less_and_the_receipt_header_agrees() -> None:
    """The weaker claim must show in the receipt itself, not only in a local variable.

    A bug found while building this: the receipt's header used to be filled from the
    run's *requested* coverage, so a run that declared STEP_OBSERVED was labelled
    STEP_GATED in its own receipt.
    """
    done = _run_demo("--leaky")
    assert done.returncode == 0, done.stdout[-1500:] + done.stderr[-800:]
    assert "websocket          LEAKED" in done.stdout
    assert "-> declared coverage: STEP_OBSERVED" in done.stdout
    assert _receipt_coverage(done.stdout) == "STEP_OBSERVED"
