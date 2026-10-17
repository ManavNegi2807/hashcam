"""The approval gate on the run console, end to end with the real pieces.

A scripted agent runs a risky step (change a vendor's bank details) on a fake portal with
fake data. The real gateway answers "needs approval". A person's click signs with the real
`abb approve`, the signature is relayed, and the real offline verifier checks the receipt.

Needs the built `abb` binaries and a test PostgreSQL (`ABB_BIN`, `ABB_SIGNER_BIN`,
`ABB_TEST_DSN`); skipped when they are not set. No money, no network, no TinyFish.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from typing import Any

import pytest

from services.dashboard.runner import GUARDED_TASK, REPO, Refused, Runner

ABB = os.environ.get("ABB_BIN")
pytestmark = pytest.mark.skipif(
    not (ABB and os.environ.get("ABB_SIGNER_BIN") and os.environ.get("ABB_TEST_DSN")),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)


def make_runner(tmp_path: Path, wait_seconds: int = 120) -> Runner:
    def command(out: Path) -> list[str]:
        script = str(REPO / "tools" / "demo_guarded.py")
        return [
            sys.executable,
            script,
            "--people-dir",
            str(tmp_path / "people"),
            "--out",
            str(out),
            "--wait-seconds",
            str(wait_seconds),
        ]

    runner = Runner(
        tmp_path / "receipts",
        people_dir=tmp_path / "people",
        abb=ABB,
        budget_path=tmp_path / "b.json",
        guarded_command=command,
    )
    (tmp_path / "receipts").mkdir()
    return runner


def wait_for(runner: Runner, job: str, until: Any, seconds: float = 180) -> dict[str, Any]:
    deadline = time.time() + seconds
    while time.time() < deadline:
        status = runner.status(job)
        if until(status):
            return status
        time.sleep(0.5)
    raise AssertionError("timed out waiting; last status: " + json.dumps(runner.status(job))[:600])


def verify(receipt: Path) -> dict[str, Any]:
    done = subprocess.run(  # noqa: S603 - fixed argv
        [
            str(ABB),
            "verify",
            str(receipt),
            "--keys",
            str(receipt) + ".keys.json",
            "--profile",
            "LOCAL_ONLY",
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    report: dict[str, Any] = json.loads(done.stdout.decode("utf-8"))
    return report


def event_types(receipt: Path) -> list[str]:
    with zipfile.ZipFile(receipt) as archive:
        document = json.loads(archive.read("receipt.json").decode("utf-8"))
    return [
        json.loads(base64.b64decode(e["canonical_b64"]))["event_type"] for e in document["events"]
    ]


def test_a_signed_grant_lets_the_risky_step_through_and_the_receipt_verifies(
    tmp_path: Path,
) -> None:
    runner = make_runner(tmp_path)
    job = runner.start(None, None, None, "guarded")
    waiting = wait_for(runner, job, lambda s: s["pending"] is not None or s["state"] != "running")
    assert waiting["pending"] is not None, waiting
    assert "bank" in waiting["pending"]["summary"].lower()

    # What the person sees is what gets signed; a stale digest is refused.
    with pytest.raises(Refused):
        runner.approve(job, "GRANTED", "0" * 64)
    done = runner.approve(job, "GRANTED", waiting["pending"]["summary_digest"])
    assert done["decision"] == "GRANTED"
    assert done["key_id"] == runner.approver_key_id()
    with pytest.raises(Refused):  # a second click cannot sign it again
        runner.approve(job, "GRANTED", waiting["pending"]["summary_digest"])

    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    assert final["result"] and "approval" in final["result"].lower()
    receipt = tmp_path / "receipts" / str(final["receipt"])
    report = verify(receipt)
    assert report["overall"] in {"VALID", "PARTIAL"}, report
    types = event_types(receipt)
    assert "APPROVAL_RECORDED" in types or any("APPROVAL" in t for t in types), types
    assert "ACTION_DISPATCHED" in types[types.index(next(t for t in types if "APPROVAL" in t)) :]
    meta = json.loads((Path(str(receipt) + ".meta.json")).read_text(encoding="utf-8"))
    assert meta["goal"] == GUARDED_TASK
    assert meta["mode"] == "guarded"


def test_a_signed_denial_blocks_the_risky_step(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start(None, None, None, "guarded")
    waiting = wait_for(runner, job, lambda s: s["pending"] is not None or s["state"] != "running")
    assert waiting["pending"] is not None, waiting
    runner.approve(job, "DENIED", waiting["pending"]["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    assert final["result"] and "denial" in final["result"].lower()
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}
    types = event_types(receipt)
    # The bank-details step was never sent: only the first (harmless) action was dispatched.
    assert types.count("ACTION_DISPATCHED") == 1, types


def test_when_nobody_answers_the_risky_step_is_not_sent(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, wait_seconds=4)
    job = runner.start(None, None, None, "guarded")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=240)
    assert final["state"] == "done", final
    assert final["result"] and "nobody answered" in final["result"].lower()
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}
    assert event_types(receipt).count("ACTION_DISPATCHED") == 1


def test_the_approver_key_is_never_shown_and_the_id_is_public(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    info = runner.info()
    assert info["guarded"]["approver_key_id"].startswith("ed25519:")
    secret = (tmp_path / "people" / "approver.key").read_bytes().strip()
    assert secret  # the key is raw bytes; none of its encodings may appear in what the page gets
    shown = json.dumps(info)
    assert secret.hex() not in shown
    assert base64.b64encode(secret).decode("ascii") not in shown
