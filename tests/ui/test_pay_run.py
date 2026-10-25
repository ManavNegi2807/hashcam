"""End-to-end tests for local mock payments through the run console."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from services.dashboard.runner import REPO, Runner
from services.dashboard.server import summarize
from services.graph.build import build
from tests.ui.test_guarded_run import event_types, verify, wait_for

ABB = os.environ.get("ABB_BIN")
pytestmark = pytest.mark.skipif(
    not (ABB and os.environ.get("ABB_SIGNER_BIN") and os.environ.get("ABB_TEST_DSN")),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)

BATCH = (
    "Pay Acme Office Supplies 12.00 USD; Pay Northwind Cloud Hosting 180 USD; "
    "Pay Contoso Heavy Equipment 900 USD"
)


def make_runner(tmp_path: Path, wait_seconds: int = 120) -> Runner:
    def command(goal: str, out: Path) -> list[str]:
        return [
            sys.executable,
            str(REPO / "tools" / "demo_pay.py"),
            "--people-dir",
            str(tmp_path / "people"),
            "--out",
            str(out),
            "--goal",
            goal,
            "--wait-seconds",
            str(wait_seconds),
        ]

    runner = Runner(
        tmp_path / "receipts",
        people_dir=tmp_path / "people",
        abb=ABB,
        budget_path=tmp_path / "b.json",
        pay_command=command,
    )
    (tmp_path / "receipts").mkdir()
    return runner


def waiting_for_approval(runner: Runner, job: str) -> dict[str, object]:
    status = wait_for(runner, job, lambda s: s["pending"] is not None or s["state"] != "running")
    assert status["pending"] is not None, status
    return status


def test_three_tiers_small_pays_big_waits_huge_is_refused(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start(BATCH, None, None, "pay")
    waiting = waiting_for_approval(runner, job)
    pending = waiting["pending"]
    assert isinstance(pending, dict)
    assert "PAY 180.00 USD to Northwind Cloud Hosting" in pending["summary"]

    runner.approve(job, "GRANTED", pending["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    result = str(final["result"])
    assert "Acme Office Supplies: 12.00 USD: **paid**" in result
    assert "Northwind Cloud Hosting: 180.00 USD: **paid**" in result
    assert "Contoso Heavy Equipment: 900.00 USD: **not paid** (over the 500.00 cap" in result
    assert final["outcome"] == "COMPLETED_WITH_BLOCKS"

    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}
    types = event_types(receipt)
    assert types.count("ACTION_DISPATCHED") == 2


def test_signed_denial_means_the_big_payment_is_never_dispatched(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start(BATCH, None, None, "pay")
    pending = waiting_for_approval(runner, job)["pending"]
    assert isinstance(pending, dict)
    runner.approve(job, "DENIED", pending["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    assert "Northwind Cloud Hosting: 180.00 USD: **not paid**" in str(final["result"])
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}


def test_no_answer_means_the_big_payment_is_never_dispatched(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, wait_seconds=4)
    job = runner.start(BATCH, None, None, "pay")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=240)
    assert final["state"] == "done", final
    assert "needed a signed approval and did not get one" in str(final["result"])


def test_graph_contains_simulated_payments_and_approval(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start(BATCH, None, None, "pay")
    pending = waiting_for_approval(runner, job)["pending"]
    assert isinstance(pending, dict)
    runner.approve(job, "GRANTED", pending["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    graph = build(summarize(tmp_path / "receipts" / str(final["receipt"])))
    actions = {n["name"]: n for n in graph["nodes"] if n["label"] == "Action"}
    assert actions["pay-1"]["amount_minor_units"] == 1200
    assert actions["pay-1"]["status"] == "succeeded"
    assert actions["pay-2"]["status"] == "succeeded"
    assert actions["pay-3"]["status"] == "blocked"
    assert any(n["label"] == "Approval" for n in graph["nodes"])


def test_payment_demo_requires_no_payment_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("STRIPE_TEST_KEY", raising=False)
    runner = make_runner(tmp_path)
    assert runner.info()["pay"]["simulated"] is True
    job = runner.start("Pay Acme 12.00 USD", None, None, "pay")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    assert "12.00 USD: **paid**" in str(final["result"])
