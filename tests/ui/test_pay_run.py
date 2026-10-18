"""Company payments with fake money, end to end with the real pieces.

Real: the run console, the gateway, the policy rules (up to 50.00 on its own, over 50.00 a signed
approval, over 500.00 refused), `abb approve` signatures, the signed receipt and the offline
verifier. NOT real: the payment service. Here it is a LOCAL STAND-IN that imitates the shape of
Stripe's reply, and the run says so in its own task text. These tests prove our side of the
contract. They do not prove how Stripe test mode behaves: that needs your key and
`tools/check_stripe_live.py`.

Needs the built `abb` binaries and a test PostgreSQL (`ABB_BIN`, `ABB_SIGNER_BIN`,
`ABB_TEST_DSN`); skipped when they are not set.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from adapters.payments.client import KEY_ENV
from services.dashboard.runner import REPO, Refused, Runner
from services.dashboard.server import summarize
from services.graph.build import build
from tests.adapter.test_payments import Handler, Stand_in
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


@pytest.fixture()
def stripe(monkeypatch: pytest.MonkeyPatch) -> Iterator[Stand_in]:
    monkeypatch.setenv(KEY_ENV, "sk_test_standin_not_a_real_key")
    server = Stand_in(("127.0.0.1", 0), Handler)
    server.seen = []
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def amounts(server: Stand_in) -> list[int]:
    return [int(dict(p.split("=") for p in s["body"].split("&"))["amount"]) for s in server.seen]


def make_runner(tmp_path: Path, server: Stand_in, wait_seconds: int = 120) -> Runner:
    url = f"http://127.0.0.1:{server.server_address[1]}"

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
            "--stand-in-url",
            url,
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


def test_the_three_tiers_small_pays_big_waits_huge_is_refused(
    tmp_path: Path, stripe: Stand_in
) -> None:
    runner = make_runner(tmp_path, stripe)
    job = runner.start(BATCH, None, None, "pay")
    waiting = waiting_for_approval(runner, job)
    pending = waiting["pending"]
    assert isinstance(pending, dict)
    # The approver reads the amount and who is paid, not a hash.
    assert "PAY 180.00 USD to Northwind Cloud Hosting" in pending["summary"]
    # Only the small payment had been sent while the big one waited.
    assert amounts(stripe) == [1200]

    with pytest.raises(Refused):  # a stale digest cannot be signed
        runner.approve(job, "GRANTED", "0" * 64)
    runner.approve(job, "GRANTED", pending["summary_digest"])

    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    # 12.00 and 180.00 were paid; 900.00 never reached the payment service.
    assert amounts(stripe) == [1200, 18000]
    result = str(final["result"])
    assert "Acme Office Supplies: 12.00 USD: **paid**" in result
    assert "Northwind Cloud Hosting: 180.00 USD: **paid**" in result
    assert "Contoso Heavy Equipment: 900.00 USD: **not paid** (over the 500.00 cap" in result
    assert final["outcome"] == "COMPLETED_WITH_BLOCKS"

    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}
    types = event_types(receipt)
    assert types.count("ACTION_DISPATCHED") == 2


def test_a_signed_denial_means_the_big_payment_is_never_sent(
    tmp_path: Path, stripe: Stand_in
) -> None:
    runner = make_runner(tmp_path, stripe)
    job = runner.start(BATCH, None, None, "pay")
    pending = waiting_for_approval(runner, job)["pending"]
    assert isinstance(pending, dict)
    runner.approve(job, "DENIED", pending["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    assert amounts(stripe) == [1200]  # only the small payment ever reached the service
    assert "Northwind Cloud Hosting: 180.00 USD: **not paid**" in str(final["result"])
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}


def test_when_nobody_answers_the_big_payment_is_never_sent(
    tmp_path: Path, stripe: Stand_in
) -> None:
    runner = make_runner(tmp_path, stripe, wait_seconds=4)
    job = runner.start(BATCH, None, None, "pay")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=240)
    assert final["state"] == "done", final
    assert amounts(stripe) == [1200]
    assert "needed a signed approval and did not get one" in str(final["result"])


def test_the_graph_of_a_payment_run_shows_amounts_and_the_approval(
    tmp_path: Path, stripe: Stand_in
) -> None:
    runner = make_runner(tmp_path, stripe)
    job = runner.start(BATCH, None, None, "pay")
    pending = waiting_for_approval(runner, job)["pending"]
    assert isinstance(pending, dict)
    runner.approve(job, "GRANTED", pending["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    graph = build(summarize(tmp_path / "receipts" / str(final["receipt"])))
    actions = {n["name"]: n for n in graph["nodes"] if n["label"] == "Action"}
    assert (
        actions["pay-1"]["amount_minor_units"] == 1200 and actions["pay-1"]["status"] == "succeeded"
    )
    assert actions["pay-2"]["status"] == "succeeded"
    assert actions["pay-3"]["status"] == "blocked"
    assert any(n["label"] == "Approval" for n in graph["nodes"])


def test_without_a_test_key_nothing_starts(
    tmp_path: Path, stripe: Stand_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = make_runner(tmp_path, stripe)
    monkeypatch.delenv(KEY_ENV)
    with pytest.raises(Refused):
        runner.start(BATCH, None, None, "pay")
    assert stripe.seen == []


def test_a_live_key_is_refused_and_never_repeated(
    tmp_path: Path, stripe: Stand_in, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = make_runner(tmp_path, stripe)
    live = "sk_live_" + "Z" * 24
    monkeypatch.setenv(KEY_ENV, live)
    with pytest.raises(Refused) as caught:
        runner.start(BATCH, None, None, "pay")
    assert "ZZZZ" not in str(caught.value)
    assert runner.info()["pay"]["test_key"] is False
    assert live not in json.dumps(runner.info())
    assert stripe.seen == []


def test_the_page_learns_whether_a_test_key_is_set_but_never_the_key(
    tmp_path: Path, stripe: Stand_in
) -> None:
    runner = make_runner(tmp_path, stripe)
    info = runner.info()
    assert info["pay"]["key_set"] is True and info["pay"]["test_key"] is True
    assert "standin" not in json.dumps(info)
