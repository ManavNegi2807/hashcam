"""The phishing-link scenario, end to end with the real pieces.

Real: the run console, the gateway, the explainable rules, the sealed artifacts, `abb approve`
signatures, the signed receipt, the offline verifier, and the alert view's data. SIMULATED: the
endpoint events (a made-up collector), the account isolation (no account exists), and, in two
tests, TinyFish's answer (a scripted fake, labelled TEST ONLY in the run's task text). The tests
that use no TinyFish key check the honest "not asked" path.

Needs the built `abb` binaries and a test PostgreSQL (`ABB_BIN`, `ABB_SIGNER_BIN`,
`ABB_TEST_DSN`); skipped when they are not set.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

import pytest

from endpoint.alerts import alerts_from
from services.dashboard.runner import REPO, Runner
from services.dashboard.server import summarize
from tests.ui.test_guarded_run import event_types, verify, wait_for

ABB = os.environ.get("ABB_BIN")
pytestmark = pytest.mark.skipif(
    not (ABB and os.environ.get("ABB_SIGNER_BIN") and os.environ.get("ABB_TEST_DSN")),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)


def make_runner(tmp_path: Path, *extra: str, wait_seconds: int = 120) -> Runner:
    def command(goal: str, out: Path) -> list[str]:
        return [
            sys.executable,
            str(REPO / "tools" / "demo_endpoint.py"),
            "--people-dir",
            str(tmp_path / "people"),
            "--out",
            str(out),
            "--goal",
            goal,
            "--wait-seconds",
            str(wait_seconds),
            *extra,
        ]

    runner = Runner(
        tmp_path / "receipts",
        people_dir=tmp_path / "people",
        abb=ABB,
        budget_path=tmp_path / "b.json",
        endpoint_command=command,
    )
    (tmp_path / "receipts").mkdir()
    return runner


@pytest.fixture(autouse=True)
def no_tinyfish_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TINYFISH_API_KEY", raising=False)


def answer_every_approval(runner: Runner, job: str, decision: str) -> dict[str, Any]:
    """Sign each isolation request as it arrives, until the run ends."""
    deadline_status: dict[str, Any] = {}
    for _ in range(10):
        status = wait_for(
            runner, job, lambda s: s["pending"] is not None or s["state"] != "running"
        )
        if status["state"] != "running":
            return status
        pending = status["pending"]
        assert "ISOLATE account" in pending["summary"]  # the analyst reads what is being asked
        runner.approve(job, decision, pending["summary_digest"])
        deadline_status = status
    return deadline_status


def test_the_phishing_link_becomes_an_explained_alert_with_evidence_and_a_signed_decision(
    tmp_path: Path,
) -> None:
    runner = make_runner(tmp_path, "--enrichment", "fake")
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "GRANTED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}

    alerts = alerts_from(receipt, summarize(receipt))
    assert len(alerts) == 1  # the two ordinary events before it raised nothing
    alert = alerts[0]
    assert alert["severity"] == "HIGH"
    assert {s["rule_id"] for s in alert["signals"]} >= {"LOOKALIKE_DOMAIN", "LOGIN_LURE"}
    assert all(s["text"] for s in alert["signals"])  # each signal is explained in words
    # The collector's own report was sealed in the receipt and read back from it.
    assert alert["subject"]["report"]["user"] == "asha"
    assert "secure-login.top" in alert["subject"]["target"]
    # TinyFish enrichment: a scripted fake here, so only that the plumbing works.
    assert alert["web_evidence"]["status"] == "DONE"
    assert "Scripted search answer" in alert["web_evidence"]["search"]["text"]
    assert "Scripted page text" in alert["web_evidence"]["fetch"]["text"]
    # Both calls went through the gateway to the two real service addresses, in order.
    requested = [
        e["payload"]["target"]
        for e in summarize(receipt)["events"]
        if e["event_type"] == "ACTION_REQUESTED" and e["payload"]["action_id"].startswith("tf-")
    ]
    assert requested == ["https://api.search.tinyfish.ai", "https://api.fetch.tinyfish.ai"]
    # The person signed, and only then did the (simulated) isolation happen.
    assert alert["isolation"]["status"] == "ISOLATED_SIMULATED"
    types = event_types(receipt)
    assert "HUMAN_APPROVAL_GRANTED" in types
    assert types.index("HUMAN_APPROVAL_GRANTED") < max(
        i for i, t in enumerate(types) if t == "ACTION_SUCCEEDED"
    )
    assert "SIMULATED" in str(final["result"])


def test_without_a_tinyfish_key_the_alert_says_not_asked_never_safe(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "GRANTED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["web_evidence"]["status"] == "NOT_RUN"
    for part in ("search", "fetch"):
        assert alert["web_evidence"][part]["status"] == "NOT_RUN"
        assert alert["web_evidence"][part]["text"].lower().startswith("tinyfish was not asked")
    blocked = [e for e in summarize(receipt)["events"] if e["event_type"] == "ACTION_BLOCKED"]
    assert any("ENRICHMENT_NOT_RUN" in str(e["payload"]) for e in blocked)
    assert "not asked" in str(final["result"])


def test_a_denied_isolation_does_nothing_and_says_so(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "DENIED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["isolation"]["status"] == "DENIED"
    types = event_types(receipt)
    assert "HUMAN_APPROVAL_DENIED" in types
    # The isolation was never dispatched: only the endpoint events themselves were.
    assert types.count("ACTION_DISPATCHED") == 3


def test_when_nobody_answers_the_isolation_stays_waiting(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, wait_seconds=4)
    job = runner.start("phishing link in chat", None, None, "endpoint")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=240)
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["isolation"]["status"] == "WAITING_FOR_APPROVAL"
    assert event_types(receipt).count("ACTION_DISPATCHED") == 3


def test_the_full_set_finds_four_alerts_and_asks_once_per_person(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    job = runner.start("", None, None, "endpoint")
    answer_every_approval(runner, job, "GRANTED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alerts = alerts_from(receipt, summarize(receipt))
    assert [a["subject"]["kind"] for a in alerts] == [
        "url_click",
        "file_download",
        "record_query",
        "process_launch",
    ]
    assert [a["severity"] for a in alerts] == ["HIGH", "HIGH", "HIGH", "MEDIUM"]
    # asha and jsmith were each asked once (jsmith has two HIGH alerts); mkhan's is only MEDIUM.
    assert event_types(receipt).count("HUMAN_APPROVAL_GRANTED") == 2
    # Only alerts that have a link were sent for web evidence; the rest are NOT_ASKED.
    assert [a["web_evidence"]["status"] for a in alerts] == [
        "NOT_RUN",
        "NOT_RUN",
        "NOT_ASKED",
        "NOT_ASKED",
    ]


def test_a_receipt_with_no_alerts_gives_an_empty_alert_list(tmp_path: Path) -> None:
    from tests.ui.test_guarded_run import make_runner as guarded_runner

    runner = guarded_runner(tmp_path)
    job = runner.start(None, None, None, "guarded")
    status = wait_for(runner, job, lambda s: s["pending"] is not None or s["state"] != "running")
    runner.approve(job, "DENIED", status["pending"]["summary_digest"])
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert alerts_from(receipt, summarize(receipt)) == []


def test_a_pasted_link_is_scored_without_ever_being_opened_here(tmp_path: Path) -> None:
    runner = make_runner(tmp_path)
    link = "https://northwind-bank.secure-login.top/verify/account"
    job = runner.start(f"is this link safe? {link}", None, None, "endpoint")
    answer_every_approval(runner, job, "DENIED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alerts = alerts_from(receipt, summarize(receipt))
    assert len(alerts) == 1 and alerts[0]["severity"] == "HIGH"
    assert alerts[0]["subject"]["target"] == link
    assert {"LOOKALIKE_DOMAIN", "SUSPICIOUS_TLD", "LOGIN_LURE"} <= {
        s["rule_id"] for s in alerts[0]["signals"]
    }
    # This computer made no request to the link: the only api calls named TinyFish's services.
    targets = [
        e["payload"]["target"]
        for e in summarize(receipt)["events"]
        if e["event_type"] == "ACTION_REQUESTED" and e["payload"]["action_type"] == "api_call"
    ]
    assert all("secure-login.top" not in t for t in targets)


def test_events_written_by_the_real_collector_go_through_the_same_pipeline(
    tmp_path: Path,
) -> None:
    from endpoint.collector import append_events
    from endpoint.events import EndpointEvent

    events = tmp_path / "events.jsonl"
    append_events(
        events,
        [
            EndpointEvent(
                "file_download",
                "local-user",
                3,
                target="https://files.randomstorage.io/a.zip",
                size_mb=300,
            ),
            EndpointEvent(
                "file_download", "local-user", 11, target="local-file:///notes.txt", size_mb=1
            ),
        ],
    )
    runner = make_runner(tmp_path, "--events-file", str(events))
    job = runner.start("", None, None, "endpoint")
    answer_every_approval(runner, job, "GRANTED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alerts = alerts_from(receipt, summarize(receipt))
    assert len(alerts) == 1  # the ordinary download raised nothing
    assert alerts[0]["subject"]["report"]["user"] == "local-user"
    assert {s["rule_id"] for s in alerts[0]["signals"]} >= {"OFF_HOURS", "LARGE_DOWNLOAD"}


def test_a_malformed_events_file_is_refused_before_anything_starts(tmp_path: Path) -> None:
    events = tmp_path / "bad.jsonl"
    events.write_text("{not json}\n", encoding="utf-8")
    runner = make_runner(tmp_path, "--events-file", str(events))
    job = runner.start("", None, None, "endpoint")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=120)
    assert final["state"] == "failed"
    assert any("not a valid event" in line for line in final["lines"])


def test_an_event_only_the_learned_model_flags_is_a_lower_tier_with_no_account_action(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sklearn")
    from endpoint.collector import append_events
    from endpoint.model import get_model
    from endpoint.scoring import score
    from endpoint.synthetic import labelled_set

    model = get_model()
    odd = next(
        d.event
        for d in labelled_set(11)
        if not d.malicious and not score(d.event).is_alert and model.score(d.event).flagged
    )
    events = tmp_path / "events.jsonl"
    append_events(events, [odd])
    runner = make_runner(tmp_path, "--events-file", str(events))
    job = runner.start("", None, None, "endpoint")
    final = wait_for(runner, job, lambda s: s["state"] != "running", seconds=300)
    assert final["state"] == "done", final  # no approval was ever asked for
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alerts = alerts_from(receipt, summarize(receipt))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["severity"] == "REVIEW" and alert["signals"] == [] and alert["score_ppm"] == 0
    assert (
        alert["model"]["reasons"] and alert["model"]["score_ppm"] > alert["model"]["threshold_ppm"]
    )
    assert alert["isolation"]["status"] == "NOT_PROPOSED"
    assert "HUMAN_APPROVAL_REQUESTED" not in event_types(receipt)
    ml = [e for e in summarize(receipt)["events"] if e["event_type"] == "ML_ANALYSIS_COMPLETED"]
    assert [e["payload"]["model_id"] for e in ml] == ["isolation-forest"]
    assert set(ml[0]["payload"]) <= {
        "model_id",
        "model_version",
        "feature_schema_id",
        "score_ppm",
        "reason_codes",
        "score_kind",
        "threshold_ppm",
    }


def test_the_phishing_alert_carries_both_the_rules_and_the_models_opinion(
    tmp_path: Path,
) -> None:
    pytest.importorskip("sklearn")
    runner = make_runner(tmp_path)
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "DENIED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["severity"] == "HIGH" and alert["model"] is not None
    assert alert["model"]["reasons"] and all(r["text"] for r in alert["model"]["reasons"])


def test_with_the_model_switched_off_the_alert_has_the_rules_only(tmp_path: Path) -> None:
    runner = make_runner(tmp_path, "--model", "off")
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "DENIED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    receipt = tmp_path / "receipts" / str(final["receipt"])
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["model"] is None and alert["severity"] == "HIGH"


@pytest.mark.skipif(
    not (os.environ.get("ABB_TEST_S3") and os.environ.get("ABB_S3_ACCESS_KEY")),
    reason="needs a running S3-compatible server (ABB_TEST_S3 and credentials)",
)
def test_the_sealed_artifacts_live_in_object_storage_and_the_receipt_still_verifies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import uuid

    from services.artifacts.s3 import S3Client
    from services.artifacts.s3_store import object_key

    bucket = "abb-e2e-" + uuid.uuid4().hex[:8]
    monkeypatch.setenv("ABB_S3_ENDPOINT", os.environ["ABB_TEST_S3"])
    monkeypatch.setenv("ABB_S3_BUCKET", bucket)
    runner = make_runner(tmp_path, "--model", "off")
    job = runner.start("phishing link in chat", None, None, "endpoint")
    answer_every_approval(runner, job, "DENIED")
    final = wait_for(runner, job, lambda s: s["state"] != "running")
    assert final["state"] == "done", final
    receipt = tmp_path / "receipts" / str(final["receipt"])
    assert verify(receipt)["overall"] in {"VALID", "PARTIAL"}

    digests = {
        e["payload"]["artifact_digest"]
        for e in summarize(receipt)["events"]
        if e["event_type"] == "ARTIFACT_CAPTURED"
    }
    assert len(digests) >= 3  # the collector reports of the three events
    client = S3Client(
        os.environ["ABB_TEST_S3"], os.environ["ABB_S3_ACCESS_KEY"], os.environ["ABB_S3_SECRET_KEY"]
    )
    for digest in digests:
        assert client.head(bucket, object_key(digest.split(":")[-1])), digest
    # And the alert view still reads the report back out of the receipt.
    alert = alerts_from(receipt, summarize(receipt))[0]
    assert alert["subject"]["report"]["user"] == "asha"
