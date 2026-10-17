"""The tamper suite: `TESTING.md` section 4, the core promise of the product.

Each test takes a real receipt from a real run — real signer, real database,
real policy gateway — applies exactly one change, and asserts both the verifier
result **and** that the broken point is named.

Covered here: TS-01 (edit an event), TS-02 (reorder), TS-03 (delete one event),
TS-04 (truncate), TS-05 (insert), TS-06 (change a checkpoint root), TS-12
(alter a run root in the global log) and TS-16 (container attacks). TS-07, TS-08
and TS-13 are signer and key cases, covered in `signer/tests/sign.rs` and
`core/abb-checkpoint`. TS-09 and TS-10 need artifacts (Step 6). TS-11 is the
deleted-run case, covered by `verify-global` in `core/abb-cli/tests/cli.rs` and
in the demo.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402


@pytest.fixture(scope="module")
def produced_receipt(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    """One real run, exported once, shared by every test in this module."""
    pytest.importorskip("psycopg")
    import os

    admin_dsn = os.environ.get("ABB_TEST_DSN")
    if not admin_dsn:
        pytest.skip("set ABB_TEST_DSN to run the tamper suite against a real database")

    from policy.engine import Policy
    from tools import demo

    try:
        abb = demo.binary("abb", "ABB_BIN")
        signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    except SystemExit as exc:
        pytest.skip(str(exc))

    work = tmp_path_factory.mktemp("tamper")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    dsn = demo.prepare_database(admin_dsn, migration)
    policy = Policy.load("default", 1)
    tokens = demo.seed(dsn, policy)

    stack = demo.Stack(
        work=work,
        dsn=dsn,
        abb=abb,
        signer_bin=signer_bin,
        signer_port=demo.free_port(),
        api_port=demo.free_port(),
    )
    demo.start_stack(stack)
    try:
        base_url = f"http://127.0.0.1:{stack.api_port}"
        run_id = demo.create_run(base_url, tokens["operator"], policy)
        demo.run_scenario(stack, base_url, tokens["adapter"], policy, run_id)
        receipt = demo.finalize_and_export(stack, run_id, policy)
        manifest = demo.key_manifest(stack)
        yield {
            "stack": stack,
            "receipt": receipt,
            "keys": manifest,
            "run_id": run_id,
            "abb": abb,
        }
    finally:
        stack.stop()


def verify(context: dict[str, Any], receipt: Path) -> tuple[int, dict[str, Any]]:
    """Run the offline verifier and return (exit code, parsed JSON report)."""
    done = subprocess.run(  # noqa: S603
        [
            context["abb"],
            "verify",
            str(receipt),
            "--keys",
            str(context["keys"]),
            "--profile",
            "LOCAL_ONLY",
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    text = done.stdout.decode("utf-8", "replace").strip()
    if not text.startswith("{"):
        return done.returncode, {"overall": "UNPARSEABLE", "raw": text}
    return done.returncode, json.loads(text)


def read_receipt(receipt: Path) -> dict[str, Any]:
    with zipfile.ZipFile(pathsafe.extended(receipt)) as archive:
        loaded = json.loads(archive.read("receipt.json").decode("utf-8"))
    return cast("dict[str, Any]", loaded)


def read_members(receipt: Path) -> dict[str, bytes]:
    """Every file in the container, including artifacts."""
    with zipfile.ZipFile(pathsafe.extended(receipt)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def write_members(members: dict[str, bytes], path: Path) -> Path:
    with zipfile.ZipFile(pathsafe.extended(path), "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return path


def write_receipt(
    document: dict[str, Any], path: Path, *, keep_artifacts_from: Path | None = None
) -> Path:
    members = {"receipt.json": json.dumps(document, separators=(",", ":")).encode()}
    if keep_artifacts_from is not None:
        members.update(
            {k: v for k, v in read_members(keep_artifacts_from).items() if k != "receipt.json"}
        )
    return write_members(members, path)


def mutate(context: dict[str, Any], name: str, change: Any) -> tuple[int, dict[str, Any]]:
    """Apply `change` to a copy of the receipt and verify the result."""
    document = read_receipt(context["receipt"])
    change(document)
    path = context["stack"].work / f"{name}.abbreceipt"
    write_receipt(document, path, keep_artifacts_from=context["receipt"])
    return verify(context, path)


def failing_dimensions(report: dict[str, Any]) -> set[str]:
    return {name for name, status in report.get("dimensions", {}).items() if status == "FAIL"}


def details_for(report: dict[str, Any], dimension: str) -> list[dict[str, Any]]:
    return [d for d in report.get("details", []) if d.get("dimension") == dimension]


# --------------------------------------------------------------------------- #
# the untouched receipt: the control
# --------------------------------------------------------------------------- #


def test_the_untouched_receipt_is_valid(produced_receipt: dict[str, Any]) -> None:
    code, report = verify(produced_receipt, produced_receipt["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    assert failing_dimensions(report) == set()
    # Every required dimension actually passed, rather than being skipped.
    for required in (
        "evidence_integrity",
        "checkpoint_signatures",
        "consistency",
        "global_log_inclusion",
        "observation_coverage",
        "policy_assessment",
    ):
        assert report["dimensions"][required] == "PASS", required


# --------------------------------------------------------------------------- #
# TS-01 edit one event
# --------------------------------------------------------------------------- #


def test_ts01_editing_one_event_names_that_event(produced_receipt: dict[str, Any]) -> None:
    edited_sequence: list[int] = []

    def change(document: dict[str, Any]) -> None:
        for index, event in enumerate(document["events"]):
            canonical = base64.b64decode(event["canonical_b64"])
            if b"BROWSER_OBSERVATION" in canonical:
                marker = b'"text_digest":"'
                at = canonical.find(marker) + len(marker)
                flipped = bytearray(canonical)
                flipped[at] = ord("0") if chr(flipped[at]) != "0" else ord("1")
                event["canonical_b64"] = base64.b64encode(bytes(flipped)).decode("ascii")
                edited_sequence.append(index)
                return
        raise AssertionError("no observation event to edit")

    code, report = mutate(produced_receipt, "ts01", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
    details = details_for(report, "evidence_integrity")
    assert details, report
    # The broken point is named, with the sequence of the edited event.
    assert any(
        f"sequence {edited_sequence[0]}" in str(detail.get("locator", "")) for detail in details
    ), details


# --------------------------------------------------------------------------- #
# TS-02 reorder two events
# --------------------------------------------------------------------------- #


def test_ts02_reordering_two_events_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        events = document["events"]
        events[2], events[3] = events[3], events[2]

    code, report = mutate(produced_receipt, "ts02", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
    messages = " ".join(d["message"] for d in details_for(report, "evidence_integrity"))
    # Either the sequence check or the proof check may speak first; both name
    # the problem as ordering or membership, not something vague.
    assert "sequence" in messages or "not in the signed tree" in messages, messages


# --------------------------------------------------------------------------- #
# TS-03 delete one event from the middle
# --------------------------------------------------------------------------- #


def test_ts03_deleting_one_event_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        del document["events"][4]

    code, report = mutate(produced_receipt, "ts03", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
    messages = " ".join(d["message"] for d in details_for(report, "evidence_integrity"))
    assert "gap" in messages or "covers" in messages, messages


# --------------------------------------------------------------------------- #
# TS-04 truncate the tail after a checkpoint
# --------------------------------------------------------------------------- #


def test_ts04_truncating_the_tail_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        document["events"] = document["events"][:-3]

    code, report = mutate(produced_receipt, "ts04", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
    messages = " ".join(d["message"] for d in details_for(report, "evidence_integrity"))
    assert "truncated" in messages or "covers" in messages, messages


# --------------------------------------------------------------------------- #
# TS-05 insert an event
# --------------------------------------------------------------------------- #


def test_ts05_inserting_an_event_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        document["events"].append(json.loads(json.dumps(document["events"][1])))

    code, report = mutate(produced_receipt, "ts05", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)


# --------------------------------------------------------------------------- #
# TS-06 change a checkpoint root
# --------------------------------------------------------------------------- #


def test_ts06_changing_a_checkpoint_root_breaks_its_signature(
    produced_receipt: dict[str, Any],
) -> None:
    def change(document: dict[str, Any]) -> None:
        checkpoint = document["checkpoints"][-1]
        payload = json.loads(base64.b64decode(checkpoint["payload_b64"]).decode("utf-8"))
        payload["root_hash"] = "ab" * 32
        # Re-canonicalize by hand is not possible here, and that is the point:
        # the bytes are what was signed. Writing different bytes breaks the
        # signature, which is exactly what must be detected.
        checkpoint["payload_b64"] = base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii")

    code, report = mutate(produced_receipt, "ts06", change)
    assert report["overall"] in {"INVALID", "UNSUPPORTED"}, report
    assert code in {1, 4, 65}
    if report["overall"] == "INVALID":
        assert {"checkpoint_signatures"} & failing_dimensions(report), report


# --------------------------------------------------------------------------- #
# TS-12 alter a run root in the global log
# --------------------------------------------------------------------------- #


def test_ts12_altering_the_run_root_breaks_global_inclusion(
    produced_receipt: dict[str, Any],
) -> None:
    def change(document: dict[str, Any]) -> None:
        global_log = document["global_log"]
        record = json.loads(base64.b64decode(global_log["record_b64"]).decode("utf-8"))
        record["tree_size"] = int(record["tree_size"]) + 1
        global_log["record_b64"] = base64.b64encode(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii")

    code, report = mutate(produced_receipt, "ts12", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "global_log_inclusion" in failing_dimensions(report)


def test_removing_the_global_log_is_incomplete_not_valid(
    produced_receipt: dict[str, Any],
) -> None:
    """A receipt without global inclusion cannot support the deleted-run check."""

    def change(document: dict[str, Any]) -> None:
        document.pop("global_log")

    code, report = mutate(produced_receipt, "no-global", change)
    assert report["overall"] == "INCOMPLETE", report
    assert code == 2
    assert report["dimensions"]["global_log_inclusion"] == "UNKNOWN"


# --------------------------------------------------------------------------- #
# TS-16 container attacks
# --------------------------------------------------------------------------- #


def test_ts16_container_attacks_are_refused_before_verification(
    produced_receipt: dict[str, Any],
) -> None:
    work = produced_receipt["stack"].work
    document = read_receipt(produced_receipt["receipt"])
    body = json.dumps(document, separators=(",", ":"))

    # Path traversal.
    traversal = work / "traversal.abbreceipt"
    with zipfile.ZipFile(pathsafe.extended(traversal), "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("receipt.json", body)
        archive.writestr("../escape.txt", "nope")
    code, report = verify(produced_receipt, traversal)
    assert code == 65, report
    assert report["overall"] == "UNPARSEABLE"

    # A nested archive.
    nested = work / "nested.abbreceipt"
    inner = work / "inner.zip"
    with zipfile.ZipFile(pathsafe.extended(inner), "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("receipt.json", "{}")
    with zipfile.ZipFile(pathsafe.extended(nested), "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("receipt.json", body)
        archive.writestr("artifacts/inner", pathsafe.read_bytes(inner))
    code, _ = verify(produced_receipt, nested)
    assert code == 65

    # A zip bomb.
    bomb = work / "bomb.abbreceipt"
    with zipfile.ZipFile(pathsafe.extended(bomb), "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("receipt.json", "0" * (16 * 1024 * 1024))
    code, _ = verify(produced_receipt, bomb)
    assert code == 65

    # Not an archive at all.
    rubbish = work / "rubbish.abbreceipt"
    pathsafe.write_text(rubbish, "definitely not a zip")
    code, _ = verify(produced_receipt, rubbish)
    assert code == 65


# --------------------------------------------------------------------------- #
# coverage honesty: the claim that makes the labels mean something
# --------------------------------------------------------------------------- #


def test_a_dispatch_without_an_authorization_fails_coverage(
    produced_receipt: dict[str, Any],
) -> None:
    """TS-15 and `R-COV-07`, from the receipt alone.

    Removing an authorization leaves a dispatch unexplained. The verifier must
    notice from the events, without trusting the gateway's own claim.
    """

    def change(document: dict[str, Any]) -> None:
        kept = []
        dropped = False
        for event in document["events"]:
            canonical = base64.b64decode(event["canonical_b64"])
            if not dropped and b'"event_type":"ACTION_AUTHORIZED"' in canonical:
                dropped = True
                continue
            kept.append(event)
        assert dropped, "no authorization to remove"
        document["events"] = kept

    code, report = mutate(produced_receipt, "ts15", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    # evidence_integrity fails too, because the tree no longer matches; what
    # matters is that coverage is not quietly reported as PASS.
    assert report["dimensions"]["observation_coverage"] == "FAIL", report
    messages = " ".join(d["message"] for d in details_for(report, "observation_coverage"))
    assert "no earlier authorization" in messages, messages


def test_claiming_more_coverage_than_was_observed_fails(
    produced_receipt: dict[str, Any],
) -> None:
    def change(document: dict[str, Any]) -> None:
        document["run"]["observed_coverage"] = "TASK_LEVEL"

    code, report = mutate(produced_receipt, "coverage-claim", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert report["dimensions"]["observation_coverage"] == "FAIL"


# --------------------------------------------------------------------------- #
# the verifier without keys
# --------------------------------------------------------------------------- #


def test_without_a_key_manifest_signatures_are_unknown_not_passed(
    produced_receipt: dict[str, Any],
) -> None:
    done = subprocess.run(  # noqa: S603
        [
            produced_receipt["abb"],
            "verify",
            str(produced_receipt["receipt"]),
            "--profile",
            "LOCAL_ONLY",
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    report = json.loads(done.stdout.decode("utf-8"))
    assert report["dimensions"]["checkpoint_signatures"] == "UNKNOWN"
    assert report["overall"] == "INCOMPLETE"
    assert done.returncode == 2


def test_a_copied_receipt_still_verifies(produced_receipt: dict[str, Any]) -> None:
    """A receipt is portable: verification needs no database and no network."""
    copy = produced_receipt["stack"].work / "copied.abbreceipt"
    shutil.copyfile(pathsafe.extended(produced_receipt["receipt"]), pathsafe.extended(copy))
    code, report = verify(produced_receipt, copy)
    assert report["overall"] == "VALID", report
    assert code == 0


# --------------------------------------------------------------------------- #
# Step 6: artifacts and the manifest
# --------------------------------------------------------------------------- #


def test_the_untouched_receipt_ships_and_passes_its_artifacts(
    produced_receipt: dict[str, Any],
) -> None:
    _, report = verify(produced_receipt, produced_receipt["receipt"])
    assert report["overall"] == "VALID", report
    assert report["dimensions"]["artifact_manifest_integrity"] == "PASS"
    assert report["dimensions"]["artifact_availability"] == "PASS"
    members = read_members(produced_receipt["receipt"])
    assert len([n for n in members if n.startswith("artifacts/")]) == 2


def test_ts09_swapping_an_artifact_file_names_the_artifact(
    produced_receipt: dict[str, Any],
) -> None:
    members = read_members(produced_receipt["receipt"])
    victim = sorted(n for n in members if n.startswith("artifacts/"))[0]
    members[victim] = b"<html>a page the agent never saw</html>"
    path = write_members(members, produced_receipt["stack"].work / "ts09.abbreceipt")

    code, report = verify(produced_receipt, path)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "artifact_manifest_integrity" in failing_dimensions(report)
    digest = victim.removeprefix("artifacts/")
    named = details_for(report, "artifact_manifest_integrity")
    assert any(digest in str(d.get("locator", "")) for d in named), named
    # Everything else still holds: only the artifact is wrong.
    assert report["dimensions"]["evidence_integrity"] == "PASS"


def test_ts10_a_broken_manifest_link_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        entries = document["artifacts"]["manifest_entries"]
        entry = json.loads(base64.b64decode(entries[1]).decode("utf-8"))
        entry["prev_manifest_hash"] = "ab" * 32
        entries[1] = base64.b64encode(
            json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii")

    code, report = mutate(produced_receipt, "ts10", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "artifact_manifest_integrity" in failing_dimensions(report)


def test_dropping_a_manifest_entry_is_caught(produced_receipt: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        del document["artifacts"]["manifest_entries"][0]

    _, report = mutate(produced_receipt, "drop-entry", change)
    assert report["overall"] == "INVALID", report
    assert "artifact_manifest_integrity" in failing_dimensions(report)


def test_removing_the_whole_manifest_is_caught_by_the_signed_head(
    produced_receipt: dict[str, Any],
) -> None:
    """The checkpoint commits to the manifest, so deleting it cannot hide."""

    def change(document: dict[str, Any]) -> None:
        document.pop("artifacts")

    _, report = mutate(produced_receipt, "no-manifest", change)
    assert report["overall"] == "INVALID", report
    assert report["dimensions"]["artifact_manifest_integrity"] == "FAIL"
    found = details_for(report, "artifact_manifest_integrity")
    messages = " ".join(d["message"] for d in found)
    assert "manifest was removed" in messages, messages


def test_artifacts_not_shipped_leave_availability_unknown_not_pass(
    produced_receipt: dict[str, Any],
) -> None:
    members = read_members(produced_receipt["receipt"])
    only_json = {"receipt.json": members["receipt.json"]}
    path = write_members(only_json, produced_receipt["stack"].work / "no-files.abbreceipt")

    code, report = verify(produced_receipt, path)
    assert report["dimensions"]["artifact_manifest_integrity"] == "PASS"
    assert report["dimensions"]["artifact_availability"] == "UNKNOWN"
    # Availability is optional, so the receipt is PARTIAL, never VALID.
    assert report["overall"] == "PARTIAL", report
    assert code == 3
