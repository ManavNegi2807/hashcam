"""Witness quorum and anchors: `PROTOCOL.md` 12 and 13, `D-02`, `D-15`, `R-WIT-*`.

The rule these tests exist to protect: **independence is never assumed**. A
witness on the signer's own machine produces a perfectly valid signature that
must still be reported `NOT_INDEPENDENT`, and a missing witness must never read
as a pass.

The "second device" here is a *label* on one machine, set through
`simulate_second_device`. That exercises the quorum rules; it does not create
independence, and nothing in these tests claims it does.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.tamper.test_tamper_suite import (  # noqa: E402,F401
    failing_dimensions,
    produced_receipt,
    read_receipt,
    verify,
    write_receipt,
)
from tools import demo  # noqa: E402


def export_with(
    context: dict[str, Any],
    name: str,
    *,
    simulate: bool,
    witness_roles: list[str],
    anchor: bool = True,
) -> Path:
    """Witness/anchor the current global checkpoint and export a receipt."""
    from services.api.canonical import Canonicalizer
    from services.api.export import Exporter
    from services.api.repository import Repository

    stack = dataclasses.replace(context["stack"], simulate_second_device=simulate)
    witnesses = [w for role in witness_roles if (w := demo.run_witness(stack, role)) is not None]
    anchors = [demo.anchor_record(stack)] if anchor else []
    repository = Repository(
        connect=demo.connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb)
    )
    out = stack.work / f"{name}.abbreceipt"
    Exporter(repository=repository, abb_path=stack.abb, store=demo.artifact_store(stack)).export(
        context["run_id"], out, witnesses=witnesses, anchors=anchors
    )
    return Path(out)


def verify_as(
    context: dict[str, Any], receipt: Path, *, simulate: bool, profile: str = "LOCAL_ONLY"
) -> tuple[int, dict[str, Any]]:
    stack = dataclasses.replace(context["stack"], simulate_second_device=simulate)
    manifest = demo.key_manifest(stack)
    done = subprocess.run(  # noqa: S603
        [
            context["abb"],
            "verify",
            str(receipt),
            "--keys",
            str(manifest),
            "--profile",
            profile,
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    return done.returncode, json.loads(done.stdout.decode("utf-8"))


def edit(context: dict[str, Any], source: Path, name: str, change: Any) -> Path:
    document = read_receipt(source)
    change(document)
    path = context["stack"].work / f"{name}.abbreceipt"
    write_receipt(document, path, keep_artifacts_from=source)
    return Path(path)


# --------------------------------------------------------------------------- #
# independence is never assumed
# --------------------------------------------------------------------------- #


def test_a_witness_on_the_signers_own_machine_is_not_independent(
    produced_receipt: dict[str, Any],
) -> None:
    path = export_with(produced_receipt, "same-box", simulate=False, witness_roles=["witness1"])
    code, report = verify_as(produced_receipt, path, simulate=False)
    assert report["dimensions"]["witness_quorum"] == "NOT_INDEPENDENT", report
    assert report["dimensions"]["anchor_match"] == "NOT_INDEPENDENT", report
    # Never VALID: independence is missing, so the best it can be is PARTIAL.
    assert report["overall"] == "PARTIAL", report
    assert code == 3


def test_two_witnesses_in_distinct_domains_apart_from_the_signer_pass(
    produced_receipt: dict[str, Any],
) -> None:
    path = export_with(
        produced_receipt, "quorum", simulate=True, witness_roles=["witness1", "witness2"]
    )
    code, report = verify_as(produced_receipt, path, simulate=True)
    assert report["dimensions"]["witness_quorum"] == "PASS", report
    assert report["dimensions"]["anchor_match"] == "PASS", report
    assert report["overall"] == "VALID", report
    assert code == 0


def test_one_independent_witness_is_short_of_the_quorum_not_a_pass(
    produced_receipt: dict[str, Any],
) -> None:
    path = export_with(produced_receipt, "one", simulate=True, witness_roles=["witness1"])
    code, report = verify_as(produced_receipt, path, simulate=True)
    assert report["dimensions"]["witness_quorum"] == "UNKNOWN", report
    assert report["overall"] == "PARTIAL", report
    assert code == 3


def test_no_witnesses_is_not_applicable_locally_and_unknown_when_required(
    produced_receipt: dict[str, Any],
) -> None:
    receipt = produced_receipt["receipt"]
    _, local = verify_as(produced_receipt, receipt, simulate=False, profile="LOCAL_ONLY")
    assert local["dimensions"]["witness_quorum"] == "NOT_APPLICABLE"
    assert local["overall"] == "VALID"

    code, connected = verify_as(
        produced_receipt, receipt, simulate=False, profile="CONNECTED_EVIDENCE"
    )
    # Under the connected profile missing witnesses are missing evidence.
    assert connected["dimensions"]["witness_quorum"] == "UNKNOWN", connected
    assert connected["dimensions"]["anchor_match"] == "UNKNOWN", connected
    assert connected["overall"] == "INCOMPLETE", connected
    assert code == 2


# --------------------------------------------------------------------------- #
# a present signature that does not verify is a failure
# --------------------------------------------------------------------------- #


def test_a_forged_witness_signature_fails(produced_receipt: dict[str, Any]) -> None:
    good = export_with(
        produced_receipt, "to-forge", simulate=True, witness_roles=["witness1", "witness2"]
    )

    def change(document: dict[str, Any]) -> None:
        signature = document["witnesses"][0]["signature"]
        flipped = "0" if signature[-1] != "0" else "1"
        document["witnesses"][0]["signature"] = signature[:-1] + flipped

    path = edit(produced_receipt, good, "forged-witness", change)
    code, report = verify_as(produced_receipt, path, simulate=True)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "witness_quorum" in failing_dimensions(report)


def test_a_witness_that_lies_about_its_domain_fails(produced_receipt: dict[str, Any]) -> None:
    """The domain in the signed statement must match the key manifest's."""
    good = export_with(
        produced_receipt, "to-lie", simulate=True, witness_roles=["witness1", "witness2"]
    )

    def change(document: dict[str, Any]) -> None:
        # Re-label the statement; the signature then covers different bytes.
        record = document["witnesses"][0]
        statement = json.loads(base64.b64decode(record["statement_b64"]).decode("utf-8"))
        statement["failure_domain"] = "host:somewhere-else/admin:nobody"
        record["statement_b64"] = base64.b64encode(
            json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
        ).decode("ascii")

    path = edit(produced_receipt, good, "lying-witness", change)
    _, report = verify_as(produced_receipt, path, simulate=True)
    assert report["overall"] == "INVALID", report
    assert "witness_quorum" in failing_dimensions(report)


# --------------------------------------------------------------------------- #
# anchors
# --------------------------------------------------------------------------- #


def test_an_anchor_that_publishes_a_different_hash_fails(
    produced_receipt: dict[str, Any],
) -> None:
    good = export_with(produced_receipt, "to-mismatch", simulate=True, witness_roles=["witness1"])

    def change(document: dict[str, Any]) -> None:
        document["anchors"][0]["checkpoint_hash"] = "ab" * 32

    path = edit(produced_receipt, good, "anchor-mismatch", change)
    code, report = verify_as(produced_receipt, path, simulate=True)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "anchor_match" in failing_dimensions(report)
    messages = " ".join(d["message"] for d in report["details"] if d["dimension"] == "anchor_match")
    assert "ANCHOR_MISMATCH" in messages


def test_an_anchor_larger_than_the_receipts_log_fails(produced_receipt: dict[str, Any]) -> None:
    good = export_with(produced_receipt, "to-grow", simulate=True, witness_roles=["witness1"])

    def change(document: dict[str, Any]) -> None:
        document["anchors"][0]["tree_size"] = 99

    path = edit(produced_receipt, good, "anchor-bigger", change)
    _, report = verify_as(produced_receipt, path, simulate=True)
    assert report["overall"] == "INVALID", report
    assert "anchor_match" in failing_dimensions(report)


# --------------------------------------------------------------------------- #
# the witness refuses what it should (R-WIT-06)
# --------------------------------------------------------------------------- #


def test_the_witness_refuses_to_sign_after_a_rollback(produced_receipt: dict[str, Any]) -> None:
    """A witness that has seen size N will not sign a smaller or different tree."""
    stack = dataclasses.replace(produced_receipt["stack"], simulate_second_device=True)
    keys = stack.work / "keys"
    assert (keys / "witness1.key").exists(), "an earlier test should have created it"
    state = stack.work / "witness1-state.json"
    saved = json.loads(state.read_text(encoding="utf-8"))
    assert saved["tree_size"] >= 1

    # Pretend this witness had already seen a much larger log.
    state.write_text(json.dumps({**saved, "tree_size": saved["tree_size"] + 5}), encoding="utf-8")
    try:
        checkpoint, records = demo.global_checkpoint_files(stack, "witness1")
        done = subprocess.run(  # noqa: S603
            [
                produced_receipt["abb"],
                "witness",
                "sign",
                "--key",
                str(keys / "witness1.key"),
                "--state",
                str(state),
                "--keys",
                str(demo.key_manifest(stack)),
                "--domain",
                demo.domain_of(stack, "witness1"),
                "--checkpoint",
                str(checkpoint),
                "--records",
                str(records),
            ],
            capture_output=True,
            check=False,
        )
        assert done.returncode != 0
        assert "SIZE_REGRESSION" in done.stderr.decode("utf-8", "replace")
    finally:
        state.write_text(json.dumps(saved), encoding="utf-8")


def test_the_witness_refuses_records_that_do_not_rebuild_the_root(
    produced_receipt: dict[str, Any],
) -> None:
    stack = dataclasses.replace(produced_receipt["stack"], simulate_second_device=True)
    keys = stack.work / "keys"
    checkpoint, records = demo.global_checkpoint_files(stack, "witness1")
    records.write_text(base64.b64encode(b'{"run_id":"forged"}').decode("ascii"), encoding="utf-8")
    done = subprocess.run(  # noqa: S603
        [
            produced_receipt["abb"],
            "witness",
            "sign",
            "--key",
            str(keys / "witness1.key"),
            "--state",
            str(stack.work / "fresh-state.json"),
            "--keys",
            str(demo.key_manifest(stack)),
            "--domain",
            demo.domain_of(stack, "witness1"),
            "--checkpoint",
            str(checkpoint),
            "--records",
            str(records),
        ],
        capture_output=True,
        check=False,
    )
    assert done.returncode != 0
    assert "ROOT_MISMATCH" in done.stderr.decode("utf-8", "replace")
    # It did not write any state for a signature it refused to give.
    assert not (stack.work / "fresh-state.json").exists()
