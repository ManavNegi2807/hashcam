"""Signed approvals, the signed mandate and salted field commitments (Step 9).

`PROTOCOL.md` 5.5 to 5.7, `D-11`, `D-16`, `TS-14`, `R-APR-*`, `R-CMT-*`.

Every test here uses the real signer, the real API, a real PostgreSQL and the
offline verifier. The approver's key and the mandate issuer's key live in a
directory the API and the signer are never pointed at, so the control plane
cannot sign for them: that separation is what the tests lean on.

What these tests do **not** show: that the person who held the approver key was
the person they claim to be. A signature shows a key signed (`R-APR-08`).
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from tests.tamper.test_tamper_suite import (  # noqa: E402
    details_for,
    failing_dimensions,
    mutate,
    read_members,
    read_receipt,
    verify,
)

CARD = "4111111111111111"  # a published fake test card number


@pytest.fixture(scope="module")
def ctx(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    pytest.importorskip("psycopg")
    import os

    admin_dsn = os.environ.get("ABB_TEST_DSN")
    if not admin_dsn:
        pytest.skip("set ABB_TEST_DSN to run the approval and mandate tests")

    from policy.engine import Policy
    from tools import demo

    try:
        abb = demo.binary("abb", "ABB_BIN")
        signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    except SystemExit as exc:
        pytest.skip(str(exc))

    work = tmp_path_factory.mktemp("approvals")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    dsn = demo.prepare_database(admin_dsn, migration)
    default = Policy.load("default", 1)
    redacting = Policy.load("redacting", 1)
    guarded = Policy.load("guarded", 1)
    tokens = demo.seed(dsn, default)
    demo.seed_policy(dsn, redacting)
    demo.seed_policy(dsn, guarded)
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
        yield {
            "stack": stack,
            "abb": abb,
            "tokens": tokens,
            "base_url": f"http://127.0.0.1:{stack.api_port}",
            "default": default,
            "redacting": redacting,
            "guarded": guarded,
        }
    finally:
        stack.stop()


def produce(
    ctx: dict[str, Any],
    scenario: str,
    *,
    policy_name: str = "default",
    disclose: list[str] | None = None,
    **options: Any,
) -> dict[str, Any]:
    """Run a scenario, finalize, export, and shape the result like the tamper suite's."""
    from tools import demo

    stack = ctx["stack"]
    policy = ctx[policy_name]
    wrap = options.pop("_policy", None)
    if wrap is not None:
        policy = wrap(policy)
    run_id, gateway, result = demo.run_with_approver(
        stack, ctx["base_url"], ctx["tokens"], policy, scenario, **options
    )
    receipt = demo.finalize_and_export(stack, run_id, policy, disclose=disclose)
    return {
        "stack": stack,
        "receipt": receipt,
        "keys": demo.key_manifest(stack),
        "run_id": run_id,
        "abb": ctx["abb"],
        "gateway": gateway,
        "result": result,
    }


def event_types(context: dict[str, Any]) -> list[str]:
    document = read_receipt(context["receipt"])
    return [
        json.loads(base64.b64decode(e["canonical_b64"]))["event_type"] for e in document["events"]
    ]


def events_of(context: dict[str, Any]) -> list[dict[str, Any]]:
    document = read_receipt(context["receipt"])
    return [json.loads(base64.b64decode(e["canonical_b64"])) for e in document["events"]]


def card_requested(context: dict[str, Any]) -> dict[str, Any]:
    """The `ACTION_REQUESTED` event for the form-fill that typed the card."""
    return next(
        e
        for e in events_of(context)
        if e["event_type"] == "ACTION_REQUESTED" and e["payload"]["action_id"] == "c-2"
    )


def reasons(report: dict[str, Any], dimension: str) -> str:
    return " | ".join(d["message"] for d in details_for(report, dimension))


# =========================================================================== #
# signed approvals
# =========================================================================== #


@pytest.fixture(scope="module")
def granted(ctx: dict[str, Any]) -> dict[str, Any]:
    return produce(ctx, "bank_change_approval", approve="GRANTED")


def test_a_signed_grant_lets_the_gated_action_through_and_the_receipt_is_valid(
    granted: dict[str, Any],
) -> None:
    code, report = verify(granted, granted["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    assert report["dimensions"]["policy_assessment"] == "PASS"
    # No mandate was used, so that dimension does not apply.
    assert report["dimensions"]["mandate_compliance"] == "NOT_APPLICABLE"

    types = event_types(granted)
    granted_at = types.index("HUMAN_APPROVAL_GRANTED")
    # The gated action is authorized only after the grant, and dispatched after that.
    assert "ACTION_AUTHORIZED" in types[granted_at:]
    assert "ACTION_DISPATCHED" in types[types.index("ACTION_AUTHORIZED", granted_at) :]
    assert "approvals" in read_receipt(granted["receipt"])


def test_the_receipt_says_a_key_signed_not_who_held_it(granted: dict[str, Any]) -> None:
    _, report = verify(granted, granted["receipt"])
    text = reasons(report, "policy_assessment")
    assert "signed" in text
    assert "not which person held it" in text


def test_waiting_for_an_approver_dispatches_nothing(ctx: dict[str, Any]) -> None:
    waiting = produce(ctx, "bank_change_approval", approve=None)
    code, report = verify(waiting, waiting["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    types = event_types(waiting)
    assert "HUMAN_APPROVAL_REQUESTED" in types
    assert "HUMAN_APPROVAL_GRANTED" not in types
    # b-2 is the gated action: only b-1 may have been dispatched.
    dispatched = [e for e in events_of(waiting) if e["event_type"] == "ACTION_DISPATCHED"]
    assert [e["payload"]["action_id"] for e in dispatched] == ["b-1"]


def test_a_signed_denial_dispatches_nothing_and_is_recorded(ctx: dict[str, Any]) -> None:
    denied = produce(ctx, "bank_change_approval", approve="DENIED")
    code, report = verify(denied, denied["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    types = event_types(denied)
    assert "HUMAN_APPROVAL_DENIED" in types
    dispatched = [e for e in events_of(denied) if e["event_type"] == "ACTION_DISPATCHED"]
    assert [e["payload"]["action_id"] for e in dispatched] == ["b-1"]


def test_ts14_a_forged_approval_signature_fails_policy_assessment(granted: dict[str, Any]) -> None:
    def change(document: dict[str, Any]) -> None:
        signature = document["approvals"][0]["signature"]
        flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
        document["approvals"][0]["signature"] = flipped

    code, report = mutate(granted, "ts14", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "policy_assessment" in failing_dimensions(report)
    assert "does not verify" in reasons(report, "policy_assessment")
    # Only the approval is wrong; the history itself is untouched.
    assert report["dimensions"]["evidence_integrity"] == "PASS"


def test_removing_the_signed_statement_means_the_grant_is_just_the_control_planes_word(
    granted: dict[str, Any],
) -> None:
    def change(document: dict[str, Any]) -> None:
        document.pop("approvals")

    _, report = mutate(granted, "no-approvals", change)
    assert report["overall"] == "INVALID", report
    assert "policy_assessment" in failing_dimensions(report)
    assert "no signed statement" in reasons(report, "policy_assessment")


def test_a_statement_for_a_different_summary_is_an_approval_mismatch(
    ctx: dict[str, Any], granted: dict[str, Any]
) -> None:
    """The approver is tricked into signing a different summary than requested."""
    import subprocess

    from tools import demo

    stack = ctx["stack"]
    document = read_receipt(granted["receipt"])
    old = json.loads(base64.b64decode(document["approvals"][0]["statement_b64"]))
    done = subprocess.run(  # noqa: S603
        [
            stack.abb,
            "approve",
            "--key",
            str(demo.people_dir(stack) / "approver.key"),
            "--run-id",
            old["run_id"],
            "--action-id",
            old["action_id"],
            "--approval-id",
            old["approval_id"],
            "--decision",
            "GRANTED",
            "--expires-at",
            str(old["expires_at"]),
            "--summary",
            "form_submit https://evil.example/collect",
        ],
        capture_output=True,
        check=True,
    )
    fields = dict(line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line)

    def change(doc: dict[str, Any]) -> None:
        doc["approvals"][0]["statement_b64"] = fields["statement_b64"]
        doc["approvals"][0]["signature"] = fields["signature"]

    _, report = mutate(granted, "mismatch", change)
    assert "policy_assessment" in failing_dimensions(report)
    assert "APPROVAL_MISMATCH" in reasons(report, "policy_assessment")


def test_an_approver_key_missing_from_the_manifest_fails(
    ctx: dict[str, Any], granted: dict[str, Any]
) -> None:
    manifest = json.loads(pathsafe.read_text(granted["keys"]))
    manifest["keys"] = [k for k in manifest["keys"] if k["role"] != "approver"]
    stripped = ctx["stack"].work / "manifest_without_approver.json"
    stripped.write_text(json.dumps(manifest), encoding="utf-8")
    context = dict(granted, keys=stripped)
    _, report = verify(context, granted["receipt"])
    assert "policy_assessment" in failing_dimensions(report)
    assert "not an active approver" in reasons(report, "policy_assessment")


def test_without_any_key_manifest_the_approval_is_unknown_never_pass(
    granted: dict[str, Any],
) -> None:
    import subprocess

    done = subprocess.run(  # noqa: S603
        [
            granted["abb"],
            "verify",
            str(granted["receipt"]),
            "--profile",
            "LOCAL_ONLY",
            "--json",
        ],
        capture_output=True,
        check=False,
    )
    report = json.loads(done.stdout.decode())
    assert report["dimensions"]["policy_assessment"] != "PASS"
    assert report["overall"] != "VALID"


def test_the_relay_refuses_an_approver_key_that_is_not_in_the_manifest(
    ctx: dict[str, Any],
) -> None:
    import subprocess

    from services.worker.approval_client import HttpApprovalClient
    from services.worker.event_sink import SinkError
    from tools import demo

    stack = ctx["stack"]
    stranger = stack.work / "stranger"
    subprocess.run(  # noqa: S603
        [stack.abb, "keygen", "--out", str(stranger), "--role", "approver"],
        capture_output=True,
        check=True,
    )

    # Reach the point where an approval is pending, then sign it with the wrong key.
    outcome: dict[str, Any] = {}

    def run() -> None:
        from adapters.replay.adapter import IN_SCOPE_ACTIONS, ReplayAdapter, load_scenario
        from policy.engine import Policy  # noqa: F401
        from services.worker.event_sink import HttpEventSink
        from services.worker.gateway import Gateway
        from services.worker.lease import LeaseStore

        policy = ctx["default"]
        run_id = demo.create_run(ctx["base_url"], ctx["tokens"]["operator"], policy)
        lease = LeaseStore(demo.connections(stack.dsn)).acquire(run_id, "w-stranger")
        sink = HttpEventSink(
            base_url=ctx["base_url"],
            run_id=run_id,
            token=ctx["tokens"]["adapter"],
            fencing_token=lease.fencing_token,
        )
        client = HttpApprovalClient(
            base_url=ctx["base_url"], run_id=run_id, token=ctx["tokens"]["adapter"]
        )
        scenario = load_scenario("bank_change_approval")
        adapter = ReplayAdapter(scenario)
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=adapter.provenance("STEP_GATED"),
            in_scope_actions=IN_SCOPE_ACTIONS,
            approvals=client,
        )
        gateway.run_started(task=scenario["task"], requested_coverage="STEP_GATED")
        adapter.run(gateway)
        pending = gateway.pending_approvals()[0]
        done = subprocess.run(  # noqa: S603
            [
                stack.abb,
                "approve",
                "--key",
                str(stranger / "approver.key"),
                "--run-id",
                run_id,
                "--action-id",
                pending["action_id"],
                "--approval-id",
                pending["approval_id"],
                "--decision",
                "GRANTED",
                "--expires-at",
                "9999999999999",
                "--summary",
                pending["summary"],
            ],
            capture_output=True,
            check=True,
        )
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line
        )
        action = next(a for a in gateway._awaiting.values())["action"]
        try:
            gateway.submit_approval(
                action,
                statement_b64=fields["statement_b64"],
                key_id=fields["key_id"],
                signature=fields["signature"],
            )
        except SinkError as exc:
            outcome["code"] = exc.code
        outcome["dispatched_authorized"] = action.action_id in gateway._authorized

    run()
    assert outcome["code"] == "UNKNOWN_APPROVER"
    assert outcome["dispatched_authorized"] is False


def test_an_already_expired_approval_is_refused_by_the_relay(ctx: dict[str, Any]) -> None:
    from services.worker.event_sink import SinkError

    with pytest.raises(SinkError) as raised:
        produce(ctx, "bank_change_approval", approve="GRANTED", expires_in_ms=-5_000)
    assert raised.value.code == "APPROVAL_EXPIRED"


def test_the_same_approval_cannot_be_decided_twice(ctx: dict[str, Any]) -> None:
    from services.worker.approval_client import HttpApprovalClient
    from services.worker.event_sink import SinkError

    context = produce(ctx, "bank_change_approval", approve="GRANTED")
    document = read_receipt(context["receipt"])
    first = document["approvals"][0]
    statement = json.loads(base64.b64decode(first["statement_b64"]))
    client = HttpApprovalClient(
        base_url=ctx["base_url"], run_id=context["run_id"], token=ctx["tokens"]["adapter"]
    )
    with pytest.raises(SinkError) as raised:
        client.submit(
            approval_id=statement["approval_id"],
            statement_b64=first["statement_b64"],
            key_id=first["key_id"],
            signature=first["signature"],
        )
    # Run is finished by now, so either answer proves a replay does nothing.
    assert raised.value.code in {"APPROVAL_ALREADY_DECIDED", "RUN_FINISHED"}


# =========================================================================== #
# signed mandate
# =========================================================================== #


def test_a_run_inside_its_mandate_verifies_and_says_so(ctx: dict[str, Any]) -> None:
    from tools import demo

    mandate = demo.signed_mandate(
        ctx["stack"], allowed_action_types=["navigate", "form_submit"], max_actions=5
    )
    context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)
    code, report = verify(context, context["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    assert report["dimensions"]["mandate_compliance"] == "PASS"
    assert "mandate" in read_receipt(context["receipt"])


def test_the_gateway_blocks_an_out_of_mandate_action_and_the_receipt_still_verifies(
    ctx: dict[str, Any],
) -> None:
    from tools import demo

    mandate = demo.signed_mandate(ctx["stack"], allowed_action_types=["navigate"])
    context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)
    code, report = verify(context, context["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    blocked = [e for e in events_of(context) if e["event_type"] == "ACTION_BLOCKED"]
    assert any("MANDATE_VIOLATION" in e["payload"]["reason_codes"] for e in blocked)
    dispatched = [e for e in events_of(context) if e["event_type"] == "ACTION_DISPATCHED"]
    assert [e["payload"]["action_id"] for e in dispatched] == ["b-1"]
    # A mandate that stopped an out-of-bounds proposal worked; it is not a violation.
    assert report["dimensions"]["mandate_compliance"] == "PASS"


def test_a_mandate_with_too_few_actions_blocks_the_next_one(ctx: dict[str, Any]) -> None:
    from tools import demo

    mandate = demo.signed_mandate(
        ctx["stack"], allowed_action_types=["navigate", "form_submit"], max_actions=1
    )
    context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)
    _, report = verify(context, context["receipt"])
    assert report["dimensions"]["mandate_compliance"] == "PASS"
    dispatched = [e for e in events_of(context) if e["event_type"] == "ACTION_DISPATCHED"]
    assert len(dispatched) == 1


def test_a_gateway_that_skipped_the_mandate_is_caught_by_the_verifier(ctx: dict[str, Any]) -> None:
    """The gateway marking its own homework proves nothing: the verifier re-checks."""
    from services.worker.gateway import Gateway

    mandate = None
    from tools import demo

    mandate = demo.signed_mandate(ctx["stack"], allowed_action_types=["navigate"])
    original = Gateway._apply_mandate
    Gateway._apply_mandate = lambda self, action, decision: decision  # type: ignore[method-assign]
    try:
        context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)
    finally:
        Gateway._apply_mandate = original  # type: ignore[method-assign]
    code, report = verify(context, context["receipt"])
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "mandate_compliance" in failing_dimensions(report)
    text = reasons(report, "mandate_compliance")
    assert "MANDATE_VIOLATION" in text and "form_submit" in text
    # The violating action is named.
    assert any("b-2" in str(d.get("locator")) for d in details_for(report, "mandate_compliance"))


def test_a_loosened_mandate_document_in_the_receipt_fails(ctx: dict[str, Any]) -> None:
    from tools import demo

    mandate = demo.signed_mandate(ctx["stack"], allowed_action_types=["navigate"], max_actions=1)
    context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)

    def change(document: dict[str, Any]) -> None:
        loosened = json.loads(base64.b64decode(document["mandate"]["document_b64"]))
        loosened["max_actions"] = 500
        text = json.dumps(loosened, sort_keys=True, separators=(",", ":"))
        document["mandate"]["document_b64"] = base64.b64encode(text.encode()).decode("ascii")

    _, report = mutate(context, "loosened", change)
    assert "mandate_compliance" in failing_dimensions(report)


def test_removing_the_mandate_document_makes_compliance_unknown_not_pass(
    ctx: dict[str, Any],
) -> None:
    from tools import demo

    mandate = demo.signed_mandate(ctx["stack"], allowed_action_types=["navigate", "form_submit"])
    context = produce(ctx, "bank_change_approval", approve="GRANTED", mandate=mandate)

    def change(document: dict[str, Any]) -> None:
        document.pop("mandate")

    _, report = mutate(context, "no-mandate", change)
    assert report["dimensions"]["mandate_compliance"] == "UNKNOWN"
    assert report["overall"] != "VALID"


def test_a_mandate_not_signed_by_an_issuer_key_is_refused_at_registration(
    ctx: dict[str, Any],
) -> None:
    """A document signed by the approver's key names itself as issuer, but is not one."""
    import subprocess
    import time
    import urllib.error
    import urllib.request

    from tools import demo

    stack = ctx["stack"]
    approver_id = demo.key_id_of(demo.people_dir(stack) / "approver.pub")
    now = int(time.time() * 1000)
    document = {
        "mandate_id": "mandate-forged",
        "issuer_key_id": approver_id,
        "subject": "replay",
        "allowed_hosts": ["portal.example"],
        "allowed_action_types": ["navigate"],
        "max_actions": 3,
        "not_before": now - 1000,
        "not_after": now + 100000,
    }
    path = stack.work / "forged_mandate.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    done = subprocess.run(  # noqa: S603
        [
            stack.abb,
            "mandate",
            "sign",
            "--key",
            str(demo.people_dir(stack) / "approver.key"),
            "--file",
            str(path),
        ],
        capture_output=True,
        check=True,
    )
    fields = dict(line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line)
    request = urllib.request.Request(  # noqa: S310
        f"{ctx['base_url']}/api/v1/mandates",
        data=json.dumps(
            {"document_b64": fields["document_b64"], "signature": fields["signature"]}
        ).encode(),
        method="POST",
        headers={
            "Authorization": f"Bearer {ctx['tokens']['operator']}",
            "Content-Type": "application/json",
        },
    )
    with pytest.raises(urllib.error.HTTPError) as raised:
        urllib.request.urlopen(request, timeout=30)  # noqa: S310
    body = json.loads(raised.value.read())
    assert body["code"] == "UNKNOWN_ISSUER"


# =========================================================================== #
# salted field commitments
# =========================================================================== #


@pytest.fixture(scope="module")
def card_run(ctx: dict[str, Any]) -> dict[str, Any]:
    return produce(ctx, "card_entry", policy_name="redacting", approve=None)


def test_the_clear_value_never_appears_in_the_ledger_or_the_receipt(
    ctx: dict[str, Any], card_run: dict[str, Any]
) -> None:
    import psycopg

    # Nowhere in the receipt container, in any member.
    for name, data in read_members(card_run["receipt"]).items():
        assert CARD.encode() not in data, f"clear value leaked into {name}"
        assert base64.b64encode(CARD.encode()) not in data
    # Nor in the committed event bytes in the database.
    with psycopg.connect(ctx["stack"].dsn) as conn:
        rows = conn.execute(
            "SELECT canonical_bytes FROM events WHERE run_id = %s", (card_run["run_id"],)
        ).fetchall()
    assert rows
    assert all(CARD.encode() not in bytes(row[0]) for row in rows)

    requested = card_requested(card_run)
    assert "typed_value" not in requested["payload"]
    commitment = requested["commitments"]["typed_value"]
    assert len(commitment) == 64 and commitment == commitment.lower()


def test_the_params_digest_does_not_let_anyone_guess_the_hidden_value(
    card_run: dict[str, Any],
) -> None:
    """A hash of the secret would be brute-forceable; the digest covers public fields only."""
    import hashlib

    requested = card_requested(card_run)
    with_secret = hashlib.sha256(
        json.dumps(
            {"field": "card_number", "typed_value": CARD}, sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()
    assert requested["payload"]["params_digest"] != with_secret


def test_a_receipt_with_a_committed_field_hidden_still_verifies_and_says_it_is_unknown(
    card_run: dict[str, Any],
) -> None:
    code, report = verify(card_run, card_run["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    assert report["dimensions"]["evidence_integrity"] == "PASS"
    assert "not disclosed" in reasons(report, "evidence_integrity")


def test_a_chosen_disclosure_verifies_against_the_commitment(
    ctx: dict[str, Any], card_run: dict[str, Any]
) -> None:
    del card_run
    context = produce(
        ctx, "card_entry", policy_name="redacting", approve=None, disclose=["typed_value"]
    )
    code, report = verify(context, context["receipt"])
    assert report["overall"] == "VALID", report
    assert code == 0
    document = read_receipt(context["receipt"])
    assert document["disclosures"][0]["value"] == CARD
    assert "not disclosed" not in reasons(report, "evidence_integrity")


def test_a_wrong_disclosed_value_is_tampering(ctx: dict[str, Any]) -> None:
    context = produce(
        ctx, "card_entry", policy_name="redacting", approve=None, disclose=["typed_value"]
    )

    def change(document: dict[str, Any]) -> None:
        document["disclosures"][0]["value"] = "4000000000000002"

    code, report = mutate(context, "wrong-value", change)
    assert report["overall"] == "INVALID", report
    assert code == 1
    assert "evidence_integrity" in failing_dimensions(report)
    assert "do not reproduce" in reasons(report, "evidence_integrity")


def test_a_wrong_salt_is_tampering(ctx: dict[str, Any]) -> None:
    context = produce(
        ctx, "card_entry", policy_name="redacting", approve=None, disclose=["typed_value"]
    )

    def change(document: dict[str, Any]) -> None:
        document["disclosures"][0]["salt_hex"] = "00" * 16

    _, report = mutate(context, "wrong-salt", change)
    assert "evidence_integrity" in failing_dimensions(report)


def test_shredding_keeps_the_ledger_valid_and_the_value_gone(ctx: dict[str, Any]) -> None:
    """Crypto-shredding (R-CMT-03): delete salt and value; the commitment stays valid."""
    from services.api.canonical import Canonicalizer
    from services.api.repository import Repository
    from tools import demo

    before = produce(
        ctx, "card_entry", policy_name="redacting", approve=None, disclose=["typed_value"]
    )
    repo = Repository(
        connect=demo.connections(ctx["stack"].dsn), canonicalizer=Canonicalizer(ctx["abb"])
    )
    held = repo.disclosures_for(before["run_id"])
    assert len(held) == 1 and held[0]["field"] == "typed_value"

    assert repo.shred_field(held[0]["event_id"], "typed_value") is True
    assert repo.disclosures_for(before["run_id"]) == []

    # The ledger is untouched: same canonical bytes, still verifies.
    after = demo.finalize_export_again(ctx["stack"], before["run_id"], disclose=["typed_value"])
    shredded = {**before, "receipt": after}
    code, report = verify(shredded, after)
    assert report["overall"] == "VALID", report
    assert code == 0
    assert report["dimensions"]["evidence_integrity"] == "PASS"
    assert "disclosures" not in read_receipt(after)
    assert "not disclosed" in reasons(report, "evidence_integrity")
    # Shredding cannot recall a copy that was already handed out, and says nothing
    # about it: the earlier receipt still carries what it was given.
    assert read_receipt(before["receipt"])["disclosures"][0]["value"] == CARD


def test_a_policy_cannot_hide_a_field_the_offline_checks_need() -> None:
    from policy.engine import Policy

    with pytest.raises(ValueError, match="offline check"):
        Policy(
            {
                "policy_id": "x",
                "version": 1,
                "redaction": {"ACTION_REQUESTED": ["target"]},
            }
        )
    with pytest.raises(ValueError, match="offline check"):
        Policy(
            {
                "policy_id": "x",
                "version": 1,
                "redaction": {"HUMAN_APPROVAL_GRANTED": ["approval_signature"]},
            }
        )
