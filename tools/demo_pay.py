"""An agent pays company bills with FAKE money, under a spend policy and a person's approval.

    python tools/demo_pay.py --dsn postgresql://abb@127.0.0.1:55432/postgres \
        --people-dir ~/.abb/people --out <receipts dir> \
        --goal "Pay Acme Supplies 12.00 USD; Pay Cloud Hosting 180 USD; Pay Big Equipment 900 USD"

What is real: a local mock payment gateway (no external API, no card data, no real money),
the gateway, the policy `company-spend`, the signed approval, the receipt and the offline verifier.
What is not: no real money, no real card, no bank account. No payment API is contacted and no credentials are needed.

The policy, like a company's spend rules: up to 50.00 an agent pays on its own; over 50.00 up to
500.00 it WAITS for a person's signed approval (the approver is shown the amount and who is paid);
over 500.00 is refused outright. Silence or a denial leaves the payment unsent.

Protocol with whatever started this script (the run console): `APPROVAL_PENDING <json>` on stdout,
then one line of JSON on stdin from `abb approve`, or `{}` for nobody. Same as `demo_guarded.py`.

A valid receipt shows that a key signed. It does not show which person held that key. Payment outcomes are simulations only.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from adapters.payments.adapter import (  # noqa: E402
    COVERAGE_REASON,
    IN_SCOPE_ACTIONS,
    PaymentAdapter,
)
from adapters.payments.client import CURRENCIES, MockPaymentClient  # noqa: E402
from policy.engine import Decision, Policy  # noqa: E402
from security.semantic.monitor import run_monitor  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.worker.approval_client import HttpApprovalClient  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402
from tools import demo  # noqa: E402
from tools.demo_guarded import stdin_lines  # noqa: E402

MAX_PAYMENTS = 5
#: What runs when the task names no amount: one payment in each tier of the policy.
DEFAULT_BATCH = (
    ("Acme Office Supplies", 1200, "usd"),
    ("Northwind Cloud Hosting", 18000, "usd"),
    ("Contoso Heavy Equipment", 90000, "usd"),
)
AMOUNT = re.compile(r"(\d{1,7}(?:[.,]\d{1,2})?)\s*(usd|eur|gbp|inr|\$|€|£|₹)?", re.IGNORECASE)
SYMBOLS = {"$": "usd", "€": "eur", "£": "gbp", "₹": "inr"}


def parse_payments(goal: str) -> list[tuple[str, int, str]]:
    """`Pay Acme 12.00 USD; Pay Cloud 180` -> [(vendor, minor units, currency)]. Empty goal text
    with no amount means the default three-tier batch. Anything odd raises ValueError."""
    segments = [s.strip() for s in re.split(r"[;\n]", goal) if s.strip()]
    found: list[tuple[str, int, str]] = []
    for segment in segments:
        match = AMOUNT.search(segment)
        if not match:
            continue
        vendor = re.sub(r"^(please\s+)?pay\s+", "", segment[: match.start()], flags=re.I).strip(
            " -:,."
        )
        number = Decimal_minor(match.group(1))
        raw = (match.group(2) or "usd").lower()
        currency = SYMBOLS.get(raw, raw)
        if currency not in CURRENCIES:
            raise ValueError(f"currency {currency} is not supported")
        if number <= 0:
            raise ValueError("an amount must be above zero")
        found.append((vendor[:80] or "Vendor", number, currency))
    if not found:
        return list(DEFAULT_BATCH)
    if len(found) > MAX_PAYMENTS:
        raise ValueError(f"at most {MAX_PAYMENTS} payments per run")
    return found


def Decimal_minor(text: str) -> int:
    """'12.5' -> 1250, '180' -> 18000. Whole minor units, never a float."""
    whole, _, frac = text.replace(",", ".").partition(".")
    return int(whole) * 100 + int((frac + "00")[:2])


def money(minor: int, currency: str) -> str:
    return f"{minor / 100:,.2f} {currency.upper()}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Pay company bills with fake money")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--goal", default="", help="payments, for example: Pay Acme 12.00 USD")
    parser.add_argument("--people-dir", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--scenario", choices=("success", "decline", "unknown"), default="success", help="simulated gateway outcome")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    try:
        payments = parse_payments(args.goal)
    except ValueError as exc:
        print(f"cannot read the payments: {exc}")
        return 2
    client = MockPaymentClient(args.scenario)
    policy = Policy.load("company-spend", 1)
    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-pay-"))
    dsn = demo.prepare_database(args.dsn, migration)
    tokens = demo.seed(dsn, policy)
    stack = demo.Stack(
        work=work,
        dsn=dsn,
        abb=abb,
        signer_bin=signer_bin,
        signer_port=demo.free_port(),
        api_port=demo.free_port(),
        people=args.people_dir,
    )
    answers = stdin_lines()
    seen: dict[str, Any] = {"key_id": None, "asked": 0}

    def decide(pending: dict[str, str], run_id: str) -> dict[str, str] | None:
        seen["asked"] += 1
        print(
            "APPROVAL_PENDING "
            + json.dumps(
                {
                    "run_id": run_id,
                    "action_id": pending["action_id"],
                    "approval_id": pending["approval_id"],
                    "summary": pending["summary"],
                    "summary_digest": pending["summary_digest"],
                }
            ),
            flush=True,
        )
        try:
            raw = answers.get(timeout=args.wait_seconds)
        except queue.Empty:
            print("no answer in time: the payment stays unsent", flush=True)
            return None
        try:
            signed = json.loads(raw) if raw is not None else None
        except ValueError:
            signed = None
        if not isinstance(signed, dict) or not signed.get("signature"):
            return None
        seen["key_id"] = signed.get("key_id")
        return {k: str(signed[k]) for k in ("statement_b64", "key_id", "signature")}

    code = 0
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"
        task = (
            "Pay company bills (local mock simulation): "
            + "; ".join(f"{v} {money(a, c)}" for v, a, c in payments)
        )
        run_id = demo.create_run(
            base_url, tokens["operator"], policy, adapter="payments", task=task
        )
        lease = LeaseStore(demo.connections(dsn)).acquire(run_id, "pay-worker")
        sink = HttpEventSink(
            base_url=base_url,
            run_id=run_id,
            token=tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        relay = HttpApprovalClient(base_url=base_url, run_id=run_id, token=tokens["adapter"])

        def approver(gw: Gateway, action: Any) -> Decision:
            pending = next(p for p in gw.pending_approvals() if p["action_id"] == action.action_id)
            signed = decide(pending, run_id)
            if signed is None:  # nobody answered: not dispatched
                return Decision(
                    outcome="REQUIRE_APPROVAL",
                    reason_codes=("APPROVAL_NOT_RECEIVED",),
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    input_digest="",
                )
            return gw.submit_approval(
                action,
                statement_b64=signed["statement_b64"],
                key_id=signed["key_id"],
                signature=signed["signature"],
            )

        shell = PaymentAdapter(None, client)
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=shell.provenance(),
            in_scope_actions=IN_SCOPE_ACTIONS,
            approvals=relay,
        )
        adapter = PaymentAdapter(gateway, client, approver=approver, run_key=run_id)
        gateway.run_started(task=task, requested_coverage="STEP_OBSERVED")
        gateway.declare_coverage(
            requested="STEP_OBSERVED", declared="STEP_OBSERVED", reason=COVERAGE_REASON
        )

        demo.say("1. pay, one bill at a time", "local mock simulation, fake money")
        rows: list[tuple[str, str, str]] = []
        for vendor, amount, currency in payments:
            out = adapter.pay(
                vendor=vendor, amount_minor_units=amount, currency=currency, note=task
            )
            shown = f"{vendor}: {money(amount, currency)}"
            print(f"  {shown} -> {out.status} {out.detail}", flush=True)
            rows.append((shown, out.status, out.detail))
        paid = sum(1 for _, s, _ in rows if s == "PAID")
        unclear = any(s in ("OUTCOME_UNKNOWN", "FAILED", "AUTH_FAILED") for _, s, _ in rows)
        outcome = (
            "FAILED" if unclear else ("COMPLETED" if paid == len(rows) else "COMPLETED_WITH_BLOCKS")
        )
        print(f"RUN_OUTCOME {outcome}", flush=True)

        run_monitor(gateway)
        gateway.run_finished(final_state="FINALIZING", outcome=outcome)
        Repository(connect=demo.connections(dsn), canonicalizer=Canonicalizer(abb)).set_state(
            run_id, "FINALIZING"
        )
        demo.say("2. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="2. verify")

        words = {
            "PAID": "**paid** (test money)",
            "BLOCKED": "**not paid**",
            "DECLINED": "**declined** by the test card",
            "OUTCOME_UNKNOWN": "**unknown**: no clear answer, and it was not retried",
            "AUTH_FAILED": "**not paid**: local mock authentication error",
            "NOT_TEST_MODE": "**not paid**: live mode is unsupported",
            "FAILED": "**failed**",
        }
        lines = []
        for shown, status, detail in rows:
            why = ""
            if status == "BLOCKED":
                why = (
                    " (over the 500.00 cap: refused by policy)"
                    if "OVER_AMOUNT_LIMIT" in detail
                    else " (needed a signed approval and did not get one)"
                    if "APPROVAL" in detail
                    else f" ({detail})"
                )
            lines.append(f"- {shown}: {words.get(status, status)}{why}")
        signer = (
            f" Approvals signed by key `{str(seen['key_id'])[:20]}…`." if seen["key_id"] else ""
        )
        text = (
            "# Company payments (local mock simulation, fake money)\n"
            + "\n".join(lines)
            + "\n- Rules: up to 50.00 pays on its own; over 50.00 up to 500.00 needs a signed "
            "approval; over 500.00 is refused."
            + signer
            + "\n- No real money moved. A signature shows a key signed, not which person held it."
        )
        print("RESULT_TEXT " + json.dumps(text), flush=True)

        if args.out is not None:
            args.out.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(receipt, args.out / receipt.name)
            shutil.copyfile(demo.key_manifest(stack), args.out / (receipt.name + ".keys.json"))
            print(f"RECEIPT_SAVED {receipt.name}", flush=True)
        return code
    finally:
        stack.stop()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
