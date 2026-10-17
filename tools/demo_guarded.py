"""A risky task that waits for a person's signed approval, run through the real gateway.

    python tools/demo_guarded.py --dsn postgresql://abb@127.0.0.1:55432/postgres \
        --people-dir ~/.abb/people --out <receipts dir>

The scenario is scripted and runs on a **fake portal with fake data** (`portal.example`;
no network, no money). What is real: the gateway, the `guarded` policy that answers
"needs approval" for the bank-details step, the approval request, the signature, the
signed receipt and the offline verifier.

Protocol with whatever started this script (the dashboard's run console, or a person):

* when an action needs approval it prints one line, `APPROVAL_PENDING <json>`, with the exact
  text the approver must be shown and its digest, then waits for ONE line on stdin;
* that line is JSON: `{"statement_b64", "key_id", "signature"}` from `abb approve`, or
  `{}` for "nobody answered". No line before `--wait-seconds` also means nobody answered;
* without a signed grant the action is **not dispatched**. A denial or silence blocks it.

A valid receipt shows that a key signed. It does not show which person held that key.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from policy.engine import Policy  # noqa: E402
from tools import demo  # noqa: E402


def stdin_lines() -> queue.Queue[str | None]:
    """Lines from stdin on a thread, so waiting can have a limit (None means closed)."""
    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        for raw in sys.stdin:
            lines.put(raw)
        lines.put(None)

    threading.Thread(target=pump, daemon=True).start()
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description="A guarded task that waits for approval")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--scenario", default="bank_change_approval")
    parser.add_argument("--people-dir", type=Path, help="where the approver's key already lives")
    parser.add_argument("--out", type=Path, help="copy the receipt and its key manifest here")
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    # Answers carry characters like the rupee sign that a Windows console encoding cannot print;
    # always speak UTF-8 so printing an answer can never crash a run.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-gd-"))
    policy = Policy.load("guarded", 1)
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
    seen: dict[str, Any] = {"asked": False, "key_id": None}

    def decide(pending: dict[str, str], run_id: str) -> dict[str, str] | None:
        seen["asked"] = True
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
            print("no answer in time: the action stays blocked", flush=True)
            return None
        if raw is None:
            return None
        try:
            signed = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(signed, dict) or not signed.get("signature"):
            return None
        seen["key_id"] = signed.get("key_id")
        return {k: str(signed[k]) for k in ("statement_b64", "key_id", "signature")}

    code = 0
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"
        demo.say("1. guarded task", f"scenario {args.scenario}, fake portal, fake data")
        run_id, _, result = demo.run_with_approver(
            stack, base_url, tokens, policy, args.scenario, decide=decide
        )
        statuses = [f"{step.action_id}: {step.status}" for step in result.steps]
        print(f"  adapter result: {result.status}  steps: {', '.join(statuses)}")
        print(f"RUN_OUTCOME {result.status}", flush=True)

        demo.say("2. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="2. verify")

        if not seen["asked"]:
            summary = "No approval was needed."
        elif seen["key_id"]:
            blocked = [e for e in result.errors if e.get("outcome") == "DENY"]
            summary = (
                "A signed **denial** was recorded. The bank-details step was **not** sent."
                if blocked
                else "A signed **approval** was recorded and the bank-details step was sent "
                "to the fake portal."
            )
            summary += f" Signed by key `{str(seen['key_id'])[:20]}…`."
        else:
            summary = "**Nobody answered.** The bank-details step was **not** sent."
        text = (
            "# Vendor bank change (test, fake data)\n"
            f"- {summary}\n"
            "- The portal and the account details are fake. No money moved.\n"
            "- A signature shows a key signed. It does not show which person held that key."
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
