"""A real browser on a real website, where submitting a form waits for a person's signed approval.

    python tools/demo_realsite.py --dsn postgresql://abb@127.0.0.1:55432/postgres \
        --people-dir ~/.abb/people --out <receipts dir> --message "hello from Hascham"

What is real: Chromium on this computer, the public site `httpbin.org` (an HTTP test service
that echoes what it receives), the gateway, the policy `realsite-guarded`, the signed approval,
the receipt and the offline verifier. What is not: no money, no account, nothing private. The
message you give is sent to httpbin.org, a public service, **only if you approve**.

The rule under test: reading a page is free; submitting a form is held until a key signs.
Every request the browser makes passes the gateway first; the bypass self-test runs before the
run, and `STEP_GATED` is claimed only if it passes.

Protocol with whatever started this script (same as `demo_guarded.py`): one line
`APPROVAL_PENDING <json>` on stdout, then ONE line of JSON on stdin from `abb approve`
(`{"statement_b64", "key_id", "signature"}`) or `{}` for "nobody answered". Silence, a denial
or an error all leave the form **unsubmitted**.

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
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from adapters.playwright.adapter import IN_SCOPE_ACTIONS, PlaywrightAdapter  # noqa: E402
from policy.engine import Decision, Policy  # noqa: E402
from security.prompt_guard.guard import DeterministicGuard  # noqa: E402
from security.semantic.monitor import run_monitor  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.worker.approval_client import HttpApprovalClient  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402
from tools import demo  # noqa: E402
from tools.demo_guarded import stdin_lines  # noqa: E402
from tools.demo_playwright import measure_coverage  # noqa: E402

DEFAULT_URL = "https://httpbin.org/forms/post"


def main() -> int:
    parser = argparse.ArgumentParser(description="Submit a real form, with your approval")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--message", required=True, help="the text to put in the form")
    parser.add_argument("--people-dir", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=300)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    policy = Policy.load("realsite-guarded", 1)
    host = urlparse(args.url).hostname or ""
    if host not in policy.body["allowed_hosts"]:
        print(f"policy realsite-guarded allows only {policy.body['allowed_hosts']}; {host} refused")
        return 2
    if not args.message.strip() or len(args.message) > 500:
        print("the message must be 1 to 500 characters")
        return 2

    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")

    demo.say("1. measure what may be claimed", "bypass probes against a local probe site")
    report, coverage, reason = measure_coverage(False)
    print(f"  -> declared coverage: {coverage}\n  -> {reason}", flush=True)

    work = Path(tempfile.mkdtemp(prefix="abb-rs-"))
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
    # decision: None until the approver has answered, then ALLOW, DENY or NONE (nobody answered)
    seen: dict[str, Any] = {"asked": False, "key_id": None, "decision": None}

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
            print("no answer in time: the form stays unsubmitted", flush=True)
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
        task = f"Submit a message through the form at {args.url}"
        run_id = demo.create_run(
            base_url, tokens["operator"], policy, adapter="playwright", task=task
        )
        lease = LeaseStore(demo.connections(dsn)).acquire(run_id, "rs-worker")
        sink = HttpEventSink(
            base_url=base_url,
            run_id=run_id,
            token=tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        relay = HttpApprovalClient(base_url=base_url, run_id=run_id, token=tokens["adapter"])
        shell = PlaywrightAdapter(None)
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=shell.provenance(coverage),
            in_scope_actions=IN_SCOPE_ACTIONS,
            approvals=relay,
            guard=DeterministicGuard(),
        )

        def approver(gw: Gateway, action: Any) -> Decision:
            pending = next(p for p in gw.pending_approvals() if p["action_id"] == action.action_id)
            signed = decide(pending, run_id)
            if signed is None:  # nobody answered: not dispatched
                seen["decision"] = "NONE"
                return Decision(
                    outcome="REQUIRE_APPROVAL",
                    reason_codes=("APPROVAL_NOT_RECEIVED",),
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    input_digest="",
                )
            answer = gw.submit_approval(
                action,
                statement_b64=signed["statement_b64"],
                key_id=signed["key_id"],
                signature=signed["signature"],
            )
            seen["decision"] = "ALLOW" if answer.allows_dispatch else "DENY"
            return answer

        gateway.run_started(task=f"{task}: {args.message}", requested_coverage="STEP_GATED")
        gateway.declare_coverage(
            requested="STEP_GATED",
            declared=coverage,
            reason=reason,
            evidence_ref=report.digest(),
        )

        demo.say("2. the real browser", f"open {args.url}")
        submitted = False
        echoed = ""
        with PlaywrightAdapter(gateway, approver=approver) as adapter:
            page = adapter.new_page()
            # A person may take minutes to decide: the browser must not give up meanwhile.
            page.set_default_timeout(args.wait_seconds * 1000 + 60_000)
            page.set_default_navigation_timeout(args.wait_seconds * 1000 + 60_000)
            opened = adapter.goto(page, args.url)
            print(f"  open the form:   {opened}", flush=True)
            if opened == "OK":
                adapter.fill(page, "input[name=custname]", "Hascham user")
                adapter.fill(page, "textarea[name=comments]", args.message)
                print("  click submit (held for approval) ...", flush=True)
                page.click("button", no_wait_after=True)
                # The held request is handled while Playwright is being used, so keep using it
                # until the approver has answered. With no approval asked at all, give up soon.
                waited = 0
                limit = args.wait_seconds * 2 + 120
                while seen["decision"] is None and waited < limit:
                    page.wait_for_timeout(500)
                    waited += 1
                    if not seen["asked"] and waited > 40:
                        break
                if seen["decision"] == "ALLOW":
                    try:
                        # The answer page is /post. The form's own address, /forms/post, also ends
                        # in "/post", so a plain pattern would match before anything was sent.
                        def is_answer_page(address: str) -> bool:
                            return urlparse(address).path.rstrip("/") == "/post"

                        page.wait_for_url(is_answer_page, timeout=60_000)
                        page.wait_for_load_state("load", timeout=60_000)
                        submitted = is_answer_page(page.url)
                    except Exception as exc:
                        print(f"  the answer page did not load ({type(exc).__name__})", flush=True)
                if submitted:
                    echoed = page.inner_text("body")[:4000]
        outcome = "COMPLETED" if submitted else "COMPLETED_WITH_BLOCKS"
        print(f"  submitted: {submitted}", flush=True)
        print(f"RUN_OUTCOME {outcome}", flush=True)

        run_monitor(gateway)
        gateway.run_finished(final_state="FINALIZING", outcome=outcome)
        Repository(connect=demo.connections(dsn), canonicalizer=Canonicalizer(abb)).set_state(
            run_id, "FINALIZING"
        )
        demo.say("3. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="3. verify")

        if submitted:
            try:
                form = json.loads(echoed).get("form", {})
            except ValueError:
                form = {}
            says = (
                f"httpbin.org echoed back your message: **{form.get('comments', '(unreadable)')}**"
            )
            lead = (
                "A signed **approval** was recorded, and only then was the form submitted to "
                f"{host}."
            )
        elif seen["decision"] == "ALLOW":
            says = "The approval was signed, but the site did not answer in time."
            lead = "A signed **approval** was recorded; the form may not have gone through."
        elif seen["decision"] == "DENY":
            says = "Nothing was sent."
            lead = "A signed **denial** was recorded. The form was **not** submitted."
        elif seen["asked"]:
            says = "Nothing was sent."
            lead = "**Nobody answered.** The form was **not** submitted."
        else:
            says = "No approval was asked for."
            lead = "The form was not submitted."
        text = (
            f"# Real form on {host}\n"
            f"- {lead}\n"
            f"- {says}\n"
            f"- Coverage claimed: **{coverage}** (every browser request passed the gateway first; "
            "the bypass probes ran before this run).\n"
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
