"""One real TinyFish run, recorded in a signed receipt and verified offline.

    set TINYFISH_API_KEY=...        (you set it; this script never prints or stores it)
    python tools/demo_tinyfish.py --dsn postgresql://abb@127.0.0.1:55432/postgres --yes-spend

This SPENDS the user's TinyFish credit (at most `--max-steps` x the per-step rate,
about 8 cents at the defaults). Without `--yes-spend` it only says what it would do.

What the receipt can and cannot say: TinyFish is capped at `STEP_OBSERVED`. The
gateway judges the *start URL* before the run is sent; what the remote browser does
after that is the provider's own report (`reported_by_adapter`), not something this
machine saw. A valid receipt proves the record is unchanged, not that the provider
told the truth.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from adapters.tinyfish.adapter import IN_SCOPE_ACTIONS, TinyFishAdapter  # noqa: E402
from adapters.tinyfish.budget import Budget  # noqa: E402
from adapters.tinyfish.http_client import KEY_ENV, HttpTinyFishClient  # noqa: E402
from policy.engine import Policy  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402
from tools import demo  # noqa: E402

#: Spend already measured through the session connector (6 + 3 steps at $0.016, rounded up per run).
PRIOR_SPEND_CENTS = 15


FORMAT_HINT = (
    " Reply in plain language: a short heading, then 3 to 5 bullet points, "
    "with the key facts in **bold**."
)


def main() -> int:
    parser = argparse.ArgumentParser(description="One real TinyFish run, recorded and verified")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--url", default="https://example.com")
    parser.add_argument(
        "--mode",
        choices=["agent", "search", "research"],
        default="agent",
        help="agent: browse a page; search: ranked web results; research: a cited report",
    )
    parser.add_argument("--goal", default="Read the page heading and the first sentence.")
    parser.add_argument("--max-steps", type=int, default=5)
    parser.add_argument(
        "--step-cap",
        action="store_true",
        help="send max_steps (the docs say this needs beta access, else HTTP 403)",
    )
    parser.add_argument(
        "--yes-spend", action="store_true", help="really call TinyFish (costs money)"
    )
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--no-format-hint",
        action="store_true",
        help="send the task exactly as typed, without the note on how to shape the reply",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="copy the receipt, and its key manifest as <name>.keys.json, into this folder",
    )
    args = parser.parse_args()
    # Answers carry characters like the rupee sign that a Windows console encoding cannot print;
    # always speak UTF-8 so printing an answer can never crash a run.
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    host = args.url.split("/")[2] if "//" in args.url else args.url
    # What is sent to the agent: the task, plus a fixed note on how to shape the reply. The
    # receipt's task digest is of this full text, so it matches what the provider received.
    plain = args.no_format_hint or args.mode != "agent"  # the note is only for the browsing agent
    sent_goal = args.goal if plain else args.goal.rstrip() + FORMAT_HINT
    budget_path = Path(
        os.environ.get("ABB_TINYFISH_BUDGET", Path.home() / ".abb" / "tinyfish.json")
    )
    budget_path.parent.mkdir(parents=True, exist_ok=True)
    if not budget_path.exists():
        budget_path.write_text(json.dumps({"spent_cents": PRIOR_SPEND_CENTS}), encoding="utf-8")
    budget = Budget.load(budget_path)

    client = HttpTinyFishClient(
        max_steps=args.max_steps,
        send_step_cap=args.step_cap,
        progress=lambda m: print("  " + m, flush=True),
    )
    estimate = client.estimate_cents(args.mode, args.goal) if os.environ.get(KEY_ENV) else None
    cap = (
        "enforced by the provider"
        if args.step_cap
        else "ASSUMED only, not sent; the 60 s limit and our deadline apply"
    )
    if args.mode == "agent":
        print(f"start URL: {args.url}\nstep cap: {args.max_steps} ({cap})")
    else:
        print(f"mode: {args.mode} (sent only to TinyFish's own {args.mode} API)")
    print(
        f"ceiling: ${budget.ceiling_cents / 100:.2f}  spent so far: ${budget.spent_cents / 100:.2f}"
    )
    print(f"worst-case cost of this run: {estimate if estimate is not None else 'unknown'} cents")
    if not os.environ.get(KEY_ENV):
        print(f"\n{KEY_ENV} is not set, so nothing was called. Set it yourself, then run again.")
        return 2
    if not args.yes_spend:
        print("\nDry run: nothing was called. Add --yes-spend to make the real call.")
        return 0

    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-tf-"))
    policy = Policy.load("tinyfish-demo" if args.mode == "agent" else "tinyfish-answers", 1)
    if args.mode == "agent" and host not in policy.body["allowed_hosts"]:
        print(f"policy tinyfish-demo allows only {policy.body['allowed_hosts']}; {host} refused")
        return 2
    dsn = demo.prepare_database(args.dsn, migration)
    tokens = demo.seed(dsn, policy)
    stack = demo.Stack(
        work=work,
        dsn=dsn,
        abb=abb,
        signer_bin=signer_bin,
        signer_port=demo.free_port(),
        api_port=demo.free_port(),
    )
    code = 0
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"
        run_id = demo.create_run(
            base_url, tokens["operator"], policy, adapter="tinyfish", task=args.goal
        )
        lease = LeaseStore(demo.connections(dsn)).acquire(run_id, "tf-worker")
        sink = HttpEventSink(
            base_url=base_url,
            run_id=run_id,
            token=tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        shell = TinyFishAdapter(None, client, budget, opt_in=True)
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=shell.provenance(),
            in_scope_actions=IN_SCOPE_ACTIONS,
        )
        adapter = TinyFishAdapter(gateway, client, budget, opt_in=True)
        gateway.run_started(task=sent_goal, requested_coverage="STEP_OBSERVED")
        gateway.declare_coverage(
            requested="STEP_OBSERVED",
            declared="STEP_OBSERVED",
            reason="TinyFish steps are the provider's own report; capped at STEP_OBSERVED",
        )
        demo.say(
            "1. the real call", f"{args.mode}" + (f" at {args.url}" if args.mode == "agent" else "")
        )
        if args.mode == "search":
            outcome = adapter.search(sent_goal)
        elif args.mode == "research":
            outcome = adapter.research(sent_goal)
        else:
            outcome = adapter.run_agent(sent_goal, args.url)
        print(
            f"  outcome: {outcome.status}  {outcome.detail if hasattr(outcome, 'detail') else ''}"
        )
        print(f"  spent so far (recorded): ${budget.spent_cents / 100:.2f}")
        print(f"RUN_OUTCOME {outcome.status}", flush=True)
        if outcome.status == "SUCCEEDED":
            # One line, JSON-encoded, for the run console to show. Not part of the receipt.
            print("RESULT_TEXT " + json.dumps(outcome.detail[:4000]), flush=True)
        gateway.run_finished(
            final_state="FINALIZING",
            outcome="COMPLETED" if outcome.status == "SUCCEEDED" else "FAILED",
        )
        Repository(connect=demo.connections(dsn), canonicalizer=Canonicalizer(abb)).set_state(
            run_id, "FINALIZING"
        )
        demo.say("2. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="2. verify")
        if args.out is not None:
            args.out.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(receipt, args.out / receipt.name)
            shutil.copyfile(demo.key_manifest(stack), args.out / (receipt.name + ".keys.json"))
            print(f"RECEIPT_SAVED {receipt.name}")
        print("\nValid means the record is unchanged. It does not mean TinyFish did what it says.")
        return code
    finally:
        stack.stop()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
