"""A real browser, a real ledger, and a coverage claim that was measured.

    python tools/demo_playwright.py --dsn postgresql://abb@127.0.0.1:55432/postgres
    python tools/demo_playwright.py --dsn ... --leaky     # an adapter with a hole

It starts the real signer and API, runs the bypass self-test against a local
probe site, declares the coverage the result justifies (and records the test's
digest as evidence), drives a Chromium through the gateway, tries a few things
a hostile page might, finalizes, exports and verifies offline.

With `--leaky` the adapter does not gate WebSockets. The self-test notices, the
run declares `STEP_OBSERVED`, and the receipt says so: a weaker claim, honestly
made, which still verifies.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

os.environ.setdefault(
    "PLAYWRIGHT_BROWSERS_PATH",
    os.environ.get("ABB_PLAYWRIGHT_BROWSERS", str(Path.home() / "AppData/Local/ms-playwright")),
)

import pathsafe  # noqa: E402
from adapters.base import Coverage  # noqa: E402
from adapters.playwright.adapter import (  # noqa: E402
    IN_SCOPE_ACTIONS,
    MemorySink,
    PlaywrightAdapter,
    probe_policy,
)
from adapters.playwright.probe_site import ProbeSite  # noqa: E402
from policy.engine import Policy  # noqa: E402
from security.prompt_guard.guard import DeterministicGuard  # noqa: E402
from security.semantic.monitor import run_monitor  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402
from tools import demo  # noqa: E402


def measure_coverage(leaky: bool) -> tuple[Any, Coverage, str]:
    """Run the bypass battery on a throwaway ledger and decide what may be claimed."""
    from adapters.base import Provenance

    throwaway = Gateway(
        sink=MemorySink(),
        policy=probe_policy(),
        provenance=Provenance("playwright", "0.1.0", "selftest", "LIVE_LOCAL", "STEP_GATED"),
        in_scope_actions=IN_SCOPE_ACTIONS,
    )
    with PlaywrightAdapter(throwaway, gate_websockets=not leaky) as adapter:
        report = adapter.self_test()
        coverage, reason = adapter.coverage_after(report)
    return report, coverage, reason


def main() -> int:
    parser = argparse.ArgumentParser(description="Gated Playwright demo")
    parser.add_argument(
        "--dsn",
        default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres"),
    )
    parser.add_argument(
        "--leaky", action="store_true", help="an adapter that does not gate WebSockets"
    )
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-pw-"))
    policy = Policy.load("local-site", 1)
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
    site = ProbeSite().start()
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"

        demo.say("1. measure what may be claimed", "running the bypass probes against a local site")
        report, coverage, reason = measure_coverage(args.leaky)
        for name, verdict in report.results.items():
            print(f"  {name:18} {verdict}")
        print(f"  -> declared coverage: {coverage}\n  -> {reason}")

        run_id = demo.create_run(
            base_url,
            tokens["operator"],
            policy,
            adapter="playwright",
            task="Update the contact form on the local portal",
        )
        lease = LeaseStore(demo.connections(dsn)).acquire(run_id, "pw-worker")
        sink = HttpEventSink(
            base_url=base_url,
            run_id=run_id,
            token=tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        shell = PlaywrightAdapter(None, trusted_origins=frozenset({site.origin}))
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=shell.provenance(coverage),
            in_scope_actions=IN_SCOPE_ACTIONS,
            guard=DeterministicGuard(),
        )
        gateway.run_started(
            task="Update the contact form on the local portal", requested_coverage="STEP_GATED"
        )
        gateway.declare_coverage(
            requested="STEP_GATED",
            declared=coverage,
            reason=reason,
            evidence_ref=report.digest(),
        )

        demo.say("2. browse", "a normal visit, then what a hostile page might try")
        with PlaywrightAdapter(
            gateway,
            trusted_origins=frozenset({site.origin}),
            gate_websockets=not args.leaky,
        ) as adapter:
            page = adapter.new_page()
            print("  open the portal:        ", adapter.goto(page, site.origin + "/"))
            print("  open the form:          ", adapter.goto(page, site.origin + "/form"))
            print(
                "  fill the email field:   ",
                "ok" if adapter.fill(page, "#email", "a@portal.example") else "blocked",
            )
            page.click("#go")
            page.wait_for_load_state()
            print("  submitted, page says:   ", page.inner_text("h1"))
            mark = site.mark()
            # A blocked navigation leaves a page on the browser's error screen, so each
            # hostile step gets a fresh page.
            hostile = adapter.new_page()
            print(
                "  hostile: forbidden name:",
                adapter.goto(hostile, site.forbidden_origin + "/secret/direct"),
            )
            print("  hostile: fetch, beacon, image, iframe ... from a page script")
            for name in ("fetch", "beacon", "img", "iframe", "websocket", "popup"):
                trial = adapter.new_page()
                adapter.goto(trial, f"{site.origin}/probe/{name}")
                trial.wait_for_timeout(400)
            print("  hostile: a redirect chain that ends at the forbidden name")
            adapter.goto(
                adapter.new_page(),
                f"{site.origin}/redirect?to={site.forbidden_origin}/secret/chain",
            )
            reached = site.leaked_since(mark)
            print(f"  requests that reached the forbidden name: {len(reached)}")
            if reached and coverage == "STEP_GATED":
                print("  PROBLEM: declared STEP_GATED but something got through")
                code = 1

        run_monitor(gateway)
        gateway.run_finished(final_state="FINALIZING", outcome="COMPLETED")
        Repository(connect=demo.connections(dsn), canonicalizer=Canonicalizer(abb)).set_state(
            run_id, "FINALIZING"
        )

        demo.say("3. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="3. verify")
        # What the receipt itself says, read back from the offline verifier, not a local variable.
        shown = subprocess.run(  # noqa: S603 - fixed argv
            [
                abb,
                "verify",
                str(receipt),
                "--keys",
                str(demo.key_manifest(stack)),
                "--profile",
                "LOCAL_ONLY",
                "--json",
            ],
            capture_output=True,
            check=False,
        ).stdout
        print(f"\ndeclared coverage in the receipt: {json.loads(shown)['declared_coverage']}")
        print(
            "A STEP_GATED claim here means: every HTTP(S) request and WebSocket the browser\n"
            "made passed the gateway first, as far as these probes can show. It does not cover\n"
            "other transports, and a probe battery is not a proof."
        )
        return code
    finally:
        site.stop()
        stack.stop()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
