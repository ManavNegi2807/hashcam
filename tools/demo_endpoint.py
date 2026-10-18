"""Endpoint events in, alerts out, everything sealed: the phishing-link scenario end to end.

    python tools/demo_endpoint.py --dsn postgresql://abb@127.0.0.1:55432/postgres \
        --people-dir ~/.abb/people --out <receipts dir> --goal "phishing link in chat"

What happens, in order, for each reported endpoint event:

1. the event is an `Action` the gateway records, allows and dispatches (a monitor records what
   happened; it cannot stop it), and the collector's report is sealed as an artifact by digest;
2. the explainable rules score it (a rule sum, not a probability); a score at or above the
   threshold is written to the ledger as an alert (`ML_ANALYSIS_COMPLETED`, advisory);
3. if the alert has a URL, TinyFish is asked about it through the gateway (Search); what it says is
   stored as an artifact and shown as the provider's claim. No key or no budget: recorded as
   NOT RUN,
   which is missing evidence, not "safe";
4. for a HIGH alert the analyst is asked to approve isolating the user's account. The approval is a
   signature with `abb approve`. The isolation itself is SIMULATED: no real account changes.

Where the events come from: `--goal` picks a built-in SIMULATED scenario, or, if it holds web
links, treats each link as one a person reported (scored, never opened from this computer); or
`--events-file` reads events the real collector (`tools/endpoint_daemon.py`) wrote.
Everything after that is the same.

Protocol with the run console: see `tools/approval_bridge.py`. A valid receipt shows the record is
unchanged since it was signed. It does not show that an alert is right or that a person is at
fault.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from adapters.base import Provenance  # noqa: E402
from adapters.tinyfish.adapter import TinyFishAdapter  # noqa: E402
from adapters.tinyfish.budget import Budget  # noqa: E402
from adapters.tinyfish.client import FakeTinyFishClient, good_answer  # noqa: E402
from adapters.tinyfish.http_client import KEY_ENV, HttpTinyFishClient  # noqa: E402
from endpoint import model as forest  # noqa: E402
from endpoint.alerts import COLLECTOR, FETCH_EVIDENCE, SEARCH_EVIDENCE, alerts_from  # noqa: E402
from endpoint.events import EndpointEvent, events_from_links, scenario_for  # noqa: E402
from endpoint.investigate import enrich  # noqa: E402
from endpoint.scoring import (  # noqa: E402
    FEATURE_SCHEMA_ID,
    MEDIUM_PPM,
    MODEL_ID,
    MODEL_VERSION,
    score,
)
from policy.engine import Action, Policy  # noqa: E402
from security.semantic.monitor import run_monitor  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.artifacts.component import ArtifactComponent  # noqa: E402
from services.dashboard.server import summarize  # noqa: E402
from services.worker.approval_client import HttpApprovalClient  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402
from tools import demo  # noqa: E402
from tools.approval_bridge import Bridge  # noqa: E402
from tools.demo_guarded import stdin_lines  # noqa: E402

IN_SCOPE = [
    "file_download",
    "process_launch",
    "url_click",
    "record_query",
    "api_call",
    "account_isolation",
]
COVERAGE_REASON = (
    "the endpoint reports are the collector's own claims, recorded and sealed but not gated; "
    "nothing proves every action on the machine was observed"
)
WORDS = {
    "NOT_RUN": "not asked (no TinyFish key for this run)",
    "NOT_ASKED": "not asked",
    "DONE": "TinyFish answered (the provider's claim, not checked here)",
    "UNKNOWN": "unknown: TinyFish gave no clear answer",
    "FAILED": "failed",
    "BLOCKED": "blocked",
}
ISOLATION_WORDS = {
    "NOT_PROPOSED": "no account action proposed",
    "WAITING_FOR_APPROVAL": "waiting for an analyst's signature",
    "APPROVED": "approved",
    "DENIED": "**denied** by the analyst: nothing was done",
    "ISOLATED_SIMULATED": "approved and **simulated** (no real account was changed)",
}


class ScriptedClient(FakeTinyFishClient):
    """TEST ONLY: scripted answers, but with the real service's two addresses so the policy and
    the receipt see the same targets as a live run."""

    def api_url(self, kind: str) -> str:
        return {"fetch": "https://api.fetch.tinyfish.ai"}.get(
            kind, "https://api.search.tinyfish.ai"
        )


def load_events(path: Path) -> list[EndpointEvent]:
    """Events from a JSON-lines file a collector wrote. Anything malformed is refused."""
    events: list[EndpointEvent] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(EndpointEvent(**json.loads(line)))
        except (ValueError, TypeError) as exc:
            raise ValueError(f"line {number} is not a valid event: {exc}") from None
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Endpoint events to alerts, sealed")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--goal", default="", help="a few words: phishing, download, records")
    parser.add_argument("--events-file", type=Path, help="JSON-lines events from the collector")
    parser.add_argument("--people-dir", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument(
        "--enrichment",
        choices=["auto", "off", "fake"],
        default="auto",
        help="auto: ask TinyFish only if TINYFISH_API_KEY is set. fake: TEST ONLY scripted answer",
    )
    parser.add_argument("--keep", action="store_true")
    parser.add_argument(
        "--model",
        choices=["auto", "off"],
        default="auto",
        help="auto: also ask the Isolation Forest if scikit-learn is installed (advisory)",
    )
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    if args.events_file:
        try:
            events = load_events(args.events_file)
        except (OSError, ValueError) as exc:
            print(f"cannot read the events: {exc}")
            return 2
        name = "collector_file"
    else:
        links = events_from_links(args.goal)
        if links:
            name, events = "reported_links", links  # a person pasted link(s) to check
        else:
            name, scripted = scenario_for(args.goal)
            events = list(scripted)
    if not events:
        print("there are no events to analyse")
        return 2

    policy = Policy.load("endpoint-monitor", 1)
    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-ep-"))
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
    # Train BEFORE the stdin reader thread starts: a thread blocked on stdin while numpy and
    # scikit-learn load made this hang on Windows.
    learned = forest.get_model() if args.model == "auto" and forest.available() else None
    print("learned model:", "Isolation Forest (advisory)" if learned else "not used", flush=True)
    bridge = Bridge(stdin_lines(), args.wait_seconds, policy)

    use_real = args.enrichment == "auto" and bool(os.environ.get(KEY_ENV))
    tf_client: Any = None
    budget: Budget | None = None
    if use_real:
        budget_path = Path(
            os.environ.get("ABB_TINYFISH_BUDGET", Path.home() / ".abb" / "tinyfish.json")
        )
        budget_path.parent.mkdir(parents=True, exist_ok=True)
        if not budget_path.exists():
            budget_path.write_text(json.dumps({"spent_cents": 15}), encoding="utf-8")
        budget = Budget.load(budget_path)
        tf_client = HttpTinyFishClient()
    elif args.enrichment == "fake":
        tf_client = ScriptedClient(
            host="api.search.tinyfish.ai",
            script=[
                good_answer(cents=0, steps=1) | {"result": text}
                for text in (
                    "Scripted search answer (TEST ONLY).",
                    "Scripted page text (TEST ONLY).",
                )
                * 4
            ],
        )
        budget = Budget()

    code = 0
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"
        task = (
            "[FAKE ENRICHMENT, TEST ONLY] " if args.enrichment == "fake" else ""
        ) + f"Review endpoint events ({name}, {len(events)} events, simulated collector)"
        run_id = demo.create_run(
            base_url, tokens["operator"], policy, adapter="endpoint", task=task
        )
        lease = LeaseStore(demo.connections(dsn)).acquire(run_id, "ep-worker")
        sink = HttpEventSink(
            base_url=base_url,
            run_id=run_id,
            token=tokens["adapter"],
            fencing_token=lease.fencing_token,
        )
        relay = HttpApprovalClient(base_url=base_url, run_id=run_id, token=tokens["adapter"])
        repo = Repository(connect=demo.connections(dsn), canonicalizer=Canonicalizer(abb))
        gateway = Gateway(
            sink=sink,
            policy=policy,
            provenance=Provenance(
                "endpoint-sim", "0.1.0", f"endpoint-{run_id}"[:60], "REPLAY", "STEP_OBSERVED"
            ),
            in_scope_actions=IN_SCOPE,
            artifacts=ArtifactComponent(
                store=demo.artifact_store(stack), repository=repo, run_id=run_id
            ),
            approvals=relay,
        )
        approve = bridge.approver(run_id)
        adapter = (
            TinyFishAdapter(gateway, tf_client, budget or Budget(), opt_in=True)
            if tf_client is not None
            else None
        )
        gateway.run_started(task=task, requested_coverage="STEP_OBSERVED")
        gateway.declare_coverage(
            requested="STEP_OBSERVED", declared="STEP_OBSERVED", reason=COVERAGE_REASON
        )

        demo.say("1. endpoint events", f"{len(events)} events from {name}")
        isolated: set[str] = set()
        counts = {"events": len(events), "alerts": 0, "high": 0, "review": 0}
        latencies: list[float] = []
        for i, event in enumerate(events, 1):
            started = time.perf_counter()
            action = Action(
                action_id=f"ev-{i}",
                action_type=event.kind,
                target=event.target or event.process,
                params={
                    "user_digest": hashlib.sha256(event.user.encode()).hexdigest()[:16],
                    "hour": event.hour,
                },
            )
            if not gateway.request(action).allows_dispatch:
                continue
            gateway.dispatch(action)
            sealed = gateway.capture_artifact(
                action, event.as_json(), media_type="application/json", capture_method=COLLECTOR
            )
            gateway.succeeded(action, evidence=[sealed.event_id])

            result = score(event)
            opinion = learned.score(event) if learned is not None else None
            line = f"  {i:>2}. {event.kind:<14} {event.user:<7} score {result.score_ppm:>7}"
            second_opinion = opinion is not None and opinion.flagged
            if not result.is_alert and not second_opinion:
                print(line + "  (no alert)", flush=True)
                continue
            if result.is_alert:
                gateway.emit_advisory(
                    "ML_ANALYSIS_COMPLETED",
                    {
                        "model_id": MODEL_ID,
                        "model_version": MODEL_VERSION,
                        "feature_schema_id": FEATURE_SCHEMA_ID,
                        "score_ppm": result.score_ppm,
                        "reason_codes": list(result.rule_ids),
                        "score_kind": "RULE_SUM",
                        "threshold_ppm": MEDIUM_PPM,
                    },
                    idempotency_key=f"endpoint-score-{i}",
                )
            if opinion is not None and opinion.flagged:
                gateway.emit_advisory(
                    "ML_ANALYSIS_COMPLETED",
                    {
                        "model_id": forest.MODEL_ID,
                        "model_version": forest.MODEL_VERSION,
                        "feature_schema_id": forest.FEATURE_SCHEMA_ID,
                        "score_ppm": opinion.score_ppm,
                        "reason_codes": list(opinion.reasons),
                        "score_kind": "ANOMALY_SCORE",
                        "threshold_ppm": opinion.threshold_ppm,
                    },
                    idempotency_key=f"endpoint-model-{i}",
                )
            latencies.append(time.perf_counter() - started)
            counts["alerts"] += 1
            counts["high"] += result.severity == "HIGH"
            counts["review"] += (not result.is_alert) and second_opinion
            why = ", ".join(result.rule_ids) if result.is_alert else "learned model only"
            tier = result.severity if result.is_alert else "REVIEW"
            print(f"{line}  ALERT {tier}: {why}", flush=True)

            if event.target.startswith("http"):
                found = enrich(gateway, adapter, event.target, i)
                print(
                    f"      web evidence: search {found.search.status}, page {found.fetch.status}",
                    flush=True,
                )
                for part, method in (
                    (found.search, SEARCH_EVIDENCE),
                    (found.fetch, FETCH_EVIDENCE),
                ):
                    if part.status == "DONE" and part.text:
                        gateway.capture_artifact(
                            action,
                            part.text[:4000].encode("utf-8"),
                            media_type="text/plain",
                            capture_method=method,
                        )

            if result.severity == "HIGH" and event.user not in isolated:
                isolated.add(event.user)
                iso = Action(
                    action_id=f"iso-{len(isolated)}",
                    action_type="account_isolation",
                    target=f"account:{event.user}",
                    params={
                        "user": event.user,
                        "readable": (
                            f"ISOLATE account {event.user}: a HIGH alert "
                            f"(rule score {result.score_ppm}). SIMULATED, no real account changes."
                        ),
                    },
                )
                decision = gateway.request(iso)
                if decision.outcome == "REQUIRE_APPROVAL":
                    decision = approve(gateway, iso)
                if decision.allows_dispatch:
                    gateway.dispatch(iso)
                    note = gateway.report_observation(
                        iso,
                        observation_kind="simulated_isolation",
                        url=f"account:{event.user}",
                        text="simulated: no real account was changed",
                    )
                    gateway.succeeded(iso, evidence=[note.event_id])

        outcome = "COMPLETED"
        print(f"RUN_OUTCOME {outcome}", flush=True)
        run_monitor(gateway)
        gateway.run_finished(final_state="FINALIZING", outcome=outcome)
        repo.set_state(run_id, "FINALIZING")
        demo.say("2. finalize, export, verify offline", "")
        receipt = demo.finalize_and_export(stack, run_id, policy)
        code |= demo.verify_step(stack, receipt, expect="VALID", title="2. verify")

        shown = alerts_from(receipt, summarize(receipt))
        lines = []
        for alert in shown:
            subject = alert["subject"]
            report = subject.get("report") or {}
            who = f"{report.get('user', '?')} at {report.get('hour', '?')}:00"
            why = "; ".join(str(s["text"]) for s in alert["signals"])
            web = str(alert["web_evidence"]["status"])
            acct = str(alert["isolation"]["status"])
            lines.append(
                f"- **{alert['severity']}** ({alert['score_ppm']} / 1,000,000) "
                f"{subject.get('kind')} by {who}: {why}\n"
                f"  Web evidence: {WORDS.get(web, web)}. "
                f"Account action: {ISOLATION_WORDS.get(acct, '')}."
            )
        speed = (
            f" Slowest alert took {max(latencies) * 1000:.0f} ms from the event to its record."
            if latencies
            else ""
        )
        text = (
            f"# Endpoint review: {counts['events']} events, {counts['alerts']} alerts "
            f"({counts['high']} high)\n"
            + ("\n".join(lines) if lines else "- No alerts.")
            + "\n- The events are SIMULATED. A score is a rule sum, not a probability, and an "
            "alert is a signal for review, not proof of wrongdoing." + speed
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
