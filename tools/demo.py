"""The demo of `PRODUCT_REQUIREMENTS.md` section 9, as far as it is built.

It starts the real signer and the real API, runs a replay scenario through the
real policy gateway, finalizes through the signer, exports a receipt and
verifies it with the offline CLI. Then it tampers and verifies again.

What it shows today (Steps 1 to 5):

1. a replay run, policy-gated, with one action denied by policy;
2. the receipt verifies: `VALID`, with coverage stated;
3. one event edited in the database: `INVALID`, and the verifier names it;
4. a whole run deleted: `abb verify-global` reports the gap.

What it does **not** show yet, and says so rather than implying otherwise:

* a *signed* approval (Step 9). The approval scenario stops at
  `HUMAN_APPROVAL_REQUESTED` and the action is not dispatched;
* an artifact swap (Step 6);
* an independent witness or anchor (Step 8), so the deleted-run check here
  compares against the local global checkpoint only.

Usage:

    python tools/demo.py --dsn postgresql://abb@127.0.0.1:55432/postgres

Everything it creates lives in a temporary directory and a throwaway database.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import psycopg

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from adapters.replay.adapter import IN_SCOPE_ACTIONS, ReplayAdapter, load_scenario  # noqa: E402
from policy.engine import Decision, Policy  # noqa: E402
from policy.mandate import SignedMandate  # noqa: E402
from security.prompt_guard.guard import DeterministicGuard  # noqa: E402
from security.semantic.monitor import run_monitor  # noqa: E402
from services.api.canonical import Canonicalizer  # noqa: E402
from services.api.export import Exporter  # noqa: E402
from services.api.finalize import Finalizer  # noqa: E402
from services.api.repository import Repository  # noqa: E402
from services.api.signer_client import SignerClient  # noqa: E402
from services.artifacts.component import ArtifactComponent  # noqa: E402
from services.artifacts.s3_store import S3ArtifactStore  # noqa: E402
from services.artifacts.store import ArtifactStore  # noqa: E402
from services.worker.approval_client import HttpApprovalClient  # noqa: E402
from services.worker.event_sink import HttpEventSink  # noqa: E402
from services.worker.gateway import Gateway  # noqa: E402
from services.worker.lease import LeaseStore  # noqa: E402

GREEN = "\033[32m" if os.name != "nt" else ""
RED = "\033[31m" if os.name != "nt" else ""
PLAIN = "\033[0m" if os.name != "nt" else ""


def connections(dsn: str) -> Any:
    """A connection factory of the shape the repository expects."""

    @contextmanager
    def connect() -> Iterator[Any]:
        with psycopg.connect(dsn) as conn:
            yield conn

    return connect


def say(step: str, message: str) -> None:
    print(f"\n=== {step} ===\n{message}", flush=True)


def binary(name: str, env_var: str) -> str:
    from_env = os.environ.get(env_var)
    if from_env and Path(from_env).is_file():
        return from_env
    found = shutil.which(name)
    if found:
        return found
    target = os.environ.get("CARGO_TARGET_DIR") or str(REPO / "core" / "target")
    for candidate in (
        Path(target) / "debug" / f"{name}.exe",
        Path(target) / "debug" / name,
    ):
        if candidate.is_file():
            return str(candidate)
    raise SystemExit(
        f"cannot find {name}. Build it with: cargo build -p abb-cli -p abb-signer "
        f"(and set {env_var} if it is somewhere unusual)"
    )


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for(
    port: int, what: str, seconds: float = 30.0, process: subprocess.Popen[bytes] | None = None
) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            if process is not None and process.poll() is not None:
                # It exited: say why, in its own words (never a key; none is printed there).
                tail = b""
                if process.stderr is not None:
                    tail = process.stderr.read()[-600:]
                raise SystemExit(
                    f"{what} exited with code {process.returncode}: "
                    + tail.decode("utf-8", "replace").strip()
                ) from None
            time.sleep(0.1)
    raise SystemExit(f"{what} did not start listening on {port}")


@dataclass
class Stack:
    """The processes and connections the demo needs."""

    work: Path
    dsn: str
    abb: str
    signer_bin: str
    signer_port: int
    api_port: int
    simulate_second_device: bool = False
    people: Path | None = None
    signer: subprocess.Popen[bytes] | None = None
    api: subprocess.Popen[bytes] | None = None

    def stop(self) -> None:
        for process in (self.api, self.signer):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:  # pragma: no cover
                    process.kill()


def prepare_database(admin_dsn: str, migration: str) -> str:
    name = f"abb_demo_{uuid.uuid4().hex[:10]}"
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        conn.execute(f'CREATE DATABASE "{name}"')
    head, _, _ = admin_dsn.rpartition("/")
    dsn = f"{head}/{name}"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(migration)
    return dsn


def seed(dsn: str, policy: Policy) -> dict[str, str]:
    """A policy version, an operator token and an adapter token."""
    seed_policy(dsn, policy)
    operator_token = "demo-operator-token"
    adapter_token = "demo-adapter-token"
    operator_id = str(uuid.uuid4())
    adapter_id = str(uuid.uuid4())
    with psycopg.connect(dsn, autocommit=True) as conn:
        for user_id, name, role, token in (
            (operator_id, "demo operator", "operator", operator_token),
            (adapter_id, "demo adapter", "adapter", adapter_token),
        ):
            conn.execute(
                "INSERT INTO users (user_id, name, role) VALUES (%s, %s, %s)",
                (user_id, name, role),
            )
            conn.execute(
                """INSERT INTO api_tokens (token_id, user_id, token_hash, expires_at_ms)
                   VALUES (%s, %s, %s, %s)""",
                (
                    str(uuid.uuid4()),
                    user_id,
                    hashlib.sha256(token.encode()).digest(),
                    int(time.time() * 1000) + 86_400_000,
                ),
            )
    return {"operator": operator_token, "adapter": adapter_token}


def start_stack(stack: Stack) -> None:
    # Keys, through the CLI an operator would use.
    keys = stack.work / "keys"
    for role in ("signer", "approver"):
        subprocess.run(  # noqa: S603
            [stack.abb, "keygen", "--out", str(keys), "--role", role],
            capture_output=True,
            check=True,
        )
    # The people's keys: a separate directory the API and the signer never see.
    for role in ("approver", "mandate_issuer"):
        if (people_dir(stack) / f"{role}.key").exists():
            continue  # a person's key that already exists is kept, never replaced
        subprocess.run(  # noqa: S603
            [stack.abb, "keygen", "--out", str(people_dir(stack)), "--role", role],
            capture_output=True,
            check=True,
        )
    ingestion_public = pathsafe.read_text(keys / "approver.pub").strip()

    env = dict(os.environ)
    env.update(
        {
            "ABB_SIGNER_STATE_DIR": str(stack.work / "signer-state"),
            "ABB_SIGNER_KEY": str(keys / "signer.key"),
            "ABB_SIGNER_INGESTION_PUBKEY": ingestion_public,
            "ABB_SIGNER_ADDR": f"127.0.0.1:{stack.signer_port}",
            "ABB_SIGNER_RATE_LIMIT": "500",
        }
    )
    stack.signer = subprocess.Popen(  # noqa: S603
        [stack.signer_bin],
        env=env,
        stdin=subprocess.DEVNULL,  # never share a stdin that something else is reading
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for(stack.signer_port, "the signer", process=stack.signer)

    api_env = dict(os.environ)
    api_env.update(
        {
            "ABB_DB_DSN": stack.dsn,
            "ABB_BIN": stack.abb,
            "ABB_KEY_MANIFEST": str(key_manifest(stack)),
            "PYTHONPATH": str(REPO),
        }
    )
    stack.api = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uvicorn",
            "services.api.main:build",
            "--factory",
            "--host",
            "127.0.0.1",
            "--port",
            str(stack.api_port),
            "--log-level",
            "warning",
        ],
        cwd=str(REPO),
        env=api_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    wait_for(stack.api_port, "the API", process=stack.api)


def main() -> int:
    parser = argparse.ArgumentParser(description="The Agent Black Box demo")
    parser.add_argument(
        "--dsn",
        default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres"),
        help="an admin DSN; the demo creates its own throwaway database",
    )
    parser.add_argument("--keep", action="store_true", help="keep the work directory")
    parser.add_argument(
        "--simulate-second-device",
        action="store_true",
        help=(
            "label the witnesses and the anchor as living elsewhere. This is a "
            "SIMULATION on one machine, printed as such; it demonstrates the "
            "quorum logic, not real independence"
        ),
    )
    args = parser.parse_args()

    abb = binary("abb", "ABB_BIN")
    signer_bin = binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    work = Path(tempfile.mkdtemp(prefix="abb-demo-"))

    say("0. setup", f"work directory: {work}\nbuilding a throwaway database")
    dsn = prepare_database(args.dsn, migration)
    policy = Policy.load("default", 1)
    tokens = seed(dsn, policy)

    stack = Stack(
        work=work,
        dsn=dsn,
        abb=abb,
        signer_bin=signer_bin,
        signer_port=free_port(),
        api_port=free_port(),
        simulate_second_device=args.simulate_second_device,
    )
    exit_code = 0
    try:
        start_stack(stack)
        say(
            "0. setup",
            f"signer on 127.0.0.1:{stack.signer_port}, API on 127.0.0.1:{stack.api_port}\n"
            f"policy {policy.policy_id} v{policy.version} digest {policy.body_digest[:16]}",
        )

        base_url = f"http://127.0.0.1:{stack.api_port}"
        run_id = create_run(base_url, tokens["operator"], policy)
        say("1. run", f"created run {run_id}")

        report = run_scenario(stack, base_url, tokens["adapter"], policy, run_id)
        say("1. run", report)

        receipt = finalize_and_export(stack, run_id, policy)
        say("2. receipt", f"exported {receipt}")

        exit_code |= verify_step(stack, receipt, expect="VALID", title="2. verify")
        exit_code |= witness_and_anchor_step(stack, run_id)
        exit_code |= tamper_receipt_step(stack, receipt)
        exit_code |= tamper_event_step(stack, receipt, run_id)
        exit_code |= artifact_swap_step(stack, receipt)
        exit_code |= signed_approval_step(stack, base_url, tokens, policy)
        exit_code |= mandate_step(stack, base_url, tokens, policy)
        exit_code |= commitment_step(stack, base_url, tokens)
        exit_code |= rollback_step(stack, base_url, tokens, policy)
        exit_code |= deleted_run_step(stack, run_id)

        say(
            "done",
            "Beats 1 to 5 of PRODUCT_REQUIREMENTS.md section 9 are covered, plus the\n"
            "witness and anchor checks, a signed approval, a signed mandate and a\n"
            "hidden-then-shredded value. A signature shows a key signed, not which\n"
            "person held it.\n"
            + (
                "The witnesses and the anchor were labelled as living on another device\n"
                "as a SIMULATION on this one machine; that demonstrates the quorum logic,\n"
                "not real independence."
                if stack.simulate_second_device
                else "Everything ran on one machine, so the witness and the anchor honestly\n"
                "report NOT_INDEPENDENT; pass --simulate-second-device to see the quorum\n"
                "logic pass, labelled as a simulation."
            ),
        )
        return exit_code
    finally:
        stack.stop()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"\nwork directory kept at {work}")


def create_run(
    base_url: str,
    token: str,
    policy: Policy,
    mandate_id: str | None = None,
    *,
    adapter: str = "replay",
    task: str = "Update vendor contact details on portal.example",
) -> str:
    import urllib.request

    body = json.dumps(
        {
            **({"mandate_id": mandate_id} if mandate_id else {}),
            "task": task,
            "adapter": adapter,
            "profile": "LOCAL_ONLY",
            "requested_coverage": "STEP_GATED",
            "policy_id": policy.policy_id,
            "policy_version": policy.version,
        }
    ).encode()
    request = urllib.request.Request(  # noqa: S310
        f"{base_url}/api/v1/runs",
        data=body,
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return str(json.loads(response.read())["run_id"])


def run_scenario(stack: Stack, base_url: str, token: str, policy: Policy, run_id: str) -> str:
    lease = LeaseStore(connections(stack.dsn)).acquire(run_id, "demo-worker")
    sink = HttpEventSink(
        base_url=base_url, run_id=run_id, token=token, fencing_token=lease.fencing_token
    )
    scenario = load_scenario("vendor_bank_update")
    adapter = ReplayAdapter(scenario)
    repo = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    artifacts = ArtifactComponent(store=artifact_store(stack), repository=repo, run_id=run_id)
    gateway = Gateway(
        sink=sink,
        policy=policy,
        provenance=adapter.provenance("STEP_GATED"),
        in_scope_actions=IN_SCOPE_ACTIONS,
        artifacts=artifacts,
        guard=DeterministicGuard(),
    )

    gateway.run_started(task=scenario["task"], requested_coverage="STEP_GATED")
    gateway.declare_coverage(
        requested="STEP_GATED",
        declared="STEP_GATED",
        reason="every in-scope action passes the local gateway before dispatch",
    )
    result = adapter.run(gateway)
    run_monitor(gateway)  # advisory: semantic invariants, recorded before the run ends
    gateway.run_finished(final_state="FINALIZING", outcome=result.status)

    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    repository.set_state(run_id, "FINALIZING")

    lines = [result.summary(), f"lease fencing token {lease.fencing_token}", ""]
    for step in result.steps:
        mark = {"SUCCEEDED": "dispatched", "BLOCKED": "blocked by policy"}.get(
            step.status, step.status.lower()
        )
        lines.append(f"  {step.action_id} {step.action_type:12} {step.target[:46]:46} {mark}")
    for error in result.errors:
        lines.append(f"  -> {error['action_id']}: {', '.join(error['reason_codes'])}")
    lines.append("")
    lines.append(f"{len(gateway.events)} events committed")
    return "\n".join(lines)


def finalize_and_export(
    stack: Stack, run_id: str, policy: Policy, disclose: list[str] | None = None
) -> Path:
    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    keys = stack.work / "keys"
    signer = SignerClient(
        base_url=f"http://127.0.0.1:{stack.signer_port}",
        abb_path=stack.abb,
        ingestion_key_path=str(keys / "approver.key"),
    )
    finalizer = Finalizer(repository=repository, signer=signer, abb_path=stack.abb)
    result = finalizer.finalize(run_id)
    print(
        f"  signed checkpoint over {result.event_count} events, "
        f"tree_size {result.run_checkpoint.tree_size}\n"
        f"  global log position {result.global_position}, "
        f"global tree_size {result.global_checkpoint.tree_size}"
    )

    exporter = Exporter(repository=repository, abb_path=stack.abb, store=artifact_store(stack))
    out = stack.work / f"{run_id}.abbreceipt"
    exported = exporter.export(run_id, out, disclose=disclose)
    print(f"  {exported.bytes_written} bytes, {exported.event_count} events")
    del policy
    return exported.path


SIGNER_DOMAIN = "host:demo-machine/admin:demo"


def domain_of(stack: Stack, role: str) -> str:
    """The independence label for a role.

    On one machine everything shares the signer's domain, and the verifier says
    so. With `--simulate-second-device` the witnesses and the anchor are
    *labelled* as elsewhere. That is a label on a single machine, printed as a
    simulation: it exercises the quorum rules, it does not create independence.
    """
    if role == "signer" or not stack.simulate_second_device:
        return SIGNER_DOMAIN
    return {
        "witness1": "host:simulated-laptop-b/admin:bob",
        "witness2": "host:simulated-vps-c/admin:carol",
        "anchor": "repo:simulated-public-repo/admin:carol",
    }[role]


def anchor_domain(stack: Stack) -> str:
    return SIGNER_DOMAIN if not stack.simulate_second_device else domain_of(stack, "anchor")


def global_checkpoint_files(stack: Stack, name: str) -> tuple[Path, Path]:
    """Write the latest global checkpoint and the run-root records for a witness."""
    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    latest = repository.checkpoints("global")[-1]
    checkpoint = stack.work / f"{name}-checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "payload_b64": base64.b64encode(latest["payload_bytes"]).decode("ascii"),
                "signature": latest["signature"],
            }
        ),
        encoding="utf-8",
    )
    records = stack.work / f"{name}-records.txt"
    records.write_text(
        "\n".join(base64.b64encode(r).decode("ascii") for r in repository.global_records()),
        encoding="utf-8",
    )
    return checkpoint, records


def run_witness(stack: Stack, role: str) -> dict[str, str] | None:
    """Run `abb witness sign` as a separate process with its own key and state."""
    keys = stack.work / "keys"
    if not (keys / f"{role}.key").exists():
        # `abb keygen` knows the four protocol roles. Each demo witness gets its
        # own scratch directory and its files are named after the witness.
        scratch = stack.work / f"{role}-keygen"
        subprocess.run(  # noqa: S603
            [stack.abb, "keygen", "--out", str(scratch), "--role", "witness"],
            capture_output=True,
            check=True,
        )
        os.replace(scratch / "witness.key", keys / f"{role}.key")
        os.replace(scratch / "witness.pub", keys / f"{role}.pub")
    checkpoint, records = global_checkpoint_files(stack, role)
    done = subprocess.run(  # noqa: S603
        [
            stack.abb,
            "witness",
            "sign",
            "--key",
            str(keys / f"{role}.key"),
            "--state",
            str(stack.work / f"{role}-state.json"),
            "--keys",
            str(key_manifest(stack)),
            "--domain",
            domain_of(stack, role),
            "--checkpoint",
            str(checkpoint),
            "--records",
            str(records),
        ],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        print(f"  {role} REFUSED: {done.stderr.decode('utf-8', 'replace').strip()}")
        return None
    fields = dict(line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line)
    print(
        f"  {role} signed global checkpoint of size {fields['tree_size']} "
        f"as {domain_of(stack, role)}"
    )
    return {"statement_b64": fields["statement_b64"], "signature": fields["signature"]}


def anchor_record(stack: Stack) -> dict[str, Any]:
    """Append the latest global checkpoint to the anchor file, and describe it."""
    checkpoint, _ = global_checkpoint_files(stack, "anchor")
    anchors_dir = stack.work / "anchors"
    anchors_dir.mkdir(exist_ok=True)
    log = anchors_dir / "global.log"
    done = subprocess.run(  # noqa: S603
        [stack.abb, "anchor", "append", "--file", str(log), "--checkpoint", str(checkpoint)],
        capture_output=True,
        check=True,
    )
    fields = dict(part.split("=", 1) for part in done.stdout.decode().split() if "=" in part)
    # Commit it to a local Git repository when Git is there. Honest scope: a
    # local repository under the same administrator is not an independent
    # anchor, and a Git commit time is not a trusted timestamp.
    if shutil.which("git"):
        env = {
            **os.environ,
            "GIT_AUTHOR_NAME": "abb demo",
            "GIT_AUTHOR_EMAIL": "demo@invalid",
            "GIT_COMMITTER_NAME": "abb demo",
            "GIT_COMMITTER_EMAIL": "demo@invalid",
        }
        if not (anchors_dir / ".git").exists():
            subprocess.run(["git", "init", "-q"], cwd=anchors_dir, env=env, check=False)  # noqa: S607
        subprocess.run(["git", "add", "global.log"], cwd=anchors_dir, env=env, check=False)  # noqa: S607
        subprocess.run(  # noqa: S603
            ["git", "commit", "-q", "-m", f"anchor global size {fields['tree_size']}"],  # noqa: S607
            cwd=anchors_dir,
            env=env,
            check=False,
            capture_output=True,
        )
    print(f"  anchored global size {fields['tree_size']} in {log.name} ({anchor_domain(stack)})")
    return {
        "checkpoint_hash": fields["checkpoint_hash"],
        "tree_size": int(fields["tree_size"]),
        "location": str(log),
        "anchor_domain": anchor_domain(stack),
        "published_at": int(time.time() * 1000),
    }


def witness_and_anchor_step(stack: Stack, run_id: str) -> int:
    """Witness the global checkpoint, anchor it, re-export, and verify."""
    say(
        "2b. witnesses and an anchor",
        "A signer alone cannot show it was not rolled back. Witnesses keep their own\n"
        "anti-rollback state and rebuild the tree before signing; an anchor publishes\n"
        "the checkpoint outside the system."
        + (
            "\n\n*** SIMULATION: --simulate-second-device labels the witnesses and anchor\n"
            "as living elsewhere. Everything still runs on this one machine. ***"
            if stack.simulate_second_device
            else "\n\nEverything runs on this one machine, so independence is not claimed."
        ),
    )
    roles = ["witness1", "witness2"] if stack.simulate_second_device else ["witness1"]
    witnesses = [w for role in roles if (w := run_witness(stack, role)) is not None]
    anchors = [anchor_record(stack)]
    out = stack.work / f"{run_id}-witnessed.abbreceipt"
    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    Exporter(repository=repository, abb_path=stack.abb, store=artifact_store(stack)).export(
        run_id, out, witnesses=witnesses, anchors=anchors
    )
    expect = "VALID" if stack.simulate_second_device else "PARTIAL"
    return verify_step(stack, out, expect=expect, title="2b. verify the witnessed receipt")


def rollback_step(stack: Stack, base_url: str, tokens: dict[str, str], policy: Policy) -> int:
    """A rollback the local check cannot see and the anchor can."""
    say(
        "3c. a rollback",
        "Run a second job, anchor the larger log, then restore the database to how it\n"
        "looked before. The restored state is internally consistent and the signer's\n"
        "old checkpoint is validly signed, so a purely local check has nothing to object to.",
    )
    # The log already holds every earlier beat's run, so measure rather than assume.
    with psycopg.connect(stack.dsn, autocommit=True) as conn:
        row = conn.execute("SELECT count(*) FROM global_log").fetchone()
        before = int(row[0]) if row else 0
    run_b = create_run(base_url, tokens["operator"], policy)
    run_scenario(stack, base_url, tokens["adapter"], policy, run_b)
    finalize_run(stack, run_b)
    run_witness(stack, "witness1")  # extends its state
    anchor_record(stack)  # the anchored size grows by one

    purge_run(stack, run_b)
    with psycopg.connect(stack.dsn, autocommit=True) as conn:
        conn.execute(
            "DELETE FROM checkpoints WHERE stream_id = 'global' AND tree_size = %s",
            (before + 1,),
        )
    print(f"restored the database to its size-{before} state (a rollback)")

    after = stack.work / "rollback-roots.json"
    export_global_file(stack, after)
    keys = str(key_manifest(stack))
    local = subprocess.run(  # noqa: S603
        [stack.abb, "verify-global", "--roots", str(after), "--keys", keys],
        capture_output=True,
        check=False,
    )
    say("3c. verify-global WITHOUT the anchor", local.stdout.decode("utf-8", "replace").strip())
    failed = 0
    if local.returncode == 0:
        print(f"{GREEN}as expected: the local check cannot see a rollback{PLAIN}")
    else:
        print(f"{RED}expected the local check to pass the rolled-back state{PLAIN}")
        failed = 1

    anchored = subprocess.run(  # noqa: S603
        [
            stack.abb,
            "verify-global",
            "--roots",
            str(after),
            "--keys",
            keys,
            "--anchor",
            str(stack.work / "anchors" / "global.log"),
        ],
        capture_output=True,
        check=False,
    )
    out = anchored.stdout.decode("utf-8", "replace")
    say("3c. verify-global WITH the anchor", out.strip())
    if anchored.returncode != 0 and ("MISSING_RUNS" in out or "ANCHOR_MISMATCH" in out):
        print(f"{GREEN}the rollback was detected by the anchor{PLAIN}")
        return failed
    print(f"{RED}the anchor did not expose the rollback{PLAIN}")
    return 1


def purge_run(stack: Stack, run_id: str) -> None:
    """Remove a run and everything referring to it, as an attacker with the DB would."""
    with psycopg.connect(stack.dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM global_log WHERE run_id = %s", (run_id,))
        conn.execute("DELETE FROM checkpoints WHERE stream_id = %s", (run_id,))
        conn.execute("DELETE FROM event_idempotency WHERE run_id = %s", (run_id,))
        conn.execute("DELETE FROM workflow_outbox WHERE run_id = %s", (run_id,))
        conn.execute("DELETE FROM manifest_entries WHERE run_id = %s", (run_id,))
        conn.execute("ALTER TABLE events DISABLE TRIGGER events_no_delete")
        conn.execute("DELETE FROM events WHERE run_id = %s", (run_id,))
        conn.execute("ALTER TABLE events ENABLE TRIGGER events_no_delete")


def finalize_run(stack: Stack, run_id: str) -> Any:
    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    signer = SignerClient(
        base_url=f"http://127.0.0.1:{stack.signer_port}",
        abb_path=stack.abb,
        ingestion_key_path=str(stack.work / "keys" / "approver.key"),
    )
    return Finalizer(repository=repository, signer=signer, abb_path=stack.abb).finalize(run_id)


def artifact_store(stack: Stack) -> ArtifactStore:
    """The demo's artifact store: local by default, or an S3-compatible server when
    `ABB_S3_ENDPOINT` (with `ABB_S3_ACCESS_KEY` and `ABB_S3_SECRET_KEY`) is set."""
    if os.environ.get("ABB_S3_ENDPOINT"):
        return S3ArtifactStore.from_environment(abb_path=stack.abb)
    return ArtifactStore(stack.work / "artifacts", abb_path=stack.abb)


def artifact_swap_step(stack: Stack, receipt: Path) -> int:
    """Swap one artifact file inside the receipt (TS-09). The manifest names it."""
    say(
        "3b. tamper: swap an artifact",
        "The manifest committed to each artifact's digest, and the signed\n"
        "checkpoint committed to the manifest. Replacing the file changes none of\n"
        "that, so the bytes no longer match what was signed for.",
    )
    with zipfile.ZipFile(receipt) as archive:
        members = {name: archive.read(name) for name in archive.namelist()}
    victims = sorted(name for name in members if name.startswith("artifacts/"))
    if not victims:
        print("the receipt carries no artifacts to swap")
        return 1
    victim = victims[0]
    members[victim] = b"<html><body>a page the agent never saw</body></html>"
    swapped = stack.work / "swapped.abbreceipt"
    with zipfile.ZipFile(swapped, "w", zipfile.ZIP_STORED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    print(f"replaced {victim} with different bytes")
    return verify_step(stack, swapped, expect="INVALID", title="3b. verify the swapped receipt")


def key_manifest(stack: Stack) -> Path:
    """A key manifest from the demo's own keys, as an out-of-band channel would."""
    keys = stack.work / "keys"
    entries = []
    for pub in sorted(keys.glob("*.pub")):
        role = pub.stem
        if role not in {"signer", "witness1", "witness2"}:
            continue
        public = pathsafe.read_text(pub).strip()
        digest = hashlib.sha256(bytes.fromhex(public)).hexdigest()
        entries.append(
            {
                "key_id": f"ed25519:{digest}",
                "public_key_hex": public,
                "role": "signer" if role == "signer" else "witness",
                "failure_domain": domain_of(stack, role),
                "valid_from": 0,
                "status": "active",
            }
        )
    if people_dir(stack).exists():
        for pub in sorted(people_dir(stack).glob("*.pub")):
            entries.append(
                {
                    "key_id": key_id_of(pub),
                    "public_key_hex": pathsafe.read_text(pub).strip(),
                    "role": pub.stem,
                    "failure_domain": f"person:{pub.stem}-device",
                    "valid_from": 0,
                    "status": "active",
                }
            )
    manifest = {
        "note": "demo key manifest; in production this is published out of band",
        "keys": entries,
    }
    path = stack.work / "key_manifest.json"
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def verify_step(stack: Stack, receipt: Path, *, expect: str, title: str) -> int:
    manifest = key_manifest(stack)
    done = subprocess.run(  # noqa: S603
        [
            stack.abb,
            "verify",
            str(receipt),
            "--keys",
            str(manifest),
            "--profile",
            "LOCAL_ONLY",
        ],
        capture_output=True,
        check=False,
    )
    out = done.stdout.decode("utf-8", "replace")
    say(title, out.strip())
    got = "VALID" if done.returncode == 0 else out.splitlines()[-2] if out else "?"
    if expect in out:
        print(f"{GREEN}as expected: {expect}{PLAIN}")
        return 0
    print(f"{RED}expected {expect}, got {got}{PLAIN}")
    return 1


def tamper_receipt_step(stack: Stack, receipt: Path) -> int:
    """Edit one event inside the receipt. The verifier must name that event.

    This is tamper case TS-01 from `TESTING.md` 4: the proofs around it still
    belong to the signed tree, so exactly one leaf stops fitting.
    """

    say(
        "3a. tamper: edit one event inside the receipt",
        "The receipt is just a file. Anyone can edit it; the question is whether\n"
        "the edit is detectable, and where.",
    )
    with zipfile.ZipFile(receipt) as archive:
        receipt_json = archive.read("receipt.json").decode("utf-8")
    document = json.loads(receipt_json)

    # Find an observation event and change one byte of its recorded text digest.
    target_index = None
    for index, event in enumerate(document["events"]):
        canonical = base64.b64decode(event["canonical_b64"])
        if b"BROWSER_OBSERVATION" in canonical:
            target_index = index
            edited = bytearray(canonical)
            # Flip one hex character of the text digest: the smallest possible lie.
            marker = b'"text_digest":"'
            at = edited.find(marker) + len(marker)
            edited[at] = ord("0") if chr(edited[at]) != "0" else ord("1")
            document["events"][index]["canonical_b64"] = base64.b64encode(bytes(edited)).decode(
                "ascii"
            )
            break
    if target_index is None:
        print("no observation event in the receipt")
        return 1

    tampered = stack.work / "edited-receipt.abbreceipt"
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("receipt.json", json.dumps(document, separators=(",", ":")))
    print(f"changed one character in event {target_index} of the receipt")
    return verify_step(stack, tampered, expect="INVALID", title="3a. verify the edited receipt")


def tamper_event_step(stack: Stack, receipt: Path, run_id: str) -> int:
    """Edit one event in the database, re-export, and watch the verifier catch it."""
    say(
        "3. tamper: edit one event",
        "A host administrator can rewrite database rows, which is why the\n"
        "defence is the signed checkpoint, not the database's permissions.",
    )
    with psycopg.connect(stack.dsn, autocommit=True) as conn:
        # The append-only trigger blocks an UPDATE, so disable it exactly as a
        # superuser could: this is the threat being demonstrated.
        conn.execute("ALTER TABLE events DISABLE TRIGGER events_no_update")
        row = conn.execute(
            """SELECT sequence, canonical_bytes FROM events
               WHERE run_id = %s AND event_type = 'BROWSER_OBSERVATION'
               ORDER BY sequence LIMIT 1""",
            (run_id,),
        ).fetchone()
        if row is None:
            print("no observation event to edit")
            return 1
        sequence, canonical = int(row[0]), bytes(row[1])
        edited = canonical.replace(
            b'"observation_kind":"page_loaded"', b'"observation_kind":"page_looted"'
        )
        if edited == canonical:
            edited = canonical.replace(b"page_loaded", b"page_xxxxed")
        conn.execute(
            "UPDATE events SET canonical_bytes = %s WHERE run_id = %s AND sequence = %s",
            (edited, run_id, sequence),
        )
        conn.execute("ALTER TABLE events ENABLE TRIGGER events_no_update")
    print(f"edited event at sequence {sequence} in the database")

    # Re-export from the tampered database. The checkpoint is unchanged,
    # because the signer signed the original tree.

    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    exporter = Exporter(repository=repository, abb_path=stack.abb, store=artifact_store(stack))
    tampered = stack.work / f"{run_id}-tampered.abbreceipt"
    try:
        exporter.export(run_id, tampered)
    except Exception as exc:
        print(f"export refused the tampered run: {exc}")
        return 0
    del receipt
    return verify_step(stack, tampered, expect="INVALID", title="3. verify the tampered receipt")


def deleted_run_step(stack: Stack, run_id: str) -> int:
    """Delete the whole run and let `abb verify-global` find the gap."""
    say(
        "4. delete a whole run",
        "One tree per run cannot show that a run is gone: if the run and its\n"
        "checkpoints vanish, nothing left refers to them. The global log is what\n"
        "makes the gap visible (D-10).",
    )
    roots = stack.work / "global-roots.json"
    export_global_file(stack, roots)

    with psycopg.connect(stack.dsn, autocommit=True) as conn:
        conn.execute("DELETE FROM global_log WHERE run_id = %s", (run_id,))
        conn.execute("DELETE FROM checkpoints WHERE stream_id = %s", (run_id,))
        # An attacker with the database removes everything that refers to the
        # run, not just the events.
        conn.execute(
            "DELETE FROM event_idempotency WHERE run_id = %s",
            (run_id,),
        )
        conn.execute("DELETE FROM workflow_outbox WHERE run_id = %s", (run_id,))
        conn.execute("DELETE FROM manifest_entries WHERE run_id = %s", (run_id,))
        conn.execute("ALTER TABLE events DISABLE TRIGGER events_no_delete")
        conn.execute("DELETE FROM events WHERE run_id = %s", (run_id,))
        conn.execute("ALTER TABLE events ENABLE TRIGGER events_no_delete")
    print(f"deleted run {run_id} and its global-log row")

    after = stack.work / "global-roots-after.json"
    export_global_file(stack, after)
    done = subprocess.run(  # noqa: S603
        [stack.abb, "verify-global", "--roots", str(after), "--keys", str(key_manifest(stack))],
        capture_output=True,
        check=False,
    )
    out = done.stdout.decode("utf-8", "replace")
    say("4. verify-global", out.strip())
    if "MISSING_RUNS" in out or "GLOBAL_ROOT_MISMATCH" in out:
        print(f"{GREEN}the gap was detected{PLAIN}")
        return 0
    print(f"{RED}the deleted run was not detected{PLAIN}")
    return 1


def export_global_file(stack: Stack, path: Path) -> None:
    """Write the global log and its latest checkpoint, for `abb verify-global`."""
    import base64

    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    records = repository.global_records()
    checkpoints = repository.checkpoints("global")
    document = {
        "records": [
            {"record_canonical_b64": base64.b64encode(record).decode("ascii")} for record in records
        ],
        "global_checkpoint": {
            "canonical_b64": base64.b64encode(checkpoints[-1]["payload_bytes"]).decode("ascii"),
            "signature": checkpoints[-1]["signature"],
        },
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def people_dir(stack: Stack) -> Path:
    """Where the approver's and the mandate issuer's keys live.

    In real use these are on other people's devices. The demo keeps them in a
    separate directory that the API and the signer are never pointed at, which
    is the part that matters: the control plane never holds them.
    """
    return stack.people if stack.people is not None else stack.work / "keys" / "people"


def key_id_of(pub_file: Path) -> str:
    public = pathsafe.read_text(pub_file).strip()
    return f"ed25519:{hashlib.sha256(bytes.fromhex(public)).hexdigest()}"


def seed_policy(dsn: str, policy: Policy) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            """INSERT INTO policy_versions (policy_id, version, body_json, body_digest,
                                            created_at_ms)
               VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING""",
            (
                policy.policy_id,
                policy.version,
                json.dumps(policy.body),
                bytes.fromhex(policy.body_digest),
                int(time.time() * 1000),
            ),
        )


def sign_approval(
    stack: Stack,
    pending: dict[str, str],
    run_id: str,
    *,
    decision: str = "GRANTED",
    expires_in_ms: int = 600_000,
) -> dict[str, str]:
    """What a person does on their own device: `abb approve`.

    The summary text is passed along with its digest, so the CLI refuses to sign
    if what is shown does not hash to what was requested.
    """
    expires_at = int(time.time() * 1000) + expires_in_ms
    done = subprocess.run(  # noqa: S603 - fixed argv
        [
            stack.abb,
            "approve",
            "--key",
            str(people_dir(stack) / "approver.key"),
            "--run-id",
            run_id,
            "--action-id",
            pending["action_id"],
            "--approval-id",
            pending["approval_id"],
            "--decision",
            decision,
            "--expires-at",
            str(expires_at),
            "--summary",
            pending["summary"],
            "--summary-digest",
            pending["summary_digest"],
        ],
        capture_output=True,
        check=True,
    )
    return dict(
        line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
    )


def signed_mandate(stack: Stack, **changes: Any) -> SignedMandate:
    """A mandate signed by the issuer's key, then checked by the core."""
    now = int(time.time() * 1000)
    document: dict[str, Any] = {
        "mandate_id": f"mandate-{uuid.uuid4().hex[:8]}",
        "issuer_key_id": key_id_of(people_dir(stack) / "mandate_issuer.pub"),
        "subject": "replay",
        "allowed_hosts": ["portal.example", "*.portal.example"],
        "allowed_action_types": ["navigate", "form_fill", "form_submit"],
        "max_actions": 10,
        "not_before": now - 3_600_000,
        "not_after": now + 3_600_000,
    }
    document.update(changes)
    document = {k: v for k, v in document.items() if v is not None}
    path = stack.work / f"{document['mandate_id']}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    done = subprocess.run(  # noqa: S603 - fixed argv
        [
            stack.abb,
            "mandate",
            "sign",
            "--key",
            str(people_dir(stack) / "mandate_issuer.key"),
            "--file",
            str(path),
        ],
        capture_output=True,
        check=True,
    )
    fields = dict(
        line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
    )
    return SignedMandate.verified(
        document_b64=fields["document_b64"],
        signature=fields["signature"],
        keys_path=str(key_manifest(stack)),
        abb_path=stack.abb,
    )


def register_mandate(base_url: str, token: str, mandate: SignedMandate) -> str:
    import urllib.request

    request = urllib.request.Request(  # noqa: S310
        f"{base_url}/api/v1/mandates",
        data=json.dumps(
            {"document_b64": mandate.document_b64, "signature": mandate.signature}
        ).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
        return str(json.loads(response.read())["mandate_id"])


def run_with_approver(
    stack: Stack,
    base_url: str,
    tokens: dict[str, str],
    policy: Policy,
    scenario_name: str,
    *,
    approve: str | None = "GRANTED",
    mandate: SignedMandate | None = None,
    expires_in_ms: int = 600_000,
    execution_id: str = "replay-9",
    decide: Callable[[dict[str, str], str], dict[str, str] | None] | None = None,
) -> tuple[str, Gateway, Any]:
    """Drive a scenario through the real gateway, with a person approving.

    `approve` is `"GRANTED"`, `"DENIED"` or `None` (nobody answers, so the
    gated action waits). Returns the run id, the gateway and the adapter result.
    """
    mandate_id = register_mandate(base_url, tokens["operator"], mandate) if mandate else None
    run_id = create_run(base_url, tokens["operator"], policy, mandate_id=mandate_id)
    lease = LeaseStore(connections(stack.dsn)).acquire(run_id, "demo-worker-9")
    sink = HttpEventSink(
        base_url=base_url,
        run_id=run_id,
        token=tokens["adapter"],
        fencing_token=lease.fencing_token,
    )
    relay = HttpApprovalClient(base_url=base_url, run_id=run_id, token=tokens["adapter"])
    scenario = load_scenario(scenario_name)

    def approver(gateway: Gateway, action: Any) -> Any:
        pending = next(p for p in gateway.pending_approvals() if p["action_id"] == action.action_id)
        say(
            "approver",
            f"asked to decide:  {pending['summary']}",
        )
        if decide is not None:
            signed = decide(pending, run_id)
            if signed is None:  # nobody answered: the action stays blocked, nothing is dispatched
                return Decision(
                    outcome="REQUIRE_APPROVAL",
                    reason_codes=("APPROVAL_NOT_RECEIVED",),
                    policy_id=policy.policy_id,
                    policy_version=policy.version,
                    input_digest="",
                )
        else:
            signed = sign_approval(
                stack, pending, run_id, decision=approve or "GRANTED", expires_in_ms=expires_in_ms
            )
        return gateway.submit_approval(
            action,
            statement_b64=signed["statement_b64"],
            key_id=signed["key_id"],
            signature=signed["signature"],
        )

    adapter = ReplayAdapter(
        scenario,
        execution_id=execution_id,
        approver=approver if (approve or decide) else None,
    )
    repo = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    gateway = Gateway(
        sink=sink,
        policy=policy,
        provenance=adapter.provenance("STEP_GATED"),
        in_scope_actions=IN_SCOPE_ACTIONS,
        artifacts=ArtifactComponent(store=artifact_store(stack), repository=repo, run_id=run_id),
        mandate=mandate,
        approvals=relay,
        guard=DeterministicGuard(),
    )
    gateway.run_started(task=scenario["task"], requested_coverage="STEP_GATED")
    gateway.declare_coverage(
        requested="STEP_GATED",
        declared="STEP_GATED",
        reason="every in-scope action passes the local gateway before dispatch",
    )
    result = adapter.run(gateway)
    run_monitor(gateway)
    gateway.run_finished(final_state="FINALIZING", outcome=result.status)
    repo.set_state(run_id, "FINALIZING")
    return run_id, gateway, result


def mutate_and_verify(
    stack: Stack, receipt: Path, name: str, change: Any, *, expect: str, title: str
) -> int:
    """Edit a copy of the receipt, then ask the offline verifier what it thinks."""
    with zipfile.ZipFile(receipt) as archive:
        members = {n: archive.read(n) for n in archive.namelist()}
    document = json.loads(members["receipt.json"].decode("utf-8"))
    change(document)
    members["receipt.json"] = json.dumps(document, separators=(",", ":")).encode()
    edited = stack.work / f"{name}.abbreceipt"
    with zipfile.ZipFile(edited, "w", zipfile.ZIP_STORED) as archive:
        for member, data in members.items():
            archive.writestr(member, data)
    return verify_step(stack, edited, expect=expect, title=title)


def signed_approval_step(
    stack: Stack, base_url: str, tokens: dict[str, str], policy: Policy
) -> int:
    """Beat 1, now honest: a human key signs, the gate opens, the verifier re-checks."""
    say(
        "5. a signed approval",
        "Changing a vendor's bank details is gated by policy. The gateway records\n"
        "the request and does not dispatch. A person then signs a decision with\n"
        "`abb approve`, on a key in a directory the API and the signer never see.\n"
        "The API relays the signature; it cannot make one. A valid signature shows\n"
        "that the key signed. It does not show which person held it.",
    )
    run_id, _, result = run_with_approver(stack, base_url, tokens, policy, "bank_change_approval")
    for step in result.steps:
        print(f"  {step.action_id} {step.action_type:12} -> {step.status}")
    receipt = finalize_and_export(stack, run_id, policy)
    code = verify_step(stack, receipt, expect="VALID", title="5a. verify: signed approval")

    def forge(document: dict[str, Any]) -> None:
        record = document["approvals"][0]
        first = "0" if record["signature"][0] != "0" else "1"
        record["signature"] = first + record["signature"][1:]

    say(
        "5b. forge the approval",
        "Flip one character of the approver's signature inside the receipt. Without\n"
        "the approver's key nobody can make it right again.",
    )
    code |= mutate_and_verify(
        stack, receipt, "forged-approval", forge, expect="INVALID", title="5b. verify: forged"
    )
    return code


def mandate_step(stack: Stack, base_url: str, tokens: dict[str, str], policy: Policy) -> int:
    """A signed mandate the gateway enforces and the verifier checks again."""
    say(
        "6. a signed mandate",
        "The issuer signs what the agent may do in this run: here, navigation only.\n"
        "The gateway blocks the form submission as MANDATE_VIOLATION before dispatch.\n"
        "The verifier re-derives the same rules from the events, so a gateway that\n"
        "skipped the check would be caught rather than trusted.",
    )
    mandate = signed_mandate(stack, allowed_action_types=["navigate"], max_actions=3)
    run_id, _, result = run_with_approver(
        stack, base_url, tokens, policy, "bank_change_approval", mandate=mandate
    )
    for step in result.steps:
        reasons = ", ".join(
            r for e in result.errors if e["action_id"] == step.action_id for r in e["reason_codes"]
        )
        print(f"  {step.action_id} {step.action_type:12} -> {step.status} {reasons}")
    receipt = finalize_and_export(stack, run_id, policy)
    return verify_step(stack, receipt, expect="VALID", title="6. verify: inside the mandate")


def commitment_step(stack: Stack, base_url: str, tokens: dict[str, str]) -> int:
    """A typed value is committed to, not stored; shredding it leaves the ledger valid."""
    say(
        "7. a value that must not sit in the ledger",
        "A fake test card number is typed into a form. The ingestion service replaces\n"
        "it with a salted commitment before the event is canonicalized, so it is\n"
        "never in the hashed or signed bytes. The clear value and its salt live in a\n"
        "separate store. Deleting them (crypto-shredding) cannot touch the ledger.",
    )
    redacting = Policy.load("redacting", 1)
    seed_policy(stack.dsn, redacting)
    run_id, _, _ = run_with_approver(stack, base_url, tokens, redacting, "card_entry", approve=None)
    receipt = finalize_and_export(stack, run_id, redacting)
    with zipfile.ZipFile(receipt) as archive:
        blob = b"".join(archive.read(n) for n in archive.namelist())
    clear = b"4111111111111111" in blob
    print(f"  the card number appears in the receipt: {clear}")
    code = 0 if not clear else 1
    code |= verify_step(stack, receipt, expect="VALID", title="7a. verify: value hidden")

    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    held = repository.disclosures_for(run_id)
    repository.shred_field(held[0]["event_id"], held[0]["field"])
    again = finalize_export_again(stack, run_id, disclose=["typed_value"])
    say("7b. after crypto-shredding", "salt and value deleted; export again, asking to disclose it")
    code |= verify_step(stack, again, expect="VALID", title="7b. verify: value gone, ledger valid")
    return code


def finalize_export_again(stack: Stack, run_id: str, disclose: list[str] | None = None) -> Path:
    """Export a second receipt for a run that is already exported."""
    repository = Repository(connect=connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb))
    exporter = Exporter(repository=repository, abb_path=stack.abb, store=artifact_store(stack))
    out = stack.work / f"{run_id}-again.abbreceipt"
    return exporter.export(run_id, out, disclose=disclose).path


if __name__ == "__main__":
    raise SystemExit(main())
