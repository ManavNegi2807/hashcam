"""A witness on a second computer: a person you trust co-signs your run's checkpoint.

Why: a signer alone cannot show it was not rolled back. A witness keeps its own anti-rollback
state and rebuilds the tree before signing. It only counts as independent if its key lives on
another computer under another person's control. This tool makes that a short exchange of files.

Three commands. The first runs on YOUR computer, the other two on your WITNESS's computer
(they only need the `abb` program and Python; no database, no TinyFish key).

  you      python tools/remote_witness.py host --dsn postgresql://... --work session
  witness  python tools/remote_witness.py witness-init --domain host:NAME-laptop/admin:NAME

`host` makes a small run, writes the files the witness needs to `session/request/`, then waits for
`session/reply/reply.json`. Send `request/` to the witness (chat, USB) and put their `reply/` back.
Nothing secret is exchanged: the witness's private key never leaves their computer, and the files
you send hold only a public checkpoint, public run-root records and your public signer key.

What it does NOT prove: the failure-domain label (`host:...`) is a claim made in the key manifest
you publish; the verifier trusts the manifest, and the manifest is yours. The witness's key being
on another computer is what makes the signature meaningful, and only the two of you know that is
true. A single witness is not a quorum either: read what the verifier says.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402


def find_abb() -> str:
    """The `abb` program: ABB_BIN, a build in core/target, or one on PATH."""
    for candidate in (
        os.environ.get("ABB_BIN", ""),
        str(REPO / "core" / "target" / "release" / "abb.exe"),
        str(REPO / "core" / "target" / "release" / "abb"),
        str(REPO / "core" / "target" / "debug" / "abb.exe"),
        str(REPO / "core" / "target" / "debug" / "abb"),
        shutil.which("abb") or "",
    ):
        if candidate and Path(candidate).exists():
            return candidate
    raise SystemExit(
        "cannot find the abb program. Build it once: cargo build --release --manifest-path "
        "core/Cargo.toml -p abb-cli   (or set ABB_BIN)"
    )


def key_id_of(public_hex: str) -> str:
    return "ed25519:" + hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()


def pairs(text: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


# --------------------------------------------------------------------- the witness's computer


def witness_init(args: argparse.Namespace) -> int:
    data = Path(args.data)
    if (data / "witness.key").exists():
        print("a witness key already exists here; it is kept, never replaced.")
    else:
        data.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603 - fixed argv
            [find_abb(), "keygen", "--out", str(data), "--role", "witness"],
            check=True,
            capture_output=True,
        )
    public = pathsafe.read_text(data / "witness.pub").strip()
    (data / "domain.txt").write_text(args.domain, encoding="utf-8")
    print(f"witness key ready in {data}")
    print(f"  public key id : {key_id_of(public)}")
    print(f"  failure domain: {args.domain}")
    print("Keep witness.key private: it never leaves this computer. Back it up if you can.")
    return 0


def witness_sign(args: argparse.Namespace) -> int:
    data, request, reply = Path(args.data), Path(args.request), Path(args.reply)
    key, pub = data / "witness.key", data / "witness.pub"
    if not key.exists():
        print("no witness key here. Run witness-init first.")
        return 2
    domain = (
        args.domain or (data / "domain.txt").read_text(encoding="utf-8").strip()
        if (data / "domain.txt").exists() or args.domain
        else ""
    )
    if not domain:
        print("no failure domain. Pass --domain host:NAME-laptop/admin:NAME")
        return 2
    done = subprocess.run(  # noqa: S603 - fixed argv
        [
            find_abb(),
            "witness",
            "sign",
            "--key",
            str(key),
            "--state",
            str(data / "state.json"),
            "--keys",
            str(request / "signer_keys.json"),
            "--domain",
            domain,
            "--checkpoint",
            str(request / "checkpoint.json"),
            "--records",
            str(request / "records.txt"),
        ],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        # The witness refuses to sign something that does not hold together, or that goes
        # backwards from what it signed before. That refusal is the point of a witness.
        print("the witness REFUSED to sign:", done.stderr.decode("utf-8", "replace").strip())
        return 3
    fields = pairs(done.stdout.decode("utf-8", "replace"))
    reply.mkdir(parents=True, exist_ok=True)
    public = pathsafe.read_text(pub).strip()
    (reply / "reply.json").write_text(
        json.dumps(
            {
                "statement_b64": fields["statement_b64"],
                "signature": fields["signature"],
                "tree_size": int(fields["tree_size"]),
                "domain": domain,
                "witness_public_key_hex": public,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"signed the checkpoint of size {fields['tree_size']} as {domain}")
    print(f"send {reply / 'reply.json'} back. It holds no secret.")
    return 0


# --------------------------------------------------------------------------- your computer


def host(args: argparse.Namespace) -> int:
    from adapters.replay.adapter import load_scenario  # noqa: F401 - imported for demo parity
    from policy.engine import Policy
    from services.api.canonical import Canonicalizer
    from services.api.export import Exporter
    from services.api.repository import Repository
    from tools import demo

    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")
    work = Path(args.work).resolve()
    request, reply = work / "request", work / "reply"
    request.mkdir(parents=True, exist_ok=True)
    reply.mkdir(parents=True, exist_ok=True)
    (reply / "reply.json").unlink(missing_ok=True)

    abb = demo.binary("abb", "ABB_BIN")
    signer_bin = demo.binary("abb-signer", "ABB_SIGNER_BIN")
    migration = pathsafe.read_migrations(REPO / "deploy" / "migrations")
    policy = Policy.load("default", 1)
    dsn = demo.prepare_database(args.dsn, migration)
    tokens = demo.seed(dsn, policy)
    stack = demo.Stack(
        work=Path(tempfile.mkdtemp(prefix="abb-rw-")),
        dsn=dsn,
        abb=abb,
        signer_bin=signer_bin,
        signer_port=demo.free_port(),
        api_port=demo.free_port(),
    )
    try:
        demo.start_stack(stack)
        base_url = f"http://127.0.0.1:{stack.api_port}"
        run_id = demo.create_run(base_url, tokens["operator"], policy)
        print(demo.run_scenario(stack, base_url, tokens["adapter"], policy, run_id))
        receipt = demo.finalize_and_export(stack, run_id, policy)
        checkpoint, records = demo.global_checkpoint_files(stack, "remote")
        shutil.copyfile(checkpoint, request / "checkpoint.json")
        shutil.copyfile(records, request / "records.txt")
        # The witness needs the signer's PUBLIC key to check the checkpoint, nothing else.
        signer_public = pathsafe.read_text(stack.work / "keys" / "signer.pub").strip()
        (request / "signer_keys.json").write_text(
            json.dumps(
                {
                    "note": "the signer's public key, from the host",
                    "keys": [
                        {
                            "key_id": key_id_of(signer_public),
                            "public_key_hex": signer_public,
                            "role": "signer",
                            "failure_domain": demo.SIGNER_DOMAIN,
                            "valid_from": 0,
                            "status": "active",
                        }
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nRequest ready in {request}")
        print("Send that folder to your witness. They run:")
        print(
            "  python tools/remote_witness.py witness-sign --data witness-data "
            "--request request --reply reply"
        )
        print(
            f"Then put their reply.json at {reply / 'reply.json'}. Waiting up to "
            f"{args.wait_minutes} minutes...",
            flush=True,
        )

        deadline = time.monotonic() + args.wait_minutes * 60
        while not (reply / "reply.json").exists():
            if time.monotonic() > deadline:
                print("no reply arrived in time; nothing was changed.")
                return 4
            time.sleep(2)
        answer: dict[str, Any] = json.loads((reply / "reply.json").read_text(encoding="utf-8"))
        public = str(answer["witness_public_key_hex"])
        # The witness's key joins the published manifest, with the domain the witness claimed.
        manifest = json.loads(demo.key_manifest(stack).read_text(encoding="utf-8"))
        manifest["keys"].append(
            {
                "key_id": key_id_of(public),
                "public_key_hex": public,
                "role": "witness",
                "failure_domain": str(answer["domain"]),
                "valid_from": 0,
                "status": "active",
            }
        )
        final_manifest = work / "key_manifest.json"
        final_manifest.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        out = work / "witnessed.abbreceipt"
        repository = Repository(
            connect=demo.connections(stack.dsn), canonicalizer=Canonicalizer(stack.abb)
        )
        Exporter(
            repository=repository, abb_path=stack.abb, store=demo.artifact_store(stack)
        ).export(
            run_id,
            out,
            witnesses=[
                {"statement_b64": answer["statement_b64"], "signature": answer["signature"]}
            ],
            anchors=[],
        )
        shutil.copyfile(receipt, work / "plain.abbreceipt")
        shown = subprocess.run(  # noqa: S603 - fixed argv
            [abb, "verify", str(out), "--keys", str(final_manifest), "--profile", "LOCAL_ONLY"],
            capture_output=True,
            check=False,
        )
        print(shown.stdout.decode("utf-8", "replace"))
        print(f"witnessed receipt: {out}")
        print(f"key manifest     : {final_manifest}")
        return 0
    finally:
        stack.stop()
        shutil.rmtree(stack.work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)
    h = sub.add_parser("host", help="your computer: make a run and ask a witness to co-sign it")
    h.add_argument("--dsn", default=os.environ.get("ABB_TEST_DSN", ""))
    h.add_argument("--work", default="session")
    h.add_argument("--wait-minutes", type=int, default=30)
    i = sub.add_parser("witness-init", help="the witness's computer: make a witness key")
    i.add_argument("--data", default="witness-data")
    i.add_argument("--domain", required=True, help="e.g. host:NAME-laptop/admin:NAME")
    s = sub.add_parser("witness-sign", help="the witness's computer: co-sign a request")
    s.add_argument("--data", default="witness-data")
    s.add_argument("--request", default="request")
    s.add_argument("--reply", default="reply")
    s.add_argument("--domain", default="")
    args = parser.parse_args()
    return {"host": host, "witness-init": witness_init, "witness-sign": witness_sign}[args.command](
        args
    )


if __name__ == "__main__":
    raise SystemExit(main())
