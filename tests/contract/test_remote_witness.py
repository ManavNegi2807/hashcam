"""A witness on a second computer, exercised end to end with the real programs.

The two sides run as separate processes in separate folders: the witness folder never sees your
database, your signer key or your work folder, only the files `host` writes to `request/`. This
proves the exchange works and that the witness's private key stays on its side. It does NOT prove
independence: both folders are on one machine here, and the failure-domain label is a claim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ABB = os.environ.get("ABB_BIN")
DSN = os.environ.get("ABB_TEST_DSN")
pytestmark = pytest.mark.skipif(
    not (ABB and DSN and os.environ.get("ABB_SIGNER_BIN")),
    reason="needs ABB_BIN, ABB_SIGNER_BIN and ABB_TEST_DSN",
)

TOOL = str(REPO / "tools" / "remote_witness.py")
ENV = {**os.environ, "PYTHONPATH": str(REPO), "PYTHONIOENCODING": "utf-8"}


def run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, TOOL, *args],
        cwd=cwd,
        env=ENV,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_a_witness_on_another_folder_co_signs_and_the_receipt_carries_it(tmp_path: Path) -> None:
    session = tmp_path / "session"
    friend = tmp_path / "friend"  # stands in for the other computer
    friend.mkdir()

    started = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            sys.executable,
            TOOL,
            "host",
            "--dsn",
            str(DSN),
            "--work",
            str(session),
            "--wait-minutes",
            "4",
        ],
        env=ENV,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
    )
    try:
        request = session / "request"
        deadline = time.time() + 180
        while not (request / "signer_keys.json").exists():
            assert time.time() < deadline, "the host never wrote its request"
            time.sleep(1)
        time.sleep(1)

        # What would be sent over: only these three files, copied into the other folder.
        sent = friend / "request"
        sent.mkdir()
        for name in ("checkpoint.json", "records.txt", "signer_keys.json"):
            (sent / name).write_bytes((request / name).read_bytes())
        everything_sent = "".join(p.read_text(encoding="utf-8") for p in sent.iterdir())
        assert "signer.key" not in everything_sent  # only the public key travels

        init = run("witness-init", "--domain", "host:friend-laptop/admin:friend", cwd=friend)
        assert init.returncode == 0, init.stderr
        assert "never leaves this computer" in init.stdout
        signed = run("witness-sign", cwd=friend)
        assert signed.returncode == 0, signed.stdout + signed.stderr

        # The reply holds no secret: it has the public key and a signature, never the key file.
        reply = json.loads((friend / "reply" / "reply.json").read_text(encoding="utf-8"))
        private = (friend / "witness-data" / "witness.key").read_bytes()
        assert private.hex() not in json.dumps(reply)
        assert reply["domain"] == "host:friend-laptop/admin:friend"

        # The reply travels back; the host finishes and verifies.
        (session / "reply").mkdir(exist_ok=True)
        (session / "reply" / "reply.json").write_text(json.dumps(reply), encoding="utf-8")
        output, _ = started.communicate(timeout=180)
    finally:
        if started.poll() is None:
            started.kill()

    assert "witnessed receipt:" in output, output[-1500:]
    # The verifier saw a witness. What it concludes about independence is its own call; here both
    # folders are on one machine, so the test only requires that the witness was counted at all.
    assert "witness_quorum" in output
    assert (session / "witnessed.abbreceipt").exists()
    manifest = json.loads((session / "key_manifest.json").read_text(encoding="utf-8"))
    witnesses = [k for k in manifest["keys"] if k["role"] == "witness"]
    assert any(k["failure_domain"] == "host:friend-laptop/admin:friend" for k in witnesses)


def test_a_witness_refuses_to_go_backwards(tmp_path: Path) -> None:
    """A witness keeps its own anti-rollback state: asked to sign an OLDER checkpoint than it has
    signed before, it refuses. That refusal is what a rollback attack runs into."""
    session_a, session_b = tmp_path / "a", tmp_path / "b"
    friend = tmp_path / "friend"
    friend.mkdir()

    def make_request(session: Path) -> subprocess.Popen[str]:
        return subprocess.Popen(  # noqa: S603 - fixed argv
            [
                sys.executable,
                TOOL,
                "host",
                "--dsn",
                str(DSN),
                "--work",
                str(session),
                "--wait-minutes",
                "1",
            ],
            env=ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
        )

    # Two independent hosts produce two unrelated histories. The witness has signed the first;
    # a second, unrelated history cannot be a continuation of it, so it must be refused.
    first = make_request(session_a)
    try:
        deadline = time.time() + 180
        while not (session_a / "request" / "signer_keys.json").exists():
            assert time.time() < deadline
            time.sleep(1)
        time.sleep(1)
        for name in ("checkpoint.json", "records.txt", "signer_keys.json"):
            (friend / "request").mkdir(exist_ok=True)
            (friend / "request" / name).write_bytes((session_a / "request" / name).read_bytes())
        assert run("witness-init", "--domain", "host:f/admin:f", cwd=friend).returncode == 0
        assert run("witness-sign", cwd=friend).returncode == 0
    finally:
        first.kill()

    second = make_request(session_b)
    try:
        deadline = time.time() + 180
        while not (session_b / "request" / "signer_keys.json").exists():
            assert time.time() < deadline
            time.sleep(1)
        time.sleep(1)
        for name in ("checkpoint.json", "records.txt", "signer_keys.json"):
            (friend / "request" / name).write_bytes((session_b / "request" / name).read_bytes())
        refused = run("witness-sign", cwd=friend)
    finally:
        second.kill()
    assert refused.returncode == 3, refused.stdout + refused.stderr
    assert "REFUSED" in refused.stdout
