"""The signer over its real HTTP API, driven by the real client.

The Rust tests in `signer/tests/sign.rs` cover the validation rules. This file
covers the thing they cannot: the wire. It starts the actual `abb-signer`
binary, talks to it with `services/api/signer_client.py`, and checks that a
returned checkpoint verifies under the signer's public key.

Covers `R-SIG-01`, `R-SIG-02`, `R-SIG-03`, `R-SIG-05`, `R-SIG-09`,
`DATABASE_AND_API_CONTRACTS.md` B4, and decision `D-20`.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from services.api.errors import AbbError  # noqa: E402
from services.api.signer_client import SignerClient  # noqa: E402

RUN = "11111111-1111-4111-8111-111111111111"


def binary(name: str, env_var: str) -> str | None:
    from_env = os.environ.get(env_var)
    if from_env and Path(from_env).is_file():
        return from_env
    found = shutil.which(name)
    if found:
        return found
    for candidate in (
        REPO / "core" / "target" / "debug" / f"{name}.exe",
        REPO / "core" / "target" / "debug" / name,
    ):
        if candidate.is_file():
            return str(candidate)
    # The short target directory Windows needs for long paths.
    target = os.environ.get("CARGO_TARGET_DIR")
    if target:
        for candidate in (
            Path(target) / "debug" / f"{name}.exe",
            Path(target) / "debug" / name,
        ):
            if candidate.is_file():
                return str(candidate)
    return None


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class RunningSigner:
    """A live signer process, its keys, and a client pointed at it."""

    def __init__(self, dir_path: Path, abb: str, signer_bin: str) -> None:
        self.dir = dir_path
        self.abb = abb
        self.signer_bin = signer_bin
        self.state_dir = dir_path / "state"
        self.port = free_port()
        self.process: subprocess.Popen[bytes] | None = None

        # Real key generation, through the CLI the operator would use.
        subprocess.run(  # noqa: S603
            [abb, "keygen", "--out", str(dir_path / "keys"), "--role", "signer"],
            capture_output=True,
            check=True,
        )
        subprocess.run(  # noqa: S603
            [abb, "keygen", "--out", str(dir_path / "keys"), "--role", "approver"],
            capture_output=True,
            check=True,
        )
        self.signer_key = dir_path / "keys" / "signer.key"
        self.signer_public_hex = (dir_path / "keys" / "signer.pub").read_text().strip()
        # The approver key doubles as the ingestion key for this test: what
        # matters is that it is a *different* key from the signer's.
        self.ingestion_key = dir_path / "keys" / "approver.key"
        self.ingestion_public_hex = (dir_path / "keys" / "approver.pub").read_text().strip()

    def start(self) -> None:
        env = dict(os.environ)
        env.update(
            {
                "ABB_SIGNER_STATE_DIR": str(self.state_dir),
                "ABB_SIGNER_KEY": str(self.signer_key),
                "ABB_SIGNER_INGESTION_PUBKEY": self.ingestion_public_hex,
                "ABB_SIGNER_ADDR": f"127.0.0.1:{self.port}",
                "ABB_SIGNER_RATE_LIMIT": "500",
            }
        )
        self.process = subprocess.Popen(  # noqa: S603
            [self.signer_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.wait_until_ready()

    def wait_until_ready(self, seconds: float = 20.0) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                out, err = self.process.communicate()
                raise AssertionError(
                    f"the signer exited early: {err.decode('utf-8', 'replace')}"
                    f"{out.decode('utf-8', 'replace')}"
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)
        raise AssertionError("the signer did not start listening")

    def stop(self) -> tuple[str, str]:
        if self.process is None:
            return "", ""
        self.process.terminate()
        try:
            out, err = self.process.communicate(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.process.kill()
            out, err = self.process.communicate()
        self.process = None
        return out.decode("utf-8", "replace"), err.decode("utf-8", "replace")

    def client(self, *, ingestion_key: Path | None = None) -> SignerClient:
        return SignerClient(
            base_url=f"http://127.0.0.1:{self.port}",
            abb_path=self.abb,
            ingestion_key_path=str(ingestion_key or self.ingestion_key),
        )


@pytest.fixture
def running_signer(tmp_path: Path) -> Iterator[RunningSigner]:
    abb = binary("abb", "ABB_BIN")
    signer_bin = binary("abb-signer", "ABB_SIGNER_BIN")
    if abb is None or signer_bin is None:
        pytest.skip(
            "needs the abb and abb-signer binaries: "
            "cargo build -p abb-cli -p abb-signer, then set ABB_BIN / ABB_SIGNER_BIN"
        )
    signer = RunningSigner(tmp_path, abb, signer_bin)
    signer.start()
    try:
        yield signer
    finally:
        signer.stop()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def event(run: str, sequence: int, event_type: str, abb: str) -> bytes:
    """A canonical event, canonicalized by the Rust core (never by Python)."""
    envelope = {
        "event_type": event_type,
        "source": "observed_by_local_gateway",
        "provenance": {
            "adapter_name": "replay",
            "adapter_version": "0.1.0",
            "execution_id": "replay-1",
            "mode": "REPLAY",
            "observed_coverage": "STEP_GATED",
        },
        "payload": {"n": sequence},
    }
    done = subprocess.run(  # noqa: S603
        [
            abb,
            "event",
            "canon",
            "--stdin",
            "--run-id",
            run,
            "--event-id",
            f"00000000-0000-4000-8000-{sequence + 1:012x}",
            "--sequence",
            str(sequence),
            "--created-at",
            str(1_760_000_000_000 + sequence),
        ],
        input=json.dumps(envelope).encode(),
        capture_output=True,
        check=True,
    )
    fields = dict(line.split("=", 1) for line in done.stdout.decode().splitlines() if "=" in line)
    return bytes.fromhex(fields["canonical_hex"])


def first_batch(abb: str) -> list[bytes]:
    return [
        event(RUN, 0, "RUN_STARTED", abb),
        event(RUN, 1, "ACTION_REQUESTED", abb),
        event(RUN, 2, "ACTION_AUTHORIZED", abb),
    ]


# --------------------------------------------------------------------------- #
# tests
# --------------------------------------------------------------------------- #


def test_health_names_the_key_but_never_the_key_itself(running_signer: RunningSigner) -> None:
    health = running_signer.client().health()
    assert health["status"] == "ok"
    assert health["protocol_version"] == "abb/1"
    assert str(health["key_id"]).startswith("ed25519:")

    seed_hex = running_signer.signer_key.read_bytes().hex()
    assert seed_hex not in json.dumps(health)


def test_a_signed_checkpoint_verifies_under_the_signers_public_key(
    running_signer: RunningSigner,
) -> None:
    """R-SIG-03: the signer recomputes the root and signs it itself."""
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    client = running_signer.client()
    events = first_batch(running_signer.abb)
    checkpoint = client.sign(stream_id=RUN, events=events)

    assert checkpoint.tree_size == 3
    assert checkpoint.payload["stream_id"] == RUN
    assert checkpoint.payload["prev_checkpoint_hash"] == "0" * 64
    assert len(checkpoint.signature) == 128

    # The signature covers exactly the bytes the signer returned.
    public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(running_signer.signer_public_hex))
    public.verify(
        bytes.fromhex(checkpoint.signature),
        b"ABB1-CHECKPOINT\x00" + checkpoint.payload_bytes,
    )

    # And the state endpoint agrees with what we were handed.
    state = client.state(RUN)
    assert state is not None
    assert state["tree_size"] == 3
    assert state["checkpoint_hash"] == checkpoint.checkpoint_hash


def test_an_empty_batch_returns_the_identical_checkpoint(
    running_signer: RunningSigner,
) -> None:
    client = running_signer.client()
    first = client.sign(stream_id=RUN, events=first_batch(running_signer.abb))
    replay = client.sign(
        stream_id=RUN,
        events=[],
        prev_checkpoint={"payload": first.payload, "signature": first.signature},
    )
    assert replay.checkpoint_hash == first.checkpoint_hash
    assert replay.signature == first.signature
    assert replay.payload_bytes == first.payload_bytes


def test_a_wrong_expected_root_is_refused(running_signer: RunningSigner) -> None:
    client = running_signer.client()
    with pytest.raises(AbbError) as err:
        client.sign(
            stream_id=RUN,
            events=first_batch(running_signer.abb),
            expected_root="ab" * 32,
        )
    assert err.value.code == "SIGNER_REFUSED"
    assert "ROOT_MISMATCH" in err.value.detail
    # Nothing was signed, so there is still no state for the stream.
    assert client.state(RUN) is None


def test_an_unknown_stream_has_no_state(running_signer: RunningSigner) -> None:
    assert running_signer.client().state(str(uuid.uuid4())) is None


def test_a_request_signed_by_the_wrong_key_is_refused(
    running_signer: RunningSigner,
) -> None:
    """D-20: the attestation must be by the key the signer was configured with."""
    stranger = running_signer.client(ingestion_key=running_signer.signer_key)
    with pytest.raises(AbbError) as err:
        stranger.sign(stream_id=RUN, events=first_batch(running_signer.abb))
    # 401 from the signer: the service's own attestation did not verify.
    assert err.value.code == "INTERNAL"
    assert "UNAUTHORIZED" in err.value.detail
    assert running_signer.client().state(RUN) is None


def test_a_second_batch_extends_the_first(running_signer: RunningSigner) -> None:
    client = running_signer.client()
    first = client.sign(stream_id=RUN, events=first_batch(running_signer.abb))
    more = [
        event(RUN, 3, "ACTION_DISPATCHED", running_signer.abb),
        event(RUN, 4, "ACTION_SUCCEEDED", running_signer.abb),
    ]
    second = client.sign(
        stream_id=RUN,
        events=more,
        prev_checkpoint={"payload": first.payload, "signature": first.signature},
    )
    assert second.tree_size == 5
    assert second.payload["prev_checkpoint_hash"] == first.checkpoint_hash
    assert second.root_hash != first.root_hash


def test_a_signer_that_is_not_running_is_never_mistaken_for_a_signature() -> None:
    client = SignerClient(
        base_url=f"http://127.0.0.1:{free_port()}",
        abb_path="abb",
        ingestion_key_path=__file__,  # exists, so the failure is the connection
    )
    with pytest.raises(AbbError) as err:
        client.health()
    assert err.value.code == "DEPENDENCY_UNAVAILABLE"


def test_the_signer_process_never_prints_key_material(
    running_signer: RunningSigner,
) -> None:
    client = running_signer.client()
    client.sign(stream_id=RUN, events=first_batch(running_signer.abb))
    out, err = running_signer.stop()

    seed_hex = running_signer.signer_key.read_bytes().hex()
    for stream in (out, err):
        assert seed_hex not in stream
        assert "BEGIN" not in stream

    # The audit log is written, and it does not contain the key either.
    audit = (running_signer.state_dir / "audit.log").read_text(encoding="utf-8")
    assert '"result":"SIGNED"' in audit
    assert seed_hex not in audit


def test_the_state_log_is_durable_across_a_restart(running_signer: RunningSigner) -> None:
    """R-SIG-09: the state is on disk before the signature is returned."""
    client = running_signer.client()
    first = client.sign(stream_id=RUN, events=first_batch(running_signer.abb))
    running_signer.stop()

    running_signer.start()
    state = running_signer.client().state(RUN)
    assert state is not None
    assert state["checkpoint_hash"] == first.checkpoint_hash
    assert state["tree_size"] == 3


def test_the_configuration_has_nowhere_to_put_a_database_credential(
    running_signer: RunningSigner,
) -> None:
    """R-SIG-02: the signer has no general database credentials."""
    expected = {
        "ABB_SIGNER_STATE_DIR",
        "ABB_SIGNER_KEY",
        "ABB_SIGNER_INGESTION_PUBKEY",
        "ABB_SIGNER_ADDR",
        "ABB_SIGNER_RATE_LIMIT",
    }
    import re

    source = (REPO / "signer" / "src" / "main.rs").read_text(encoding="utf-8")
    # Only the names actually looked up, not the words of an error message.
    used = set(re.findall(r'(?:env_var|std::env::var)\("([A-Z_]+)"\)', source))
    assert used <= expected, f"the signer reads an unexpected variable: {used - expected}"
    for forbidden in ("ABB_DB_DSN", "POSTGRES", "DATABASE_URL"):
        assert forbidden not in source


def test_a_checkpoint_payload_has_the_nine_protocol_fields(
    running_signer: RunningSigner,
) -> None:
    checkpoint = running_signer.client().sign(stream_id=RUN, events=first_batch(running_signer.abb))
    assert set(checkpoint.payload) == {
        "protocol_version",
        "stream_id",
        "tree_size",
        "root_hash",
        "manifest_size",
        "manifest_head",
        "prev_checkpoint_hash",
        "key_id",
        "created_at",
    }
    assert checkpoint.payload["protocol_version"] == "abb/1"


def test_the_payload_bytes_are_what_the_signature_covers(
    running_signer: RunningSigner,
) -> None:
    """R-PRO-04: store the exact bytes, never a re-serialization."""
    checkpoint = running_signer.client().sign(stream_id=RUN, events=first_batch(running_signer.abb))
    # Python's own dump of the payload object is NOT the canonical form, which
    # is exactly why the signer returns the bytes.
    python_dump = json.dumps(checkpoint.payload, separators=(",", ":")).encode()
    canonical: Any = checkpoint.payload_bytes
    assert canonical != python_dump or sorted(checkpoint.payload) == list(checkpoint.payload)
    # The declared hash is the hash of the tagged canonical bytes.
    import hashlib

    digest = hashlib.sha256(b"ABB1-CHECKPOINT\x00" + checkpoint.payload_bytes).hexdigest()
    assert digest == checkpoint.checkpoint_hash
