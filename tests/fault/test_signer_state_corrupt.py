"""The signer fails closed on corrupt state (`R-SIG-10`, `PROTOCOL.md` 11.3).

`TESTING.md` section 7 asks for a scripted fault per recovery row. This is the
signer one: edit its state log the way a host administrator could, start it
again, and check that it refuses to sign rather than carrying on from a state it
cannot vouch for. It must also **not** reset itself.

The test drives the real binary, because "fails closed" is a property of the
process, not of a function.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from tests.contract.test_signer_api import (  # noqa: E402
    RUN,
    RunningSigner,
    binary,
    event,
)


@pytest.fixture
def signer(tmp_path: Path) -> RunningSigner:
    abb = binary("abb", "ABB_BIN")
    signer_bin = binary("abb-signer", "ABB_SIGNER_BIN")
    if abb is None or signer_bin is None:
        pytest.skip("needs the abb and abb-signer binaries; see tests/contract/test_signer_api.py")
    return RunningSigner(tmp_path, abb, signer_bin)


def start_and_capture(signer: RunningSigner) -> tuple[int, str]:
    """Start the signer, expecting it to exit. Returns (exit code, stderr)."""
    env = dict(os.environ)
    env.update(
        {
            "ABB_SIGNER_STATE_DIR": str(signer.state_dir),
            "ABB_SIGNER_KEY": str(signer.signer_key),
            "ABB_SIGNER_INGESTION_PUBKEY": signer.ingestion_public_hex,
            "ABB_SIGNER_ADDR": f"127.0.0.1:{signer.port}",
        }
    )
    process = subprocess.Popen(  # noqa: S603
        [signer.signer_bin], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    try:
        _, err = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:  # pragma: no cover - it should exit
        process.kill()
        _, err = process.communicate()
        raise AssertionError("the signer kept running on a corrupt state log") from None
    return process.returncode, err.decode("utf-8", "replace")


def port_is_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return True
    except OSError:
        return False


def test_an_edited_state_log_stops_the_signer(signer: RunningSigner) -> None:
    signer.start()
    client = signer.client()
    first = client.sign(stream_id=RUN, events=[event(RUN, 0, "RUN_STARTED", signer.abb)])
    signer.stop()

    log = signer.state_dir / "state.log"
    original = log.read_text(encoding="utf-8")
    # Pretend the run was longer than it was.
    log.write_text(original.replace('"tree_size":1', '"tree_size":2', 1), encoding="utf-8")
    assert log.read_text(encoding="utf-8") != original, "the test must change the log"

    code, err = start_and_capture(signer)
    assert code != 0, "a corrupt state log must stop the signer"
    assert "state log is corrupt" in err
    assert "recovery ceremony" in err
    assert not port_is_open(signer.port), "it must not serve requests"

    # It did not rewrite or truncate the log: an operator can still inspect it.
    assert log.read_text(encoding="utf-8").count("\n") == 1
    assert first.checkpoint_hash in log.read_text(encoding="utf-8")


def test_a_removed_state_log_line_stops_the_signer(signer: RunningSigner) -> None:
    """Deleting history is as detectable as editing it: the chain breaks."""
    signer.start()
    client = signer.client()
    first = client.sign(stream_id=RUN, events=[event(RUN, 0, "RUN_STARTED", signer.abb)])
    client.sign(
        stream_id=RUN,
        events=[event(RUN, 1, "ACTION_REQUESTED", signer.abb)],
        prev_checkpoint={"payload": first.payload, "signature": first.signature},
    )
    signer.stop()

    log = signer.state_dir / "state.log"
    lines = log.read_text(encoding="utf-8").splitlines(keepends=True)
    assert len(lines) == 2
    # Drop the first entry, leaving the second one pointing at nothing.
    log.write_text(lines[1], encoding="utf-8")

    code, err = start_and_capture(signer)
    assert code != 0
    assert "state log is corrupt" in err
    assert not port_is_open(signer.port)


def test_a_rolled_back_state_log_stops_the_signer(signer: RunningSigner) -> None:
    """An older copy of the log is not silently accepted.

    Rolling the signer back to an earlier checkpoint is how a fork would be
    prepared, so the signer must refuse any log whose chain it cannot verify.
    """
    signer.start()
    client = signer.client()
    first = client.sign(stream_id=RUN, events=[event(RUN, 0, "RUN_STARTED", signer.abb)])
    log = signer.state_dir / "state.log"
    snapshot = log.read_text(encoding="utf-8")

    client.sign(
        stream_id=RUN,
        events=[event(RUN, 1, "ACTION_REQUESTED", signer.abb)],
        prev_checkpoint={"payload": first.payload, "signature": first.signature},
    )
    signer.stop()

    # Restore the older log, then corrupt one byte of it so the chain is broken
    # in a way a restore alone would not be. A plain older-but-valid log is a
    # rollback the signer cannot detect on its own; that is what the witnesses
    # and anchors are for, and it is stated as a limit in SECURITY.md 16.
    log.write_text(snapshot.replace('"tree_size":1', '"tree_size":7', 1), encoding="utf-8")
    code, err = start_and_capture(signer)
    assert code != 0
    assert "state log is corrupt" in err


def test_a_valid_log_still_starts(signer: RunningSigner) -> None:
    """The negative control: the fault tests above must not pass vacuously."""
    signer.start()
    signer.client().sign(stream_id=RUN, events=[event(RUN, 0, "RUN_STARTED", signer.abb)])
    signer.stop()

    # Untouched log: the signer starts and serves.
    signer.start()
    time.sleep(0.1)
    assert port_is_open(signer.port)
    assert signer.client().health()["status"] == "ok"
    signer.stop()
