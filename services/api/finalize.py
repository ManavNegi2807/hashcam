"""Finalization: freeze the run, get it signed, put it in the global log.

`DESIGN.md` 7 steps 7 and 8, `PROTOCOL.md` 8.5 and 11, `R-GLB-01`, `R-GLB-03`.
The order matters and is the point of this module:

1. freeze the committed prefix and read the exact canonical bytes;
2. ask the **signer** for a checkpoint. It recomputes the root itself; this
   service never sends one and never holds a key;
3. store the checkpoint;
4. build the run-root record from that checkpoint, append it to the global log,
   and ask the signer for a global checkpoint;
5. only then may the run become `EXPORTED` (`R-GLB-03`).

A run that stops between 2 and 4 stays `CHECKPOINTED`, which is a resumable
state, not a lost one (`ERROR_HANDLING.md` 5).
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any

from .errors import AbbError
from .repository import Repository, now_ms
from .signer_client import SignedCheckpoint, SignerClient

GLOBAL_STREAM = "global"


@dataclass(frozen=True)
class FinalizeResult:
    """What finalization produced."""

    run_checkpoint: SignedCheckpoint
    global_checkpoint: SignedCheckpoint
    global_position: int
    event_count: int


class Finalizer:
    """Finalizes one run at a time."""

    def __init__(self, *, repository: Repository, signer: SignerClient, abb_path: str) -> None:
        self._repo = repository
        self._signer = signer
        self._abb = abb_path

    # ------------------------------------------------------------------ steps

    def finalize(self, run_id: str) -> FinalizeResult:
        events = self._repo.canonical_events(run_id)
        if not events:
            raise AbbError("VALIDATION_FAILED", "a run with no events cannot be finalized")

        # 1 and 2. The signer gets the bytes, never a root.
        previous = self._repo.latest_checkpoint(run_id)
        from_sequence = 0 if previous is None else int(previous["payload"]["tree_size"])
        new_events = events[from_sequence:]
        done_manifest = 0 if previous is None else int(previous["payload"]["manifest_size"])
        new_manifest = self._repo.manifest_entry_bytes(run_id)[done_manifest:]
        if new_events or new_manifest:
            run_checkpoint = self._signer.sign(
                stream_id=run_id,
                events=new_events,
                prev_checkpoint=previous,
                manifest_entries=new_manifest,
            )
            self._repo.store_checkpoint(stream_id=run_id, checkpoint=run_checkpoint)
        else:
            # Already checkpointed at this size: re-deliver what we have rather
            # than asking for a second signature over the same tree.
            run_checkpoint = self._signer.sign(
                stream_id=run_id, events=[], prev_checkpoint=previous
            )

        # 3. State: the run is checkpointed even if the global append fails.
        self._repo.set_state(run_id, "CHECKPOINTED")

        # 4. The run root, canonicalized by the Rust core, then the global log.
        record = self._run_root_record(run_id, run_checkpoint)
        position = self._repo.append_global_log(run_id=run_id, record=record)
        global_records = self._repo.global_records()
        global_previous = self._repo.latest_checkpoint(GLOBAL_STREAM)
        global_from = 0 if global_previous is None else int(global_previous["payload"]["tree_size"])
        global_checkpoint = self._signer.sign(
            stream_id=GLOBAL_STREAM,
            events=global_records[global_from:],
            prev_checkpoint=global_previous,
        )
        self._repo.store_checkpoint(stream_id=GLOBAL_STREAM, checkpoint=global_checkpoint)

        return FinalizeResult(
            run_checkpoint=run_checkpoint,
            global_checkpoint=global_checkpoint,
            global_position=position,
            event_count=len(events),
        )

    # -------------------------------------------------------------- internals

    def _run_root_record(self, run_id: str, checkpoint: SignedCheckpoint) -> bytes:
        """The six-field record of `PROTOCOL.md` 8.5, canonicalized by `abb`."""
        record = {
            "run_id": run_id,
            "checkpoint_hash": checkpoint.checkpoint_hash,
            "tree_size": checkpoint.tree_size,
            "root_hash": checkpoint.root_hash,
            "manifest_head": str(checkpoint.payload["manifest_head"]),
            "finalized_at": now_ms(),
        }
        return self._canonicalize(record)

    def _canonicalize(self, value: dict[str, Any]) -> bytes:
        """Canonical bytes from the one implementation that owns them."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "canon", "--stdin", "--text"],
                input=json.dumps(value).encode("utf-8"),
                capture_output=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "canonicalizer unavailable") from exc
        if done.returncode != 0:
            raise AbbError(
                "INTERNAL", done.stderr.decode("utf-8", "replace")[:200] or "canon failed"
            )
        # `--text` prints the canonical JSON and a newline; the newline is not
        # part of the bytes that get hashed.
        return done.stdout.decode("utf-8").rstrip("\r\n").encode("utf-8")
