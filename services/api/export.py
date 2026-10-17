"""Receipt export: gather the bundle, let the core build the receipt.

`PROTOCOL.md` 15, `R-REC-01`, `R-GLB-03`, `R-GLB-04`.

This module reads the database and writes a **bundle**: the canonical event
bytes exactly as stored, the checkpoints the signer returned, the global-log
records, and the policy identity. It computes no hash and no proof — `abb
receipt build` does that, so there is one implementation of the protocol and
one place where a receipt's layout is decided.

A run may only reach `EXPORTED` once its root is in the global log and a global
checkpoint covers it (`R-GLB-03`). Exporting earlier would hand out a receipt
whose deleted-run detection cannot work.
"""

from __future__ import annotations

import base64
import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import AbbError
from .repository import Repository, now_ms


@dataclass(frozen=True)
class ExportResult:
    """Where the receipt went, and what is inside it."""

    path: Path
    bytes_written: int
    event_count: int
    checkpoint_count: int
    global_position: int


class Exporter:
    """Builds `*.abbreceipt` files for finalized runs."""

    def __init__(self, *, repository: Repository, abb_path: str, store: Any = None) -> None:
        self._repo = repository
        self._abb = abb_path
        self._store = store

    def export(
        self,
        run_id: str,
        out_path: Path,
        *,
        witnesses: list[dict[str, str]] | None = None,
        anchors: list[dict[str, Any]] | None = None,
        disclose: list[str] | None = None,
    ) -> ExportResult:
        """Build the receipt for a finalized run.

        `disclose` names committed fields to reveal in this receipt. The default
        reveals nothing: a committed field stays hidden unless the exporter chooses
        otherwise, and a shredded field cannot be revealed at all (`D-11`).
        """
        run = self._repo.get_run(run_id)
        if run is None:
            raise AbbError("NOT_FOUND", "unknown run")

        events = self._repo.canonical_events(run_id)
        if not events:
            raise AbbError("VALIDATION_FAILED", "a run with no events has nothing to export")

        checkpoints = self._repo.checkpoints(run_id)
        if not checkpoints:
            raise AbbError(
                "VALIDATION_FAILED", "the run is not checkpointed yet, so there is nothing to prove"
            )

        position = self._repo.global_position(run_id)
        global_checkpoints = self._repo.checkpoints("global")
        if position is None or not global_checkpoints:
            # R-GLB-03: refusing here is the point. A receipt without global
            # inclusion cannot support the deleted-run check.
            raise AbbError(
                "VALIDATION_FAILED",
                "the run is not in the global log yet, so it cannot be exported (R-GLB-03)",
            )

        policy = self._repo.policy_of(run_id)

        bundle = {
            "run": {
                "run_id": run_id,
                "adapter_name": run["adapter"],
                "adapter_version": "0.1.0",
                # The declared coverage is what the run claimed, not what we
                # would like it to be.
                "declared_coverage": run["declared_coverage"] or run["requested_coverage"],
                "observed_coverage": run["declared_coverage"] or run["requested_coverage"],
                "profile": run["profile"],
            },
            "events": [base64.b64encode(event).decode("ascii") for event in events],
            "checkpoints": [
                {
                    "payload_b64": base64.b64encode(checkpoint["payload_bytes"]).decode("ascii"),
                    "signature": checkpoint["signature"],
                }
                for checkpoint in checkpoints
            ],
            "policy": {
                "policy_id": policy["policy_id"],
                "policy_version": policy["policy_version"],
                "body_digest": policy["body_digest"],
            },
            "global": {
                "position": position,
                "records": [
                    base64.b64encode(record).decode("ascii")
                    for record in self._repo.global_records()
                ],
                "checkpoints": [
                    {
                        "payload_b64": base64.b64encode(checkpoint["payload_bytes"]).decode(
                            "ascii"
                        ),
                        "signature": checkpoint["signature"],
                    }
                    for checkpoint in global_checkpoints
                ],
            },
            "manifest_entries": [
                base64.b64encode(entry).decode("ascii")
                for entry in self._repo.manifest_entry_bytes(run_id)
            ],
            "artifacts": self._artifact_files(run_id),
            "witnesses": witnesses or [],
            "anchors": anchors or [],
            "approvals": self._approvals(run_id),
            "mandate": self._mandate(run_id),
            "disclosures": self._disclosures(run_id, disclose or []),
            "key_manifest_ref": "published out of band; see deploy/README.md",
            "exported_at": now_ms(),
        }

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as handle:
            json.dump(bundle, handle)
            bundle_path = Path(handle.name)
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [
                    self._abb,
                    "receipt",
                    "build",
                    "--bundle",
                    str(bundle_path),
                    "--out",
                    str(out_path),
                ],
                capture_output=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "the receipt builder is unavailable") from exc
        finally:
            bundle_path.unlink(missing_ok=True)

        if done.returncode != 0:
            raise AbbError(
                "INTERNAL",
                done.stderr.decode("utf-8", "replace")[:300] or "receipt build failed",
            )

        # Only now is the run exported. Exporting again (a new receipt for the same
        # run, for example with a different disclosure) is legal and changes no state.
        if run["state"] != "EXPORTED":
            self._repo.set_state(run_id, "EXPORTED")

        return ExportResult(
            path=out_path,
            bytes_written=out_path.stat().st_size,
            event_count=len(events),
            checkpoint_count=len(checkpoints),
            global_position=position,
        )

    def _approvals(self, run_id: str) -> list[dict[str, str]]:
        """The approvers' own signed statements, as stored. Never re-signed."""
        return [
            {
                "statement_b64": base64.b64encode(item["statement"]).decode("ascii"),
                "key_id": item["key_id"],
                "signature": item["signature"],
            }
            for item in self._repo.signed_approvals(run_id)
        ]

    def _mandate(self, run_id: str) -> dict[str, str] | None:
        found = self._repo.mandate_of(run_id)
        if found is None:
            return None
        return {
            "document_b64": base64.b64encode(found["document"]).decode("ascii"),
            "signature": found["signature"],
        }

    def _disclosures(self, run_id: str, fields: list[str]) -> list[dict[str, Any]]:
        """Reveal only the fields asked for, and only what still exists."""
        if not fields:
            return []
        return [
            {
                "event_id": item["event_id"],
                "field": item["field"],
                "salt_hex": item["salt_hex"],
                "value": json.loads(item["value_json"]),
            }
            for item in self._repo.disclosures_for(run_id)
            if item["field"] in fields
        ]

    def _artifact_files(self, run_id: str) -> list[dict[str, str]]:
        """The artifact bytes, each re-verified on the way out (`R-DAT-09`).

        Without a store the receipt ships no bytes, and the verifier reports
        availability as UNKNOWN rather than PASS.
        """
        if self._store is None:
            return []
        return [
            {
                "digest": digest,
                "bytes_b64": base64.b64encode(self._store.get(digest)).decode("ascii"),
            }
            for digest in self._repo.manifest_digests(run_id)
        ]
