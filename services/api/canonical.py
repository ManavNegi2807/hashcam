"""The only way this service turns an event into bytes: ask the Rust core.

`AGENTS.md` 3.10 allows one implementation of the canonical rules, and it is
`core/abb-jcs`. So this module shells out to `abb event canon` and hands it the
producer's **raw body**, never a Python-parsed object: a permissive parser here
would drop a duplicate key or widen a float before the protocol rules saw it.

Cost, stated plainly: one subprocess per event. That is slow and it is the
hackathon cut's deliberate trade (`R-SVC-04` says benchmark before tuning, and
nothing here claims a throughput figure). The replacement is a PyO3 binding to
the same crate, not a second implementation.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import CODES, AbbError


@dataclass(frozen=True)
class CanonicalEvent:
    """What the core says about an accepted event."""

    canonical_bytes: bytes
    leaf_hash: bytes
    run_id: str
    event_id: str
    sequence: int
    event_type: str
    source: str
    created_at: int
    idempotency_key: str | None


class Canonicalizer:
    """A thin, testable wrapper around the `abb` binary."""

    def __init__(self, abb_path: str | Path, timeout_seconds: float = 10.0) -> None:
        self._abb = str(abb_path)
        self._timeout = timeout_seconds

    def assign_and_validate(
        self,
        body: bytes,
        *,
        run_id: str,
        event_id: str,
        sequence: int,
        created_at: int,
    ) -> CanonicalEvent:
        """Insert the server-assigned fields, canonicalize, validate.

        Raises `AbbError` with the protocol's own code when the core rejects it.
        """
        argv = [
            self._abb,
            "event",
            "canon",
            "--stdin",
            "--run-id",
            run_id,
            "--event-id",
            event_id,
            "--sequence",
            str(sequence),
            "--created-at",
            str(created_at),
        ]
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                argv,
                input=body,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing dependent
            raise AbbError("DEPENDENCY_UNAVAILABLE", "canonicalizer timed out") from exc
        except OSError as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "canonicalizer unavailable") from exc

        if done.returncode != 0:
            raise self._error_from(done.stderr)
        return self._parse(done.stdout)

    def canonical_json(self, value: dict[str, object]) -> bytes:
        """Canonical bytes of a JSON value, from the Rust core."""
        import json

        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "canon", "--stdin", "--text"],
                input=json.dumps(value).encode("utf-8"),
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "canonicalizer unavailable") from exc
        if done.returncode != 0:
            raise self._error_from(done.stderr)
        return done.stdout.decode("utf-8").rstrip("\r\n").encode("utf-8")

    def commit(self, value_json: bytes) -> tuple[str, str]:
        """A salted commitment to one JSON value: `(salt_hex, commitment)`.

        The value goes in on stdin, never in argv, so a secret does not show up
        in a process list. The salt is 16 bytes from the core's CSPRNG.
        """
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "commit", "--stdin"],
                input=value_json,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "commitment tool unavailable") from exc
        if done.returncode != 0:
            raise AbbError("VALIDATION_FAILED", "the value cannot be committed to")
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return fields["salt_hex"], fields["commitment"]
        except KeyError as exc:
            raise AbbError("INTERNAL", "commitment output not understood") from exc

    def tagged_digest(self, tag: str, data: bytes) -> bytes:
        """`SHA-256(tag || 0x00 || data)`, from the Rust core."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "leaf", "--tag", tag, "--stdin"],
                input=data,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "digest unavailable") from exc
        if done.returncode != 0:
            raise self._error_from(done.stderr)
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return bytes.fromhex(fields["tagged_digest"])
        except (KeyError, ValueError) as exc:
            raise AbbError("INTERNAL", "digest output not understood") from exc

    def leaf_hash(self, tag: str, data: bytes) -> bytes:
        """The Merkle leaf hash of tagged data, computed by the Rust core.

        Python never hashes protocol material itself (`AGENTS.md` 3.10), which
        is why even a one-line digest goes through `abb leaf`.
        """
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "leaf", "--tag", tag, "--stdin"],
                input=data,
                capture_output=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "leaf hashing unavailable") from exc
        if done.returncode != 0:
            raise self._error_from(done.stderr)
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return bytes.fromhex(fields["leaf_hash"])
        except (KeyError, ValueError) as exc:
            raise AbbError("INTERNAL", "leaf output not understood") from exc

    @staticmethod
    def _error_from(stderr: bytes) -> AbbError:
        """Map the core's `error_code=` line onto an API error code."""
        fields = dict(
            line.split("=", 1)
            for line in stderr.decode("utf-8", "replace").splitlines()
            if "=" in line
        )
        code = fields.get("error_code", "VALIDATION_FAILED")
        if code not in CODES:
            code = "VALIDATION_FAILED"
        # The detail comes from the core and names a rule or a field. It never
        # contains the payload itself, so it is safe to return.
        return AbbError(code, fields.get("error_detail", "")[:200])

    @staticmethod
    def _parse(stdout: bytes) -> CanonicalEvent:
        fields = dict(
            line.split("=", 1) for line in stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return CanonicalEvent(
                canonical_bytes=bytes.fromhex(fields["canonical_hex"]),
                leaf_hash=bytes.fromhex(fields["leaf_hash"]),
                run_id=fields["run_id"],
                event_id=fields["event_id"],
                sequence=int(fields["sequence"]),
                event_type=fields["event_type"],
                source=fields["source"],
                created_at=int(fields["created_at"]),
                idempotency_key=fields.get("idempotency_key"),
            )
        except (KeyError, ValueError) as exc:
            raise AbbError("INTERNAL", "canonicalizer output not understood") from exc
