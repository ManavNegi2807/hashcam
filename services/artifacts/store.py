"""The artifact component: the one path by which bytes enter evidence storage.

`R-DAT-08`..`R-DAT-12`, `R-ART-01`..`R-ART-07`. Workers and adapters never write
objects themselves; they hand bytes to this component, which

1. writes them to a **temporary** file,
2. asks the Rust core for the digest and compares it with what was claimed,
3. renames the file into place atomically under a name derived from the digest,
4. and re-checks the digest on every read.

Honest scope: this is a **local content-addressed store**. The target design
uses MinIO (`DESIGN.md` 10), but no Docker daemon or MinIO binary was available
when this was built, so there is no MinIO backend and none is claimed. The
interface is the part that matters, and a MinIO store can sit behind it later
without touching the manifest, the checkpoint or the verifier.

A matching digest proves the stored bytes equal what was committed. It does not
prove the capture is genuine or the page truthful (`R-ART-07`).
"""

from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

import pathsafe
from services.api.errors import AbbError

#: Media types a worker may submit. Anything else is refused, not guessed at.
ALLOWED_MEDIA_TYPES = frozenset(
    {"text/html", "text/plain", "application/json", "image/png", "image/jpeg", "application/pdf"}
)

#: A single artifact over this size is refused (an upload limit, not a quota).
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class StoredArtifact:
    """What a successful `put` returns."""

    digest: str
    size: int
    media_type: str


class ArtifactStore:
    """A content-addressed directory. Object name = `SHA-256(raw bytes)`."""

    def __init__(self, root: str | Path, *, abb_path: str) -> None:
        self._root = Path(root)
        self._abb = abb_path
        pathsafe.makedirs(self._root / "tmp")

    # --------------------------------------------------------------- hashing

    def _digest(self, data: bytes) -> str:
        """The digest, from the Rust core. Python never hashes protocol bytes."""
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self._abb, "digest", "--stdin"],
                input=data,
                capture_output=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "the digest tool is unavailable") from exc
        if done.returncode != 0:
            raise AbbError("INTERNAL", "digest tool failed")
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return fields["digest"]
        except KeyError as exc:
            raise AbbError("INTERNAL", "digest output not understood") from exc

    def path_for(self, digest: str) -> Path:
        """Where an object lives. Fan-out by prefix so one directory stays small."""
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise AbbError("VALIDATION_FAILED", "not a lowercase 64-character digest")
        return self._root / "objects" / digest[:2] / digest

    # ------------------------------------------------------------------- put

    def put(
        self, data: bytes, *, media_type: str, claimed_digest: str | None = None
    ) -> StoredArtifact:
        """Store bytes, verifying the digest before anything becomes visible."""
        if media_type not in ALLOWED_MEDIA_TYPES:
            raise AbbError("MEDIA_TYPE_REJECTED", f"{media_type} is not allowed")
        if len(data) > MAX_ARTIFACT_BYTES:
            raise AbbError("PAYLOAD_TOO_LARGE", "over the artifact size limit")

        digest = self._digest(data)
        if claimed_digest is not None and claimed_digest != digest:
            # The uploader's claim is checked, never trusted (R-DAT-09).
            raise AbbError(
                "ARTIFACT_DIGEST_MISMATCH", "the bytes do not match the digest that was claimed"
            )

        target = self.path_for(digest)
        if pathsafe.exists(target):
            # Same bytes already stored: content addressing makes this a no-op,
            # and a worker cannot overwrite an existing object (R-DAT-11).
            return StoredArtifact(digest=digest, size=len(data), media_type=media_type)

        # Temporary object first, so a crash never leaves a half-written name.
        temp = self._root / "tmp" / f"{uuid.uuid4().hex}.part"
        pathsafe.write_bytes(temp, data)
        try:
            pathsafe.makedirs(target.parent)
            os.replace(pathsafe.extended(temp), pathsafe.extended(target))
        except OSError as exc:
            pathsafe.remove(temp)
            raise AbbError("DEPENDENCY_UNAVAILABLE", "cannot finalize the artifact") from exc
        return StoredArtifact(digest=digest, size=len(data), media_type=media_type)

    # ------------------------------------------------------------------- get

    def get(self, digest: str) -> bytes:
        """Read an object, re-verifying it. Corruption is reported, never served."""
        path = self.path_for(digest)
        if not pathsafe.exists(path):
            raise AbbError("ARTIFACT_MISSING", "the object is not in storage")
        data = pathsafe.read_bytes(path)
        if self._digest(data) != digest:
            raise AbbError(
                "ARTIFACT_DIGEST_MISMATCH",
                "the stored object no longer matches its digest: it is corrupt or was replaced",
            )
        return data

    def cleanup_abandoned(self) -> int:
        """Remove temporary objects left by a crash (`R-DAT-12`). Returns the count."""
        removed = 0
        tmp = self._root / "tmp"
        for name in pathsafe.listdir(tmp):
            if name.endswith(".part"):
                pathsafe.remove(tmp / name)
                removed += 1
        return removed
