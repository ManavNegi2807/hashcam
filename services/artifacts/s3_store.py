"""The artifact store on an S3-compatible object server (the deck's MinIO slot).

Same interface and same rules as the local store (`store.py`): bytes enter only through `put`, the
digest comes from the Rust core and is compared with any claim, an existing object is never
overwritten, and every read is re-verified, so a swapped object is reported and never served.

Why "S3-compatible" and not "MinIO": MinIO's community edition was archived upstream in April 2026
and stopped publishing images, with older releases carrying a known high-severity flaw, so a new
deployment should not start on it. Nothing here depends on MinIO: any S3-compatible server works. It
was tested against SeaweedFS (Apache-2.0). Pointing it at a MinIO you already run also works.

Configuration is by environment variable, read here and never printed:
`ABB_S3_ENDPOINT`, `ABB_S3_ACCESS_KEY`, `ABB_S3_SECRET_KEY`, optional `ABB_S3_BUCKET`.
"""

from __future__ import annotations

import os
from pathlib import Path

from services.api.errors import AbbError
from services.artifacts.s3 import S3Client, S3Error
from services.artifacts.store import (
    ALLOWED_MEDIA_TYPES,
    MAX_ARTIFACT_BYTES,
    ArtifactStore,
    StoredArtifact,
)

DEFAULT_BUCKET = "abb-artifacts"


def object_key(digest: str) -> str:
    """`objects/ab/abcd...`: the same fan-out as the local store."""
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise AbbError("VALIDATION_FAILED", "not a lowercase 64-character digest")
    return f"objects/{digest[:2]}/{digest}"


class S3ArtifactStore(ArtifactStore):
    """Content-addressed objects in a bucket. Object name = `SHA-256(raw bytes)`."""

    def __init__(self, client: S3Client, bucket: str = DEFAULT_BUCKET, *, abb_path: str) -> None:
        # No local directory: the base class is used only for its digest helper.
        self._root = Path(".")
        self._abb = abb_path
        self._client = client
        self._bucket = bucket
        try:
            client.ensure_bucket(bucket)
        except S3Error as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", f"object storage refused: {exc.code}") from exc

    @classmethod
    def from_environment(cls, *, abb_path: str) -> S3ArtifactStore:
        env = os.environ
        endpoint = env.get("ABB_S3_ENDPOINT", "")
        access, secret = env.get("ABB_S3_ACCESS_KEY", ""), env.get("ABB_S3_SECRET_KEY", "")
        if not (endpoint and access and secret):
            raise AbbError("DEPENDENCY_UNAVAILABLE", "object storage is not configured")
        return cls(
            S3Client(endpoint, access, secret),
            env.get("ABB_S3_BUCKET", DEFAULT_BUCKET),
            abb_path=abb_path,
        )

    def put(
        self, data: bytes, *, media_type: str, claimed_digest: str | None = None
    ) -> StoredArtifact:
        if media_type not in ALLOWED_MEDIA_TYPES:
            raise AbbError("MEDIA_TYPE_REJECTED", f"{media_type} is not allowed")
        if len(data) > MAX_ARTIFACT_BYTES:
            raise AbbError("PAYLOAD_TOO_LARGE", "over the artifact size limit")
        digest = self._digest(data)
        if claimed_digest is not None and claimed_digest != digest:
            raise AbbError(
                "ARTIFACT_DIGEST_MISMATCH", "the bytes do not match the digest that was claimed"
            )
        try:
            # `only_if_new`: a worker can never overwrite an existing object (R-DAT-11).
            self._client.put(self._bucket, object_key(digest), data, media_type, only_if_new=True)
        except S3Error as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", f"object storage refused: {exc.code}") from exc
        return StoredArtifact(digest=digest, size=len(data), media_type=media_type)

    def get(self, digest: str) -> bytes:
        key = object_key(digest)
        try:
            data = self._client.get(self._bucket, key)
        except S3Error as exc:
            if exc.status == 404 or exc.code in {"NoSuchKey", "NotFound"}:
                raise AbbError("ARTIFACT_MISSING", "the object is not in storage") from exc
            raise AbbError("DEPENDENCY_UNAVAILABLE", f"object storage refused: {exc.code}") from exc
        if self._digest(data) != digest:
            raise AbbError(
                "ARTIFACT_DIGEST_MISMATCH",
                "the stored object no longer matches its digest: it is corrupt or was replaced",
            )
        return data

    def path_for(self, digest: str) -> Path:  # pragma: no cover - local stores only
        raise AbbError("INTERNAL", "an object store has no local path")

    def cleanup_abandoned(self) -> int:
        return 0  # nothing is staged locally, so a crash leaves nothing behind
