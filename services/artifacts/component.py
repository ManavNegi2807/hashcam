"""The designated artifact component: store the bytes, then register them.

`R-DAT-11`: this is the single path by which an artifact enters evidence. A
worker hands bytes to it; it verifies, stores and, once the announcing
`ARTIFACT_CAPTURED` event is committed, appends the hash-linked manifest entry.
"""

from __future__ import annotations

from services.api.repository import Repository

from .store import ArtifactStore, StoredArtifact


class ArtifactComponent:
    """Artifact intake for one run."""

    def __init__(self, *, store: ArtifactStore, repository: Repository, run_id: str) -> None:
        self._store = store
        self._repository = repository
        self._run_id = run_id
        self._next_index = len(repository.manifest_entry_bytes(run_id))

    @property
    def next_index(self) -> int:
        """The manifest index the next capture will take."""
        return self._next_index

    def put(self, data: bytes, *, media_type: str) -> StoredArtifact:
        return self._store.put(data, media_type=media_type)

    def register(self, *, event_id: str, artifact: StoredArtifact, capture_method: str) -> int:
        """Append the manifest entry for an already-committed capture event."""
        index = self._repository.add_manifest_entry(
            run_id=self._run_id,
            event_id=event_id,
            digest=artifact.digest,
            media_type=artifact.media_type,
            size=artifact.size,
            capture_method=capture_method,
        )
        self._next_index = index + 1
        return index
