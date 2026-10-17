"""The artifact component: R-DAT-08..12 and R-ART-02, against the real Rust digest."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import pathsafe  # noqa: E402
from services.api.errors import AbbError  # noqa: E402
from services.artifacts.store import ArtifactStore  # noqa: E402
from tests.contract.test_signer_api import binary  # noqa: E402


@pytest.fixture
def store(tmp_path: Path) -> ArtifactStore:
    abb = binary("abb", "ABB_BIN")
    if abb is None:
        pytest.skip("needs the abb binary")
    return ArtifactStore(tmp_path / "artifacts", abb_path=abb)


def test_put_then_get_round_trips_and_the_name_is_the_digest(store: ArtifactStore) -> None:
    stored = store.put(b"<html>hello</html>", media_type="text/html")
    assert len(stored.digest) == 64
    assert store.get(stored.digest) == b"<html>hello</html>"
    assert store.path_for(stored.digest).name == stored.digest


def test_identical_bytes_are_stored_once(store: ArtifactStore) -> None:
    first = store.put(b"same", media_type="text/plain")
    second = store.put(b"same", media_type="text/plain")
    assert first.digest == second.digest


def test_a_wrong_claimed_digest_is_refused_and_nothing_is_stored(store: ArtifactStore) -> None:
    with pytest.raises(AbbError) as err:
        store.put(b"real bytes", media_type="text/plain", claimed_digest="ab" * 32)
    assert err.value.code == "ARTIFACT_DIGEST_MISMATCH"
    assert not pathsafe.exists(store.path_for("ab" * 32))


def test_a_disallowed_media_type_is_refused(store: ArtifactStore) -> None:
    with pytest.raises(AbbError) as err:
        store.put(b"MZ...", media_type="application/x-msdownload")
    assert err.value.code == "MEDIA_TYPE_REJECTED"


def test_a_missing_object_is_reported_not_invented(store: ArtifactStore) -> None:
    with pytest.raises(AbbError) as err:
        store.get("cd" * 32)
    assert err.value.code == "ARTIFACT_MISSING"


def test_a_replaced_object_is_detected_on_read(store: ArtifactStore) -> None:
    """Corruption is reported, never served (R-DAT-09)."""
    stored = store.put(b"original", media_type="text/plain")
    pathsafe.write_bytes(store.path_for(stored.digest), b"replaced behind our back")
    with pytest.raises(AbbError) as err:
        store.get(stored.digest)
    assert err.value.code == "ARTIFACT_DIGEST_MISMATCH"


def test_a_digest_that_is_not_a_digest_cannot_become_a_path(store: ArtifactStore) -> None:
    for bad in ["../../etc/passwd", "AB" * 32, "ab" * 31, ""]:
        with pytest.raises(AbbError):
            store.path_for(bad)


def test_abandoned_temporary_objects_are_cleaned_up(store: ArtifactStore, tmp_path: Path) -> None:
    pathsafe.write_bytes(tmp_path / "artifacts" / "tmp" / "crashed.part", b"half")
    assert store.cleanup_abandoned() == 1
    assert store.cleanup_abandoned() == 0
