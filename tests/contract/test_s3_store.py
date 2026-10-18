"""The artifact store on an S3-compatible server, and the signing it relies on.

The signing tests need nothing: they check AWS's own published Signature Version 4 example. The
store tests need a running S3-compatible server and are skipped unless `ABB_TEST_S3` (its address),
`ABB_S3_ACCESS_KEY`, `ABB_S3_SECRET_KEY` and `ABB_BIN` are set. They were run against SeaweedFS
4.48 (Apache-2.0), not MinIO: MinIO's community edition is archived and no longer published.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest

from services.api.errors import AbbError
from services.artifacts.s3 import EMPTY_SHA256, S3Client, S3Error, signature
from services.artifacts.s3_store import S3ArtifactStore, object_key

ENDPOINT = os.environ.get("ABB_TEST_S3", "")
ACCESS = os.environ.get("ABB_S3_ACCESS_KEY", "")
SECRET = os.environ.get("ABB_S3_SECRET_KEY", "")
ABB = os.environ.get("ABB_BIN", "")
needs_server = pytest.mark.skipif(
    not (ENDPOINT and ACCESS and SECRET and ABB),
    reason="needs ABB_TEST_S3, ABB_S3_ACCESS_KEY, ABB_S3_SECRET_KEY and ABB_BIN",
)


# ---- signing: AWS's published example ----------------------------------------------------------


def test_the_signature_matches_awss_published_signature_version_4_example() -> None:
    """From AWS's documentation: GET https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08
    on 2015-08-30 with the documentation's example key. The expected signature is theirs."""
    signed, hexsig = signature(
        secret="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",  # AWS's documented example secret
        method="GET",
        path="/",
        query="Action=ListUsers&Version=2010-05-08",
        headers={
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
            "host": "iam.amazonaws.com",
            "x-amz-date": "20150830T123600Z",
        },
        payload_hash=EMPTY_SHA256,
        amz_date="20150830T123600Z",
        region="us-east-1",
        service="iam",
    )
    assert signed == "content-type;host;x-amz-date"
    assert hexsig == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"


def test_a_different_secret_or_body_gives_a_different_signature() -> None:
    base = {
        "method": "PUT",
        "path": "/b/k",
        "query": "",
        "headers": {"host": "h", "x-amz-date": "20260101T000000Z"},
        "amz_date": "20260101T000000Z",
        "region": "us-east-1",
    }
    one = signature(secret="s1", payload_hash="a" * 64, **base)  # type: ignore[arg-type]
    assert one != signature(secret="s2", payload_hash="a" * 64, **base)  # type: ignore[arg-type]
    assert one != signature(secret="s1", payload_hash="b" * 64, **base)  # type: ignore[arg-type]


def test_a_remote_unencrypted_endpoint_is_refused() -> None:
    with pytest.raises(ValueError):
        S3Client("http://storage.example.com", "a", "b")
    S3Client("https://storage.example.com", "a", "b")  # https is fine
    S3Client("http://127.0.0.1:9", "a", "b")  # loopback may be plain


def test_empty_credentials_are_refused_and_the_secret_never_shows() -> None:
    with pytest.raises(ValueError):
        S3Client("http://127.0.0.1:9", "", "b")
    client = S3Client("http://127.0.0.1:9", "ACCESSKEY", "TOP-SECRET-VALUE")
    assert "TOP-SECRET-VALUE" not in repr(client) and "ACCESSKEY" not in repr(client)


def test_an_unreachable_server_is_reported_without_credentials() -> None:
    client = S3Client("http://127.0.0.1:1", "ACCESSKEY", "TOP-SECRET-VALUE", timeout=2)
    with pytest.raises(S3Error) as caught:
        client.ensure_bucket("b")
    assert "TOP-SECRET-VALUE" not in str(caught.value) and caught.value.code == "unreachable"


def test_object_keys_use_the_same_fan_out_as_the_local_store_and_refuse_junk() -> None:
    digest = "ab" * 32
    assert object_key(digest) == f"objects/ab/{digest}"
    for bad in ("", "xyz", "AB" * 32, "ab" * 31, "../" + "a" * 61):
        with pytest.raises(AbbError):
            object_key(bad)


# ---- the store, against a real server ---------------------------------------------------------


@pytest.fixture(scope="module")
def bucket_name() -> str:
    """One bucket for the module: a small test server has only a few volumes to give."""
    return "abb-test-" + uuid.uuid4().hex[:10]


@pytest.fixture()
def store(bucket_name: str) -> Iterator[S3ArtifactStore]:
    yield S3ArtifactStore(S3Client(ENDPOINT, ACCESS, SECRET), bucket_name, abb_path=ABB)


@needs_server
def test_bytes_put_come_back_identical_and_the_digest_comes_from_the_rust_core(
    store: S3ArtifactStore,
) -> None:
    stored = store.put(b"<html>hello</html>", media_type="text/html")
    assert len(stored.digest) == 64 and stored.size == 18
    assert store.get(stored.digest) == b"<html>hello</html>"


@needs_server
def test_putting_the_same_bytes_twice_is_one_object(store: S3ArtifactStore) -> None:
    first = store.put(b"same", media_type="text/plain")
    second = store.put(b"same", media_type="text/plain")
    assert first == second


@needs_server
def test_a_wrong_claimed_digest_is_refused_and_nothing_is_stored(store: S3ArtifactStore) -> None:
    with pytest.raises(AbbError) as caught:
        store.put(b"real bytes", media_type="text/plain", claimed_digest="ab" * 32)
    assert caught.value.code == "ARTIFACT_DIGEST_MISMATCH"
    client = S3Client(ENDPOINT, ACCESS, SECRET)
    assert not client.head(store._bucket, object_key("ab" * 32))


@needs_server
def test_a_media_type_that_is_not_allowed_is_refused(store: S3ArtifactStore) -> None:
    with pytest.raises(AbbError) as caught:
        store.put(b"MZ...", media_type="application/x-msdownload")
    assert caught.value.code == "MEDIA_TYPE_REJECTED"


@needs_server
def test_reading_an_object_that_is_not_there_says_missing(store: S3ArtifactStore) -> None:
    with pytest.raises(AbbError) as caught:
        store.get("cd" * 32)
    assert caught.value.code == "ARTIFACT_MISSING"


@needs_server
def test_an_object_replaced_behind_the_stores_back_is_reported_never_served(
    store: S3ArtifactStore,
) -> None:
    stored = store.put(os.urandom(16), media_type="text/plain")
    raw = S3Client(ENDPOINT, ACCESS, SECRET)
    raw.put(store._bucket, object_key(stored.digest), b"replaced", "text/plain", only_if_new=False)
    with pytest.raises(AbbError) as caught:
        store.get(stored.digest)
    assert caught.value.code == "ARTIFACT_DIGEST_MISMATCH"


@needs_server
def test_a_put_never_overwrites_an_existing_object(store: S3ArtifactStore) -> None:
    original = os.urandom(16)
    stored = store.put(original, media_type="text/plain")
    raw = S3Client(ENDPOINT, ACCESS, SECRET)
    raw.put(store._bucket, object_key(stored.digest), b"tampered", "text/plain", only_if_new=False)
    store.put(original, media_type="text/plain")  # the same bytes again must not "repair" it
    assert raw.get(store._bucket, object_key(stored.digest)) == b"tampered"


@needs_server
def test_wrong_credentials_are_refused_without_leaking_them() -> None:
    bad = S3Client(ENDPOINT, ACCESS, "definitely-not-the-secret")
    with pytest.raises(AbbError) as caught:
        S3ArtifactStore(bad, "abb-test-bad", abb_path=ABB)
    assert caught.value.code == "DEPENDENCY_UNAVAILABLE"
    assert "definitely-not-the-secret" not in str(caught.value)


@needs_server
def test_the_store_can_be_built_from_environment_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ABB_S3_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("ABB_S3_BUCKET", "abb-test-env-" + uuid.uuid4().hex[:8])
    built = S3ArtifactStore.from_environment(abb_path=ABB)
    assert built.get(built.put(b"via env", media_type="text/plain").digest) == b"via env"
    monkeypatch.delenv("ABB_S3_ENDPOINT")
    with pytest.raises(AbbError):
        S3ArtifactStore.from_environment(abb_path=ABB)
