"""A very small S3 client: just enough for a content-addressed artifact store.

Works with any S3-compatible server (MinIO, SeaweedFS, Garage, RustFS, AWS). It speaks the public
S3 REST API signed with AWS Signature Version 4 (HMAC-SHA256, specified by AWS; nothing invented
here) using only the standard library, so there is no new dependency.

* Credentials come from the caller (environment variables in `services/artifacts/s3_store.py`), are
  sent only in the signed `Authorization` header, and never appear in an error or a repr.
* Plain `http://` is accepted only for a loopback address; anything else must be `https://`.
* Path-style addressing (`/bucket/key`), because that is what a self-hosted server expects.
"""

from __future__ import annotations

import hashlib
import hmac
import urllib.error
import urllib.request
from datetime import UTC, datetime
from urllib.parse import quote, urlparse

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
MAX_OBJECT_BYTES = 70 * 1024 * 1024


class S3Error(Exception):
    """The server said no (or could not be reached). Never holds a key or a header."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"S3 {status} {code}")
        self.status = status
        self.code = code


def _hmac(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def signature(
    *,
    secret: str,
    method: str,
    path: str,
    query: str,
    headers: dict[str, str],
    payload_hash: str,
    amz_date: str,
    region: str,
    service: str = "s3",
) -> tuple[str, str]:
    """(signed header names, hex signature) for one request, per the SigV4 specification."""
    names = sorted(name.lower() for name in headers)
    lowered = {k.lower(): " ".join(v.split()) for k, v in headers.items()}
    canonical_headers = "".join(f"{n}:{lowered[n]}\n" for n in names)
    signed = ";".join(names)
    canonical_request = "\n".join([method, path, query, canonical_headers, signed, payload_hash])
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    key = _hmac(("AWS4" + secret).encode("utf-8"), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    return signed, hmac.new(key, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()


class S3Client:
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        *,
        region: str = "us-east-1",
        timeout: float = 20.0,
    ) -> None:
        parts = urlparse(endpoint)
        if parts.scheme != "https" and not (parts.scheme == "http" and parts.hostname in LOOPBACK):
            raise ValueError("the S3 endpoint must be https (http only on loopback)")
        if not access_key or not secret_key:
            raise ValueError("the S3 credentials are empty")
        self._host = parts.netloc
        self._base = f"{parts.scheme}://{parts.netloc}"
        self._access = access_key
        self._secret = secret_key
        self._region = region
        self._timeout = timeout

    def __repr__(self) -> str:  # never shows a credential
        return f"S3Client(host={self._host!r})"

    def _request(
        self,
        method: str,
        bucket: str,
        key: str = "",
        *,
        body: bytes = b"",
        extra: dict[str, str] | None = None,
        now: datetime | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        path = "/" + quote(bucket, safe="") + (("/" + quote(key, safe="/~")) if key else "")
        payload_hash = hashlib.sha256(body).hexdigest() if body else EMPTY_SHA256
        amz_date = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
        headers = {
            "host": self._host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
            **(extra or {}),
        }
        signed, sig = signature(
            secret=self._secret,
            method=method,
            path=path,
            query="",
            headers=headers,
            payload_hash=payload_hash,
            amz_date=amz_date,
            region=self._region,
        )
        scope = f"{amz_date[:8]}/{self._region}/s3/aws4_request"
        sent = {k: v for k, v in headers.items() if k != "host"}
        sent["Authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self._access}/{scope}, "
            f"SignedHeaders={signed}, Signature={sig}"
        )
        request = urllib.request.Request(  # noqa: S310 - scheme checked in __init__
            self._base + path, data=body or None, method=method, headers=sent
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                data = response.read(MAX_OBJECT_BYTES + 1)
                return response.status, data, {k.lower(): v for k, v in response.getheaders()}
        except urllib.error.HTTPError as exc:
            detail = exc.read(2000).decode("utf-8", "replace")
            code = ""
            if "<Code>" in detail:
                code = detail.split("<Code>", 1)[1].split("</Code>", 1)[0][:60]
            raise S3Error(exc.code, code) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise S3Error(0, "unreachable") from None

    def ensure_bucket(self, bucket: str) -> None:
        try:
            self._request("PUT", bucket)
        except S3Error as exc:
            if exc.code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
                raise

    def head(self, bucket: str, key: str) -> bool:
        try:
            self._request("HEAD", bucket, key)
        except S3Error as exc:
            if exc.status == 404 or exc.code in {"NoSuchKey", "NotFound"}:
                return False
            raise
        return True

    def put(
        self, bucket: str, key: str, data: bytes, content_type: str, *, only_if_new: bool = True
    ) -> None:
        """Store an object. With `only_if_new`, an existing key is never overwritten."""
        extra = {"content-type": content_type}
        if only_if_new:
            extra["if-none-match"] = "*"
        try:
            self._request("PUT", bucket, key, body=data, extra=extra)
        except S3Error as exc:
            if only_if_new and exc.status == 412:
                return  # already there: content addressing makes this a no-op
            raise

    def get(self, bucket: str, key: str) -> bytes:
        status, data, _ = self._request("GET", bucket, key)
        if status != 200:
            raise S3Error(status, "unexpected")
        if len(data) > MAX_OBJECT_BYTES:
            raise S3Error(200, "too_large")
        return data
