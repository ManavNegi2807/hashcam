"""The only caller of the signer.

Two rules this module exists to keep (`DESIGN.md` 5, `R-SIG-01`, `R-SVC-05`):

* the control plane and the worker never hold the signing key — they ask this
  client, which asks the signer over its own network;
* the signer is never handed a root. It gets the canonical event bytes and
  recomputes the root itself (`D-12`), so this client sends bytes, never
  digests.

It also never canonicalizes anything itself: `abb attest` builds the request
body and signs it with the ingestion key, so the request layout has exactly one
implementation (`AGENTS.md` 3.10, decision `D-20`).

Only the standard library is used for HTTP, so the service gains no dependency
for a call it makes once per finalization.
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request
from base64 import b64encode
from dataclasses import dataclass, field
from pathlib import Path

from .errors import AbbError


@dataclass(frozen=True)
class SignedCheckpoint:
    """What the signer returned, with the exact bytes it signed."""

    payload: dict[str, object]
    signature: str
    #: The canonical payload bytes. Store these, never a re-serialization.
    payload_bytes: bytes
    checkpoint_hash: str

    @property
    def tree_size(self) -> int:
        return _as_int(self.payload, "tree_size")

    @property
    def root_hash(self) -> str:
        return str(self.payload["root_hash"])


@dataclass
class SignerClient:
    """A thin client for `POST /sign`, `GET /state/{id}` and `GET /health`."""

    base_url: str
    abb_path: str
    ingestion_key_path: str
    timeout_seconds: float = 30.0
    _session: None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ calls

    def sign(
        self,
        *,
        stream_id: str,
        events: list[bytes],
        prev_checkpoint: dict[str, object] | None = None,
        manifest_entries: list[bytes] | None = None,
        expected_root: str | None = None,
    ) -> SignedCheckpoint:
        """Ask for a checkpoint over `events`.

        `expected_root` is only a cross-check: the signer computes the root
        itself and refuses the request if the two differ (`ROOT_MISMATCH`).
        """
        request: dict[str, object] = {
            "stream_id": stream_id,
            "append": {
                "from_sequence": _from_sequence(prev_checkpoint),
                "events": [b64encode(event).decode("ascii") for event in events],
            },
        }
        if manifest_entries:
            append = request["append"]
            if not isinstance(append, dict):  # pragma: no cover - built just above
                raise AbbError("INTERNAL", "malformed signing request")
            append["manifest_entries"] = [
                b64encode(entry).decode("ascii") for entry in manifest_entries
            ]
        if prev_checkpoint is not None:
            request["prev_checkpoint"] = prev_checkpoint
        if expected_root is not None:
            request["expected_root"] = expected_root

        body = self._attest(request)
        raw = self._post("/sign", body)
        return _parse_checkpoint(raw)

    def state(self, stream_id: str) -> dict[str, object] | None:
        """The signer's last checkpoint for a stream, for idempotent re-delivery."""
        try:
            raw = self._get(f"/state/{stream_id}")
        except AbbError as exc:
            if exc.code == "NOT_FOUND":
                return None
            raise
        return _as_object(json.loads(raw), "state")

    def health(self) -> dict[str, object]:
        return _as_object(json.loads(self._get("/health")), "health")

    # -------------------------------------------------------------- internals

    def _attest(self, request: dict[str, object]) -> bytes:
        """Canonicalize and sign the request with the Rust core."""
        if not Path(self.ingestion_key_path).is_file():
            raise AbbError("INTERNAL", "the ingestion key is not available")
        try:
            done = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.abb_path, "attest", "--key", self.ingestion_key_path, "--stdin"],
                input=json.dumps(request).encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "cannot attest the request") from exc
        if done.returncode != 0:
            # The detail comes from the core and names a rule, not a secret.
            raise AbbError("INTERNAL", done.stderr.decode("utf-8", "replace")[:200])
        fields = dict(
            line.split("=", 1) for line in done.stdout.decode("utf-8").splitlines() if "=" in line
        )
        try:
            return bytes.fromhex(fields["body_hex"])
        except (KeyError, ValueError) as exc:
            raise AbbError("INTERNAL", "attestation output not understood") from exc

    def _post(self, path: str, body: bytes) -> str:
        request = urllib.request.Request(  # noqa: S310 - fixed http(s) base URL
            f"{self.base_url}{path}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        return self._send(request)

    def _get(self, path: str) -> str:
        request = urllib.request.Request(  # noqa: S310
            f"{self.base_url}{path}", method="GET"
        )
        return self._send(request)

    def _send(self, request: urllib.request.Request) -> str:
        try:
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=self.timeout_seconds
            ) as response:
                return str(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise _signer_error(exc) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            # The signer being down must never look like a signed checkpoint.
            raise AbbError("DEPENDENCY_UNAVAILABLE", "the signer is not reachable") from exc


def _as_object(value: object, what: str) -> dict[str, object]:
    """The signer answered with something other than an object: that is a bug."""
    if not isinstance(value, dict):
        raise AbbError("INTERNAL", f"the signer's {what} answer was not an object")
    return value


def _as_int(payload: dict[str, object], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise AbbError("INTERNAL", f"the signer's {field} was not an integer")
    return value


def _from_sequence(prev_checkpoint: dict[str, object] | None) -> int:
    """The batch starts where the previous checkpoint ended."""
    if prev_checkpoint is None:
        return 0
    payload = _as_object(prev_checkpoint.get("payload"), "prev_checkpoint.payload")
    return _as_int(payload, "tree_size")


def _parse_checkpoint(raw: str) -> SignedCheckpoint:
    from base64 import b64decode

    parsed = json.loads(raw)
    checkpoint = parsed["checkpoint"]
    return SignedCheckpoint(
        payload=checkpoint["payload"],
        signature=checkpoint["signature"],
        payload_bytes=b64decode(parsed["payload_b64"]),
        checkpoint_hash=parsed["checkpoint_hash"],
    )


def _signer_error(exc: urllib.error.HTTPError) -> AbbError:
    """Map the signer's own code onto an API error, keeping the code visible.

    An integrity answer from the signer — a fork, a root mismatch, corrupt
    state — must never be flattened into a generic failure: those are the
    alerts of `ERROR_HANDLING.md` 11.
    """
    try:
        body = json.loads(exc.read().decode("utf-8"))
        code = str(body.get("code", "INTERNAL"))
        detail = str(body.get("detail", ""))
    except (ValueError, OSError):
        # The body was unreadable or not JSON; the status still tells us enough.
        code, detail = "INTERNAL", ""
    if exc.code == 404 and code == "UNKNOWN_STREAM":
        return AbbError("NOT_FOUND", "the signer has no state for that stream")
    # The signer's codes are not API codes, so they travel as the detail with a
    # stable API code of their own.
    mapped = {
        401: "INTERNAL",  # the service's own attestation failed: a bug, not the caller's fault
        429: "RATE_LIMITED",
        503: "DEPENDENCY_UNAVAILABLE",
    }.get(exc.code, "SIGNER_REFUSED")
    return AbbError(mapped, f"{code}: {detail}"[:200])
