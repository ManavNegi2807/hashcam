"""A software passkey for tests: a real P-256 key that answers like a platform authenticator.

It builds the same bytes a browser hands back from `navigator.credentials` (client data JSON,
authenticator data, a DER ECDSA signature), so the checks in `services/recorder/passkey.py` run
on real signatures, not mocks.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from services.recorder.passkey import ES256, b64url_encode, rp_id_of

ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"


@dataclass
class SoftPasskey:
    origin: str = ORIGIN
    key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    credential_id: str = field(default_factory=lambda: b64url_encode(secrets.token_bytes(16)))
    user_verified: bool = True

    def _client(self, kind: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps(
            {"type": kind, "challenge": challenge, "origin": origin or self.origin}
        ).encode()

    #: What a browser hashes as the relying-party id: the extension's host, or (as Chromium
    #: does for extension pages) its full origin.
    rp_id_is_origin: bool = True

    def _auth(self, flags: int) -> bytes:
        rp = self.origin if self.rp_id_is_origin else rp_id_of(self.origin)
        return hashlib.sha256(rp.encode()).digest() + bytes([flags]) + (1).to_bytes(4, "big")

    def registration(self, challenge: str) -> dict[str, Any]:
        spki = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return {
            "credential_id": self.credential_id,
            "client_data_json": b64url_encode(self._client("webauthn.create", challenge)),
            "public_key_spki": b64url_encode(spki),
            "algorithm": ES256,
            "authenticator_data": b64url_encode(self._auth(0x45)),
        }

    def assertion(self, challenge: str, *, origin: str | None = None) -> dict[str, Any]:
        client = self._client("webauthn.get", challenge, origin)
        auth = self._auth(0x01 | (0x04 if self.user_verified else 0))
        signature = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "credential_id": self.credential_id,
            "client_data_json": b64url_encode(client),
            "authenticator_data": b64url_encode(auth),
            "signature": b64url_encode(signature),
        }
