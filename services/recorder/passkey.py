"""Checking a passkey (WebAuthn) answer before the local approver key is used.

What this is: a presence check. The side panel asks the platform authenticator (fingerprint,
face or PIN) to sign a challenge that names the decision and the digest of the text the person
was shown. Only if that signature checks out does the recorder call `abb approve`.

What this is not: the approval in the receipt. That is still the Ed25519 signature of the local
approver key, checked again offline by the verifier. The passkey decides whether that key may
be used; it is not recorded in the receipt, and a receipt does not show a passkey was used.

Nothing here is new cryptography: it is the WebAuthn assertion check (W3C WebAuthn Level 2,
section 7.2) done with the `cryptography` library. The registration is trust-on-first-use: the
attestation statement is not examined, so it proves "the same authenticator as at pairing",
not which make of authenticator it is.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

ES256 = -7
RS256 = -257
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04


class PasskeyError(Exception):
    """The passkey answer was not accepted. The approver key must not be used."""


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def approval_challenge(decision: str, summary_digest: str) -> str:
    """The challenge the authenticator signs: the decision and what was shown, as text.

    Plain bytes, not a hash, so the binding is easy to audit: the signed client data
    contains this exact string (base64url).
    """
    return b64url_encode(f"hashcam-approval:{decision}:{summary_digest}".encode("ascii"))


def new_challenge() -> str:
    return b64url_encode(secrets.token_bytes(32))


@dataclass(frozen=True)
class Credential:
    """The public half of a registered passkey. There is no secret in here."""

    credential_id: str
    public_key_spki_b64: str
    algorithm: int
    origin: str
    #: The relying-party hash the authenticator used at registration (first 32 bytes of its
    #: authenticator data). Every later answer must carry the same one.
    rp_id_hash_b64: str

    def to_json(self) -> dict[str, Any]:
        return {
            "credential_id": self.credential_id,
            "public_key_spki_b64": self.public_key_spki_b64,
            "algorithm": self.algorithm,
            "origin": self.origin,
            "rp_id_hash_b64": self.rp_id_hash_b64,
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Credential:
        return cls(
            credential_id=str(raw["credential_id"]),
            public_key_spki_b64=str(raw["public_key_spki_b64"]),
            algorithm=int(raw["algorithm"]),
            origin=str(raw["origin"]),
            rp_id_hash_b64=str(raw["rp_id_hash_b64"]),
        )


def allowed_rp_hashes(origin: str) -> set[bytes]:
    """The relying-party ids a browser may use for an extension page: its host, or the full
    origin (Chromium uses the origin for `chrome-extension://` pages)."""
    return {
        hashlib.sha256(rp_id_of(origin).encode()).digest(),
        hashlib.sha256(origin.encode()).digest(),
    }


def _client_data(raw_b64: str, *, expected_type: str, challenge: str, origin: str) -> bytes:
    try:
        raw = b64url_decode(raw_b64)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise PasskeyError("the client data is not readable") from exc
    if not isinstance(data, dict) or data.get("type") != expected_type:
        raise PasskeyError("the client data is for a different ceremony")
    if not secrets.compare_digest(str(data.get("challenge", "")), challenge):
        raise PasskeyError("the passkey signed a different challenge")
    if data.get("origin") != origin:
        raise PasskeyError("the passkey answer came from a different origin")
    return raw


def rp_id_of(origin: str) -> str:
    """The relying-party id of an extension page is the extension's id (its host)."""
    return origin.split("://", 1)[-1].split("/", 1)[0]


def register(payload: dict[str, Any], *, challenge: str, origin: str) -> Credential:
    """Accept a new passkey. Trust on first use: the attestation is not examined."""
    for name in (
        "credential_id",
        "client_data_json",
        "public_key_spki",
        "algorithm",
        "authenticator_data",
    ):
        if name not in payload:
            raise PasskeyError(f"the registration is missing {name}")
    try:
        auth_data = b64url_decode(str(payload["authenticator_data"]))
    except ValueError as exc:
        raise PasskeyError("the registration's authenticator data is not readable") from exc
    if len(auth_data) < 37 or auth_data[:32] not in allowed_rp_hashes(origin):
        raise PasskeyError("the passkey was made for a different relying party")
    if not auth_data[32] & FLAG_USER_VERIFIED:
        raise PasskeyError("the authenticator did not verify the person at registration")
    _client_data(
        str(payload["client_data_json"]),
        expected_type="webauthn.create",
        challenge=challenge,
        origin=origin,
    )
    algorithm = payload["algorithm"]
    if algorithm not in (ES256, RS256):
        raise PasskeyError("only ES256 and RS256 passkeys are supported")
    spki = str(payload["public_key_spki"])
    try:
        key = serialization.load_der_public_key(b64url_decode(spki))
    except ValueError as exc:
        raise PasskeyError("the passkey's public key is not readable") from exc
    if algorithm == ES256 and not (
        isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
    ):
        raise PasskeyError("an ES256 passkey must use the P-256 curve")
    if algorithm == RS256 and not isinstance(key, rsa.RSAPublicKey):
        raise PasskeyError("an RS256 passkey must be an RSA key")
    return Credential(
        credential_id=str(payload["credential_id"]),
        public_key_spki_b64=spki,
        algorithm=int(algorithm),
        origin=origin,
        rp_id_hash_b64=b64url_encode(auth_data[:32]),
    )


def verify_assertion(credential: Credential, payload: dict[str, Any], *, challenge: str) -> None:
    """Raise `PasskeyError` unless this is a fresh, user-verified signature by `credential`."""
    for name in ("credential_id", "client_data_json", "authenticator_data", "signature"):
        if name not in payload:
            raise PasskeyError(f"the passkey answer is missing {name}")
    if not secrets.compare_digest(str(payload["credential_id"]), credential.credential_id):
        raise PasskeyError("this is not the passkey that was registered")
    client_data = _client_data(
        str(payload["client_data_json"]),
        expected_type="webauthn.get",
        challenge=challenge,
        origin=credential.origin,
    )
    try:
        auth_data = b64url_decode(str(payload["authenticator_data"]))
        signature = b64url_decode(str(payload["signature"]))
    except ValueError as exc:
        raise PasskeyError("the passkey answer is not readable") from exc
    if len(auth_data) < 37:
        raise PasskeyError("the authenticator data is too short")
    expected_rp = b64url_decode(credential.rp_id_hash_b64)
    if not secrets.compare_digest(auth_data[:32], expected_rp):
        raise PasskeyError("the passkey answered for a different relying party")
    flags = auth_data[32]
    if not flags & FLAG_USER_PRESENT:
        raise PasskeyError("the authenticator did not see a person")
    if not flags & FLAG_USER_VERIFIED:
        raise PasskeyError("the authenticator did not verify the person (fingerprint, face or PIN)")
    signed = auth_data + hashlib.sha256(client_data).digest()
    key = serialization.load_der_public_key(b64url_decode(credential.public_key_spki_b64))
    try:
        if credential.algorithm == ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif credential.algorithm == RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise PasskeyError("the stored passkey does not match its algorithm")
    except InvalidSignature as exc:
        raise PasskeyError("the passkey signature does not verify") from exc
