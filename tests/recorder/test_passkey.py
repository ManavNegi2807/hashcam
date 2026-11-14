"""The passkey check on its own: no database, no binaries. Each rule is broken once."""

from __future__ import annotations

import pytest

from services.recorder import passkey
from tests.recorder.softkey import SoftPasskey


def registered(soft: SoftPasskey) -> passkey.Credential:
    challenge = passkey.new_challenge()
    return passkey.register(soft.registration(challenge), challenge=challenge, origin=soft.origin)


def test_a_fresh_user_verified_answer_is_accepted() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
    passkey.verify_assertion(cred, soft.assertion(challenge), challenge=challenge)


def test_an_answer_for_the_other_decision_is_refused() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    signed_deny = soft.assertion(passkey.approval_challenge("DENIED", "ab" * 32))
    with pytest.raises(passkey.PasskeyError, match="different challenge"):
        passkey.verify_assertion(
            cred, signed_deny, challenge=passkey.approval_challenge("GRANTED", "ab" * 32)
        )


def test_an_answer_for_other_text_is_refused() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    answer = soft.assertion(passkey.approval_challenge("GRANTED", "cd" * 32))
    with pytest.raises(passkey.PasskeyError):
        passkey.verify_assertion(
            cred, answer, challenge=passkey.approval_challenge("GRANTED", "ab" * 32)
        )


def test_another_authenticator_is_refused() -> None:
    cred = registered(SoftPasskey())
    stranger = SoftPasskey()
    stranger.credential_id = cred.credential_id  # same id, different key
    challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
    with pytest.raises(passkey.PasskeyError, match="does not verify"):
        passkey.verify_assertion(cred, stranger.assertion(challenge), challenge=challenge)


def test_presence_without_verification_is_refused() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    soft.user_verified = False
    challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
    with pytest.raises(passkey.PasskeyError, match="did not verify the person"):
        passkey.verify_assertion(cred, soft.assertion(challenge), challenge=challenge)


def test_a_web_page_origin_is_refused() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
    with pytest.raises(passkey.PasskeyError, match="different origin"):
        passkey.verify_assertion(
            cred, soft.assertion(challenge, origin="https://evil.example"), challenge=challenge
        )


def test_both_known_relying_party_forms_register() -> None:
    for as_origin in (True, False):
        soft = SoftPasskey(rp_id_is_origin=as_origin)
        cred = registered(soft)
        challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
        passkey.verify_assertion(cred, soft.assertion(challenge), challenge=challenge)


def test_a_passkey_made_for_another_site_is_refused() -> None:
    import hashlib

    soft = SoftPasskey()
    challenge = passkey.new_challenge()
    payload = soft.registration(challenge)
    payload["authenticator_data"] = passkey.b64url_encode(
        hashlib.sha256(b"evil.example").digest() + bytes([0x45]) + bytes(4)
    )
    with pytest.raises(passkey.PasskeyError, match="different relying party"):
        passkey.register(payload, challenge=challenge, origin=soft.origin)


def test_a_tampered_signature_is_refused() -> None:
    soft = SoftPasskey()
    cred = registered(soft)
    challenge = passkey.approval_challenge("GRANTED", "ab" * 32)
    answer = soft.assertion(challenge)
    raw = passkey.b64url_decode(answer["signature"])
    answer["signature"] = passkey.b64url_encode(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(passkey.PasskeyError):
        passkey.verify_assertion(cred, answer, challenge=challenge)
