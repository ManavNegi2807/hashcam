"""Registering a signed mandate (`PROTOCOL.md` 5.7, D-16).

The signature is checked by the Rust core (`abb mandate check`) against the key
manifest, never in Python. A mandate nobody with a `mandate_issuer` key signed is
refused, so a run cannot be tied to instructions that were made up afterwards.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pathsafe
from policy.mandate import MandateError, SignedMandate

from .errors import AbbError
from .repository import Repository


def register_mandate(
    repo: Repository,
    *,
    abb_path: str,
    key_manifest_path: str | None,
    document_b64: str,
    signature: str,
) -> dict[str, Any]:
    if not key_manifest_path:
        # Fail closed: no manifest, nothing to check an issuer against.
        raise AbbError("DEPENDENCY_UNAVAILABLE", "no key manifest is configured on this service")
    try:
        mandate = SignedMandate.verified(
            document_b64=document_b64,
            signature=signature,
            keys_path=key_manifest_path,
            abb_path=abb_path,
        )
    except MandateError as exc:
        text = str(exc)
        if "UNKNOWN_ISSUER" in text:
            raise AbbError("UNKNOWN_ISSUER", "the issuer is not a mandate_issuer key") from None
        if "BAD_SIGNATURE" in text:
            raise AbbError("BAD_SIGNATURE", "the mandate signature does not verify") from None
        raise AbbError("VALIDATION_FAILED", "the mandate was not accepted") from None

    # The mandates table references the key registry, so make sure the issuer's
    # entry from the verified manifest is there.
    listed = json.loads(pathsafe.read_text(Path(key_manifest_path)))["keys"]
    for entry in listed:
        if entry["key_id"] == mandate.issuer_key_id:
            repo.ensure_key(entry)
    repo.store_mandate(
        mandate_id=mandate.mandate_id,
        document=base64.b64decode(mandate.document_b64),
        signature=mandate.signature,
        issuer_key_id=mandate.issuer_key_id,
    )
    return {"mandate_id": mandate.mandate_id, "mandate_digest": mandate.digest}
