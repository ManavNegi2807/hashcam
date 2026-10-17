"""Redaction at ingestion (`D-11`), without a database or the Rust binary.

These pin the behavior around the one place a clear secret is handled in
Python: `Repository._redact`. The commitment itself is computed by the Rust core
(`abb commit`); here a fake stands in so the Python logic is tested alone.
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from typing import Any

import pytest

from services.api.canonical import Canonicalizer
from services.api.errors import AbbError
from services.api.repository import Repository

SECRET = "4111111111111111"  # a published fake test card number


class FakeCanonicalizer:
    def __init__(self) -> None:
        self.seen: list[bytes] = []

    def commit(self, value_json: bytes) -> tuple[str, str]:
        self.seen.append(value_json)
        return "00" * 16, "ab" * 32


def make() -> tuple[Repository, FakeCanonicalizer]:
    fake = FakeCanonicalizer()
    return Repository(connect=None, canonicalizer=fake), fake  # type: ignore[arg-type]


def body(**changes: Any) -> bytes:
    event: dict[str, Any] = {
        "event_type": "ACTION_REQUESTED",
        "source": "observed_by_local_gateway",
        "payload": {"action_id": "a1", "typed_value": SECRET},
    }
    event.update(changes)
    return json.dumps(event).encode()


def test_a_listed_field_is_replaced_by_its_commitment() -> None:
    repo, fake = make()
    out, disclosures = repo._redact(body(), {"ACTION_REQUESTED": ["typed_value"]})
    event = json.loads(out)
    assert "typed_value" not in event["payload"]
    assert SECRET.encode() not in out
    assert event["commitments"] == {"typed_value": "ab" * 32}
    assert event["payload"]["action_id"] == "a1"
    assert [d[0] for d in disclosures] == ["typed_value"]
    # The clear value goes to the secret store, not the ledger bytes.
    assert disclosures[0][2] == json.dumps(SECRET).encode()
    assert fake.seen == [json.dumps(SECRET).encode()]


def test_other_event_types_and_other_fields_are_untouched() -> None:
    repo, fake = make()
    original = body(event_type="BROWSER_OBSERVATION")
    out, disclosures = repo._redact(original, {"ACTION_REQUESTED": ["typed_value"]})
    assert out == original
    assert disclosures == []
    assert fake.seen == []


def test_a_listed_field_that_is_absent_changes_nothing() -> None:
    repo, _ = make()
    original = body(payload={"action_id": "a1"})
    out, disclosures = repo._redact(original, {"ACTION_REQUESTED": ["typed_value"]})
    assert out == original
    assert disclosures == []


def test_a_duplicate_key_is_refused_before_anything_is_committed() -> None:
    repo, fake = make()
    dup = b'{"event_type":"ACTION_REQUESTED","payload":{"typed_value":"a","typed_value":"b"}}'
    with pytest.raises(AbbError) as raised:
        repo._redact(dup, {"ACTION_REQUESTED": ["typed_value"]})
    assert raised.value.code == "DUPLICATE_KEY"
    assert fake.seen == []


def test_a_float_is_refused() -> None:
    repo, _ = make()
    floaty = b'{"event_type":"ACTION_REQUESTED","payload":{"typed_value":1.5}}'
    with pytest.raises(AbbError) as raised:
        repo._redact(floaty, {"ACTION_REQUESTED": ["typed_value"]})
    assert raised.value.code == "FLOAT_NOT_ALLOWED"


def test_a_body_that_is_not_json_is_a_syntax_error() -> None:
    repo, _ = make()
    with pytest.raises(AbbError) as raised:
        repo._redact(b"{not json", {"ACTION_REQUESTED": ["typed_value"]})
    assert raised.value.code == "SYNTAX_ERROR"


def test_a_malformed_envelope_is_left_for_the_core_to_reject() -> None:
    repo, _ = make()
    odd = b'{"event_type":"ACTION_REQUESTED","payload":"not an object"}'
    out, disclosures = repo._redact(odd, {"ACTION_REQUESTED": ["typed_value"]})
    assert out == odd
    assert disclosures == []


def test_the_secret_goes_to_the_commit_tool_on_stdin_never_in_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process list must not show a card number."""
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv: list[str], **kwargs: Any) -> Any:
        calls.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0, stdout=f"salt_hex={'00' * 16}\ncommitment={'ab' * 32}\n".encode()
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    Canonicalizer("abb").commit(json.dumps(SECRET).encode())
    argv, kwargs = calls[0]
    assert SECRET not in " ".join(argv)
    assert kwargs["input"] == json.dumps(SECRET).encode()
    assert "--stdin" in argv


def test_every_shipped_policy_still_loads() -> None:
    """A policy that hides a protected field must not ship."""
    from policy.engine import VERSIONS_DIR, Policy

    names = sorted(p.name for p in VERSIONS_DIR.glob("*.json"))
    assert "redacting.v1.json" in names
    for name in names:
        policy_id, _, rest = name.partition(".v")
        Policy.load(policy_id, int(rest.removesuffix(".json")))
