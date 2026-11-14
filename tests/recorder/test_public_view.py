"""What the website's viewer may see of a session (services/recorder/public.py). No stack needed."""

from __future__ import annotations

from typing import Any

from services.recorder.public import (
    HIDDEN_HOST,
    WAITING_NOTICE,
    WITHHELD_TASK,
    public_row,
    public_view,
    strip_url,
)


def _view(*, sensitive: bool) -> dict[str, Any]:
    return {
        "session_id": "abc123abc123",
        "agent": "Agent",
        "task": "Pay the invoice at bank.test",
        "sensitive": sensitive,
        "passport": {
            "hosts": ["bank.test"],
            "minutes": 30,
            "max_spend_minor_units": 5000,
            "expires_at": 1,
            "mandate_id": "m-1",
        },
        "state": "recording",
        "timeline": [
            {
                "n": 1,
                "kind": "navigate",
                "status": "ALLOWED",
                "target": "https://user:pw@bank.test:8443/accounts/42?token=SECRET#frag",
                "snapshot": 0,
                "drift": {"reason": "HOST_NOT_IN_TASK", "host": "x.test", "task_hosts": ["a.test"]},
            },
            {"n": 2, "kind": "SESSION", "status": "RECORDING", "target": ""},
        ],
        "waiting": [
            {
                "action_id": "form-submit-3",
                "summary": "Agent | Agent wants to submit a form to bank.test (fields: iban, pin)",
                "summary_digest": "d" * 64,
                "seconds_left": 90,
            }
        ],
    }


def test_strip_url_drops_query_fragment_and_credentials() -> None:
    url = "https://user:pw@bank.test:8443/accounts/42?token=SECRET#frag"
    assert strip_url(url, keep_path=True) == "https://bank.test:8443/accounts/42"
    assert strip_url(url, keep_path=False) == "https://bank.test:8443"
    assert strip_url("javascript:alert(1)", keep_path=True) == ""
    assert strip_url("not a url", keep_path=True) == ""
    assert strip_url("https://[::1", keep_path=True) == ""


def test_the_site_never_sees_query_strings_or_approval_text() -> None:
    out = public_view(_view(sensitive=False))
    first = out["timeline"][0]
    assert first["target"] == "https://bank.test:8443/accounts/42"
    assert "task_hosts" not in first["drift"] and first["drift"]["host"] == "x.test"
    assert first["snapshot"] == 0  # screenshots stay available for an ordinary agent
    assert out["task"] == "Pay the invoice at bank.test"
    assert out["passport"]["hosts"] == ["bank.test"] and "mandate_id" not in out["passport"]
    assert out["waiting"] == [
        {"action_id": "form-submit-3", "summary": WAITING_NOTICE, "seconds_left": 90}
    ]
    assert "SECRET" not in repr(out) and "iban" not in repr(out)


def test_a_sensitive_agent_is_cut_down_further() -> None:
    out = public_view(_view(sensitive=True))
    assert out["task"] == WITHHELD_TASK
    assert out["passport"]["hosts"] == [HIDDEN_HOST]
    assert "max_spend_minor_units" not in out["passport"]
    assert out["timeline"][0]["target"] == "https://bank.test:8443"
    assert "snapshot" not in out["timeline"][0]
    assert "bank.test" not in out["task"] and "accounts" not in repr(out["timeline"])


def test_the_original_view_is_not_changed() -> None:
    view = _view(sensitive=True)
    public_view(view)
    assert view["task"].startswith("Pay the invoice")
    assert view["timeline"][0]["target"].startswith("https://user:pw@")


def test_the_session_list_hides_a_sensitive_task() -> None:
    row = {"session_id": "x", "agent": "A", "task": "secret plan", "sensitive": True}
    assert public_row(row)["task"] == WITHHELD_TASK
    plain = {"session_id": "x", "agent": "A", "task": "read docs", "sensitive": False}
    assert public_row(plain) == plain
