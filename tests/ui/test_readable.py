"""The plain-language reader (ui/readable.js): what people read instead of JSON, and what is hidden.

* Events read as sentences, for the recorder's timeline, receipt events and sandbox events alike.
* Raw records are never the default, and a sensitive record's raw form is never produced at all.
* Passwords, tokens, card numbers, emails and URL query strings never reach the page.

The same file is used by the console and the extension (ES module) and by the site (a generated
classic script); the last tests check that those copies cannot drift. Needs only a browser.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from typing import Any

import pytest

from tests.ui.sitehelp import REPO, SITE

sync_api = pytest.importorskip("playwright.sync_api")


@pytest.fixture(scope="module")
def reader() -> Iterator[Any]:
    """A blank page with the classic build loaded, so nothing else can interfere."""
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto("about:blank")
        page.add_script_tag(path=str(SITE / "readable.js"))
        yield page
        browser.close()


def describe(page: Any, event: Any, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = page.evaluate("([e, c]) => HCReadable.describe(e, c)", [event, ctx or {}])
    return out


def technical(page: Any, event: Any, ctx: dict[str, Any] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = page.evaluate(
        "([e, c]) => HCReadable.technical(e, c)", [event, ctx or {}]
    )
    return out


def call(page: Any, name: str, *args: Any) -> Any:
    return page.evaluate(f"(a) => HCReadable.{name}(...a)", list(args))


# ---------------------------------------------------------------- sentences


@pytest.mark.parametrize(
    ("event", "title", "badge", "tone", "why"),
    [
        (
            {
                "kind": "navigate",
                "status": "ALLOWED",
                "target": "https://shop.test/cart?token=abc",
                "reasons": ["ALLOWED_BY_POLICY"],
            },
            "Opened shop.test/cart",
            "Allowed",
            "ok",
            "The rules allow it",
        ),
        (
            {
                "kind": "navigate",
                "status": "BLOCKED",
                "target": "https://evil.test/x",
                "reasons": ["MANDATE_VIOLATION", "DOMAIN_NOT_ALLOWED"],
            },
            "Stopped from opening evil.test/x",
            "Blocked",
            "stop",
            "outside what this agent's passport allows",
        ),
        (
            {"kind": "form_submit", "status": "WAITING", "target": "https://shop.test/pay"},
            "Wants to send a form to shop.test/pay",
            "Needs a person",
            "hold",
            "A person has to approve this first",
        ),
        (
            {"kind": "form_submit", "status": "APPROVED", "target": "https://shop.test/pay"},
            "Sent a form to shop.test/pay",
            "Approved",
            "ok",
            "A person approved it with a passkey",
        ),
        (
            {"kind": "download", "status": "TIMED_OUT", "target": "https://shop.test/f.zip"},
            "Did not download a file from shop.test/f.zip",
            "Not sent",
            "stop",
            "never sent",
        ),
        (
            {
                "kind": "secret",
                "status": "COMMITTED",
                "field_kind": "password",
                "target": "https://shop.test/login",
            },
            "Typed a password on shop.test/login",
            "Protected",
            "note",
            "never recorded",
        ),
    ],
)
def test_recorder_steps_read_as_sentences(
    reader: Any, event: dict[str, Any], title: str, badge: str, tone: str, why: str
) -> None:
    said = describe(reader, event)
    assert said["title"] == title
    assert said["badge"] == badge
    assert said["tone"] == tone
    assert why in said["why"]


def test_heads_ups_are_in_words(reader: Any) -> None:
    said = describe(
        reader,
        {
            "kind": "navigate",
            "status": "ALLOWED",
            "target": "https://shop.test/",
            "drift": {"host": "other.test"},
            "tripwire": {"verdict": "FLAG_FOR_REVIEW", "reasons": ["PROMPT_GUARD_ESCALATION"]},
        },
    )
    assert any("other.test is not one of the sites the task mentions" in n for n in said["notes"])
    assert any("tried to steer the agent" in n for n in said["notes"])


def test_receipt_and_sandbox_events_read_as_sentences(reader: Any) -> None:
    assert (
        describe(
            reader,
            {
                "event_type": "ACTION_BLOCKED",
                "payload": {"action_type": "navigate", "target": "https://evil.test/"},
            },
        )["title"]
        == "Stopped from opening evil.test"
    )
    assert (
        describe(reader, {"event_type": "RUN_FINISHED", "payload": {"outcome": "KILLED_BY_USER"}})[
            "why"
        ]
        == "The kill switch was pressed."
    )
    held = describe(
        reader,
        {
            "body": {
                "type": "POLICY_DECISION",
                "data": {
                    "rule": "HUMAN_SIGNOFF_REQUIRED",
                    "outcome": "HOLD",
                    "trigger_reason": "$35.00 is more than the $10.00 the agent may spend alone",
                },
            }
        },
    )
    assert held["title"] == "Held for a person to sign"
    assert held["why"] == "$35.00 is more than the $10.00 the agent may spend alone."
    denied = describe(
        reader,
        {
            "type": "POLICY_DECISION",
            "data": {
                "rule": "DOMAIN_NOT_ALLOWED",
                "outcome": "DENY",
                "trigger_reason": "hooks.partner-sync.example is not on the allow-list",
            },
        },
    )
    assert denied["why"] == "hooks.partner-sync.example is not on the allow-list."  # host untouched


def test_a_code_nobody_wrote_words_for_still_reads_as_words(reader: Any) -> None:
    assert call(reader, "reasonText", "SOME_NEW_CODE") == "Some new code."
    assert (
        call(reader, "reasonText", "R2 OVER_BUDGET")
        == "It costs more than what is left of the budget."
    )
    event = {"event_type": "BRAND_NEW_EVENT", "payload": {}}
    assert describe(reader, event)["title"] == "Brand new event"
    assert describe(reader, None)["badge"] == "Unreadable"


@pytest.mark.parametrize(
    "code",
    [
        "DOMAIN_NOT_ALLOWED", "DOMAIN_DENIED", "HOST_NOT_IN_TASK", "ACTION_TYPE_NOT_ALLOWED",
        "MANDATE_VIOLATION", "OVER_AMOUNT_LIMIT", "OVER_ACTION_LIMIT", "OVER_BUDGET",
        "BUDGET_RESERVE_REACHED", "APPROVAL_REQUIRED", "REQUIRE_APPROVAL", "APPROVAL_GRANTED",
        "APPROVAL_DENIED", "APPROVAL_NOT_RECEIVED", "ALLOWED_BY_POLICY", "TARGET_NOT_A_URL",
        "SSRF_BLOCKED", "PROMPT_GUARD_ESCALATION", "PAYMENT_KEY_MISSING",
        "PAYMENT_KEY_NOT_TEST_MODE", "PROVIDER_QUOTA_EXHAUSTED",
    ],
)  # fmt: skip
def test_every_policy_reason_has_its_own_sentence(reader: Any, code: str) -> None:
    fallback = call(reader, "humanize", code) + "."
    assert call(reader, "reasonText", code) != fallback, code


def test_the_verdict_is_restated_without_claiming_honesty(reader: Any) -> None:
    valid = call(reader, "verdictText", "VALID")
    assert "has not been changed" in valid and "does not mean the agent was honest" in valid
    assert "Do not trust it" in call(reader, "verdictText", "INVALID")
    assert "cannot be called valid" in call(reader, "verdictText", "UNKNOWN")
    assert (
        call(reader, "dimensionText", "evidence_integrity") == "Nothing in the record was changed"
    )
    assert call(reader, "statusText", "FAIL") == "Problem"


# ---------------------------------------------------------------- what is never shown


def test_a_query_string_never_reaches_the_page(reader: Any) -> None:
    event = {
        "kind": "navigate",
        "status": "ALLOWED",
        "target": "https://shop.test/a?token=SECRET#f",
    }
    assert "SECRET" not in repr(describe(reader, event))
    raw = technical(reader, event)
    assert raw["withheld"] is False and "SECRET" not in raw["text"]
    assert call(reader, "safeUrl", "https://user:pw@shop.test/a/b?x=1#y") == "shop.test/a/b"
    assert call(reader, "safeUrl", "javascript:alert(1)") == ""


def test_values_behind_sensitive_names_are_masked(reader: Any) -> None:
    redacted = call(
        reader,
        "redact",
        {
            "password": "hunter2",
            "apiKey": "k-123",
            "Authorization": "x",
            "session_id": "s",
            "note": "mail jane.doe@example.com",
            "ok": 5,
            "nested": {"token": "t", "keep": "fine"},
            "empty": {"token": ""},
        },
    )
    assert redacted["password"] == redacted["apiKey"] == redacted["Authorization"] == "••••"
    assert redacted["session_id"] == "••••" and redacted["nested"]["token"] == "••••"
    assert redacted["nested"]["keep"] == "fine" and redacted["ok"] == 5
    assert redacted["empty"]["token"] == ""  # nothing to hide
    assert "jane.doe" not in redacted["note"] and "@example.com" in redacted["note"]


def test_names_are_matched_as_whole_words(reader: Any) -> None:
    for harmless in (
        "passport",
        "key_id",
        "public_key_jwk",
        "keys_json",
        "signature",
        "commitment",
    ):
        assert call(reader, "isSensitiveKey", harmless) is False, harmless
    for sensitive in ("password", "apiKey", "STRIPE_SECRET_KEY", "card_number", "fencing_token"):
        assert call(reader, "isSensitiveKey", sensitive) is True, sensitive


@pytest.mark.parametrize(
    "text",
    [
        "Bearer abcdefgh12345678",
        "sk_live_abcdefgh",
        "ghp_" + "a" * 24,
        "AKIA" + "A" * 16,
        "4242 4242 4242 4242",
        "123-45-6789",
        "someone@example.com",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
    ],
)
def test_secret_looking_text_is_recognised(reader: Any, text: str) -> None:
    assert call(reader, "looksSecret", text) is True
    assert text not in call(reader, "scrub", f"here: {text} end")


def test_ordinary_text_is_left_alone(reader: Any) -> None:
    for text in ("hello world", "1234 5678 9012 3456", "a" * 64, "shop.test/cart"):
        assert call(reader, "looksSecret", text) is False, text


@pytest.mark.parametrize(
    "event",
    [
        {
            "kind": "secret",
            "status": "COMMITTED",
            "field_kind": "password",
            "commitment": "ab" * 32,
        },
        {"kind": "navigate", "status": "ALLOWED", "target": "https://x.test/?email=a@b.co"},
        {"kind": "form_submit", "status": "ALLOWED", "payload": {"password": "hunter2"}},
        {"kind": "form_submit", "status": "ALLOWED", "note": "card 4242 4242 4242 4242"},
        {"kind": "navigate", "status": "ALLOWED", "sensitive": True},
    ],
)
def test_a_sensitive_record_never_gets_a_raw_form(reader: Any, event: dict[str, Any]) -> None:
    raw = technical(reader, event)
    assert raw["withheld"] is True
    assert (
        "hunter2" not in raw["text"] and "4242" not in raw["text"] and "a@b.co" not in raw["text"]
    )
    assert raw["text"].startswith("Not shown")


def test_a_sensitive_agent_hides_every_raw_record_and_the_path(reader: Any) -> None:
    event = {
        "kind": "navigate",
        "status": "ALLOWED",
        "target": "https://bank.test/accounts/12/statement",
    }
    ctx = {"sensitive": True}
    assert technical(reader, event, ctx)["withheld"] is True
    said = describe(reader, event, ctx)
    assert said["title"] == "Opened bank.test" and said["sensitive"] is True
    assert "accounts" not in repr(said)
    assert (
        technical(reader, event)["withheld"] is False
    )  # an ordinary agent's step still can be read


def test_nothing_an_agent_wrote_can_inject_markup(reader: Any) -> None:
    hostile = '<img src=x onerror="window.pwned=1">'
    result = reader.evaluate(
        """(h) => {
            const s = HCReadable.describe({ kind: "navigate", status: "BLOCKED", target: "https://x.test/",
                                            reasons: [h] }, {});
            const root = HCReadable.storyNode(document, s, HCReadable.technical({ kind: h }, {}));
            const li = HCReadable.stripNode(document, s, null, h);
            document.body.append(root, li);
            return { imgs: document.querySelectorAll("img").length, pwned: window.pwned === 1,
                     text: root.textContent + li.textContent };
        }""",
        hostile,
    )
    assert result["imgs"] == 0 and result["pwned"] is False
    assert "<img" in result["text"]  # shown as plain text, not built into the page


def test_story_nodes_close_the_technical_details_by_default(reader: Any) -> None:
    opened = reader.evaluate(
        """() => {
            const e = { kind: "navigate", status: "ALLOWED", target: "https://shop.test/" };
            const n = HCReadable.storyNode(
                document, HCReadable.describe(e, {}), HCReadable.technical(e, {}));
            const d = n.querySelector("details.tech");
            return { has: !!d, open: d.open, label: d.querySelector("summary").textContent };
        }"""
    )
    assert opened == {"has": True, "open": False, "label": "Technical details"}


# ---------------------------------------------------------------- one source, three copies


def test_the_site_copy_is_generated_from_the_ui_source() -> None:
    sys.path.insert(0, str(REPO / "tools"))
    from build_site import to_classic  # type: ignore[import-not-found]

    source = (REPO / "ui" / "readable.js").read_text(encoding="utf-8")
    assert (SITE / "readable.js").read_text(encoding="utf-8") == to_classic(
        source, "readable", "HCReadable"
    ), "run: python tools/build_site.py"


def test_the_extension_copy_is_identical_to_the_ui_source() -> None:
    for name in ("readable.js", "theme.css", "fx3d.js"):
        assert (REPO / "ui" / name).read_bytes() == (REPO / "extension" / name).read_bytes(), name
