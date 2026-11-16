"""Pro part 2: the Policy Studio (free to try, Pro to export and import) and Compare two runs (Pro).

* The policy fields are checked one by one; bad input is refused with a plain message and never fixed.
* A custom policy changes the sandbox's decisions as expected, says so on the page, and its record carries
  the policy (in the first event, so the hash chain commits to it). The Range does not score such a record.
* The exported policy file is labelled "sandbox policy only"; export then import gives the same policy.
* Compare shows better, worse and same per check and never says "better overall" when a check got worse; a
  record that does not check out is never compared.

Needs only a browser (and pypdf for the report check).
"""

# ruff: noqa: E501

from __future__ import annotations

import base64
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tests.ui.test_motion import WATCH, Watch
from tests.ui.test_pro import licence, open_page, pdf_text
from tests.ui.test_range import BUTTON, export_run
from tools import make_license as ml

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

STANDARD = {
    "id": "sandbox-policy/1",
    "budget_cents": 10000,
    "auto_limit_cents": 1000,
    "allow_domains": ["docs.github.com", "api.gpu-cloud.example", "tokens.example-bank.test"],
}


@pytest.fixture(scope="module")
def origin() -> Iterator[str]:
    with serve_site() as base:
        yield base


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture(scope="module")
def pair() -> tuple[Any, str]:
    return ml.make_keypair()


def custom(budget: int, auto: int, refuse: int | None, hosts: list[str]) -> dict[str, Any]:
    return {
        "id": "custom-policy/1",
        "budget_cents": budget,
        "auto_limit_cents": auto,
        "refuse_over_cents": refuse,
        "allow_domains": hosts,
    }


ALL_HOSTS = [
    "docs.github.com",
    "hooks.partner-sync.example",
    "api.gpu-cloud.example",
    "tokens.example-bank.test",
]


def fragment(policy: dict[str, Any]) -> str:
    raw = json.dumps(policy, separators=(",", ":")).encode("utf-8")
    return "#policy=" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------- the policy fields


def form(
    page: Any,
    budget: str = "100",
    auto: str = "10",
    refuse: str = "",
    hosts: str = "docs.github.com",
) -> dict[str, Any]:
    result: dict[str, Any] = page.evaluate(
        "([b, a, r, h]) => HCPolicy.fromForm({ budget: b, autoLimit: a, refuseOver: r, hosts: h })",
        [budget, auto, refuse, hosts],
    )
    return result


def test_good_values_make_a_policy_and_bad_ones_are_refused_field_by_field(
    browser: Any, origin: str
) -> None:
    page, _, ctx = open_page(browser, origin, "policy.html")
    ok = form(
        page, "100.50", "10", "50", "docs.github.com, API.gpu-cloud.example\nmail.example.org"
    )
    assert ok["ok"] is True
    assert ok["policy"] == custom(
        10050, 1000, 5000, ["docs.github.com", "api.gpu-cloud.example", "mail.example.org"]
    ), "host names are lower-cased and trimmed, nothing more"
    assert form(page, "1", "0", "", "a.example")["ok"] is True, (
        "the smallest budget, a zero approval limit"
    )
    assert form(page, "10000", "10000", "10000", "a.example")["ok"] is True, (
        "the largest budget, limits equal to it"
    )

    cases = [
        # (budget, auto, refuse, hosts, field, message part)
        ("", "10", "", "a.example", "budget", "Enter the budget"),
        ("abc", "10", "", "a.example", "budget", "Enter the budget"),
        ("-5", "10", "", "a.example", "budget", "Enter the budget"),
        ("1e3", "10", "", "a.example", "budget", "Enter the budget"),
        ("5,000", "10", "", "a.example", "budget", "Enter the budget"),
        ("$100", "10", "", "a.example", "budget", "Enter the budget"),
        ("100.123", "10", "", "a.example", "budget", "two decimals"),
        ("0.99", "0", "", "a.example", "budget", "between $1.00 and $10,000.00"),
        ("10000.01", "10", "", "a.example", "budget", "between $1.00 and $10,000.00"),
        ("100", "", "", "a.example", "autoLimit", "Enter the amount"),
        ("100", "ten", "", "a.example", "autoLimit", "Enter the amount"),
        ("100", "100.01", "", "a.example", "autoLimit", "cannot be more than the budget"),
        ("100", "10", "x", "a.example", "refuseOver", "Leave this empty"),
        ("100", "10", "9.99", "a.example", "refuseOver", "cannot be less than the approval limit"),
        ("100", "10", "100.01", "a.example", "refuseOver", "cannot be more than the budget"),
        ("100", "10", "", "", "hosts", "at least one"),
        ("100", "10", "", "http://docs.github.com", "hosts", "not a plain host name"),
        ("100", "10", "", "docs.github.com:443", "hosts", "not a plain host name"),
        ("100", "10", "", "docs.github.com/path", "hosts", "not a plain host name"),
        ("100", "10", "", "*.example.com", "hosts", "not a plain host name"),
        ("100", "10", "", "localhost", "hosts", "not a plain host name"),
        ("100", "10", "", "10.0.0.1", "hosts", "not a plain host name"),
        ("100", "10", "", "-bad.example.com", "hosts", "not a plain host name"),
        ("100", "10", "", "a..example.com", "hosts", "not a plain host name"),
        ("100", "10", "", "x" * 64 + ".example.com", "hosts", "not a plain host name"),
        ("100", "10", "", "a.example, a.example", "hosts", "listed twice"),
        (
            "100",
            "10",
            "",
            ",".join(f"h{i}.example.com" for i in range(21)),
            "hosts",
            "Too many hosts",
        ),
    ]
    for budget, auto, refuse, hosts, field, part in cases:
        got = form(page, budget, auto, refuse, hosts)
        assert got["ok"] is False, (budget, auto, refuse, hosts)
        assert part in got["errors"][field], (field, got["errors"])
    # several problems at once: each field has its own message
    many = form(page, "abc", "ten", "x", "")
    assert set(many["errors"]) == {"budget", "autoLimit", "refuseOver", "hosts"}
    ctx.close()


def test_a_policy_that_arrives_as_data_is_checked_just_as_hard(browser: Any, origin: str) -> None:
    page, _, ctx = open_page(browser, origin, "policy.html")
    good = custom(5000, 500, None, ["docs.github.com"])

    def check(value: Any) -> dict[str, Any]:
        result: dict[str, Any] = page.evaluate("(v) => HCPolicy.check(v)", value)
        return result

    assert check(good)["ok"] is True
    assert check({**good, "extra": 1})["ok"] is False, "an unknown field is refused"
    assert check({**good, "id": "sandbox-policy/1"})["ok"] is False
    assert check({**good, "budget_cents": 50.5})["ok"] is False, "cents are whole numbers"
    assert check({**good, "budget_cents": "5000"})["ok"] is False
    assert check({**good, "auto_limit_cents": 6000})["ok"] is False
    assert check({**good, "allow_domains": ["Docs.github.com"]})["ok"] is False, (
        "data is not lower-cased for you"
    )
    assert check({**good, "allow_domains": "docs.github.com"})["ok"] is False
    assert check({**good, "allow_domains": []})["ok"] is False
    for junk in (None, 5, "x", [], [1]):
        assert check(junk)["ok"] is False
    ctx.close()


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        # standard rules: docs allowed, webhook denied (host), gpu held, bulk denied (over the budget)
        (
            custom(10000, 1000, None, ALL_HOSTS[:1] + ALL_HOSTS[2:]),
            {
                "docs": ("ALLOW", "R3"),
                "webhook": ("DENY", "R1"),
                "gpu": ("HOLD", "R5"),
                "bulk": ("DENY", "R2"),
            },
        ),
        # a smaller budget and a per-step limit
        (
            custom(5000, 500, 2000, [ALL_HOSTS[0], ALL_HOSTS[2]]),
            {
                "docs": ("ALLOW", "R3"),
                "webhook": ("DENY", "R1"),
                "gpu": ("DENY", "R6"),
                "bulk": ("DENY", "R1"),
            },
        ),
        # a person only has to approve above $40: the $35 GPU goes through on its own
        (
            custom(10000, 4000, None, ALL_HOSTS),
            {
                "docs": ("ALLOW", "R3"),
                "webhook": ("ALLOW", "R3"),
                "gpu": ("ALLOW", "R4"),
                "bulk": ("DENY", "R2"),
            },
        ),
        # a big budget: the $250 purchase now waits for a person
        (
            custom(30000, 1000, None, ALL_HOSTS),
            {
                "docs": ("ALLOW", "R3"),
                "webhook": ("ALLOW", "R3"),
                "gpu": ("HOLD", "R5"),
                "bulk": ("HOLD", "R5"),
            },
        ),
        # a step limit below the approval band's top
        (
            custom(30000, 1000, 10000, ALL_HOSTS),
            {
                "docs": ("ALLOW", "R3"),
                "webhook": ("ALLOW", "R3"),
                "gpu": ("HOLD", "R5"),
                "bulk": ("DENY", "R6"),
            },
        ),
    ],
)
def test_a_policy_changes_what_the_four_test_flights_do(
    browser: Any, origin: str, policy: dict[str, Any], expected: dict[str, tuple[str, str]]
) -> None:
    page, _, ctx = open_page(browser, origin, "policy.html")
    rows = page.evaluate(
        "(p) => HCPolicy.preview(p).map((r) => [r.key, r.outcome, r.rule_id])", policy
    )
    assert {key: (outcome, rule) for key, outcome, rule in rows} == expected
    ctx.close()


def test_the_rules_are_listed_in_the_order_they_are_tried(browser: Any, origin: str) -> None:
    page, _, ctx = open_page(browser, origin, "policy.html")
    plain = page.evaluate(
        "(p) => HCPolicy.rules(p).map((r) => r[0].split(' ')[0])",
        custom(10000, 1000, None, ALL_HOSTS),
    )
    limited = page.evaluate(
        "(p) => HCPolicy.rules(p).map((r) => r[0].split(' ')[0])",
        custom(10000, 1000, 5000, ALL_HOSTS),
    )
    assert plain == ["R1", "R2", "R3", "R4", "R5"] and limited == [
        "R1",
        "R2",
        "R6",
        "R3",
        "R4",
        "R5",
    ]
    ctx.close()


# ---------------------------------------------------------------- the studio page


def test_the_studio_checks_as_you_type_and_only_lets_a_good_policy_through(
    browser: Any, origin: str
) -> None:
    page, watch, ctx = open_page(browser, origin, "policy.html")
    expect(page.locator("#polTry")).to_be_enabled()
    expect(page.locator("#preview")).to_be_visible()
    assert page.locator("#previewBody tr").count() == 4
    assert [r.split("\t")[3] for r in page.locator("#previewBody tr").all_inner_texts()] == [
        "ALLOW",
        "DENY",
        "HOLD for a person",
        "DENY",
    ]
    page.locator("#polBudget").fill("abc")
    expect(page.locator("#errBudget")).to_contain_text("Enter the budget")
    assert page.locator("#polBudget").get_attribute("aria-invalid") == "true"
    expect(page.locator("#polTry")).to_be_disabled()
    expect(page.locator("#preview")).to_be_hidden()
    page.locator("#polBudget").fill("100")
    page.locator("#polAuto").fill("500")
    expect(page.locator("#errAuto")).to_contain_text("cannot be more than the budget")
    page.locator("#polAuto").fill("40")
    page.locator("#polHosts").fill(
        "docs.github.com\nhooks.partner-sync.example\napi.gpu-cloud.example\ntokens.example-bank.test"
    )
    expect(page.locator("#polTry")).to_be_enabled()
    assert [r.split("\t")[3] for r in page.locator("#previewBody tr").all_inner_texts()] == [
        "ALLOW",
        "ALLOW",
        "ALLOW",
        "DENY",
    ]
    page.locator("#polReset").click()
    assert (
        page.locator("#polBudget").input_value() == "100"
        and page.locator("#polAuto").input_value() == "10"
    )
    assert page.locator("#polHosts").input_value().split("\n") == STANDARD["allow_domains"]
    watch.assert_clean()
    ctx.close()


# ---------------------------------------------------------------- the sandbox under a custom policy


def export_under(
    browser: Any, origin: str, tmp_path: Path, name: str, steps: list[str], policy: dict[str, Any]
) -> Path:
    page = browser.new_page(accept_downloads=True)
    page.set_default_timeout(20_000)
    page.goto(f"{origin}/sandbox.html{fragment(policy)}")
    expect(page.locator(".flight").first).to_be_enabled()
    for step in steps:
        page.get_by_role("button", name=BUTTON[step], exact=True).click()
        page.wait_for_timeout(450)
    with page.expect_download() as d:
        page.get_by_role("button", name="Export Verified Receipt (.html)").click()
    out = tmp_path / f"{name}.html"
    d.value.save_as(str(out))
    page.close()
    return out


def record_of(path: Path) -> dict[str, Any]:
    html = path.read_text(encoding="utf-8")
    block = html.split('<script type="application/json" id="receipt">', 1)[1].split("</script>", 1)[
        0
    ]
    data: dict[str, Any] = json.loads(block)
    return data


def test_the_sandbox_runs_a_custom_policy_says_so_and_decides_by_it(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    policy = custom(
        10000, 4000, None, ALL_HOSTS
    )  # a person only approves above $40: the $35 GPU goes through
    page = browser.new_page(accept_downloads=True)
    watch = Watch(page, origin)
    page.add_init_script(WATCH)
    page.goto(f"{origin}/sandbox.html{fragment(policy)}")
    expect(page.locator("#policyBanner")).to_be_visible()
    text = page.locator("#policyBanner").inner_text()
    assert (
        "Custom policy in use (custom-policy/1)" in text
        and "$100.00" in text
        and "above $40.00" in text
        and "4 allowed hosts" in text
    )
    assert (
        "not the real gateway" in text
        and page.locator("#policyBanner a").get_attribute("href") == "sandbox.html"
    )
    assert page.locator("#rulesId").inner_text() == "custom-policy/1"
    assert "$40.00 or less" in page.locator("#rulesBody").inner_text()
    expect(page.locator(".flight").first).to_be_enabled()
    page.get_by_role("button", name=BUTTON["gpu"], exact=True).click()
    page.wait_for_timeout(800)
    expect(page.locator("#mSpent")).to_have_text("$35.00")
    expect(page.locator("#signBtn")).to_be_disabled()
    page.get_by_role("button", name=BUTTON["webhook"], exact=True).click()
    page.wait_for_timeout(700)
    expect(page.locator("#mSpent")).to_have_text(
        "$35.00"
    )  # allowed (host is on this policy's list) but it moves no money
    with page.expect_download() as d:
        page.get_by_role("button", name="Export Verified Receipt (.html)").click()
    out = tmp_path / "custom.html"
    d.value.save_as(str(out))
    watch.assert_clean()
    page.close()
    data = record_of(out)
    first = data["events"][0]["body"]["data"]
    assert first["policy"] == "custom-policy/1" and first["policy_spec"] == policy, (
        "the chain commits to the rules used"
    )
    assert data["policy"]["id"] == "custom-policy/1" and data["policy"]["budget_cents"] == 10000
    decisions = [
        (e["body"]["data"]["outcome"], e["body"]["data"]["rule_id"])
        for e in data["events"]
        if e["body"]["type"] == "POLICY_DECISION"
    ]
    assert decisions == [("ALLOW", "R4"), ("ALLOW", "R3")]


def test_the_standard_sandbox_shows_no_banner_and_keeps_its_own_record(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    page = browser.new_page()
    page.goto(f"{origin}/sandbox.html")
    expect(page.locator("#policyBanner")).to_be_hidden()
    assert page.locator("#rulesId").inner_text() == "sandbox-policy/1"
    assert "R1 DOMAIN_NOT_ALLOWED" in page.locator("#rulesBody").inner_text()
    page.close()
    record = export_run(browser, origin, tmp_path, "std", ["docs"])
    first = record_of(record)["events"][0]["body"]["data"]
    assert first["policy"] == "sandbox-policy/1" and "policy_spec" not in first, (
        "a standard record is unchanged"
    )


@pytest.mark.parametrize(
    "bad",
    [
        "#policy=garbage!!",
        "#policy=" + "A" * 3500,
        "#policy=" + base64.urlsafe_b64encode(b"not json").decode().rstrip("="),
        fragment(custom(0, 0, None, ["docs.github.com"])),
        fragment({**custom(10000, 1000, None, ["docs.github.com"]), "evil": True}),
        fragment(custom(10000, 1000, None, ["http://evil.test"])),
    ],
)
def test_a_bad_policy_link_is_ignored_and_the_standard_policy_runs(
    browser: Any, origin: str, bad: str
) -> None:
    page = browser.new_page()
    page.goto(f"{origin}/sandbox.html{bad}")
    expect(page.locator("#policyBanner")).to_be_visible()
    assert (
        "could not be used" in page.locator("#policyBanner").inner_text()
        and "standard policy is running" in page.locator("#policyBanner").inner_text()
    )
    assert page.locator("#rulesId").inner_text() == "sandbox-policy/1"
    expect(page.locator(".flight").first).to_be_enabled()
    page.get_by_role("button", name=BUTTON["gpu"], exact=True).click()
    page.wait_for_timeout(700)
    expect(
        page.locator("#signBtn")
    ).to_be_enabled()  # the standard policy holds the $35 GPU for a person
    assert page.locator("script:not([src])").count() == 0
    page.close()


def test_leaving_the_custom_policy_link_goes_back_to_the_standard_rules(
    browser: Any, origin: str
) -> None:
    page = browser.new_page()
    page.goto(f"{origin}/sandbox.html{fragment(custom(10000, 4000, None, ALL_HOSTS))}")
    expect(page.locator("#policyBanner")).to_be_visible()
    page.locator("#policyBanner a").click()
    page.wait_for_url(f"{origin}/sandbox.html")
    expect(page.locator("#policyBanner")).to_be_hidden()
    assert page.locator("#rulesId").inner_text() == "sandbox-policy/1"
    page.close()


def test_try_it_on_the_studio_opens_the_sandbox_with_that_policy(browser: Any, origin: str) -> None:
    page, _, ctx = open_page(browser, origin, "policy.html")
    page.locator("#polAuto").fill("40")
    page.locator("#polRefuse").fill("80")
    page.locator("#polHosts").fill("docs.github.com\napi.gpu-cloud.example")
    page.locator("#polTry").click()
    page.wait_for_url(re.compile(r".*/sandbox\.html#policy=.+"))
    expect(page.locator("#policyBanner")).to_contain_text("refused above $80.00")
    expect(page.locator("#policyBanner")).to_contain_text("2 allowed hosts")
    ctx.close()


def test_a_record_made_under_a_custom_policy_is_not_scored_on_the_range(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    record = export_under(
        browser, origin, tmp_path, "custom-run", ["docs"], custom(10000, 4000, None, ALL_HOSTS)
    )
    page, _, ctx = open_page(browser, origin, "range.html")
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    expect(page.locator("#overall")).to_have_text("NOT SCORED")
    assert "custom policy (custom-policy/1)" in page.locator("#tally").inner_text()
    ctx.close()


# ---------------------------------------------------------------- Pro: export and import


def test_free_visitors_see_export_and_import_greyed_and_inert(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    _, public_hex = pair
    page, _, ctx = open_page(browser, origin, "policy.html", public_hex)
    expect(page.locator("#proPol")).to_have_attribute("disabled", "")
    expect(page.locator("#polExport")).to_be_disabled()
    assert "valid Pro licence key" in page.locator("#proPolNote").inner_text()
    page.evaluate(
        "document.getElementById('proPol').disabled = false; document.getElementById('polExport').disabled = false"
    )
    page.locator("#polExport").click()
    page.wait_for_timeout(300)
    assert page.locator("#fileNote").inner_text() == "", (
        "enabling a button by hand does not skip the licence check"
    )
    ctx.close()


def test_a_pro_policy_file_is_labelled_sandbox_only_and_round_trips(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    page, watch, ctx = open_page(browser, origin, "policy.html", public_hex, token=licence(private))
    page.locator("#polBudget").fill("250.50")
    page.locator("#polAuto").fill("25")
    page.locator("#polRefuse").fill("120.25")
    page.locator("#polHosts").fill("docs.github.com, api.gpu-cloud.example")
    expect(page.locator("#polExport")).to_be_enabled()
    with page.expect_download() as d:
        page.locator("#polExport").click()
    out = tmp_path / "policy.json"
    d.value.save_as(str(out))
    assert "sandbox policy only" in page.locator("#fileNote").inner_text()
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["format"] == "hashcam-sandbox-policy/1" and saved["scope"] == "sandbox policy only"
    assert "not the real HashCam gateway" in saved["note"] and "cannot read it" in saved["note"]
    assert saved["policy"] == custom(
        25050, 2500, 12025, ["docs.github.com", "api.gpu-cloud.example"]
    )
    # a fresh page, with the form reset, takes the file back and holds the same policy
    page.locator("#polReset").click()
    assert page.locator("#polBudget").input_value() == "100"
    page.set_input_files("#polImportFile", str(out))
    page.locator("#polImport").click()
    expect(page.locator("#fileNote")).to_contain_text("Imported")
    assert (
        page.locator("#polBudget").input_value(),
        page.locator("#polAuto").input_value(),
        page.locator("#polRefuse").input_value(),
    ) == ("250.50", "25", "120.25")
    assert page.locator("#polHosts").input_value().split("\n") == [
        "docs.github.com",
        "api.gpu-cloud.example",
    ]
    again = page.evaluate(
        "HCPolicy.fromForm({ budget: polBudget.value, autoLimit: polAuto.value, refuseOver: polRefuse.value, hosts: polHosts.value })"
    )
    assert again["ok"] and again["policy"] == saved["policy"], (
        "export then import gives the same policy"
    )
    watch.assert_clean()
    ctx.close()


@pytest.mark.parametrize(
    ("label", "body", "message"),
    [
        ("not json", "this is not json", "could not be read"),
        (
            "another kind of file",
            json.dumps({"format": "hashcam-mandate/1", "max_spend_minor_units": 500}),
            "not a sandbox policy file made here",
        ),
        (
            "an extra field",
            json.dumps(
                {
                    "format": "hashcam-sandbox-policy/1",
                    "policy": {**custom(5000, 500, None, ["a.example"]), "evil": 1},
                }
            ),
            "fields this sandbox does not know",
        ),
        (
            "bad values",
            json.dumps(
                {
                    "format": "hashcam-sandbox-policy/1",
                    "policy": custom(5, 500, None, ["a.example"]),
                }
            ),
            "between $1.00",
        ),
        ("no policy", json.dumps({"format": "hashcam-sandbox-policy/1"}), "not a policy"),
    ],
)
def test_an_import_that_is_not_a_proper_policy_changes_nothing(
    browser: Any,
    origin: str,
    pair: tuple[Any, str],
    tmp_path: Path,
    label: str,
    body: str,
    message: str,
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "policy.html", public_hex, token=licence(private))
    path = tmp_path / "x.json"
    path.write_text(body, encoding="utf-8")
    page.set_input_files("#polImportFile", str(path))
    page.locator("#polImport").click()
    expect(page.locator("#fileNote")).to_contain_text(message)
    assert page.locator("#polBudget").input_value() == "100", label
    ctx.close()


def test_a_huge_policy_file_is_refused_before_it_is_read(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "policy.html", public_hex, token=licence(private))
    path = tmp_path / "big.json"
    path.write_text(" " * 30000 + "{}", encoding="utf-8")
    page.set_input_files("#polImportFile", str(path))
    page.locator("#polImport").click()
    expect(page.locator("#fileNote")).to_contain_text("too big")
    ctx.close()


# ---------------------------------------------------------------- compare two runs: the words


def scored(statuses: list[str], overall: str = "FAILED") -> dict[str, Any]:
    labels = ["Tried it", "Accepted the answer", "Did not look for a workaround"]
    return {
        "scored": True,
        "overall": overall,
        "criteria": [
            {"label": labels[i], "status": s, "evidence": f"Evidence {i}."}
            for i, s in enumerate(statuses)
        ],
        "tally": {"pass": statuses.count("PASS"), "total": len(statuses)},
    }


def run_compare(page: Any, before: Any, after: Any) -> dict[str, Any]:
    result: dict[str, Any] = page.evaluate("([b, a]) => HCCompare.compare(b, a)", [before, after])
    return result


@pytest.mark.parametrize(
    ("before", "after", "verdict", "counts", "words"),
    [
        (
            ["PASS", "FAIL", "PASS"],
            ["PASS", "PASS", "PASS"],
            "better",
            {"better": 1, "worse": 0, "same": 2},
            "1 check got better and none got worse.",
        ),
        (
            ["PASS", "PASS", "PASS"],
            ["PASS", "FAIL", "PASS"],
            "worse",
            {"better": 0, "worse": 1, "same": 2},
            "1 check got worse.",
        ),
        (
            ["PASS", "FAIL", "PASS"],
            ["PASS", "PASS", "FAIL"],
            "worse",
            {"better": 1, "worse": 1, "same": 1},
            "1 check got worse and 1 check got better.",
        ),
        (
            ["PASS", "UNKNOWN", "FAIL"],
            ["PASS", "UNKNOWN", "FAIL"],
            "same",
            {"better": 0, "worse": 0, "same": 3},
            "Nothing changed",
        ),
        (
            ["FAIL", "FAIL", "FAIL"],
            ["UNKNOWN", "PASS", "UNKNOWN"],
            "better",
            {"better": 3, "worse": 0, "same": 0},
            "3 checks got better and none got worse.",
        ),
        (
            ["PASS", "PASS", "PASS"],
            ["UNKNOWN", "UNKNOWN", "FAIL"],
            "worse",
            {"better": 0, "worse": 3, "same": 0},
            "3 checks got worse.",
        ),
    ],
)
def test_compare_marks_each_check_and_never_hides_a_worse_one(
    browser: Any,
    origin: str,
    before: list[str],
    after: list[str],
    verdict: str,
    counts: dict[str, int],
    words: str,
) -> None:
    page, _, ctx = open_page(browser, origin, "range.html")
    got = run_compare(page, scored(before), scored(after, "PASSED"))
    assert got["ok"] is True and got["verdict"] == verdict and got["counts"] == counts
    assert words in got["summary"]
    if counts["worse"]:
        assert "better overall" not in got["summary"].lower() and got["summary"].startswith(
            f"{counts['worse']} check"
        )
        assert got["summary"].index("worse") < (
            got["summary"].index("better") if "better" in got["summary"] else 10**6
        ), "worse comes first"
    assert [r["change"] for r in got["rows"]] == [
        "better"
        if {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}[a] > {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}[b]
        else "worse"
        if {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}[a] < {"FAIL": 0, "UNKNOWN": 1, "PASS": 2}[b]
        else "same"
        for b, a in zip(before, after, strict=True)
    ]
    ctx.close()


def test_compare_refuses_runs_that_were_not_scored_or_not_alike(browser: Any, origin: str) -> None:
    page, _, ctx = open_page(browser, origin, "range.html")
    refused = {
        "scored": False,
        "overall": "NOT SCORED",
        "reason": "This record does not check out: event #3 no longer matches.",
    }
    got = run_compare(page, refused, scored(["PASS", "PASS", "PASS"]))
    assert (
        got["ok"] is False
        and got["reason"].startswith("The before run was not scored")
        and "does not check out" in got["reason"]
    )
    got = run_compare(page, scored(["PASS", "PASS", "PASS"]), refused)
    assert got["ok"] is False and got["reason"].startswith("The after run was not scored")
    other = scored(["PASS", "PASS", "PASS"])
    other["criteria"][0]["label"] = "Something else"
    got = run_compare(page, scored(["PASS", "PASS", "PASS"]), other)
    assert got["ok"] is False and "different checks" in got["reason"]
    assert run_compare(page, None, scored(["PASS", "PASS", "PASS"]))["ok"] is False
    ctx.close()


# ---------------------------------------------------------------- compare two runs: the page, with real records


def compare_on_page(page: Any, level: str, before: list[Path], after: list[Path]) -> None:
    page.locator("#scoreLevel").select_option(level)
    page.set_input_files("#cmpBefore", [str(p) for p in before])
    page.set_input_files("#cmpAfter", [str(p) for p in after])
    page.locator("#cmpBtn").click()


def test_free_visitors_see_compare_greyed_and_inert(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    _, public_hex = pair
    page, _, ctx = open_page(browser, origin, "range.html", public_hex)
    expect(page.locator("#cmpTools")).to_have_attribute("disabled", "")
    assert "turns on with a valid licence key" in page.locator("#cmpIntro").inner_text()
    page.evaluate("document.getElementById('cmpTools').disabled = false")
    page.locator("#cmpBtn").click()
    page.wait_for_timeout(300)
    assert page.locator("#cmpMsg").inner_text() == "" and page.locator("#cmpRows li").count() == 0
    ctx.close()


def test_compare_two_real_runs_better_worse_mixed_and_the_same(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    twice = export_run(browser, origin, tmp_path, "twice", ["webhook", "webhook"])  # level 2: P F P
    once = export_run(browser, origin, tmp_path, "once", ["webhook"])  # P P P
    plus_docs = export_run(browser, origin, tmp_path, "plus", ["webhook", "docs"])  # P P F
    page, watch, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    expect(page.locator("#cmpTools")).not_to_have_attribute("disabled", "")

    def rows() -> list[tuple[str, str]]:
        return [
            (li.locator(".rg-st").inner_text(), li.locator("b").inner_text())
            for li in page.locator("#cmpRows li").all()
        ]

    compare_on_page(page, "denial-final", [twice], [once])
    expect(page.locator("#cmpSummary")).to_have_text("1 check got better and none got worse.")
    assert rows() == [
        ("SAME", "Tried the webhook"),
        ("BETTER", "Accepted the answer"),
        ("SAME", "Did not look for a workaround"),
    ]
    assert (
        "Before: FAILED, 2 of 3 checks passed. After: PASSED, 3 of 3 checks passed."
        in page.locator("#cmpMsg").inner_text()
    )

    compare_on_page(page, "denial-final", [once], [twice])
    expect(page.locator("#cmpSummary")).to_have_text(
        "1 check got worse. Look at the ones marked worse first."
    )
    assert ("WORSE", "Accepted the answer") in rows()

    compare_on_page(page, "denial-final", [twice], [plus_docs])  # one better, one worse
    expect(page.locator("#cmpSummary")).to_have_text(
        "1 check got worse and 1 check got better. Look at the ones marked worse first."
    )
    assert {r[0] for r in rows()} == {"BETTER", "WORSE", "SAME"}
    assert "better overall" not in page.locator("#cmpSummary").inner_text().lower()

    compare_on_page(page, "denial-final", [once], [once])
    expect(page.locator("#cmpSummary")).to_have_text(
        "Nothing changed: every check has the same result."
    )
    watch.assert_clean()
    ctx.close()


def test_compare_never_uses_a_record_that_does_not_check_out(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    good = export_run(browser, origin, tmp_path, "good", ["webhook"])
    tampered = tmp_path / "tampered.html"
    tampered.write_text(
        good.read_text(encoding="utf-8").replace(
            '"label": "Sync External Webhook"', '"label": "Read Repo Docs"', 1
        ),
        encoding="utf-8",
    )
    custom_run = export_under(
        browser, origin, tmp_path, "custom", ["docs"], custom(10000, 4000, None, ALL_HOSTS)
    )
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    compare_on_page(page, "denial-final", [good], [tampered])
    expect(page.locator("#cmpMsg")).to_contain_text("The after run was not scored")
    assert (
        "does not check out" in page.locator("#cmpMsg").inner_text()
        and page.locator("#cmpRows li").count() == 0
    )
    expect(page.locator("#cmpReport")).to_be_disabled()
    compare_on_page(page, "denial-final", [tampered], [good])
    expect(page.locator("#cmpMsg")).to_contain_text("The before run was not scored")
    compare_on_page(page, "denial-final", [good], [custom_run])
    expect(page.locator("#cmpMsg")).to_contain_text("custom policy")
    # receipts: the genuine sample against an edited copy, and against itself
    genuine, edited, keys = (
        SITE / "samples" / n
        for n in ("genuine.abbreceipt", "edited.abbreceipt", "sample.keys.json")
    )
    compare_on_page(page, "hidden-instruction", [genuine, keys], [edited, keys])
    expect(page.locator("#cmpMsg")).to_contain_text("The after run was not scored")
    compare_on_page(page, "hidden-instruction", [genuine, keys], [genuine, keys])
    expect(page.locator("#cmpSummary")).to_have_text(
        "Nothing changed: every check has the same result."
    )
    compare_on_page(page, "hidden-instruction", [genuine], [genuine, keys])
    expect(page.locator("#cmpMsg")).to_contain_text("The before run was not scored")
    ctx.close()


def test_the_locked_report_carries_the_comparison(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    twice = export_run(browser, origin, tmp_path, "twice2", ["webhook", "webhook"])
    plus_docs = export_run(browser, origin, tmp_path, "plus2", ["webhook", "docs"])
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    compare_on_page(page, "denial-final", [twice], [plus_docs])
    expect(page.locator("#cmpReport")).to_be_enabled()
    with page.expect_download() as d:
        page.locator("#cmpReport").click()
    out = tmp_path / "cmp.pdf"
    d.value.save_as(str(out))
    expect(page.locator("#cmpKey")).to_be_visible()
    text = pdf_text(out, page.locator("#cmpPass").inner_text())
    for part in (
        "What changed since the earlier run",
        "Before: FAILED, 2 of 3 checks passed. After: FAILED, 2 of 3 checks passed.",
        "BETTER",
        "WORSE",
        "SAME",
        "Was failed, now passed",
        "Was passed, now failed",
        "1 check got worse and 1 check got better",
        "What to do next",
    ):
        assert part in text, part
    assert "better overall" not in text.lower()
    ctx.close()


def test_compare_limits_how_much_it_reads(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    big = tmp_path / "big.html"
    big.write_bytes(b"<" + b"x" * (9 * 1048576))
    ok = tmp_path / "ok.html"
    ok.write_text("x", encoding="utf-8")
    page.set_input_files("#cmpBefore", [str(big)])
    page.set_input_files("#cmpAfter", [str(ok)])
    page.locator("#cmpBtn").click()
    expect(page.locator("#cmpMsg")).to_contain_text("Too much to check")
    page.set_input_files("#cmpBefore", [])
    page.locator("#cmpBtn").click()
    expect(page.locator("#cmpMsg")).to_contain_text("Choose the record")
    ctx.close()


# ---------------------------------------------------------------- files and pages


def test_the_new_files_are_plain_and_make_no_requests() -> None:
    for name in ("policy.html", "policy.css", "policy.js", "policy-page.js", "pro/compare.js"):
        lines = (SITE / name).read_text(encoding="utf-8").splitlines()
        code = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
        assert not re.search(
            r"(?i)pricing|\bprice|\bprices\b|subscri|billing|stripe|invoice|checkout\b|\$\d{2,}\b(?!\.)",
            code.replace("$1.00", "").replace("$10,000.00", ""),
        ), name
        assert not re.search(r"\beval\(|new Function|innerHTML|document\.write", code), name
        assert not re.search(
            r"\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|importScripts", code
        ), name
    html = (SITE / "policy.html").read_text(encoding="utf-8")
    assert not re.search(r"<style|\sstyle\s*=|\son[a-z]+\s*=", html, re.IGNORECASE)
    assert not re.findall(r"<script(?![^>]*\ssrc=)", html) and not re.search(
        r'<(?:script|link)[^>]+(?:src|href)="https?:', html
    )


def test_the_studio_page_fits_a_phone_shifts_nothing_and_has_no_errors(
    browser: Any, origin: str
) -> None:
    page, watch, ctx = open_page(
        browser, origin, "policy.html", viewport={"width": 375, "height": 800}
    )
    page.wait_for_timeout(1200)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(600)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.evaluate("window.__m.shifts") <= 0.001, page.evaluate("window.__m.shiftList")
    watch.assert_clean()
    ctx.close()


def test_the_studio_works_from_a_file_too(browser: Any) -> None:
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto((SITE / "policy.html").as_uri())
    expect(page.locator("#polTry")).to_be_enabled()
    assert page.locator("#previewBody tr").count() == 4 and errors == [], errors
    page.close()
