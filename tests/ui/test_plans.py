"""Free / Pro / Enterprise: plans in the licence, three sets of limits, the local usage meter, the Plans page, the
organisation licence and the Enterprise report footer.

Limits and seats are SHOWN and counted on this device; nothing is enforced (no server). The tests make their own
key pair, never the real one.
"""

# ruff: noqa: E501

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tests.ui.test_pro import licence, open_page, pdf_text, png, set_brand
from tests.ui.test_range import export_run
from tools import make_license as ml

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect


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


def ent(private: Any, **more: Any) -> str:
    return licence(private, plan="enterprise", org="Acme Ltd", seats=25, **more)


# ---------------------------------------------------------------- the licence


def test_the_tool_makes_enterprise_keys_and_refuses_bad_fields(pair: tuple[Any, str]) -> None:
    private, public_hex = pair
    key = ml.sign_license(private, "Pat Doe", plan="enterprise", org="Acme Ltd", seats=25)
    got = ml.check_license(key, public_hex)
    assert (got["plan"], got["org"], got["seats"]) == ("enterprise", "Acme Ltd", 25)
    assert "org" not in ml.check_license(ml.sign_license(private, "Pat"), public_hex), (
        "a plain Pro key is unchanged"
    )
    for kwargs in (
        {"plan": "gold"},
        {"seats": 0},
        {"seats": 10001},
        {"org": ""},
        {"org": "x" * 81},
        {"org": "a\nb"},
    ):
        with pytest.raises(ValueError, match=r"plan|seats|organisation"):
            ml.sign_license(private, "Pat", **kwargs)


def test_the_browser_accepts_both_paid_plans_and_refuses_bad_org_and_seats(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex)

    def check(token: str) -> dict[str, Any]:
        result: dict[str, Any] = page.evaluate(
            "([t, k]) => HCLicense.verifyLicense(t, k)", [token, public_hex]
        )
        return result

    good = check(ent(private))
    assert (
        good["ok"] is True
        and good["licence"]["plan"] == "enterprise"
        and good["licence"]["org"] == "Acme Ltd"
        and good["licence"]["seats"] == 25
    )
    assert (
        check(licence(private))["licence"].get("org") is None
        and check(licence(private))["licence"]["plan"] == "pro"
    )
    for fields, part in (
        ({"plan": "gold"}, "not a Pro key"),
        ({"org": ""}, "organisation name"),
        ({"org": "bad\nname"}, "organisation name"),
        ({"org": 5}, "organisation name"),
        ({"seats": 0}, "seats"),
        ({"seats": 10001}, "seats"),
        ({"seats": 2.5}, "seats"),
        ({"seats": "9"}, "seats"),
    ):
        base = {"plan": "enterprise", "org": "Acme Ltd", "seats": 25, **fields}
        got = check(licence(private, **base))
        assert got["ok"] is False and part in got["reason"], (fields, got)
    ctx.close()


def test_the_pro_page_shows_the_organisation_and_says_seats_are_not_counted(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=ent(private))
    expect(page.locator("#licPlan")).to_contain_text("Enterprise · Acme Ltd · 25 seats")
    assert "not counted or enforced" in page.locator("#licPlan").inner_text()
    expect(page.locator("#proTools")).not_to_have_attribute("disabled", "")
    ctx.close()


# ---------------------------------------------------------------- limits and the usage meter


def test_three_plans_three_sets_of_numbers(browser: Any, origin: str) -> None:
    page, _, ctx = open_page(browser, origin, "range.html")
    got = page.evaluate(
        "() => Object.fromEntries(HCLimits.plans.map((p) => [p, HCLimits.limitsFor(p)]))"
    )
    assert list(got) == ["anonymous", "pro", "enterprise"]
    assert [got[p]["runs_per_day"] for p in got] == [20, 200, 2000]
    assert [got[p]["pack_records"] for p in got] == [0, 20, 500]
    assert [len(got[p]["scenarios"]) for p in got] == [6, 16, 16]
    assert (
        got["enterprise"]["seats"] == 0
        and got["anonymous"]["seats"] == 1
        and HCLimitsEnforced(page) is False
    )
    ctx.close()


def HCLimitsEnforced(page: Any) -> bool:
    return bool(page.evaluate("HCLimits.ENFORCED"))


def test_the_range_shows_the_plans_own_limits(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=ent(private))
    assert (
        "Enterprise" in page.locator("#limitList").inner_text()
        and "2000" in page.locator("#limitList").inner_text()
    )
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 2000 runs today (counted on this device, not enforced)."
    )
    ctx.close()
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 200 runs today (counted on this device, not enforced)."
    )
    ctx.close()


def test_the_usage_meter_counts_scored_runs_warns_past_the_limit_never_blocks_and_stores_no_record(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    record = export_run(browser, origin, tmp_path, "usage", ["docs"])
    page, _, ctx = open_page(browser, origin, "range.html")
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 20 runs today (counted on this device, not enforced)."
    )
    expect(page.locator("#usageNotice")).to_be_hidden()

    def score() -> None:
        page.locator("#scoreLevel").select_option("first-flight")
        page.set_input_files("#files", str(record))
        page.locator("#scoreBtn").click()
        expect(page.locator("#result")).to_be_visible()

    score()
    expect(page.locator("#usageLine")).to_have_text(
        "1 of 20 runs today (counted on this device, not enforced)."
    )
    stored = json.loads(page.evaluate("localStorage.getItem('hashcam-usage')"))
    assert (
        set(stored) == {"date", "n"}
        and stored["n"] == 1
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}", stored["date"])
    ), "a date and a number, nothing about the record"
    # past the limit: a clear notice, and it still scores
    today = stored["date"]
    page.evaluate(
        f"localStorage.setItem('hashcam-usage', JSON.stringify({{ date: '{today}', n: 20 }}))"
    )
    page.reload()
    score()
    expect(page.locator("#usageLine")).to_have_text(
        "21 of 20 runs today (counted on this device, not enforced)."
    )
    expect(page.locator("#usageNotice")).to_be_visible()
    assert (
        "past today's limit" in page.locator("#usageNotice").inner_text()
        and "Nothing is blocked" in page.locator("#usageNotice").inner_text()
    )
    assert "starts again at zero" in page.locator("#usageNotice").inner_text()
    expect(page.locator("#overall")).to_have_text("PASSED")
    # a tampered record is not scored and is not counted; reset starts again
    page.locator("#usageReset").click()
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 20 runs today (counted on this device, not enforced)."
    )
    bad = tmp_path / "bad.html"
    bad.write_text(
        record.read_text(encoding="utf-8").replace(
            '"label": "Read Repo Docs', '"label": "Read Repo Dox', 1
        ),
        encoding="utf-8",
    )
    page.set_input_files("#files", str(bad))
    page.locator("#scoreBtn").click()
    expect(page.locator("#overall")).to_have_text("NOT SCORED")
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 20 runs today (counted on this device, not enforced)."
    )
    # yesterday's count is ignored
    page.evaluate(
        "localStorage.setItem('hashcam-usage', JSON.stringify({ date: '2000-01-01', n: 99 }))"
    )
    page.reload()
    expect(page.locator("#usageLine")).to_have_text(
        "0 of 20 runs today (counted on this device, not enforced)."
    )
    ctx.close()


# ---------------------------------------------------------------- Enterprise: no HashCam footer on the report


def report_text(
    browser: Any, origin: str, public_hex: str, token: str, tmp_path: Path, name: str
) -> str:
    record = export_run(browser, origin, tmp_path, name, ["docs"])
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=token)
    set_brand(page, tmp_path, "Acme Audit", png(80, 80))
    expect(page.locator("#brandNote")).to_have_text("Saved on this device.")
    page.goto(f"{origin}/range.html")
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    with page.expect_download() as d:
        page.locator("#reportBtn").click()
    out = tmp_path / f"{name}.pdf"
    d.value.save_as(str(out))
    text = pdf_text(out, page.locator("#reportPass").inner_text())
    ctx.close()
    return text


def test_enterprise_reports_have_no_made_with_hashcam_footer_and_pro_reports_do(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    pro = report_text(browser, origin, public_hex, licence(private), tmp_path, "pro")
    big = report_text(browser, origin, public_hex, ent(private), tmp_path, "ent")
    assert "Acme Audit" in pro and "Made with HashCam" in pro
    assert (
        "Acme Audit" in big
        and "Made with HashCam" not in big
        and "A report is a summary, not a proof" in big
    )


# ---------------------------------------------------------------- the Plans page


def test_the_plans_page_says_what_is_built_and_what_is_planned_and_shows_no_price_by_default(
    browser: Any, origin: str
) -> None:
    page, watch, ctx = open_page(browser, origin, "plans.html")
    expect(page.locator("#pricePro")).to_have_text("Ask")
    assert [page.locator(i).inner_text() for i in ("#priceFree", "#pricePro", "#priceEnt")] == [
        "Ask"
    ] * 3
    text = page.locator("main").inner_text()
    for part in (
        "1 to 6",
        "200",
        "2000",
        "named in the licence",
        "not enforced",
        "clearing your browser data starts the count again",
    ):
        assert part in text, part
    planned = page.locator(".ab-tag.plan").count()
    assert planned == 8, "eight planned features, each with its tag"
    for name in (
        "Signed reports",
        "Private level packs",
        "Self-host bundle",
        "Single sign-on",
        "central usage dashboard",
        "Server-enforced limits",
        "Invoices",
    ):
        assert name in text
    assert "$" not in re.sub(r"\s", "", page.locator("main").inner_text()), "no price"
    expect(page.locator("#planNote")).to_contain_text("Enterprise contact link has not been set up")
    assert page.locator("#entContact").get_attribute("href") == "#"
    watch.assert_clean()
    ctx.close()


def test_price_text_and_the_contact_link_come_from_one_config_and_only_safe_links_are_used(
    browser: Any, origin: str
) -> None:
    page = browser.new_page()
    cfg = json.dumps(
        {
            "getLicenseUrl": "#",
            "enterpriseContact": "https://example.test/talk",
            "prices": {"free": "", "pro": "per month", "enterprise": "<b>x</b>" * 20},
        }
    )
    page.route(
        "**/pro/config.js",
        lambda r: r.fulfill(content_type="text/javascript", body=f"window.HCProConfig = {cfg};"),
    )
    page.goto(f"{origin}/plans.html")
    expect(page.locator("#pricePro")).to_have_text("per month")
    expect(page.locator("#priceEnt")).to_have_text("Ask")  # too long to be a price: not shown
    assert (
        page.locator("#priceEnt b").count() == 0
        and page.locator("#entContact").get_attribute("href") == "https://example.test/talk"
    )
    page.close()

    def serve(body: str) -> Any:
        return lambda route, _request: route.fulfill(content_type="text/javascript", body=body)

    for bad in ("javascript:alert(1)", "http://insecure.test/", "//evil.test"):
        page = browser.new_page()
        page.route(
            "**/pro/config.js",
            serve(f"window.HCProConfig = {{ enterpriseContact: {json.dumps(bad)} }};"),
        )
        page.goto(f"{origin}/plans.html")
        assert page.locator("#entContact").get_attribute("href") == "#", bad
        page.close()


def test_every_page_has_plans_in_its_nav_and_the_plans_page_is_plain_and_fits_a_phone(
    browser: Any, origin: str
) -> None:
    for name in (
        "index.html",
        "sandbox.html",
        "range.html",
        "about.html",
        "pro.html",
        "audit.html",
        "policy.html",
        "plans.html",
    ):
        assert 'href="plans.html"' in (SITE / name).read_text(encoding="utf-8"), name
    html = (SITE / "plans.html").read_text(encoding="utf-8")
    assert (
        'href="plans.html" aria-current="page"' in html and html.count('aria-current="page"') == 1
    )
    assert not re.search(
        r"<style|\sstyle\s*=|\son[a-z]+\s*=|(?:src|href)=\"https?:", html, re.IGNORECASE
    )
    for name in ("plans.js", "pro/usage.js", "pro/config.js"):
        lines = (SITE / name).read_text(encoding="utf-8").splitlines()
        code = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
        assert not re.search(
            r"\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|eval\(|innerHTML", code
        ), name
    page, watch, ctx = open_page(
        browser, origin, "plans.html", viewport={"width": 375, "height": 800}
    )
    page.wait_for_timeout(1200)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(600)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.evaluate("window.__m.shifts") <= 0.001, page.evaluate("window.__m.shiftList")
    watch.assert_clean()
    ctx.close()
