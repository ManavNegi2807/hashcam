# ruff: noqa: E501
"""The company console (site/enterprise.html): company certificates, Boss and Member keys, isolation between
companies, and customer-issue analytics that only ever counts verified records. Real Chromium; keys are made here
with tools/make_license.py, so the CLI and the page are tested against each other. No network."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tools import make_license as ml

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

GENUINE = (SITE / "samples" / "genuine.abbreceipt").read_bytes()
EDITED = (SITE / "samples" / "edited.abbreceipt").read_bytes()
KEYS = (SITE / "samples" / "sample.keys.json").read_bytes()


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


class World:
    """An owner, and two companies each with its own key, a Boss and a Member."""

    def __init__(self) -> None:
        self.owner, self.owner_pub = ml.make_keypair()
        self.orgs: dict[str, Any] = {}
        for org_id, org_name in (("orga", "Org A Ltd"), ("orgb", "Org B Inc")):
            key, pub = ml.make_keypair()
            cert = ml.sign_org_cert(self.owner, org_id, org_name, pub)
            self.orgs[org_id] = {
                "key": key,
                "cert": cert,
                "boss": ml.sign_member(
                    key, org_id, f"{org_id} boss", "boss", member_id=f"{org_id}-boss"
                ),
                "member": ml.sign_member(
                    key, org_id, f"{org_id} member", "member", member_id=f"{org_id}-sam"
                ),
            }

    def access(self, org: str, who: str) -> str:
        return f"{self.orgs[org]['cert']}\n{self.orgs[org][who]}"


@pytest.fixture(scope="module")
def world() -> World:
    return World()


def open_page(
    browser: Any,
    origin: str,
    world: World,
    session: str | None = None,
    seed: dict[str, str] | None = None,
    **kw: Any,
) -> tuple[Any, Any, list[str]]:
    ctx = browser.new_context(**{"viewport": {"width": 1280, "height": 900}, **kw})
    body = f'window.HCProKey = {{ publicKeyHex: "{world.owner_pub}" }};'
    ctx.route(
        "**/pro/pubkey.js",
        lambda route, _request: route.fulfill(content_type="text/javascript", body=body),
    )
    if session:
        ctx.add_init_script(
            f"try {{ localStorage.setItem('hashcam-org-session', {json.dumps(session)}); }} catch (e) {{}}"
        )
    for key, value in (seed or {}).items():
        ctx.add_init_script(
            f"try {{ localStorage.setItem({json.dumps(key)}, {json.dumps(value)}); }} catch (e) {{}}"
        )
    page = ctx.new_page()
    page.set_default_timeout(20_000)
    problems: list[str] = []
    page.on("pageerror", lambda e: problems.append(str(e)))
    page.on("console", lambda m: problems.append(m.text) if m.type == "error" else None)
    page.goto(f"{origin}/enterprise.html")
    return page, ctx, problems


def sign_in(page: Any, text: str) -> None:
    page.fill("#accessKey", text)
    page.click("#signInBtn")


def badge(page: Any) -> str:
    return str(page.locator("#entBadge").inner_text()).strip()


# ---------------------------------------------------------------- the CLI
def test_the_cli_makes_a_company_and_unique_member_keys_without_exposing_any_private_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(ml, "PUBKEY_JS", tmp_path / "pubkey.js")
    owner = tmp_path / "owner.pem"
    assert ml.main(["--key-file", str(owner), "init"]) == 0
    owner_pub = ml.public_hex_in_site()
    assert owner_pub
    capsys.readouterr()

    orgs = tmp_path / "orgs"
    assert (
        ml.main(
            [
                "--key-file",
                str(owner),
                "org-init",
                "--org-id",
                "acme",
                "--org-name",
                "Acme Ltd",
                "--org-dir",
                str(orgs),
            ]
        )
        == 0
    )
    out = capsys.readouterr()
    cert = out.out.strip()
    cert_payload = ml.check_signed(ml.ORG_PREFIX, cert, owner_pub)
    assert cert_payload["org_id"] == "acme" and cert_payload["org_name"] == "Acme Ltd"
    for text in (out.out, out.err):
        assert "PRIVATE KEY" not in text
    org_pem = (orgs / "acme-private.pem").read_text()
    assert "PRIVATE KEY" in org_pem and org_pem.split("\n")[1] not in out.out + out.err

    keys = []
    for name, role in (("Dana", "boss"), ("Sam", "member"), ("Sam2", "member")):
        assert (
            ml.main(
                [
                    "member",
                    "--org-id",
                    "acme",
                    "--role",
                    role,
                    "--name",
                    name,
                    "--org-dir",
                    str(orgs),
                ]
            )
            == 0
        )
        token = capsys.readouterr().out.strip()
        payload = ml.check_signed(ml.MEMBER_PREFIX, token, cert_payload["org_pubkey"])
        assert payload["role"] == role and payload["org_id"] == "acme"
        keys.append(payload["member_id"])
    assert len(set(keys)) == 3, "every person gets a unique member id"

    assert (
        ml.main(
            [
                "member",
                "--org-id",
                "acme",
                "--role",
                "member",
                "--name",
                "Eve",
                "--scopes",
                "policy",
                "--org-dir",
                str(orgs),
            ]
        )
        == 2
    )
    assert "scopes for a member" in capsys.readouterr().err

    assert (
        ml.main(["revoke", "--org-id", "acme", "--member-id", keys[1], "--org-dir", str(orgs)]) == 0
    )
    assert (
        ml.main(["revoke", "--org-id", "acme", "--member-id", keys[2], "--org-dir", str(orgs)]) == 0
    )
    revoked = ml.check_signed(
        ml.REVOKE_PREFIX,
        capsys.readouterr().out.strip().splitlines()[-1],
        cert_payload["org_pubkey"],
    )
    assert revoked["revoked"] == sorted(keys[1:])


def test_the_cli_refuses_a_company_key_inside_the_repo_or_without_an_owner_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    inside = ml.REPO / "tests" / "_never_created"
    assert (
        ml.main(
            [
                "--key-file",
                str(tmp_path / "none.pem"),
                "org-init",
                "--org-id",
                "x1",
                "--org-name",
                "X",
                "--org-dir",
                str(inside),
            ]
        )
        == 2
    )
    assert not inside.exists()
    assert "OUTSIDE the repository" in capsys.readouterr().err
    assert (
        ml.main(
            [
                "--key-file",
                str(tmp_path / "none.pem"),
                "org-init",
                "--org-id",
                "x1",
                "--org-name",
                "X",
                "--org-dir",
                str(tmp_path),
            ]
        )
        == 2
    )
    assert "No owner private key" in capsys.readouterr().err


# ---------------------------------------------------------------- Boss and Member
def test_the_header_badge_names_the_company_and_the_role(
    browser: Any, origin: str, world: World
) -> None:
    page, ctx, problems = open_page(browser, origin, world)
    expect(page.locator("#entBadge")).to_have_text("NOT SIGNED IN")
    sign_in(page, world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_have_text("ORG: Org A Ltd • ROLE: BOSS (ADMIN)")
    page.reload()
    expect(page.locator("#entBadge")).to_have_text(
        "ORG: Org A Ltd • ROLE: BOSS (ADMIN)"
    )  # kept on this device
    page.click("#signOut")
    sign_in(page, world.access("orga", "member"))
    expect(page.locator("#entBadge")).to_have_text("ORG: Org A Ltd • ROLE: MEMBER (MAINTAINER)")
    assert problems == []
    ctx.close()


def test_a_boss_can_use_the_controls_a_member_sees_locked(
    browser: Any, origin: str, world: World
) -> None:
    page, ctx, _ = open_page(browser, origin, world, session=world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    for fs in ("#fsMembers", "#fsPolicy", "#fsImport"):
        assert page.locator(fs).get_attribute("disabled") is None
    assert page.locator("#lockMembers").is_hidden() and page.locator("#lockPolicy").is_hidden()
    page.fill("#polBudget", "250")
    page.click("#polSave")
    expect(page.locator("#polMsg")).to_have_text("Saved as this company's default.")
    page.fill("#memName", "Sam Lee")
    page.click("#memCmd")
    expect(page.locator("#cmdOut")).to_contain_text('--org-id orga --role member --name "Sam Lee"')
    assert "PRIVATE" not in page.locator("#cmdOut").inner_text()
    ctx.close()

    page, ctx, _ = open_page(browser, origin, world, session=world.access("orga", "member"))
    expect(page.locator("#entBadge")).to_contain_text("MEMBER (MAINTAINER)")
    for fs in ("#fsMembers", "#fsPolicy"):
        assert page.locator(fs).get_attribute("disabled") is not None, (
            f"{fs} must be locked for a Member"
        )
    assert page.locator("#fsImport").get_attribute("disabled") is None, (
        "a Member may verify customer files"
    )
    assert (
        page.locator("#lockMembers").is_visible()
        and page.locator("#lockPolicy").is_visible()
        and page.locator("#lockInsights").is_visible()
    )
    assert page.locator("#insightsBody").inner_text().strip() == "", "the insights are for a Boss"
    ctx.close()


# ---------------------------------------------------------------- one company cannot open another
def test_company_a_cannot_read_company_b_and_a_key_does_not_work_with_another_companys_certificate(
    browser: Any, origin: str, world: World
) -> None:
    secret = json.dumps(
        [
            {
                "id": "b-secret",
                "title": "ORG B SECRET",
                "category": "DOMAIN_ALERT",
                "assignee": None,
                "status": "open",
                "notes": [],
            }
        ]
    )
    page, ctx, _ = open_page(browser, origin, world, seed={"hashcam-org:orgb:issues": secret})
    sign_in(page, world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("Org A Ltd")
    expect(page.locator("#issueList")).to_contain_text("No issues yet")
    assert "ORG B SECRET" not in page.content()
    assert page.evaluate("HCOrg.storeFor('orga').get('issues', 'none')") == "none"
    assert page.evaluate("HCOrg.storeFor('orga').get('../orgb:issues', 'refused')") == "refused"
    page.click("#signOut")

    # A's Boss key with B's certificate: refused
    sign_in(page, f"{world.orgs['orgb']['cert']}\n{world.orgs['orga']['boss']}")
    expect(page.locator("#signinMsg")).to_contain_text("not made by this company")
    expect(page.locator("#entBadge")).to_have_text("NOT SIGNED IN")
    # a certificate the owner never signed (a company made up by someone else): refused
    fake_key, fake_pub = ml.make_keypair()
    fake_owner, _ = ml.make_keypair()
    fake_cert = ml.sign_org_cert(fake_owner, "orga", "Org A Ltd", fake_pub)
    fake_member = ml.sign_member(fake_key, "orga", "Mallory", "boss")
    sign_in(page, f"{fake_cert}\n{fake_member}")
    expect(page.locator("#signinMsg")).to_contain_text("not made for this site")
    expect(page.locator("#entBadge")).to_have_text("NOT SIGNED IN")
    ctx.close()


def test_a_member_key_has_to_be_unique_current_and_within_what_a_member_may_have(
    browser: Any, origin: str, world: World
) -> None:
    org = world.orgs["orga"]
    expired = ml.sign_member(
        org["key"], "orga", "Old Sam", "member", expires_at="2025-01-31", member_id="old-1"
    )
    greedy = ml._signed(
        ml.MEMBER_PREFIX,
        org["key"],
        {
            "v": 1,
            "org_id": "orga",
            "member_id": "greedy-1",
            "name": "Greedy",
            "role": "member",
            "scopes": ["triage", "policy"],
            "issued": "2026-01-01",
            "expires_at": None,
        },
    )
    page, ctx, _ = open_page(browser, origin, world)
    sign_in(page, f"{org['cert']}\n{expired}")
    expect(page.locator("#signinMsg")).to_contain_text("ended on 2025-01-31")
    sign_in(page, f"{org['cert']}\n{greedy}")
    expect(page.locator("#signinMsg")).to_contain_text("more than a member may have")
    sign_in(page, f"{org['cert']}\n{org['member'][:-6]}AAAAAA")
    expect(page.locator("#entBadge")).to_have_text("NOT SIGNED IN")
    # two real members: different ids, both work
    other = ml.sign_member(org["key"], "orga", "Pat", "member")
    assert other != org["member"]
    sign_in(page, f"{org['cert']}\n{other}")
    expect(page.locator("#entBadge")).to_contain_text("MEMBER (MAINTAINER)")
    ctx.close()


def test_a_revoked_member_is_refused_once_the_signed_list_is_imported_and_a_forged_list_is_not(
    browser: Any, origin: str, world: World
) -> None:
    org = world.orgs["orga"]
    good = ml.sign_revocations(org["key"], "orga", ["orga-sam"])
    forged = ml.sign_revocations(world.orgs["orgb"]["key"], "orga", ["orga-boss"])
    page, ctx, _ = open_page(browser, origin, world, session=world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    page.fill("#revText", forged)
    page.click("#revGo")
    expect(page.locator("#revMsg")).to_contain_text("not signed by this company")
    page.fill("#revText", good)
    page.click("#revGo")
    expect(page.locator("#revMsg")).to_contain_text("Imported: 1 revoked")
    page.click("#signOut")
    sign_in(page, world.access("orga", "member"))
    expect(page.locator("#signinMsg")).to_contain_text("revoked by the company")
    sign_in(page, world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    ctx.close()


# ---------------------------------------------------------------- customer issues
def bundle(name: str, data: bytes) -> dict[str, Any]:
    return {"name": name, "mimeType": "application/octet-stream", "buffer": data}


def issue_note(category: str, note: str) -> bytes:
    return json.dumps({"format": "hashcam-issue/1", "category": category, "note": note}).encode()


def test_only_verified_bundles_are_counted_and_the_rest_are_marked_not_included(
    browser: Any, origin: str, world: World
) -> None:
    page, ctx, _ = open_page(browser, origin, world, session=world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    page.set_input_files(
        "#bundleFiles",
        [
            bundle("case1.abbreceipt", GENUINE),
            bundle("case1.keys.json", KEYS),
            bundle("case1.issue.json", issue_note("WASM_LOAD", "verifier will not load")),
            bundle("case2.abbreceipt", EDITED),
            bundle("case2.keys.json", KEYS),
            bundle("case2.issue.json", issue_note("CHAIN_BROKEN", "edited by mistake")),
            bundle("case3.issue.json", issue_note("DOMAIN_ALERT", "a note with no record")),
        ],
    )
    page.click("#bundleGo")
    expect(page.locator("#bundleMsg")).to_have_text("1 verified, 2 not included.")
    rows = page.locator("#bundleList li")
    expect(rows).to_have_count(3)
    expect(page.locator("#bundleList li:has-text('case1')")).to_contain_text("VERIFIED")
    expect(page.locator("#bundleList li:has-text('case2')")).to_contain_text("NOT INCLUDED")
    expect(page.locator("#bundleList li:has-text('case3')")).to_contain_text(
        "a note alone is not counted"
    )
    # the table counts them apart; the ranking holds verified ones only
    expect(page.locator("#insightsBody tr[data-cat='WASM_LOAD'] .n-ok")).to_have_text("1")
    expect(page.locator("#insightsBody tr[data-cat='CHAIN_BROKEN'] .n-ok")).to_have_text("0")
    expect(page.locator("#insightsBody tr[data-cat='CHAIN_BROKEN'] .n-no")).to_have_text("1")
    expect(page.locator("#insightsBody tr[data-cat='DOMAIN_ALERT'] .n-no")).to_have_text("1")
    ranked = page.locator(".ent-rank li")
    expect(ranked).to_have_count(1)
    expect(ranked.first).to_contain_text("WASM_LOAD (1)")
    expect(ranked.first).to_contain_text("verifier.wasm")  # a recommended next fix
    ctx.close()


def test_a_member_triages_an_assigned_issue_and_a_boss_decides_the_escalation(
    browser: Any, origin: str, world: World
) -> None:
    page, ctx, _ = open_page(browser, origin, world)
    sign_in(page, world.access("orga", "member"))  # lands in the company's roster
    expect(page.locator("#entBadge")).to_contain_text("MEMBER")
    page.click("#signOut")
    sign_in(page, world.access("orga", "boss"))
    page.set_input_files(
        "#bundleFiles",
        [
            bundle("tick1.abbreceipt", GENUINE),
            bundle("tick1.keys.json", KEYS),
            bundle("tick1.issue.json", issue_note("POLICY_HOLD_TIMEOUT", "held step timed out")),
            bundle("tick2.abbreceipt", GENUINE),
            bundle("tick2.keys.json", KEYS),
        ],
    )
    page.click("#bundleGo")
    expect(page.locator("#bundleMsg")).to_contain_text("2 verified")
    page.locator("li.ent-issue[data-id='tick1'] select").select_option("orga-sam")
    page.click("#signOut")

    sign_in(page, world.access("orga", "member"))
    expect(page.locator("#issueList li.ent-issue")).to_have_count(
        1
    )  # only the one assigned to this Member
    page.fill("li.ent-issue input[type=text]", "seen on the customer's laptop; reproducing")
    page.click("text=Save note")
    expect(page.locator("li.ent-issue .ent-note")).to_contain_text("orga member")
    assert (
        page.locator("li.ent-issue a:has-text('Reproduce in the sandbox')").get_attribute("href")
        == "sandbox.html"
    )
    page.click("text=Escalate to a Boss")
    expect(page.locator("#issueList li.ent-issue .tag")).to_have_text("ESCALATED")
    expect(page.locator("#holdList li button").first).to_be_disabled()  # a Member cannot decide
    page.click("#signOut")

    sign_in(page, world.access("orga", "boss"))
    page.click("#holdList li button:has-text('Approve')")
    expect(page.locator("#holdList li .tag")).to_have_text("APPROVED")
    expect(page.locator("#holdList li")).to_contain_text("approved by orga boss")
    ctx.close()


# ---------------------------------------------------------------- the look: watermark, animation, company-only, honest, CSP
def test_the_console_keeps_the_watermark_and_the_motion_and_respects_reduced_motion(
    browser: Any, origin: str, world: World
) -> None:
    page, ctx, problems = open_page(browser, origin, world, session=world.access("orga", "boss"))
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    mark = page.evaluate(
        "(() => { const s = getComputedStyle(document.body, '::before'); return [s.backgroundImage.slice(0, 20), s.opacity]; })()"
    )
    assert mark[0].startswith("url(") and float(mark[1]) > 0, (
        "the faint logo watermark stays behind the console"
    )
    assert (
        page.evaluate("getComputedStyle(document.querySelector('#sec-issues')).animationName")
        == "entIn"
    )
    assert (
        page.evaluate(
            "getComputedStyle(document.querySelector('.ent-badge'), '::before').animationName"
        )
        == "entPulse"
    )
    assert page.evaluate("document.querySelectorAll('[style]').length") == 0, (
        "strict CSP: no inline styles"
    )
    assert page.evaluate("document.querySelectorAll('script:not([src])').length") == 0
    assert problems == []
    ctx.close()

    page, ctx, _ = open_page(
        browser, origin, world, session=world.access("orga", "boss"), reduced_motion="reduce"
    )
    expect(page.locator("#entBadge")).to_contain_text("BOSS")
    assert (
        page.evaluate("getComputedStyle(document.querySelector('#sec-issues')).animationName")
        == "none"
    )
    ctx.close()


def test_the_console_is_company_only_and_says_what_is_built_and_not_enforced(origin: str) -> None:
    html = (SITE / "enterprise.html").read_text(encoding="utf-8")
    assert 'name="robots" content="noindex"' in html
    assert "NOT ENFORCED" in html and "PLANNED" in html and "BUILT" in html
    assert "Company console" in html and 'class="ent-side"' in html, (
        "its own sidebar layout, not the public site's top bar"
    )
    assert 'class="topbar"' not in html
    for page in sorted(SITE.glob("*.html")):
        if page.name != "enterprise.html":
            assert "enterprise.html" not in page.read_text(encoding="utf-8"), (
                f"{page.name} must not advertise the company console"
            )
    assert "private" not in (SITE / "enterprise.js").read_text(encoding="utf-8").lower().replace(
        "private window", ""
    )
