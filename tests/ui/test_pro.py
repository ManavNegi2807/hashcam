"""HashCam Pro (licence, your name and logo on reports, audit pack, CSV) and the Book-an-audit page.

* The licence tool (tools/make_license.py) makes and checks keys; the private key is never printed and never
  written inside the repository. The real public key is NOT in the repo yet (null), so nothing unlocks until
  the owner runs `init`. Tests make their own key pair and hand its public half to the page.
* The browser check accepts a good key and refuses a changed, foreign, expired, wrong-plan or garbage one.
* Pro tools are greyed for free users and work with a valid key: white-label report (PDF opened with pypdf),
  audit pack (a record that does not check out is NOT INCLUDED), CSV (scrubbed, formula-safe).
* Nothing is uploaded; no billing words; the audit page has no script and one mailto link.

Needs only a browser (and pypdf for the PDF checks).
"""

# ruff: noqa: E501

from __future__ import annotations

import csv
import io
import json
import re
import stat
import struct
import zipfile
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tests.ui.test_motion import WATCH, Watch
from tests.ui.test_range import export_run
from tools import make_license as ml

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

REPO = SITE.parent
GENUINE = SITE / "samples" / "genuine.abbreceipt"
EDITED = SITE / "samples" / "edited.abbreceipt"
KEYS = SITE / "samples" / "sample.keys.json"
STORE = "hashcam-pro-licence"
BRAND_STORE = "hashcam-pro-brand"


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


def signed(private: Any, payload: bytes) -> str:
    return f"{ml.PREFIX}.{ml.b64u(payload)}.{ml.b64u(private.sign(payload))}"


def licence(private: Any, **fields: Any) -> str:
    payload = {
        "v": 1,
        "name": "Acme Audit Ltd",
        "plan": "pro",
        "issued": "2026-01-01",
        "expires": None,
        "id": "abc123",
        **fields,
    }
    return signed(private, json.dumps(payload, separators=(",", ":")).encode("utf-8"))


def open_page(
    browser: Any,
    origin: str,
    name: str,
    public_hex: str | None = None,
    token: str | None = None,
    brand: dict[str, str] | None = None,
    config_url: str | None = None,
    **kw: Any,
) -> tuple[Any, Watch, Any]:
    ctx = browser.new_context(
        **{"viewport": {"width": 1280, "height": 900}, "accept_downloads": True, **kw}
    )
    if public_hex:
        body = f'window.HCProKey = {{ publicKeyHex: "{public_hex}" }};'
        ctx.route(
            "**/pro/pubkey.js", lambda r: r.fulfill(content_type="text/javascript", body=body)
        )
    if config_url is not None:
        cfg = f"window.HCProConfig = {{ getLicenseUrl: {json.dumps(config_url)} }};"
        ctx.route("**/pro/config.js", lambda r: r.fulfill(content_type="text/javascript", body=cfg))
    if token:
        ctx.add_init_script(
            f"try {{ localStorage.setItem({json.dumps(STORE)}, {json.dumps(token)}); }} catch (e) {{}}"
        )
    if brand:
        ctx.add_init_script(
            f"try {{ localStorage.setItem({json.dumps(BRAND_STORE)}, {json.dumps(json.dumps(brand))}); }} catch (e) {{}}"
        )
    page = ctx.new_page()
    page.set_default_timeout(20_000)
    watch = Watch(page, origin)
    page.add_init_script(WATCH)
    page.goto(f"{origin}/{name}")
    return page, watch, ctx


def png(width: int, height: int, rgb: tuple[int, int, int] = (200, 120, 30)) -> bytes:
    raw = b"".join(b"\x00" + bytes(rgb) * width for _ in range(height))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    head = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", head)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


def pdf_text(pdf: Path, password: str) -> str:
    import pypdf

    reader = pypdf.PdfReader(str(pdf))
    assert reader.decrypt(password) != 0
    return " ".join(" ".join(p.extract_text() for p in reader.pages).split())


# ---------------------------------------------------------------- the licence tool


def test_a_key_round_trips_and_the_tool_checks_its_inputs(pair: tuple[Any, str]) -> None:
    private, public_hex = pair
    token = ml.sign_license(private, "Acme Audit Ltd", expires="2030-06-15")
    payload = ml.check_license(token, public_hex)
    assert payload["name"] == "Acme Audit Ltd" and payload["plan"] == "pro"
    assert payload["expires"] == "2030-06-15" and re.fullmatch(r"[0-9a-f]{8}", payload["id"])
    assert token.startswith("HCPRO1.") and len(token) < 400, "short enough to paste"
    other_private, other_public = ml.make_keypair()
    with pytest.raises(ValueError, match="signature"):
        ml.check_license(token, other_public)
    for name in ("", "x" * 81, "bad\nname"):
        with pytest.raises(ValueError, match="name"):
            ml.sign_license(private, name)
    for expires in ("2030-13-45", "soon", "2030-6-1"):
        with pytest.raises(ValueError, match=r"expires|day|month"):
            ml.sign_license(private, "Acme", expires=expires)
    assert other_private is not private


def test_init_keeps_the_private_key_out_of_the_repo_and_out_of_the_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from cryptography.hazmat.primitives import serialization

    pubkey = tmp_path / "pubkey.js"
    monkeypatch.setattr(ml, "PUBKEY_JS", pubkey)
    # Refused inside the repository, and nothing is written.
    inside = REPO / "oops-license-private.pem"
    assert ml.main(["--key-file", str(inside), "init"]) == 2
    assert not inside.exists() and not pubkey.exists()
    # Made outside it: the file exists, the public key is written, the private key is never printed.
    key_file = tmp_path / "secret" / "license-private.pem"
    capsys.readouterr()
    assert ml.main(["--key-file", str(key_file), "init"]) == 0
    out = capsys.readouterr()
    private = ml.load_private(key_file)
    raw = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    shown = out.out + out.err
    assert "PRIVATE KEY" not in shown and raw.hex() not in shown and ml.b64u(raw) not in shown
    assert str(key_file) in shown, "it says where the key is, not what it is"
    public_hex = ml.public_hex_in_site()
    assert public_hex and re.fullmatch(r"[0-9a-f]{64}", public_hex)
    if hasattr(stat, "S_IMODE") and key_file.stat().st_mode & 0o077 == 0:
        assert stat.S_IMODE(key_file.stat().st_mode) == 0o600
    # It will not overwrite a key by accident.
    assert ml.main(["--key-file", str(key_file), "init"]) == 2
    # sign prints only the licence; check verifies it against the site's public key.
    capsys.readouterr()
    assert (
        ml.main(["--key-file", str(key_file), "sign", "--name", "Acme", "--expires", "2031-01-01"])
        == 0
    )
    token = capsys.readouterr().out.strip()
    assert ml.check_license(token, public_hex)["name"] == "Acme"
    assert ml.main(["check", token]) == 0
    assert ml.main(["check", token[:-4] + "AAAA"]) == 1


def test_the_real_public_key_is_not_in_the_repo_yet_and_no_private_key_is() -> None:
    assert "publicKeyHex: null" in (SITE / "pro" / "pubkey.js").read_text(encoding="utf-8")
    ignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    assert "license-private*" in ignore and "*.pem" in ignore
    found = [
        p
        for p in REPO.rglob("*")
        if p.is_file()
        and ".git" not in p.parts
        and "node_modules" not in p.parts
        and "target" not in p.parts
        and p.suffix in {".pem", ".key"}
    ]
    assert found == [], found
    assert ml.REPO == REPO and not ml.inside_repo(Path.home() / ".hashcam" / "license-private.pem")


# ---------------------------------------------------------------- the browser check


def verdict(page: Any, token: str, public_hex: str, now: int | None = None) -> dict[str, Any]:
    result: dict[str, Any] = page.evaluate(
        "([t, k, now]) => HCLicense.verifyLicense(t, k, now === null ? undefined : now)",
        [token, public_hex, now],
    )
    return result


def test_a_good_key_is_accepted_and_every_bad_one_is_refused(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    other, _ = ml.make_keypair()
    good = licence(private)
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex)
    ok = verdict(page, good, public_hex)
    assert ok["ok"] is True and ok["licence"] == {
        "name": "Acme Audit Ltd",
        "plan": "pro",
        "issued": "2026-01-01",
        "expires": None,
        "id": "abc123",
    }
    # change the payload but keep the old signature
    payload_part = good.split(".")[1]
    changed = ml.b64u(ml.unb64u(payload_part).replace(b"Acme", b"Evil"))
    cases = {
        "empty": ("", "does not look like"),
        "garbage": ("hello world", "does not look like"),
        "two parts": ("HCPRO1.abc", "does not look like"),
        "wrong prefix": ("HCPRO2." + good.split(".", 1)[1], "does not look like"),
        "too long": ("HCPRO1." + "A" * 3000 + ".B", "does not look like"),
        "bad characters": ("HCPRO1.!!!.???", "damaged"),
        "short signature": (f"HCPRO1.{good.split('.')[1]}.AAAA", "damaged"),
        "payload changed, old signature": (f"HCPRO1.{changed}.{good.split('.')[2]}", "changed"),
        "signed by another key": (licence(other), "not made for this site"),
        "wrong plan": (licence(private, plan="basic"), "not a Pro key"),
        "unknown version": (licence(private, v=2), "version"),
        "control character in name": (licence(private, name="bad\nname"), "name"),
        "name too long": (licence(private, name="x" * 81), "name"),
        "blank name": (licence(private, name="  "), "name"),
        "bad date": (licence(private, issued="2026-13-45"), "date"),
        "bad expiry": (licence(private, expires="tomorrow"), "date"),
        "bad id": (licence(private, id="has space"), "id"),
        "issued in the future": (
            licence(private, issued=(datetime.now(UTC) + timedelta(days=10)).date().isoformat()),
            "future",
        ),
        "not json": (signed(private, b"not json at all"), "damaged"),
    }
    for label, (token, reason) in cases.items():
        got = verdict(page, token, public_hex)
        assert got["ok"] is False, label
        assert reason in got["reason"], (label, got["reason"])
    # no public key to check against: nothing is accepted
    assert verdict(page, good, "")["ok"] is False
    assert verdict(page, good, "z" * 64)["ok"] is False
    ctx.close()


def test_expiry_counts_to_the_end_of_the_last_day(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    token = licence(private, expires="2030-06-15")
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex)
    last_second = int(datetime(2030, 6, 15, 23, 59, 0, tzinfo=UTC).timestamp() * 1000)
    next_second = int(datetime(2030, 6, 16, 0, 0, 1, tzinfo=UTC).timestamp() * 1000)
    assert verdict(page, token, public_hex, last_second)["ok"] is True
    ended = verdict(page, token, public_hex, next_second)
    assert ended["ok"] is False and ended["expired"] is True and "2030-06-15" in ended["reason"]
    forever = licence(private, expires=None)
    assert verdict(page, forever, public_hex, next_second * 3)["ok"] is True
    ctx.close()


def test_the_pro_page_unlocks_with_a_good_key_remembers_it_and_lets_it_go(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, watch, ctx = open_page(browser, origin, "pro.html", public_hex)
    expect(page.locator("#licState")).to_have_text("No licence on this device: the free plan.")
    expect(page.locator("#proTools")).to_have_attribute("disabled", "")
    page.locator("#licenseKey").fill(licence(private))
    page.locator("#licenseCheck").click()
    expect(page.locator("#licState")).to_have_text("Pro licence active.")
    assert page.locator("#licName").inner_text() == "Acme Audit Ltd"
    assert (
        page.locator("#licPlan").inner_text() == "Pro"
        and page.locator("#licExpires").inner_text() == "no end date"
    )
    expect(page.locator("#proTools")).not_to_have_attribute("disabled", "")
    assert page.locator("#licenseKey").input_value() == "", (
        "the key box is emptied once it is saved"
    )
    page.reload()
    expect(page.locator("#licPlan")).to_have_text("Pro")
    expect(page.locator("#proTools")).not_to_have_attribute("disabled", "")
    page.locator("#licenseRemove").click()
    expect(page.locator("#licPlan")).to_have_text("Free")
    expect(page.locator("#proTools")).to_have_attribute("disabled", "")
    page.reload()
    expect(page.locator("#licPlan")).to_have_text("Free")
    assert page.evaluate(f"localStorage.getItem({json.dumps(STORE)})") is None
    watch.assert_clean()
    ctx.close()


@pytest.mark.parametrize("which", ["changed", "foreign", "expired", "garbage"])
def test_a_bad_key_pasted_on_the_page_unlocks_nothing_and_is_not_kept(
    browser: Any, origin: str, pair: tuple[Any, str], which: str
) -> None:
    private, public_hex = pair
    other, _ = ml.make_keypair()
    good = licence(private)
    token = {
        "changed": f"HCPRO1.{ml.b64u(ml.unb64u(good.split('.')[1]).replace(b'Acme', b'Evil'))}.{good.split('.')[2]}",
        "foreign": licence(other),
        "expired": licence(private, expires="2020-01-01"),
        "garbage": "<script>alert(1)</script>",
    }[which]
    page, watch, ctx = open_page(browser, origin, "pro.html", public_hex)
    page.locator("#licenseKey").fill(token)
    page.locator("#licenseCheck").click()
    expect(page.locator("#licenseNote")).not_to_have_text("Saved on this device.")
    assert page.locator("#licenseNote").inner_text().strip() not in {"", "Checking…"}
    expect(page.locator("#proTools")).to_have_attribute("disabled", "")
    assert page.evaluate(f"localStorage.getItem({json.dumps(STORE)})") is None
    assert page.locator("script:not([src])").count() == 0, (
        "a pasted key is shown as text, never as markup"
    )
    watch.assert_clean()
    ctx.close()


def test_a_key_that_went_bad_while_stored_reads_as_the_free_plan(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(
        browser, origin, "pro.html", public_hex, token=licence(private, expires="2020-01-01")
    )
    expect(page.locator("#licState")).to_contain_text("ended on 2020-01-01")
    expect(page.locator("#licPlan")).to_have_text("Free")
    expect(page.locator("#proTools")).to_have_attribute("disabled", "")
    ctx.close()


def test_without_a_public_key_in_the_site_nothing_unlocks_and_the_page_says_so(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, _ = pair
    page, _, ctx = open_page(browser, origin, "pro.html")  # the real pubkey.js: null
    expect(page.locator("#licState")).to_contain_text("not set up on this site yet")
    page.locator("#licenseKey").fill(licence(private))
    page.locator("#licenseCheck").click()
    expect(page.locator("#licenseNote")).to_contain_text("not set up")
    expect(page.locator("#proTools")).to_have_attribute("disabled", "")
    ctx.close()


def test_the_get_a_licence_link_is_one_constant_and_only_takes_safe_addresses(
    browser: Any, origin: str
) -> None:
    page, _, ctx = open_page(browser, origin, "pro.html")
    assert page.locator("#getLicense").get_attribute("href") == "#"
    expect(page.locator("#getNote")).to_contain_text("has not been set up yet")
    ctx.close()
    page, _, ctx = open_page(browser, origin, "pro.html", config_url="https://example.test/buy")
    assert page.locator("#getLicense").get_attribute("href") == "https://example.test/buy"
    ctx.close()
    for bad in ("javascript:alert(1)", "http://insecure.test/", "//evil.test", "data:text/html,x"):
        page, _, ctx = open_page(browser, origin, "pro.html", config_url=bad)
        assert page.locator("#getLicense").get_attribute("href") == "#", bad
        ctx.close()


# ---------------------------------------------------------------- free users see what Pro does, greyed


def test_a_free_visitor_sees_the_pro_tools_greyed_and_the_range_csv_greyed(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    _, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex)
    for selector in ("#brandName", "#brandLogo", "#brandSave", "#packFiles", "#packBtn"):
        expect(page.locator(selector)).to_be_disabled()
    assert page.locator("#tools .pro-tag").count() >= 3
    assert "turn on with a valid licence key" in page.locator("#toolsNote").inner_text()
    record = export_run(browser, origin, tmp_path, "free", ["docs"])
    page.goto(f"{origin}/range.html")
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    expect(page.locator("#csvBtn")).to_be_disabled()
    assert "Pro adds your own company name and logo" in page.locator("#proNote").inner_text()
    # A name saved earlier does nothing without a licence: the report stays HashCam's.
    ctx.close()


def test_a_saved_brand_is_ignored_without_a_licence(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    _, public_hex = pair
    record = export_run(browser, origin, tmp_path, "freebrand", ["docs"])
    page, _, ctx = open_page(
        browser, origin, "range.html", public_hex, brand={"name": "Acme Audit"}
    )
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    with page.expect_download() as d:
        page.locator("#reportBtn").click()
    out = tmp_path / "free.pdf"
    d.value.save_as(str(out))
    text = pdf_text(out, page.locator("#reportPass").inner_text())
    assert "HashCam Range" in text and "Acme Audit" not in text
    ctx.close()


# ---------------------------------------------------------------- white-label report


def set_brand(
    page: Any, tmp_path: Path, name: str, logo: bytes | None = None, filename: str = "logo.png"
) -> None:
    page.locator("#brandName").fill(name)
    if logo is not None:
        path = tmp_path / filename
        path.write_bytes(logo)
        page.set_input_files("#brandLogo", str(path))
    page.locator("#brandSave").click()


def test_a_pro_report_carries_the_buyers_name_and_logo_and_still_says_made_with_hashcam(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    record = export_run(browser, origin, tmp_path, "wl", ["webhook", "docs"])
    page, watch, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    set_brand(page, tmp_path, "Acme Audit", png(120, 60))
    expect(page.locator("#brandNote")).to_have_text("Saved on this device.")
    expect(page.locator("#brandPreview")).to_be_visible()
    assert (
        page.locator("#brandPreview").get_attribute("src").startswith("data:image/jpeg;base64,/9j/")
    )
    page.reload()
    assert page.locator("#brandName").input_value() == "Acme Audit", "remembered on this device"
    page.goto(f"{origin}/range.html")
    page.locator("#scoreLevel").select_option("denial-final")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    with page.expect_download() as d:
        page.locator("#reportBtn").click()
    out = tmp_path / "wl.pdf"
    d.value.save_as(str(out))
    password = page.locator("#reportPass").inner_text()
    import pypdf

    assert pypdf.PdfReader(str(out)).decrypt("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA") == 0
    text = pdf_text(out, password)
    assert "Acme Audit" in text and "Made with HashCam" in text and "AES-256" in text
    assert "HashCam Range" not in text, "the header is the buyer's own"
    raw = out.read_bytes()
    assert raw.count(b"/DCTDecode") == 2 and b"Acme" not in raw and b"/AESV3" in raw
    watch.assert_clean()
    ctx.close()


def test_a_long_company_name_is_cut_to_what_the_header_can_hold(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    page.locator("#brandName").evaluate("e => e.removeAttribute('maxlength')")
    set_brand(page, Path("."), "W" * 60 + "\n\x07X")
    expect(page.locator("#brandNote")).to_have_text("Saved on this device.")
    assert page.locator("#brandName").input_value() == "W" * 24
    ctx.close()


@pytest.mark.parametrize(
    ("label", "data", "filename", "message"),
    [
        (
            "an SVG",
            b'<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"><script>1</script></svg>',
            "logo.png",
            "PNG or a JPEG",
        ),
        ("text named like a picture", b"hello" * 100, "logo.jpg", "PNG or a JPEG"),
        ("a broken PNG", b"\x89PNG\r\n\x1a\n" + b"junk" * 50, "logo.png", "could not be read"),
        ("too big a file", png(900, 900), "big.png", "too big"),
        ("too many pixels", png(4100, 10), "wide.png", "too large"),
        ("too small", png(8, 8), "tiny.png", "too small"),
    ],
)
def test_a_logo_that_is_not_a_proper_picture_is_refused(
    browser: Any,
    origin: str,
    pair: tuple[Any, str],
    tmp_path: Path,
    label: str,
    data: bytes,
    filename: str,
    message: str,
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    if label == "too big a file":
        data = data + b"\x00" * (1048576 + 1)  # trailing bytes: a valid PNG, over the 1 MB cap
    set_brand(page, tmp_path, "Acme", data, filename)
    expect(page.locator("#brandNote")).to_contain_text(message)
    assert page.evaluate(f"localStorage.getItem({json.dumps(BRAND_STORE)})") is None, label
    expect(page.locator("#brandPreview")).to_be_hidden()
    ctx.close()


def test_the_brand_can_be_cleared(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    set_brand(page, tmp_path, "Acme", png(64, 64))
    expect(page.locator("#brandPreview")).to_be_visible()
    page.locator("#brandClear").click()
    expect(page.locator("#brandPreview")).to_be_hidden()
    assert page.locator("#brandName").input_value() == ""
    assert page.evaluate(f"localStorage.getItem({json.dumps(BRAND_STORE)})") is None
    ctx.close()


# ---------------------------------------------------------------- audit pack


def receipt_counts() -> dict[str, int]:
    import base64
    from collections import Counter

    events = json.loads(zipfile.ZipFile(GENUINE).read("receipt.json"))["events"]
    kinds = Counter(json.loads(base64.b64decode(e["canonical_b64"]))["event_type"] for e in events)
    return {
        "events": len(events),
        "allowed": kinds["ACTION_AUTHORIZED"],
        "blocked": kinds["ACTION_BLOCKED"],
    }


def sandbox_events(path: Path) -> int:
    html = path.read_text(encoding="utf-8")
    block = html.split('<script type="application/json" id="receipt">', 1)[1].split("</script>", 1)[
        0
    ]
    return len(json.loads(block)["events"])


def test_the_audit_pack_uses_only_records_that_check_out_and_says_what_it_left_out(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    one = export_run(browser, origin, tmp_path, "docs-run", ["docs"])
    two = export_run(browser, origin, tmp_path, "mixed-run", ["webhook", "gpu"])
    tampered = tmp_path / "tampered-run.html"
    tampered.write_text(
        two.read_text(encoding="utf-8").replace(
            '"label": "Sync External Webhook"', '"label": "Read Repo Docs"', 1
        ),
        encoding="utf-8",
    )
    junk = tmp_path / "notes.html"
    junk.write_text("<html><body>hello</body></html>", encoding="utf-8")
    page, watch, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    sent: list[str] = []
    page.on(
        "request",
        lambda r: sent.append(f"{r.method} {r.url}")
        if r.method != "GET"
        or (not r.url.startswith(origin) and not r.url.startswith(("blob:", "data:")))
        else None,
    )
    page.set_input_files(
        "#packFiles",
        [str(one), str(two), str(tampered), str(junk), str(GENUINE), str(EDITED), str(KEYS)],
    )
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_have_text("3 included, 3 not included.")
    rows = {
        li.locator("b").inner_text(): li.inner_text() for li in page.locator("#packList li").all()
    }
    assert set(rows) == {
        "docs-run.html",
        "mixed-run.html",
        "tampered-run.html",
        "notes.html",
        "genuine.abbreceipt",
        "edited.abbreceipt",
    }
    for name in ("docs-run.html", "mixed-run.html", "genuine.abbreceipt"):
        assert rows[name].startswith("INCLUDED"), name
    assert (
        rows["tampered-run.html"].startswith("NOT INCLUDED")
        and "does not check out" in rows["tampered-run.html"]
    )
    assert (
        rows["notes.html"].startswith("NOT INCLUDED")
        and "not a sandbox receipt" in rows["notes.html"]
    )
    assert (
        rows["edited.abbreceipt"].startswith("NOT INCLUDED")
        and "does not check out" in rows["edited.abbreceipt"]
    )
    with page.expect_download() as d:
        page.locator("#packPdf").click()
    pdf = tmp_path / "pack.pdf"
    d.value.save_as(str(pdf))
    expect(page.locator("#packKey")).to_be_visible()
    password = page.locator("#packPass").inner_text()
    assert re.fullmatch(r"(?:[2-9A-HJKMNP-Z]{5}-){4}[2-9A-HJKMNP-Z]{5}", password)
    text = pdf_text(pdf, password)
    r = receipt_counts()
    assert "AUDIT PACK" in text and "3 sessions included, 3 not included" in text
    # one allowed in the docs run, one blocked and one held in the mixed run, plus what the genuine receipt shows
    assert f"{1 + r['allowed']} steps. Allowed by the rules." in text
    assert f"{1 + r['blocked']} steps. Stopped by the rules." in text
    assert "1 steps. Waited for a person to decide." in text
    for part in (
        "Session 1 (docs-run.html)",
        "Session 2 (mixed-run.html)",
        "Session 3 (genuine.abbreceipt)",
        "Not included",
        "tampered-run.html",
        "edited.abbreceipt",
        "notes.html",
    ):
        assert part in text, part
    assert "Session 4" not in text, "a record that did not check out has no session of its own"
    assert (
        "SHA-256" in text
        and "locked with AES-256" in text
        and "not legal or compliance advice" in text
    )
    assert "HashCam Pro" in text, "no name saved: HashCam's own header"
    import pypdf

    assert pypdf.PdfReader(str(pdf)).decrypt(password.lower()) == 0
    assert sent == [], sent
    watch.assert_clean()
    # The same records as a spreadsheet: one row per step of the included records only.
    with page.expect_download() as d2:
        page.locator("#packCsv").click()
    csv_path = tmp_path / "steps.csv"
    d2.value.save_as(str(csv_path))
    raw = csv_path.read_bytes().decode("utf-8")
    assert raw.startswith("﻿")
    rows_csv = list(csv.reader(io.StringIO(raw.lstrip("﻿"))))
    assert rows_csv[0] == [
        "session",
        "file",
        "step",
        "kind",
        "event",
        "result",
        "tone",
        "what_happened",
        "why",
        "where",
    ]
    assert len(rows_csv) - 1 == sandbox_events(one) + sandbox_events(two) + r["events"]
    assert {row[1] for row in rows_csv[1:]} == {
        "docs-run.html",
        "mixed-run.html",
        "genuine.abbreceipt",
    }
    assert "tampered-run.html" not in raw and "edited.abbreceipt" not in raw
    ctx.close()


def test_a_receipt_without_its_keys_is_not_included(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    page.set_input_files("#packFiles", [str(GENUINE)])
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_have_text("0 included, 1 not included.")
    text = page.locator("#packList").inner_text()
    assert "INCOMPLETE" in text and ".keys.json" in text and "not included" in text
    expect(page.locator("#packPdf")).to_be_disabled()
    expect(page.locator("#packCsv")).to_be_disabled()
    ctx.close()


def test_the_pack_has_limits_on_how_much_it_will_read(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    many = []
    for i in range(21):
        f = tmp_path / f"r{i}.html"
        f.write_text("x", encoding="utf-8")
        many.append(str(f))
    page.set_input_files("#packFiles", many)
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_contain_text("Too much to check")
    big = tmp_path / "big.html"
    big.write_bytes(b"<" + b"x" * (9 * 1048576))
    page.set_input_files("#packFiles", [str(big)])
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_contain_text("Too much to check")
    page.set_input_files("#packFiles", [])
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_contain_text("first")
    ctx.close()


def test_the_pack_header_uses_the_buyers_name(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    record = export_run(browser, origin, tmp_path, "pk", ["docs"])
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex, token=licence(private))
    set_brand(page, tmp_path, "Acme Audit", png(80, 80))
    expect(page.locator("#brandNote")).to_have_text("Saved on this device.")
    page.set_input_files("#packFiles", [str(record)])
    page.locator("#packBtn").click()
    expect(page.locator("#packNote")).to_have_text("1 included, 0 not included.")
    with page.expect_download() as d:
        page.locator("#packPdf").click()
    pdf = tmp_path / "pk.pdf"
    d.value.save_as(str(pdf))
    text = pdf_text(pdf, page.locator("#packPass").inner_text())
    assert "Acme Audit" in text and "Made with HashCam" in text and "HashCam Pro" not in text
    ctx.close()


# ---------------------------------------------------------------- CSV: scrubbed and formula-safe


def test_the_csv_never_carries_secrets_or_web_address_queries_and_is_formula_safe(
    browser: Any, origin: str
) -> None:
    page, _, ctx = open_page(browser, origin, "pro.html")
    events = [
        {
            "event_type": "ACTION_REQUESTED",
            "payload": {
                "action_type": "form_submit",
                "target": "https://shop.test/pay?token=SECRETVALUE99&u=x",
            },
        },
        {
            "event_type": "ACTION_BLOCKED",
            "payload": {
                "action_type": "navigate",
                "target": "https://bank.example/home#frag",
                "reason_codes": ["DOMAIN_NOT_ALLOWED"],
            },
        },
        {
            "event_type": "BROWSER_OBSERVATION",
            "payload": {"note": "sk_live_ABCDEFGH12345678", "password": "hunter2"},
        },
    ]
    sandbox = [
        {
            "body": {
                "type": "ACTION_REQUESTED",
                "data": {
                    "label": '=HYPERLINK("http://evil.test","x")',
                    "action": "a",
                    "amount_cents": 0,
                    "domain": "shop.test",
                },
            }
        },
        {
            "body": {
                "type": "POLICY_DECISION",
                "data": {"outcome": "DENY", "trigger_reason": "+cmd|' /C calc'!A0"},
            }
        },
        {"body": {"type": "SESSION_HALTED", "data": {"reason": "@SUM(1+1)"}}},
    ]
    text = page.evaluate(
        "([a, b]) => HCPack.csv([{ name: '=evil.abbreceipt', kind: 'receipt', events: a }, { name: 'ok.html', kind: 'sandbox', events: b }])",
        [events, sandbox],
    )
    assert text.startswith("﻿") and text.endswith("\r\n")
    for secret in ("SECRETVALUE99", "sk_live_ABCDEFGH12345678", "hunter2", "token=", "#frag"):
        assert secret not in text, secret
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    assert len(rows) == 1 + len(events) + len(sandbox)
    for row in rows:
        assert len(row) == 10
        for value in row:
            assert not re.match(r"^[=+\-@\t]", value), ("a spreadsheet could run this", value)
    assert any(row[1] == "'=evil.abbreceipt" for row in rows), (
        "a formula-looking file name is made harmless, not dropped"
    )
    assert any("bank.example" in row[7] for row in rows)
    ctx.close()


def test_the_range_csv_has_every_step_for_pro_and_none_for_free(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    record = export_run(browser, origin, tmp_path, "csvrun", ["docs", "webhook"])
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(record))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    expect(page.locator("#csvBtn")).to_be_enabled()
    assert "Pro is on" in page.locator("#proNote").inner_text()
    with page.expect_download() as d:
        page.locator("#csvBtn").click()
    out = tmp_path / "range.csv"
    d.value.save_as(str(out))
    rows = list(csv.reader(io.StringIO(out.read_text(encoding="utf-8").lstrip("﻿"))))
    assert len(rows) - 1 == sandbox_events(record) and {r[1] for r in rows[1:]} == {"csvrun.html"}
    assert any(r[4] == "POLICY_DECISION" and r[5] == "Denied" for r in rows[1:])
    ctx.close()


def test_a_tampered_record_gives_no_csv_on_the_range(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    private, public_hex = pair
    record = export_run(browser, origin, tmp_path, "csvbad", ["docs"])
    bad = tmp_path / "bad.html"
    bad.write_text(
        record.read_text(encoding="utf-8").replace(
            '"label": "Read Repo Docs', '"label": "Read Repo Dox', 1
        ),
        encoding="utf-8",
    )
    page, _, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    page.locator("#scoreLevel").select_option("first-flight")
    page.set_input_files("#files", str(bad))
    page.locator("#scoreBtn").click()
    expect(page.locator("#result")).to_be_visible()
    expect(page.locator("#overall")).to_have_text("NOT SCORED")
    expect(page.locator("#csvBtn")).to_be_disabled()
    ctx.close()


# ---------------------------------------------------------------- the plan on the Range


def test_the_range_shows_the_pro_plan_with_a_valid_key_and_the_free_plan_without(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, watch, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    limits = page.locator("#limitList").inner_text()
    assert "Pro" in limits and "8 of 8" in limits and "200" in limits
    assert page.locator(".level .lv-chip.lock").count() == 0
    assert "not enforced" in page.locator("#limitNote").inner_text()
    watch.assert_clean()
    ctx.close()
    page, _, ctx = open_page(browser, origin, "range.html", public_hex)
    limits = page.locator("#limitList").inner_text()
    assert "Anonymous" in limits and "6 of 8" in limits
    assert page.locator(".level .lv-chip.lock").count() == 2
    ctx.close()


def test_the_range_shifts_nothing_with_a_licence(
    browser: Any, origin: str, pair: tuple[Any, str]
) -> None:
    private, public_hex = pair
    page, watch, ctx = open_page(browser, origin, "range.html", public_hex, token=licence(private))
    page.wait_for_timeout(1500)
    seen = page.evaluate("window.__m")
    assert seen["shifts"] <= 0.001, seen["shiftList"]
    watch.assert_clean()
    ctx.close()


def test_the_limits_module_has_both_plans_and_still_says_nothing_is_enforced(
    browser: Any, origin: str
) -> None:
    page, _, ctx = open_page(browser, origin, "range.html")
    got = page.evaluate(
        "() => ({ plans: HCLimits.plans, enforced: HCLimits.ENFORCED, pro: HCLimits.limitsFor('pro') })"
    )
    assert got["plans"] == ["anonymous", "pro"] and got["enforced"] is False
    assert len(got["pro"]["scenarios"]) == 8 and got["pro"]["name"] == "Pro"
    ctx.close()


# ---------------------------------------------------------------- the pages


def test_every_page_has_pro_in_its_nav_and_marks_only_its_own() -> None:
    for name in (
        "index.html",
        "sandbox.html",
        "range.html",
        "about.html",
        "pro.html",
        "audit.html",
    ):
        html = (SITE / name).read_text(encoding="utf-8")
        assert html.count('href="pro.html"') >= 1 and ">Pro</a>" in html, name
    pro = (SITE / "pro.html").read_text(encoding="utf-8")
    assert 'href="pro.html" aria-current="page"' in pro and pro.count('aria-current="page"') == 1
    about = (SITE / "about.html").read_text(encoding="utf-8")
    assert (
        'href="about.html" aria-current="page"' in about
        and 'href="pro.html" aria-current' not in about
    )


def test_the_audit_page_has_no_script_no_form_and_one_mailto_address() -> None:
    html = (SITE / "audit.html").read_text(encoding="utf-8")
    assert not re.search(r"<script|<form|<style|\sstyle\s*=|\son[a-z]+\s*=", html, re.IGNORECASE)
    mails = re.findall(r'href="(mailto:[^"]+)"', html)
    assert len(mails) == 1 and mails[0].startswith("mailto:CHANGE-ME@example.com"), mails
    assert not re.search(r'(?:src|href)="https?:', html)
    assert "not a guarantee" in html and "not legal or compliance advice" in html


def test_pro_files_are_plain_have_no_billing_and_make_no_requests() -> None:
    names = [
        "pro.html",
        "audit.html",
        "pro.css",
        "pro/license.js",
        "pro/records.js",
        "pro/brand.js",
        "pro/pack.js",
        "pro/pro.js",
        "pro/config.js",
        "pro/pubkey.js",
    ]
    for name in names:
        lines = (SITE / name).read_text(encoding="utf-8").splitlines()
        code = "\n".join(line for line in lines if not line.lstrip().startswith("//"))
        assert not re.search(
            r"(?i)pricing|\bprice|\bprices\b|subscri|billing|stripe|invoice|checkout\b|\$\d", code
        ), name
        assert not re.search(r"\beval\(|new Function|innerHTML|document\.write", code), name
        assert not re.search(
            r"\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket|importScripts", code
        ), name
    for name in ("pro.html", "audit.html"):
        html = (SITE / name).read_text(encoding="utf-8")
        assert not re.search(r"<style|\sstyle\s*=|\son[a-z]+\s*=", html, re.IGNORECASE), name
        assert not re.search(r'<(?:script|link)[^>]+(?:src|href)="https?:', html), name
        assert not re.findall(r"<script(?![^>]*\ssrc=)", html), name


@pytest.mark.parametrize("name", ["pro.html", "audit.html"])
def test_the_new_pages_fit_a_phone_and_shift_nothing(browser: Any, origin: str, name: str) -> None:
    page, watch, ctx = open_page(browser, origin, name, viewport={"width": 375, "height": 800})
    page.wait_for_timeout(1200)
    page.evaluate("window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(600)
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.evaluate("window.__m.shifts") <= 0.001, page.evaluate("window.__m.shiftList")
    watch.assert_clean()
    ctx.close()


def test_the_pro_page_over_file_has_no_errors(browser: Any, pair: tuple[Any, str]) -> None:
    page = browser.new_page()
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.goto((SITE / "pro.html").as_uri())
    expect(page.locator("#licState")).not_to_have_text("Checking…")
    assert errors == [], errors
    page.close()


def test_a_button_only_acts_for_pro_even_if_it_is_enabled_by_hand(
    browser: Any, origin: str, pair: tuple[Any, str], tmp_path: Path
) -> None:
    """Enabling a control in the developer tools must not skip the check (a browser check is not strong, but it is not absent)."""
    _, public_hex = pair
    page, _, ctx = open_page(browser, origin, "pro.html", public_hex)
    page.evaluate("document.getElementById('proTools').disabled = false")
    f = tmp_path / "r.html"
    f.write_text("x", encoding="utf-8")
    page.set_input_files("#packFiles", [str(f)])
    page.locator("#packBtn").click()
    page.wait_for_timeout(300)
    assert (
        page.locator("#packList li").count() == 0 and page.locator("#packNote").inner_text() == ""
    )
    page.locator("#packPdf").evaluate("e => { e.disabled = false; }")
    page.locator("#packPdf").click()
    page.wait_for_timeout(300)
    expect(page.locator("#packKey")).to_be_hidden()
    ctx.close()
