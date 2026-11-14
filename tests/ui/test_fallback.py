"""The JavaScript receipt checker (site/fallback.js) and how the page falls back to it.

It is a second implementation of the cryptographic core of `abb verify`, so it is held to the
project's own evidence, not to a reading of the Rust:

* the conformance vectors (Merkle roots, inclusion and consistency proofs, malformed proofs,
  canonical JSON and the inputs it must reject, domain tags);
* a corpus of real receipts, genuine and tampered nineteen ways, against `abb verify` itself: the
  four checks it covers must agree, it must say INVALID whenever `abb` does, and it must never say
  VALID (it does not check coverage, policy or the mandate);
* the page: with WebAssembly unavailable, the sample buttons and the drop zone still give the right
  answer, on http and from file://, and say that the fallback did it.

The vector and page tests need only a browser; the corpus needs `ABB_BIN`.
"""

from __future__ import annotations

import base64
import copy
import io
import json
import os
import subprocess
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import REPO, SITE, serve_site

sync_api = pytest.importorskip("playwright.sync_api")
expect = sync_api.expect

SAMPLES = SITE / "samples"
NEEDS_ABB = pytest.mark.skipif(not os.environ.get("ABB_BIN"), reason="needs ABB_BIN")


@pytest.fixture(scope="module")
def browser() -> Iterator[Any]:
    with sync_api.sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture(scope="module")
def checker(browser: Any) -> Iterator[Any]:
    """A page with only fallback.js loaded. A file:// page is a secure context (Web Crypto works)
    and has no content security policy, so the script can be injected."""
    page = browser.new_page()
    page.goto((SITE / "vercel.json").as_uri())
    page.add_script_tag(path=str(SITE / "fallback.js"))
    yield page
    page.close()


def vectors(name: str) -> list[dict[str, Any]]:
    data = json.loads((REPO / "vectors" / name).read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


# ---------------------------------------------------------------- the conformance vectors


def test_merkle_roots_match_the_vectors(checker: Any) -> None:
    for case in vectors("merkle/roots.json"):
        size = case["input"]["leaf_count"]
        got = checker.evaluate(
            """async (n) => {
                const I = HCFallback.internals, te = new TextEncoder();
                const leaves = Array.from({length: n}, (_, i) => te.encode("abb1-test-leaf-" + i));
                return I.hex(await I.mth(leaves));
            }""",
            size,
        )
        assert got == case["expect"]["root_hash"], case["id"]


def test_inclusion_and_consistency_proofs_match_the_vectors(checker: Any) -> None:
    inclusion = [
        (c["input"]["tree_size"], c["input"]["leaf_index"], c["expect"]["path"],
         c["expect"]["root_hash"])
        for c in vectors("merkle/inclusion.json")
    ]  # fmt: skip
    assert len(inclusion) == 30
    bad = checker.evaluate(
        """async (cases) => {
            const I = HCFallback.internals, te = new TextEncoder(), wrong = [];
            for (const [size, index, path, root] of cases) {
                const leaf = await I.leafHash(te.encode("abb1-test-leaf-" + index));
                const proof = path.map((h) => I.fromHex(h));
                const got = await I.verifyInclusion(leaf, index, size, proof);
                if (I.hex(got) !== root) wrong.push([size, index]);
            }
            return wrong;
        }""",
        inclusion,
    )
    assert bad == []
    consistency = [
        (c["input"]["first_size"], c["input"]["second_size"], c["expect"]["first_root"],
         c["expect"]["path"], c["expect"]["second_root"])
        for c in vectors("merkle/consistency.json")
    ]  # fmt: skip
    assert len(consistency) == 27
    bad = checker.evaluate(
        """async (cases) => {
            const I = HCFallback.internals, wrong = [];
            for (const [a, b, firstRoot, path, secondRoot] of cases) {
                const proof = path.map((h) => I.fromHex(h));
                const got = await I.verifyConsistency(a, b, I.fromHex(firstRoot), proof);
                if (I.hex(got) !== secondRoot) wrong.push([a, b]);
            }
            return wrong;
        }""",
        consistency,
    )
    assert bad == []


def test_malformed_proofs_are_rejected_for_the_stated_reason(checker: Any) -> None:
    cases = vectors("merkle/malformed.json")
    out = checker.evaluate(
        """async (cases) => {
            const I = HCFallback.internals, te = new TextEncoder(), got = {};
            for (const c of cases) {
                const i = c.input;
                got[c.id] = "ACCEPTED";
                try {
                    const path = i.path.map((h) => I.fromHex(h));
                    if (i.proof_kind === "inclusion") {
                        const leaf = te.encode("abb1-test-leaf-" + i.leaf_index);
                        const hashed = await I.leafHash(leaf);
                        await I.verifyInclusion(hashed, i.leaf_index, i.tree_size, path);
                    } else {
                        const first = I.fromHex(i.first_root);
                        await I.verifyConsistency(i.first_size, i.second_size, first, path);
                    }
                } catch (e) {
                    // A path that is not lowercase hex is refused while the receipt is read.
                    got[c.id] = /lowercase hex/.test(e.message) ? "NOT_HEX" : e.message;
                }
            }
            return got;
        }""",
        cases,
    )
    for case in cases:
        assert out[case["id"]] == case["expect"]["reason"], case["id"]


def test_canonical_json_matches_the_vectors_and_refuses_what_it_must(checker: Any) -> None:
    canonical = vectors("jcs/canonical.json")
    out = checker.evaluate(
        """async (cases) => {
            const I = HCFallback.internals, te = new TextEncoder(), got = {};
            for (const c of cases) {
                const text = I.canon(JSON.parse(JSON.stringify(c.input)));
                got[c.id] = [text, I.hex(await I.sha256(te.encode(text)))];
            }
            return got;
        }""",
        canonical,
    )
    for case in canonical:
        assert out[case["id"]] == [case["expect"]["canonical"], case["expect"]["canonical_sha256"]]
    invalid = vectors("jcs/invalid.json")
    accepted = checker.evaluate(
        """(cases) => cases.filter((c) => {
            const I = HCFallback.internals;
            try { I.parseStrict(c.input_text, I.PROTOCOL_LIMITS); return true; }
            catch (e) { return false; }
        }).map((c) => c.id)""",
        invalid,
    )
    assert accepted == [], f"these must be rejected: {accepted}"


def test_domain_tags_match_the_vectors(checker: Any) -> None:
    cases = [c for c in vectors("hashing/domain_tags.json") if c["input"].get("tag")]
    assert len(cases) == 9
    out = checker.evaluate(
        """async (cases) => {
            const I = HCFallback.internals, got = {};
            for (const c of cases) {
                const data = Uint8Array.from(atob(c.input.data_b64), (ch) => ch.charCodeAt(0));
                got[c.id] = I.hex(await I.sha256(I.tagged(c.input.tag, data)));
            }
            return got;
        }""",
        cases,
    )
    for case in cases:
        assert out[case["id"]] == case["expect"]["digest"], case["id"]


# ---------------------------------------------------------------- real receipts against abb verify


def zipped(
    receipt: dict[str, Any], *, deflate: bool = False, extra: dict[str, bytes] | None = None
) -> bytes:
    buffer = io.BytesIO()
    kind = zipfile.ZIP_DEFLATED if deflate else zipfile.ZIP_STORED
    with zipfile.ZipFile(buffer, "w", kind) as z:
        z.writestr("receipt.json", json.dumps(receipt, separators=(",", ":"), ensure_ascii=False))
        for name, data in (extra or {}).items():
            z.writestr(name, data)
    return buffer.getvalue()


def genuine() -> dict[str, Any]:
    with zipfile.ZipFile(SAMPLES / "genuine.abbreceipt") as z:
        loaded: dict[str, Any] = json.loads(z.read("receipt.json"))
    return loaded


def reencode(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return base64.b64encode(text.encode()).decode()


def edit_canonical(receipt: dict[str, Any], index: int, old: bytes, new: bytes) -> None:
    raw = base64.b64decode(receipt["events"][index]["canonical_b64"])
    assert old in raw
    receipt["events"][index]["canonical_b64"] = base64.b64encode(raw.replace(old, new, 1)).decode()


def mutated(name: str) -> bytes:
    r = copy.deepcopy(genuine())
    if name == "genuine":
        return zipped(r)
    if name == "genuine-deflated":
        return zipped(r, deflate=True)
    if name == "edited-event":
        edit_canonical(r, 3, b"observed_by_local_gateway", b"observed_by_local_gatewaz")
    elif name == "drop-last-event":
        r["events"].pop()
    elif name == "swap-two-events":
        r["events"][1], r["events"][2] = r["events"][2], r["events"][1]
    elif name == "flip-signature":
        sig = r["checkpoints"][0]["signature"]
        r["checkpoints"][0]["signature"] = ("1" if sig[0] != "1" else "2") + sig[1:]
    elif name == "edit-checkpoint-root":
        payload = json.loads(base64.b64decode(r["checkpoints"][0]["payload_b64"]))
        payload["root_hash"] = "ab" * 32
        r["checkpoints"][0]["payload_b64"] = reencode(payload)
    elif name == "edit-checkpoint-size":
        payload = json.loads(base64.b64decode(r["checkpoints"][0]["payload_b64"]))
        payload["tree_size"] = payload["tree_size"] + 1
        r["checkpoints"][0]["payload_b64"] = reencode(payload)
    elif name == "edit-global-record":
        record = json.loads(base64.b64decode(r["global_log"]["record_b64"]))
        record["run_id"] = "00000000-0000-4000-8000-000000000000"
        r["global_log"]["record_b64"] = reencode(record)
    elif name == "edit-global-proof":
        r["global_log"]["inclusion_proof"]["leaf_index"] = 3
    elif name == "protocol-v2":
        r["protocol_version"] = "abb/2"
    elif name == "path-traversal":
        return zipped(r, extra={"../evil.txt": b"x"})
    elif name == "nested-archive":
        return zipped(r, extra={"artifacts/inner.zip": b"x"})
    else:
        raise AssertionError(name)
    return zipped(r)


CORPUS = [
    "genuine", "genuine-deflated", "edited-event", "drop-last-event", "swap-two-events",
    "flip-signature", "edit-checkpoint-root", "edit-checkpoint-size", "edit-global-record",
    "edit-global-proof", "protocol-v2", "path-traversal", "nested-archive",
]  # fmt: skip
CHECKED = ("evidence_integrity", "checkpoint_signatures", "consistency", "global_log_inclusion")


def cli_verdict(receipt: bytes, keys: Path | None, tmp: Path) -> dict[str, Any]:
    path = tmp / "r.abbreceipt"
    path.write_bytes(receipt)
    argv = [os.environ["ABB_BIN"], "verify", str(path), "--json", "--profile", "LOCAL_ONLY"]
    if keys:
        argv += ["--keys", str(keys)]
    done = subprocess.run(argv, capture_output=True, check=False)  # noqa: S603 - fixed argv
    if done.returncode == 65:
        return {"overall": "UNREADABLE"}
    text = done.stdout.decode()
    if text.startswith("overall="):
        return {"overall": text.split("=", 1)[1].splitlines()[0]}
    loaded: dict[str, Any] = json.loads(text)
    return loaded


def fallback_verdict(page: Any, receipt: bytes, keys: bytes) -> dict[str, Any]:
    out: dict[str, Any] = page.evaluate(
        "([r, k]) => HCFallback.verifyReceipt(new Uint8Array(r), new Uint8Array(k))",
        [list(receipt), list(keys)],
    )
    return out


@NEEDS_ABB
@pytest.mark.parametrize("name", CORPUS)
@pytest.mark.parametrize("with_keys", [True, False], ids=["keys", "no-keys"])
def test_the_fallback_agrees_with_abb_verify(
    checker: Any, name: str, with_keys: bool, tmp_path: Path
) -> None:
    receipt = mutated(name)
    keys_path = SAMPLES / "sample.keys.json"
    cli = cli_verdict(receipt, keys_path if with_keys else None, tmp_path)
    mine = fallback_verdict(checker, receipt, keys_path.read_bytes() if with_keys else b"")
    assert mine["overall"] != "VALID", "the fallback must never call a receipt VALID"
    if cli["overall"] in ("UNREADABLE", "UNSUPPORTED"):
        assert mine["overall"] == cli["overall"], (cli, mine)
        return
    if cli["overall"] == "INVALID":
        assert mine["overall"] == "INVALID", (name, cli["overall"], mine["overall"])
    else:
        assert mine["overall"] == "INCOMPLETE", (name, cli["overall"], mine["overall"])
    for dim in CHECKED:
        assert mine["dimensions"][dim] == cli["dimensions"][dim], (name, dim, cli, mine)


# ---------------------------------------------------------------- the page


FORCE_NO_WASM = (
    "WebAssembly.instantiate = () => Promise.reject(new Error('WebAssembly is blocked'));"
)


@pytest.fixture(scope="module")
def origin() -> Iterator[str]:
    with serve_site() as base:
        yield base


def page_at(browser: Any, origin: str, how: str, *, no_wasm: bool) -> tuple[Any, list[str]]:
    page = browser.new_page()
    page.set_default_timeout(20_000)
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    if no_wasm:
        page.add_init_script(FORCE_NO_WASM)
    page.goto(f"{origin}/index.html" if how == "http" else (SITE / "index.html").as_uri())
    return page, errors


@pytest.mark.parametrize("how", ["http", "file"])
def test_the_samples_verify_without_webassembly(browser: Any, origin: str, how: str) -> None:
    page, errors = page_at(browser, origin, how, no_wasm=True)
    page.get_by_role("button", name="Genuine sample").click()
    expect(page.locator("#stamp")).to_have_text("INCOMPLETE")
    expect(page.locator("#engineNote")).to_contain_text("JavaScript fallback checked this receipt")
    expect(page.locator("#engineNote")).to_contain_text("never VALID")
    expect(page.locator("#verdictPlain")).to_contain_text("No problem was found")
    expect(page.locator("#dominoes .d-PASS").first).to_be_visible()

    page.get_by_role("button", name="Same sample, one event edited").click()
    expect(page.locator("#stamp")).to_have_text("INVALID")
    expect(page.locator("#details")).to_contain_text("Nothing in the record was changed (Problem)")
    expect(page.locator("#details")).to_contain_text("this event is not in the signed tree")
    assert errors == [], errors
    page.close()


@pytest.mark.parametrize("how", ["http", "file"])
def test_the_drop_zone_verifies_without_webassembly(
    browser: Any, origin: str, how: str, tmp_path: Path
) -> None:
    page, errors = page_at(browser, origin, how, no_wasm=True)
    keys = SAMPLES / "sample.keys.json"
    page.set_input_files("#files", [str(SAMPLES / "genuine.abbreceipt"), str(keys)])
    expect(page.locator("#stamp")).to_have_text("INCOMPLETE")
    page.set_input_files("#files", [str(SAMPLES / "edited.abbreceipt"), str(keys)])
    expect(page.locator("#stamp")).to_have_text("INVALID")
    # Without its key manifest the signatures are UNKNOWN, never passed.
    page.set_input_files("#files", [str(SAMPLES / "genuine.abbreceipt")])
    expect(page.locator("#stamp")).to_have_text("INCOMPLETE")
    expect(page.locator("#details")).to_contain_text("signatures were not checked")
    junk = tmp_path / "junk.abbreceipt"
    junk.write_bytes(b"this is not a zip")
    page.set_input_files("#files", [str(junk)])
    expect(page.locator("#stamp")).to_have_text("UNREADABLE")
    assert errors == [], errors
    page.close()


def test_a_missing_wasm_file_falls_back_with_one_clear_reason(browser: Any, origin: str) -> None:
    """The live-site failure: verifier.wasm answers 404. The page now says why and still checks."""
    page = browser.new_page()
    page.set_default_timeout(20_000)
    page.route("**/verifier.wasm", lambda route: route.fulfill(status=404, body="Not found"))
    errors: list[str] = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{origin}/index.html")
    page.get_by_role("button", name="Genuine sample").click()
    expect(page.locator("#stamp")).to_have_text("INCOMPLETE")
    expect(page.locator("#engineNote")).to_contain_text("verifier.wasm answered HTTP 404")
    page.get_by_role("button", name="Same sample, one event edited").click()
    expect(page.locator("#stamp")).to_have_text("INVALID")
    assert errors == [], errors  # no uncaught error: the 404 itself is the only thing logged
    page.close()


@pytest.mark.skipif(not (SITE / "verifier.wasm").exists(), reason="needs site/verifier.wasm")
@pytest.mark.parametrize("how", ["http", "file"])
def test_with_webassembly_the_full_verdict_is_still_used(
    browser: Any, origin: str, how: str
) -> None:
    page, errors = page_at(browser, origin, how, no_wasm=False)
    page.get_by_role("button", name="Genuine sample").click()
    expect(page.locator("#stamp")).to_have_text("VALID")
    expect(page.locator("#engineNote")).to_contain_text("compiled to WebAssembly")
    page.get_by_role("button", name="Same sample, one event edited").click()
    expect(page.locator("#stamp")).to_have_text("INVALID")
    assert errors == [], errors
    page.close()


# ------------------------------------------------------------ the file the live site was missing


def test_the_verifier_is_a_real_wasm_file_and_git_does_not_ignore_it() -> None:
    wasm = SITE / "verifier.wasm"
    assert wasm.exists(), "site/verifier.wasm is missing: run python tools/build_site.py"
    assert wasm.read_bytes()[:4] == b"\x00asm"
    argv = ["git", "check-ignore", "-q", str(wasm)]
    done = subprocess.run(argv, cwd=REPO, check=False)  # noqa: S603 - fixed argv
    assert done.returncode == 1, "git ignores site/verifier.wasm, so it would never be deployed"
