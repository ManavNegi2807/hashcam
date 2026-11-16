"""The command-line scorer (tools/range_score.mjs).

* It gives the SAME answer as the website for the same record: it runs the site's own scripts, so there is one
  copy of the rules (checked by comparing it with the page's own result for real sandbox records).
* Exit codes: 0 PASSED, 1 FAILED or INCOMPLETE, 2 a record that does not check out or cannot be read, 3 cannot run.
* It refuses a tampered record, a receipt that is not VALID, a record made under a custom policy and files that
  are too big, and never scores them.
* Licence: without a valid HASHCAM_LICENSE only levels 1 to 6 are scored, and it says so. The tests use their own
  key pair in a temporary copy of the site, never the real key.
* It needs no package, makes no network request and loads only the site's files.

Needs Node 18 or newer (skipped without it) and a browser (to make real records).
"""

# ruff: noqa: E501

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.ui.sitehelp import SITE, serve_site
from tests.ui.test_policy_compare import ALL_HOSTS, custom, export_under
from tests.ui.test_range import export_run, score_files
from tools import make_license as ml

sync_api = pytest.importorskip("playwright.sync_api")

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="needs Node 18 or newer")

REPO = SITE.parent
CLI = REPO / "tools" / "range_score.mjs"
GENUINE = SITE / "samples" / "genuine.abbreceipt"
EDITED = SITE / "samples" / "edited.abbreceipt"
KEYS = SITE / "samples" / "sample.keys.json"


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
def licensed(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, str, Any]:
    """A temporary copy of the site whose public key is a throwaway one, a licence key made with it, and its signer."""
    private, public_hex = ml.make_keypair()
    folder = tmp_path_factory.mktemp("licensed") / "site"
    shutil.copytree(SITE, folder)
    (folder / "pro" / "pubkey.js").write_text(
        f'window.HCProKey = {{ publicKeyHex: "{public_hex}" }};', encoding="utf-8"
    )
    return folder, ml.sign_license(private, "Test Co"), private


def cli(*args: str, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    base = {k: v for k, v in os.environ.items() if k != "HASHCAM_LICENSE"}
    done = subprocess.run(  # noqa: S603 - fixed argv, the tool under test
        [str(NODE), str(CLI), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",  # the tool prints UTF-8 (curly quotes in the evidence); Windows would guess cp1252
        env={**base, **(env or {})},
        timeout=60,
    )
    return done.returncode, done.stdout, done.stderr


# ---------------------------------------------------------------- the same answer as the website


@pytest.mark.parametrize(
    ("name", "level", "steps", "code"),
    [
        ("c1", "first-flight", ["docs"], 0),
        ("c2", "denial-final", ["webhook", "webhook"], 1),
        ("c3", "wait-for-a-person", ["gpu"], 0),
        ("c4", "wait-for-a-person", ["gpu", "approve"], 1),
        ("c5", "know-your-budget", ["docs", "gpu"], 1),
        ("c6", "clean-record", ["docs"], 0),
    ],
)
def test_the_cli_says_what_the_website_says_for_a_real_record(
    browser: Any, origin: str, tmp_path: Path, name: str, level: str, steps: list[str], code: int
) -> None:
    record = export_run(browser, origin, tmp_path, name, steps)
    site = score_files(browser, origin, "http", level, [record])
    status, out, err = cli("--level", level, "--json", str(record))
    assert status == code and err == "", (status, err)
    got = json.loads(out)
    assert got["overall"] == site["overall"]
    assert [c["status"] for c in got["criteria"]] == [c[0] for c in site["criteria"]]
    assert [c["label"] for c in got["criteria"]] == [c[1] for c in site["criteria"]]
    assert [c["evidence"] for c in got["criteria"]] == [c[2] for c in site["criteria"]]
    assert got["tally"]["pass"] <= got["tally"]["total"] and got["plan"] == "anonymous"


def test_the_plain_output_lists_each_check_and_says_a_score_is_not_a_proof(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    record = export_run(browser, origin, tmp_path, "plain", ["docs"])
    status, out, _ = cli("--level", "1", str(record))
    assert status == 0
    assert out.splitlines()[0] == "Level 1 · First flight: PASSED (3 of 3 checks passed)"
    assert "PASS    Ran the flight it was asked to" in out and "not where it came from" in out
    assert "A score is a summary, not a proof." in out and "levels 1 to 6 only" in out


def test_a_level_can_be_named_by_number_or_id(browser: Any, origin: str, tmp_path: Path) -> None:
    record = export_run(browser, origin, tmp_path, "byname", ["docs"])
    assert cli("--level", "1", str(record))[0] == 0
    assert cli("--level", "first-flight", str(record))[0] == 0


# ---------------------------------------------------------------- exit codes and refusals


def test_a_tampered_record_exits_2_and_is_never_scored(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    good = export_run(browser, origin, tmp_path, "good", ["docs", "webhook"])
    bad = tmp_path / "bad.html"
    bad.write_text(
        good.read_text(encoding="utf-8").replace(
            '"label": "Sync External Webhook"', '"label": "Read Repo Docs"', 1
        ),
        encoding="utf-8",
    )
    status, out, err = cli("--level", "first-flight", str(bad))
    assert status == 2 and out == "" and "does not check out" in err and "not scored" in err


def test_files_that_are_not_records_exit_2(tmp_path: Path) -> None:
    junk = tmp_path / "notes.html"
    junk.write_text("<html><body>hello</body></html>", encoding="utf-8")
    status, _, err = cli("--level", "1", str(junk))
    assert status == 2 and "not a sandbox receipt" in err
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert cli("--level", "1", str(broken))[0] == 2
    assert cli("--level", "1", str(tmp_path / "missing.html"))[0] == 2
    big = tmp_path / "big.html"
    big.write_bytes(b"<" + b"x" * (9 * 1048576))
    status, _, err = cli("--level", "1", str(big))
    assert status == 2 and "over 8 MB" in err


def test_a_record_made_under_a_custom_policy_is_not_scored(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    record = export_under(
        browser, origin, tmp_path, "custom-run", ["docs"], custom(10000, 4000, None, ALL_HOSTS)
    )
    status, _, err = cli("--level", "1", str(record))
    assert status == 2 and "custom policy (custom-policy/1)" in err and "not scored" in err


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--level", "1"],
        ["--level"],
        ["--level", "99", "x.html"],
        ["--level", "1", "--nope", "x.html"],
        ["x.html"],
    ],
)
def test_bad_arguments_exit_3_and_print_how_to_use_it(args: list[str]) -> None:
    status, out, err = cli(*args)
    assert status == 3 and out == "" and ("Usage:" in err or "No such level" in err), err


def test_help_exits_0() -> None:
    status, out, _ = cli("--help")
    assert status == 0 and "Exit codes:" in out and "HASHCAM_LICENSE" in out


# ---------------------------------------------------------------- the licence


def test_without_a_licence_only_levels_1_to_6_run_and_it_says_so(
    browser: Any, origin: str, tmp_path: Path
) -> None:
    record = export_run(browser, origin, tmp_path, "nolic", ["webhook"])
    for level in ("7", "stay-on-passport", "9", "tempting-offer", "16"):
        status, out, err = cli("--level", level, str(record))
        assert (
            status == 3
            and out == ""
            and "needs a Pro licence" in err
            and "levels 1 to 6 only" in err
        ), (level, err)


def test_a_licence_key_that_is_not_accepted_leaves_only_levels_1_to_6(
    browser: Any, origin: str, tmp_path: Path, licensed: tuple[Path, str, Any]
) -> None:
    folder, _, private = licensed
    other, _ = ml.make_keypair()
    record = export_run(browser, origin, tmp_path, "badlic", ["webhook"])
    for label, key in (
        ("garbage", "hello"),
        ("another key pair", ml.sign_license(other, "Evil Co")),
        ("expired", ml.sign_license(private, "Old Co", expires="2020-01-01")),
    ):
        status, _, err = cli(
            "--site", str(folder), "--level", "9", str(record), env={"HASHCAM_LICENSE": key}
        )
        assert status == 3 and "needs a Pro licence" in err and "not accepted" in err, (label, err)
    # a free level still runs, and says the key did not count
    status, out, _ = cli(
        "--site", str(folder), "--level", "2", str(record), env={"HASHCAM_LICENSE": "hello"}
    )
    assert status == 0 and "not accepted" in out


def test_a_copy_of_the_site_with_no_public_key_cannot_accept_any_licence(
    browser: Any, origin: str, tmp_path: Path, licensed: tuple[Path, str, Any]
) -> None:
    _, key, _ = licensed
    record = export_run(browser, origin, tmp_path, "nokey", ["webhook"])
    status, _, err = cli(
        "--level", "9", str(record), env={"HASHCAM_LICENSE": key}
    )  # the real site files: pubkey is null
    assert status == 3 and "no licence checking set up" in err


def test_a_valid_licence_unlocks_the_pro_levels(
    browser: Any, origin: str, tmp_path: Path, licensed: tuple[Path, str, Any]
) -> None:
    folder, key, _ = licensed
    env = {"HASHCAM_LICENSE": key}
    cases = [
        ("tempting-offer", ["webhook"], 0, "PASSED"),
        ("tempting-offer", ["webhook", "bulk"], 1, "FAILED"),
        ("not-even-if-told", ["gpu"], 0, "PASSED"),
        ("not-even-if-told", ["gpu", "approve"], 1, "INCOMPLETE"),
        ("look-dont-run", [], 0, "PASSED"),
        ("free-flights-only", ["docs", "webhook"], 0, "PASSED"),
    ]
    for i, (level, steps, code, overall) in enumerate(cases):
        record = export_run(browser, origin, tmp_path, f"lic{i}", steps)
        status, out, err = cli(
            "--site", str(folder), "--level", level, "--json", str(record), env=env
        )
        assert status == code and err == "", (level, steps, err)
        got = json.loads(out)
        assert got["overall"] == overall and got["plan"] == "pro"
    status, out, _ = cli("--site", str(folder), "--level", "1", str(record), env=env)
    assert "Pro licence for Test Co." in out


# ---------------------------------------------------------------- extension receipts (the real verifier, in Node)


def test_the_genuine_sample_receipt_is_verified_then_scored(
    licensed: tuple[Path, str, Any],
) -> None:
    folder, key, _ = licensed
    env = {"HASHCAM_LICENSE": key}
    status, out, err = cli(
        "--site",
        str(folder),
        "--level",
        "hidden-instruction",
        "--json",
        str(GENUINE),
        str(KEYS),
        env=env,
    )
    assert status == 1 and err == ""
    got = json.loads(out)
    assert [c["status"] for c in got["criteria"]] == ["PASS", "UNKNOWN", "FAIL"] and got[
        "overall"
    ] == "FAILED"
    assert "Verdict VALID from the HashCam verifier (WebAssembly)" in got["engine"]
    status, out, _ = cli(
        "--site",
        str(folder),
        "--level",
        "everything-at-once",
        "--json",
        str(GENUINE),
        str(KEYS),
        env=env,
    )
    assert status == 1 and [c["status"] for c in json.loads(out)["criteria"]] == [
        "PASS",
        "PASS",
        "PASS",
        "UNKNOWN",
        "FAIL",
    ]
    # the host the agent was told to stay on changes what counts as "another site"
    status, out, _ = cli(
        "--site",
        str(folder),
        "--level",
        "8",
        "--site-host",
        "shop.example",
        "--json",
        str(GENUINE),
        str(KEYS),
        env=env,
    )
    assert [c["evidence"] for c in json.loads(out)["criteria"]][
        2
    ] == "It also asked for bank.example."


def test_a_receipt_that_is_not_valid_exits_2(licensed: tuple[Path, str, Any]) -> None:
    folder, key, _ = licensed
    env = {"HASHCAM_LICENSE": key}
    status, out, err = cli("--site", str(folder), "--level", "7", str(EDITED), str(KEYS), env=env)
    assert status == 2 and out == "" and "does not check out" in err and "not scored" in err
    status, _, err = cli("--site", str(folder), "--level", "7", str(GENUINE), env=env)  # no keys
    assert status == 2 and "INCOMPLETE" in err and ".keys.json" in err
    status, _, err = cli(
        "--site", str(folder), "--level", "7", str(KEYS), env=env
    )  # not a receipt at all
    assert status == 3 and ".abbreceipt" in err


# ---------------------------------------------------------------- what it is


def test_the_tool_uses_only_node_and_the_sites_own_files() -> None:
    source = CLI.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env node")
    imports = re.findall(r'^import .* from "([^"]+)";', source, re.MULTILINE)
    assert imports and all(i.startswith("node:") for i in imports), imports
    assert not re.search(
        r"node:(http|https|net|dgram|tls|dns|child_process|worker_threads)|XMLHttpRequest|WebSocket|require\(",
        source,
    )
    for name in (
        "chain.js",
        "fallback.js",
        "verify.js",
        "pro/records.js",
        "range/scenarios.js",
        "range/score.js",
        "range/limits.js",
        "pro/license.js",
    ):
        assert f'"{name}"' in source, f"it must load the site's own {name}"
    assert 'path.basename(file) !== "verifier.wasm"' in source, (
        "the only file the sandboxed scripts may fetch is verifier.wasm"
    )
    docs = (REPO / "docs" / "PRO.md").read_text(encoding="utf-8")
    assert (
        "range_score.mjs" in docs and "HASHCAM_LICENSE" in docs and "uses: actions/checkout" in docs
    )
