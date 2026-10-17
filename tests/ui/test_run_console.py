"""The run console: a human gives the task and confirms the cost; nothing else starts a run.

No test here calls TinyFish or spends anything: the cost estimate is a stub and the
"run" is a tiny local Python command.
"""

from __future__ import annotations

import http.client
import json
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from adapters.tinyfish.http_client import KEY_ENV
from services.dashboard.runner import Runner
from services.dashboard.server import Config, serve

DUMMY_KEY = "dummy-key-for-tests-only"
URL = "https://example.com"


class Console:
    def __init__(self, port: int, runner: Runner) -> None:
        self.port = port
        self.runner = runner

    def call(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        token: bool = True,
    ) -> tuple[int, Any, str]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        sent = {"Content-Type": "application/json", **(headers or {})}
        if token:
            sent.setdefault("X-ABB-Token", self.runner.token)
        payload = json.dumps(body) if body is not None else None
        conn.request(method, path, body=payload, headers=sent)
        response = conn.getresponse()
        text = response.read().decode()
        conn.close()
        try:
            return response.status, json.loads(text), text
        except ValueError:
            return response.status, None, text

    def start(self, **overrides: Any) -> tuple[int, Any, str]:
        body = {"goal": "read the page", "url": URL, "confirm_cents": 8, **overrides}
        return self.call("POST", "/api/run/start", body)


def make(tmp_path: Path, command: Any, estimate: Any = lambda: 8) -> Iterator[Console]:
    runner = Runner(
        tmp_path,
        budget_path=tmp_path / "budget.json",
        estimate=estimate,
        command=command,
    )
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb", runner=runner), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Console(server.server_address[1], runner)
    server.shutdown()
    server.server_close()


def quick(goal: str, url: str, out: Path) -> list[str]:
    code = (
        "import json; print('working'); "
        "print('RESULT_TEXT ' + json.dumps('Manchester is a city.')); "
        "print('RECEIPT_SAVED made.abbreceipt')"
    )
    return [sys.executable, "-c", code]


def slow(goal: str, url: str, out: Path) -> list[str]:
    return [sys.executable, "-c", "import time; time.sleep(3)"]


@pytest.fixture()
def key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(KEY_ENV, DUMMY_KEY)


@pytest.fixture()
def console(tmp_path: Path, key: None) -> Iterator[Console]:
    yield from make(tmp_path, quick)


def wait_done(console: Console, job: str) -> dict[str, Any]:
    for _ in range(100):
        _, status, _ = console.call("GET", f"/api/run/status?id={job}")
        if status["state"] != "running":
            return status  # type: ignore[no-any-return]
        time.sleep(0.1)
    raise AssertionError("the run did not finish")


def test_the_dashboard_stays_read_only_unless_runs_are_enabled(tmp_path: Path) -> None:
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb"), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        bare = Console(server.server_address[1], Runner(tmp_path))
        assert bare.call("GET", "/api/run/info")[0] == 404
        assert bare.call("POST", "/api/run/start", {"goal": "x"})[0] == 405
    finally:
        server.shutdown()
        server.server_close()


def test_info_shows_cost_and_hosts_but_never_the_key(console: Console) -> None:
    status, info, text = console.call("GET", "/api/run/info")
    assert status == 200
    assert info["key_set"] is True
    assert info["estimate_cents"] == 8
    assert info["hosts"] == ["en.wikipedia.org", "example.com"]
    assert DUMMY_KEY not in text


def test_a_confirmed_task_runs_and_reports_its_receipt(console: Console) -> None:
    status, body, _ = console.start()
    assert status == 202
    done = wait_done(console, body["job"])
    assert done["state"] == "done"
    assert done["receipt"] == "made.abbreceipt"
    assert "working" in done["lines"]


def test_nothing_starts_without_this_pages_token(console: Console) -> None:
    body = {"goal": "x", "url": URL, "confirm_cents": 8}
    assert console.call("POST", "/api/run/start", body, token=False)[0] == 403
    assert console.call("POST", "/api/run/start", body, headers={"X-ABB-Token": "guess"})[0] == 403


def test_a_page_on_another_name_or_origin_is_refused(console: Console) -> None:
    body = {"goal": "x", "url": URL, "confirm_cents": 8}
    assert console.call("POST", "/api/run/start", body, headers={"Host": "evil.example"})[0] == 403
    assert (
        console.call("POST", "/api/run/start", body, headers={"Origin": "https://evil.example"})[0]
        == 403
    )
    assert console.call("GET", "/api/run/info", headers={"Host": "evil.example"})[0] == 403


def test_a_lower_confirmed_cost_than_the_worst_case_is_refused(console: Console) -> None:
    status, body, _ = console.start(confirm_cents=1)
    assert status == 400
    assert "lower" in body["error"]


def test_an_unknown_cost_means_nothing_starts(tmp_path: Path, key: None) -> None:
    for c in make(tmp_path, quick, estimate=lambda: None):
        status, body, _ = c.start()
        assert status == 400
        assert "unknown" in body["error"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"url": "https://evil.example"},
        {"url": "http://example.com"},
        {"url": "https://user:pw@example.com"},
        {"url": "https://example.com.evil.example"},
        {"url": "https://example.com/a b"},
        {"url": "https://example.com/#frag"},
        {"goal": ""},
        {"goal": "x" * 501},
        {"goal": "bad\x00text"},
        {"confirm_cents": True},
        {"confirm_cents": "8"},
    ],
)
def test_bad_inputs_are_refused(console: Console, overrides: dict[str, Any]) -> None:
    assert console.start(**overrides)[0] == 400


def test_without_a_key_in_the_environment_nothing_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    for c in make(tmp_path, quick):
        status, body, _ = c.start()
        assert status == 400
        assert KEY_ENV in body["error"]
        assert c.call("GET", "/api/run/info")[1]["key_set"] is False


def test_only_one_run_at_a_time(tmp_path: Path, key: None) -> None:
    for c in make(tmp_path, slow):
        assert c.start()[0] == 202
        status, body, _ = c.start()
        assert status == 409
        assert "already" in body["error"]


def test_a_failing_run_is_reported_as_failed(tmp_path: Path, key: None) -> None:
    def broken(goal: str, url: str, out: Path) -> list[str]:
        return [sys.executable, "-c", "import sys; print('boom'); sys.exit(3)"]

    for c in make(tmp_path, broken):
        _, body, _ = c.start()
        done = wait_done(c, body["job"])
        assert done["state"] == "failed"
        assert done["receipt"] is None
        assert any("exit code 3" in line for line in done["lines"])


def test_the_key_is_never_on_the_command_line_the_runner_builds(tmp_path: Path, key: None) -> None:
    runner = Runner(tmp_path, budget_path=tmp_path / "b.json", estimate=lambda: 8)
    argv = runner._default_command("read the page", URL, tmp_path)
    assert DUMMY_KEY not in " ".join(argv)
    assert "--yes-spend" in argv
    assert "--out" in argv


def test_a_finished_run_gets_a_readable_name_beside_its_receipt(console: Console) -> None:
    _, body, _ = console.start(goal="read   the page\nand tell me the first sentence")
    done = wait_done(console, body["job"])
    meta = Path(console.runner.receipts) / (done["receipt"] + ".meta.json")
    assert json.loads(meta.read_text(encoding="utf-8"))["title"] == (
        "Read the page and tell me the first sentence"
    )
    (Path(console.runner.receipts) / done["receipt"]).write_bytes(b"x")  # the list reads files
    _, listing, _ = console.call("GET", "/api/receipts")
    assert listing["labels"][done["receipt"]]["title"].startswith("Read the page")
    assert listing["labels"][done["receipt"]]["when"] > 0


def test_a_start_page_with_a_path_is_allowed_and_the_answer_is_returned(console: Console) -> None:
    status, body, _ = console.start(url="https://en.wikipedia.org/wiki/Manchester")
    assert status == 202
    done = wait_done(console, body["job"])
    assert done["result"] == "Manchester is a city."
    assert not any(line.startswith("RESULT_TEXT") for line in done["lines"])
    meta = json.loads(
        (Path(console.runner.receipts) / "made.abbreceipt.meta.json").read_text("utf-8")
    )
    assert meta["answer"] == "Manchester is a city."


def test_the_answer_is_shown_as_heading_bullets_and_bold_and_never_as_markup(
    console: Console,
) -> None:
    sync_api = pytest.importorskip("playwright.sync_api")
    text = (
        "# Manchester\n- a **big** city\n- in `England`\n\n"
        "Plain <script>window.pwned=1</script> text. See [the site](https://a.example/x?y=1) and "
        "[bad](javascript:alert(1)) and https://b.example/z now."
    )
    with sync_api.sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(f"http://127.0.0.1:{console.port}/run")
        shape = page.evaluate(
            """(t) => {
                const box = renderRich(t);
                document.body.appendChild(box);
                return {
                  h: box.querySelectorAll('h4').length,
                  li: box.querySelectorAll('li').length,
                  strong: box.querySelectorAll('strong').length,
                  code: box.querySelectorAll('code').length,
                  scripts: box.querySelectorAll('script').length,
                  links: [...box.querySelectorAll('a')].map(
                    a => [a.href, a.rel, a.target, a.textContent]),
                  pwned: window.pwned === 1,
                  text: box.textContent,
                };
            }""",
            text,
        )
        browser.close()
    assert (shape["h"], shape["li"], shape["strong"], shape["code"]) == (1, 2, 1, 1)
    assert shape["scripts"] == 0
    # Only the two real web links became links, and both open safely in a new tab.
    assert shape["links"] == [
        ["https://a.example/x?y=1", "noopener noreferrer", "_blank", "the site"],
        ["https://b.example/z", "noopener noreferrer", "_blank", "https://b.example/z"],
    ]
    assert shape["pwned"] is False
    assert "<script>" in shape["text"]  # shown as text, not run


def test_a_long_answer_is_not_cut_off_and_the_outcome_is_reported(
    tmp_path: Path, key: None
) -> None:
    long_text = "Spain is a country. " * 400  # about 8000 characters

    def long_answer(goal: str, url: str, out: Path) -> list[str]:
        code = (
            "import json; print('RUN_OUTCOME SUCCEEDED'); "
            f"print('RESULT_TEXT ' + json.dumps({long_text!r})); "
            "print('RECEIPT_SAVED long.abbreceipt')"
        )
        return [sys.executable, "-c", code]

    for c in make(tmp_path, long_answer):
        _, body, _ = c.start()
        done = wait_done(c, body["job"])
        assert done["outcome"] == "SUCCEEDED"
        assert done["result"] == long_text[:4000]  # the cap is ours, not an accident
        assert not any("could not be read" in line for line in done["lines"])


def test_a_succeeded_run_with_an_empty_answer_is_reported_as_empty_not_failed(
    tmp_path: Path, key: None
) -> None:
    def empty(goal: str, url: str, out: Path) -> list[str]:
        code = (
            "print('RUN_OUTCOME SUCCEEDED'); print('RESULT_TEXT \"\"'); "
            "print('RECEIPT_SAVED empty.abbreceipt')"
        )
        return [sys.executable, "-c", code]

    for c in make(tmp_path, empty):
        _, body, _ = c.start()
        done = wait_done(c, body["job"])
        assert done["outcome"] == "SUCCEEDED"
        assert done["result"] == ""
        assert done["state"] == "done"


def answer_runner(tmp_path: Path, estimate: Any = lambda mode: 0) -> Iterator[Console]:
    def command(mode: str, goal: str, out: Path) -> list[str]:
        code = (
            "print('RUN_OUTCOME SUCCEEDED'); "
            f"print('RESULT_TEXT ' + repr('{mode} done').replace(chr(39), chr(34))); "
            "print('RECEIPT_SAVED a.abbreceipt')"
        )
        return [sys.executable, "-c", code]

    runner = Runner(
        tmp_path,
        budget_path=tmp_path / "b.json",
        estimate=lambda: 8,
        command=quick,
        estimate_answer=estimate,
        answer_command=command,
    )
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb", runner=runner), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Console(server.server_address[1], runner)
    server.shutdown()
    server.server_close()


@pytest.mark.parametrize("mode", ["search", "research"])
def test_search_and_research_start_with_no_start_page_and_return_their_text(
    tmp_path: Path, key: None, mode: str
) -> None:
    for c in answer_runner(tmp_path):
        status, body, _ = c.call(
            "POST", "/api/run/start", {"goal": "what is x", "confirm_cents": 0, "mode": mode}
        )
        assert status == 202, body
        done = wait_done(c, body["job"])
        assert done["mode"] == mode
        assert done["result"] == f"{mode} done"
        assert done["outcome"] == "SUCCEEDED"


def test_the_page_is_told_what_search_and_research_cost(tmp_path: Path, key: None) -> None:
    for c in answer_runner(tmp_path):
        info = c.call("GET", "/api/run/info")[1]
        assert info["modes"] == {"search": {"estimate_cents": 0}, "research": {"estimate_cents": 0}}


def test_a_cost_above_the_confirmed_amount_stops_search_and_research(
    tmp_path: Path, key: None
) -> None:
    for c in answer_runner(tmp_path, estimate=lambda mode: 5):
        status, body, _ = c.call(
            "POST", "/api/run/start", {"goal": "q", "confirm_cents": 0, "mode": "research"}
        )
        assert status == 400
        assert "lower" in body["error"]


def test_an_unknown_search_cost_means_nothing_starts_and_unknown_modes_are_refused(
    tmp_path: Path, key: None
) -> None:
    for c in answer_runner(tmp_path, estimate=lambda mode: None):
        status, body, _ = c.call(
            "POST", "/api/run/start", {"goal": "q", "confirm_cents": 0, "mode": "search"}
        )
        assert status == 400
        assert "unknown" in body["error"]
        assert c.call("POST", "/api/run/start", {"goal": "q", "mode": "hack"})[0] == 400


def test_search_needs_the_key_and_a_real_question(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)
    for c in answer_runner(tmp_path):
        status, body, _ = c.call(
            "POST", "/api/run/start", {"goal": "q", "confirm_cents": 0, "mode": "search"}
        )
        assert status == 400
        assert KEY_ENV in body["error"]
    monkeypatch.setenv(KEY_ENV, DUMMY_KEY)
    for c in answer_runner(tmp_path):
        for bad in ("", "x" * 501, "bad\x00q"):
            body = {"goal": bad, "confirm_cents": 0, "mode": "search"}
            assert c.call("POST", "/api/run/start", body)[0] == 400


def test_an_answer_with_a_rupee_sign_does_not_crash_a_run(tmp_path: Path, key: None) -> None:
    """A real Search result held the rupee sign, which a Windows console encoding cannot print;
    the script crashed while printing it. Runs now speak UTF-8, so the answer arrives intact."""

    def rupee(goal: str, url: str, out: Path) -> list[str]:
        code = (
            "import sys; "
            "text = 'from \u20b917,999'; "
            "sys.stdout.write('RUN_OUTCOME SUCCEEDED' + chr(10)); "
            "sys.stdout.write('RESULT_TEXT ' + __import__('json').dumps(text) + chr(10)); "
            "print('shown: ' + text); "  # printing it would crash under a cp1252 console
            "print('RECEIPT_SAVED r.abbreceipt')"
        )
        return [sys.executable, "-c", code]

    for c in make(tmp_path, rupee):
        _, body, _ = c.start()
        done = wait_done(c, body["job"])
        assert done["state"] == "done", done
        assert done["result"] == "from \u20b917,999"
        assert any("\u20b917,999" in line for line in done["lines"])


def realsite_runner(tmp_path: Path) -> Iterator[Console]:
    seen: list[str] = []

    def command(message: str, out: Path) -> list[str]:
        seen.append(message)
        code = (
            "print('RUN_OUTCOME COMPLETED'); "
            "print('RESULT_TEXT \"real form done\"'); "
            "print('RECEIPT_SAVED rs.abbreceipt')"
        )
        return [sys.executable, "-c", code]

    runner = Runner(
        tmp_path,
        budget_path=tmp_path / "b.json",
        estimate=lambda: 8,
        command=quick,
        realsite_command=command,
    )
    runner.seen = seen  # type: ignore[attr-defined]
    server = serve(Config(receipts=tmp_path, keys=None, abb="abb", runner=runner), 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield Console(server.server_address[1], runner)
    server.shutdown()
    server.server_close()


def test_the_real_website_mode_needs_no_tinyfish_key_and_passes_the_message(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.delenv(KEY_ENV, raising=False)  # nothing here calls TinyFish
    for c in realsite_runner(tmp_path):
        status, body, _ = c.call(
            "POST", "/api/run/start", {"goal": "  hello there  ", "mode": "realsite"}
        )
        assert status == 202, body
        done = wait_done(c, body["job"])
        assert done["mode"] == "realsite"
        assert done["result"] == "real form done"
        assert c.runner.seen == ["hello there"]  # type: ignore[attr-defined]
        meta = json.loads((tmp_path / "rs.abbreceipt.meta.json").read_text(encoding="utf-8"))
        assert meta["mode"] == "realsite"
        assert meta["title"].startswith("Real form: hello there")
        assert meta["url"] == "https://httpbin.org/forms/post"


@pytest.mark.parametrize("message", ["", "   ", "x" * 501, "bad\x00message", 5, None])
def test_the_real_website_mode_refuses_a_bad_message(tmp_path: Path, message: Any) -> None:
    for c in realsite_runner(tmp_path):
        status, _, _ = c.call("POST", "/api/run/start", {"goal": message, "mode": "realsite"})
        assert status == 400


def test_the_page_is_told_which_site_and_which_key_the_real_website_mode_uses(
    tmp_path: Path,
) -> None:
    for c in realsite_runner(tmp_path):
        info = c.call("GET", "/api/run/info")[1]
        assert info["realsite"]["host"] == "httpbin.org"
