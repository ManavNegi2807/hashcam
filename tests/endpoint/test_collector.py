"""The real collector: what it reports, and, as important, what it must never record.

The watchers are driven with temporary folders and a fake process list, so nothing on this
computer is watched. One smoke test reads the machine's real process table once, to prove that
reading works; it asserts nothing about what is running.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from endpoint.collector import (
    ClickFileWatcher,
    DownloadWatcher,
    ProcessWatcher,
    append_events,
    list_processes,
    origin_of,
    parse_zone_identifier,
)
from endpoint.events import events_from_links
from endpoint.scoring import score

REPO = Path(__file__).resolve().parents[2]


def hour() -> int:
    return 14


# ---- downloads -------------------------------------------------------------------------------


def test_a_new_finished_file_is_reported_once_with_its_name_and_size_only(tmp_path: Path) -> None:
    (tmp_path / "old.pdf").write_bytes(b"x")  # already there at the start: ignored
    watcher = DownloadWatcher(tmp_path, "local-user", hour)
    (tmp_path / "report.zip").write_bytes(b"z" * (3 * 1024 * 1024))
    assert watcher.poll() == []  # first sight: it might still be growing
    events = watcher.poll()  # size unchanged: finished
    assert len(events) == 1
    event = events[0]
    assert (event.kind, event.size_mb, event.user, event.hour) == (
        "file_download",
        3,
        "local-user",
        14,
    )
    assert event.target == "local-file:///report.zip"
    assert watcher.poll() == []  # never reported twice


def test_a_file_that_is_still_growing_waits(tmp_path: Path) -> None:
    watcher = DownloadWatcher(tmp_path, "u", hour)
    target = tmp_path / "big.bin"
    target.write_bytes(b"a" * 1000)
    watcher.poll()
    target.write_bytes(b"a" * 2000)  # grew between looks
    assert watcher.poll() == []
    assert len(watcher.poll()) == 1


def test_temporary_download_files_are_not_reported(tmp_path: Path) -> None:
    watcher = DownloadWatcher(tmp_path, "u", hour)
    (tmp_path / "file.crdownload").write_bytes(b"x")
    assert watcher.poll() == [] and watcher.poll() == []


def test_the_folder_path_and_file_contents_never_reach_the_event(tmp_path: Path) -> None:
    watcher = DownloadWatcher(tmp_path, "u", hour)
    (tmp_path / "secret-plans.txt").write_text("TOP-SECRET-CONTENT", encoding="utf-8")
    watcher.poll()
    event = watcher.poll()[0]
    blob = event.as_json().decode()
    assert "TOP-SECRET-CONTENT" not in blob
    assert str(tmp_path) not in blob and tmp_path.name not in blob


def test_a_download_collected_for_real_is_scored_like_any_other(tmp_path: Path) -> None:
    watcher = DownloadWatcher(tmp_path, "u", lambda: 2)
    (tmp_path / "customers.zip").write_bytes(b"z" * (200 * 1024 * 1024 // 100))
    watcher.poll()
    event = watcher.poll()[0]
    assert "OFF_HOURS" in score(event).rule_ids and "ARCHIVE_FILE" in score(event).rule_ids


def test_the_source_address_is_read_from_a_zone_identifier_stream() -> None:
    text = "[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://a.example/page\nHostUrl=https://files.x.example/f.zip\n"
    assert parse_zone_identifier(text) == "https://files.x.example/f.zip"
    assert parse_zone_identifier("[ZoneTransfer]\nZoneId=3\n") == ""
    assert parse_zone_identifier("HostUrl=javascript:alert(1)") == ""  # only web addresses


def test_a_missing_zone_stream_is_not_an_error(tmp_path: Path) -> None:
    plain = tmp_path / "plain.txt"
    plain.write_text("x", encoding="utf-8")
    assert origin_of(plain) == ""


@pytest.mark.skipif(os.name != "nt", reason="Zone.Identifier streams exist only on Windows (NTFS)")
def test_on_windows_the_download_source_is_read_from_the_stream(tmp_path: Path) -> None:
    file = tmp_path / "fetched.zip"
    file.write_bytes(b"x")
    try:
        with open(str(file) + ":Zone.Identifier", "w", encoding="utf-8") as stream:
            stream.write("[ZoneTransfer]\nZoneId=3\nHostUrl=https://files.randomstorage.io/a.zip\n")
    except OSError:
        pytest.skip("this file system has no alternate data streams")
    assert origin_of(file) == "https://files.randomstorage.io/a.zip"


# ---- program launches ------------------------------------------------------------------------


def test_only_script_shells_that_start_while_watching_are_reported() -> None:
    table = {1: ("explorer.exe", 0), 2: ("winword.exe", 1)}
    watcher = ProcessWatcher("u", hour, lambda: dict(table))
    table[10] = ("notepad.exe", 1)  # ordinary: never reported
    table[11] = ("powershell.exe", 2)  # a shell started by Word
    table[12] = ("cmd.exe", 1)  # a shell started by the desktop
    events = watcher.poll()
    assert [(e.process, e.parent) for e in events] == [
        ("powershell.exe", "winword.exe"),
        ("cmd.exe", "explorer.exe"),
    ]
    assert watcher.poll() == []  # reported once


def test_processes_that_were_already_running_are_ignored() -> None:
    table = {5: ("powershell.exe", 1), 1: ("explorer.exe", 0)}
    watcher = ProcessWatcher("u", hour, lambda: dict(table))
    assert watcher.poll() == []


def test_a_shell_started_by_word_scores_as_an_alert_and_by_the_desktop_does_not() -> None:
    table = {1: ("explorer.exe", 0), 2: ("winword.exe", 1)}
    watcher = ProcessWatcher("u", hour, lambda: dict(table))
    table[11] = ("powershell.exe", 2)
    table[12] = ("powershell.exe", 1)
    word, desktop = watcher.poll()
    assert score(word).is_alert and not score(desktop).is_alert


def test_no_command_line_or_arguments_are_ever_part_of_an_event() -> None:
    table = {1: ("explorer.exe", 0)}
    watcher = ProcessWatcher("u", hour, lambda: dict(table))
    table[9] = ("powershell.exe", 1)
    blob = watcher.poll()[0].as_json().decode()
    assert set(json.loads(blob)) == {
        "kind",
        "user",
        "hour",
        "target",
        "size_mb",
        "process",
        "parent",
        "source",
        "count",
    }


def test_reading_the_real_process_table_works() -> None:
    table = list_processes()
    assert table, "the process table was empty"
    assert os.getpid() in table  # this very process is in it


# ---- links -----------------------------------------------------------------------------------


def test_only_web_links_appended_to_the_file_are_collected(tmp_path: Path) -> None:
    clicks = tmp_path / "links.txt"
    clicks.write_text("https://old.example/ignored\n", encoding="utf-8")
    watcher = ClickFileWatcher(clicks, "u", hour)
    with open(clicks, "a", encoding="utf-8") as out:
        out.write("https://phish.example/login chat\n")
        out.write("javascript:alert(1)\n")
        out.write("not a link\n")
        out.write("http://other.example/a\n")
    events = watcher.poll()
    assert [(e.target, e.source) for e in events] == [
        ("https://phish.example/login", "chat"),
        ("http://other.example/a", "reported"),
    ]
    assert watcher.poll() == []


def test_a_replaced_links_file_is_read_from_the_start(tmp_path: Path) -> None:
    clicks = tmp_path / "links.txt"
    clicks.write_text("https://a.example/1\nhttps://a.example/2\n", encoding="utf-8")
    watcher = ClickFileWatcher(clicks, "u", hour)
    clicks.write_text("https://b.example/new\n", encoding="utf-8")
    assert [e.target for e in watcher.poll()] == ["https://b.example/new"]


def test_pasted_links_become_events_up_to_five_and_are_never_opened() -> None:
    text = "check https://a.example/x, and https://b.example/y. also " + " ".join(
        f"https://c{i}.example/" for i in range(10)
    )
    events = events_from_links(text, hour=9)
    assert len(events) == 5 and events[0].target == "https://a.example/x"
    assert events[1].target == "https://b.example/y"
    assert all(e.kind == "url_click" and e.source == "reported" and e.hour == 9 for e in events)
    assert events_from_links("no links here") == []


# ---- the file and the daemon -----------------------------------------------------------------


def test_events_are_appended_as_readable_json_lines(tmp_path: Path) -> None:
    out = tmp_path / "events.jsonl"
    events = events_from_links("https://a.example/x", hour=9)
    append_events(out, events)
    append_events(out, events)
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and json.loads(lines[0])["target"] == "https://a.example/x"


def run_daemon(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, str(REPO / "tools" / "endpoint_daemon.py"), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONPATH": str(REPO)},
        timeout=60,
        check=False,
    )


def test_the_daemon_refuses_without_the_authorisation_flag(tmp_path: Path) -> None:
    done = run_daemon("--out", str(tmp_path / "e.jsonl"), "--watch-processes")
    assert done.returncode == 2 and "--i-am-authorised" in done.stdout
    assert not (tmp_path / "e.jsonl").exists()


def test_the_daemon_refuses_to_watch_nothing(tmp_path: Path) -> None:
    done = run_daemon("--i-am-authorised", "--out", str(tmp_path / "e.jsonl"))
    assert done.returncode == 2 and "Nothing to watch" in done.stdout


def test_the_daemon_collects_a_download_and_a_link_end_to_end(tmp_path: Path) -> None:
    folder = tmp_path / "downloads"
    folder.mkdir()
    clicks = tmp_path / "links.txt"
    clicks.write_text("", encoding="utf-8")
    out = tmp_path / "events.jsonl"
    proc = subprocess.Popen(  # noqa: S603 - fixed argv
        [
            sys.executable,
            str(REPO / "tools" / "endpoint_daemon.py"),
            "--i-am-authorised",
            "--out",
            str(out),
            "--seconds",
            "12",
            "--interval",
            "0.5",
            "--watch-downloads",
            str(folder),
            "--clicks-file",
            str(clicks),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    import time

    time.sleep(2.5)  # let it take its first look
    (folder / "invoice.zip").write_bytes(b"z" * 1024)
    with open(clicks, "a", encoding="utf-8") as stream:
        stream.write("https://northwind-bank.secure-login.top/verify chat\n")
    output, _ = proc.communicate(timeout=60)
    assert proc.returncode == 0, output
    written = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    kinds = sorted(e["kind"] for e in written)
    assert kinds == ["file_download", "url_click"], written
    assert str(folder) not in out.read_text(encoding="utf-8")
