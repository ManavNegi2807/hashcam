"""A small opt-in collector for THIS computer: downloads, script-shell launches, reported links.

    python tools/endpoint_daemon.py --i-am-authorised --out events.jsonl --seconds 120 \
        --watch-downloads "C:\\Users\\you\\Downloads" --watch-processes --clicks-file links.txt

Then analyse what it wrote (scores, explanations, TinyFish evidence, an analyst's signature):

    python tools/demo_endpoint.py ... --events-file events.jsonl

It watches ONLY what you point it at, for as long as you let it run, and writes everything it
records to one JSON-lines file you can open and read first. It never reads file contents, never
records the folder path, command lines or arguments, and never reads browser history. See
`endpoint/collector.py` for exactly what each watcher can see. Use it only on a computer you are
authorised to monitor. Nothing is sent anywhere from here.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from endpoint.collector import (  # noqa: E402
    ClickFileWatcher,
    DownloadWatcher,
    ProcessWatcher,
    append_events,
    local_hour,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Opt-in endpoint collector for this computer")
    parser.add_argument(
        "--i-am-authorised", action="store_true", help="required: you may monitor this computer"
    )
    parser.add_argument("--out", type=Path, required=True, help="the JSON-lines file to append to")
    parser.add_argument("--seconds", type=int, default=120, help="how long to watch (default 120)")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between looks")
    parser.add_argument("--watch-downloads", type=Path, help="ONE folder whose new files to report")
    parser.add_argument(
        "--watch-processes", action="store_true", help="report script shells that start"
    )
    parser.add_argument("--clicks-file", type=Path, help="a file of links, one per line, to report")
    parser.add_argument(
        "--user", default="local-user", help="the label to record (not your login name)"
    )
    args = parser.parse_args()

    if not args.i_am_authorised:
        print("Refused: add --i-am-authorised to confirm you may monitor this computer.")
        return 2
    if not (args.watch_downloads or args.watch_processes or args.clicks_file):
        print(
            "Nothing to watch. Pick at least one of --watch-downloads, --watch-processes, "
            "--clicks-file."
        )
        return 2
    if not 1 <= args.seconds <= 3600:
        print("--seconds must be 1 to 3600")
        return 2
    if args.watch_downloads is not None and not args.watch_downloads.is_dir():
        print("--watch-downloads must be an existing folder")
        return 2

    watchers: list[Any] = []
    print("Watching (Ctrl+C stops early):")
    if args.watch_downloads:
        watchers.append(DownloadWatcher(args.watch_downloads, args.user, local_hour))
        print("  - new finished files in one folder: name, size and where it came from only")
    if args.watch_processes:
        watchers.append(ProcessWatcher(args.user, local_hour))
        print("  - script shells starting, with the program that started them (names only)")
    if args.clicks_file:
        watchers.append(ClickFileWatcher(args.clicks_file, args.user, local_hour))
        print("  - links appended to the file you named (browser history is never read)")
    print(f"Writing to {args.out} for {args.seconds} seconds.")

    total = 0
    deadline = time.monotonic() + args.seconds
    try:
        while time.monotonic() < deadline:
            for watcher in watchers:
                found = watcher.poll()
                if found:
                    append_events(args.out, found)
                    total += len(found)
                    for event in found:
                        print(f"  + {event.kind}: {event.target or event.process}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Stopped.")
    print(f"Done: {total} event(s) written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
