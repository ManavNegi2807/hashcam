"""One real check of TinyFish Search (and, if you ask, Research) with YOUR key.

    set TINYFISH_API_KEY=...            (in your own window; this script never prints it)
    python tools/check_tinyfish_live.py                 # Search only: free per your rate card
    python tools/check_tinyfish_live.py --research      # also start one Research run (see below)
    python tools/check_tinyfish_live.py --fetch         # also fetch https://example.com

It uses this project's own client, `adapters/tinyfish/http_client.py`, and prints only what is
safe to show: whether each call worked, how many results came back, how long it took, and the
cost the client measured. It prints no key, no header and no raw reply.

Research is slow (usually 5 to 20 minutes) and must be switched on for your TinyFish account; with
`--research` this script waits for it, up to `--wait-minutes`, and cancels it if that is not enough.
The docs state no price for Research, so the script reads your wallet before and after and prints
the difference. Nothing is retried. Paste the output back to Claude, or into an issue.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from adapters.tinyfish.client import (  # noqa: E402
    AuthFailure,
    BadResponse,
    ProviderTimeout,
    QuotaExhausted,
    RateLimited,
    RunFailed,
)
from adapters.tinyfish.http_client import KEY_ENV, HttpTinyFishClient  # noqa: E402

PROBLEMS = (AuthFailure, BadResponse, ProviderTimeout, QuotaExhausted, RateLimited, RunFailed)


def attempt(label: str, call: Callable[[], dict[str, Any]]) -> dict[str, Any] | None:
    started = time.monotonic()
    try:
        answer = call()
    except PROBLEMS as exc:
        took = time.monotonic() - started
        print(f"  {label}: FAILED after {took:.0f} s: {type(exc).__name__}: {exc}")
        return None
    took = time.monotonic() - started
    usage = answer.get("usage", {})
    print(
        f"  {label}: OK in {took:.0f} s | {len(answer['steps'])} item(s) | "
        f"text {len(answer['result'])} characters | cost {usage.get('cents', '?')} cent(s)"
    )
    return answer


def main() -> int:
    parser = argparse.ArgumentParser(description="One real TinyFish Search/Research check")
    parser.add_argument("--query", default="What is Plus Jakarta Sans and who designed it?")
    parser.add_argument("--research", action="store_true", help="also run one Research query")
    parser.add_argument("--fetch", action="store_true", help="also fetch one harmless page")
    parser.add_argument("--wait-minutes", type=int, default=25)
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    if not os.environ.get(KEY_ENV):
        print(f"{KEY_ENV} is not set in this window, so nothing was called.")
        return 2
    print(f"{KEY_ENV} is set (not shown).")
    client = HttpTinyFishClient(
        research_deadline_seconds=args.wait_minutes * 60,
        progress=lambda message: print("    " + message, flush=True),
    )
    code = 0

    print("1. Search")
    found = attempt("search", lambda: client.run("search", args.query, ""))
    if found is None:
        code = 1
    else:
        first = found["result"].splitlines()[2:4]
        print("  first results (titles and snippets, from TinyFish):")
        for line in first:
            print("   ", line[:160])

    if args.fetch:
        print("1b. Fetch (the page text of https://example.com, read by TinyFish)")
        page = attempt("fetch", lambda: client.run("fetch", "live check", "https://example.com"))
        if page is None:
            code = 1
        else:
            print("  starts:", page["result"][:160].replace(chr(10), " "))

    if args.research:
        print("2. Research (this can take 5 to 20 minutes; keep this window open)")
        before = client.remaining_cents()
        reply = attempt("research", lambda: client.run("research", args.query, ""))
        after = client.remaining_cents()
        if reply is None:
            code = 1
        else:
            print("  report starts:", reply["result"][:200].replace("\n", " "))
            print(f"  sources cited: {len(reply['steps'])}")
        if before is not None and after is not None:
            print(
                f"  wallet before/after (cents): {before} / {after}  (difference {before - after})"
            )
    else:
        print("2. Research was not run (add --research to try it).")

    print("Done. This output holds no key. Paste it back.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
