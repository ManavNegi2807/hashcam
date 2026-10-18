"""Run the audit dashboard on 127.0.0.1.

    python tools/ui_server.py --receipts <dir> --keys <key_manifest.json> --port 8765

Then open http://127.0.0.1:8765. The page shows what `abb verify` says; it never
decides anything itself.
"""

from __future__ import annotations

from dotenv import load_dotenv
import argparse
import os
import sys
from pathlib import Path

load_dotenv()

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from services.dashboard.server import Config, serve  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipts", required=True, type=Path, help="directory of *.abbreceipt")
    parser.add_argument("--keys", type=Path, help="key manifest from an independent channel")
    parser.add_argument("--abb", default=os.environ.get("ABB_BIN", "abb"), help="the abb binary")
    parser.add_argument(
        "--profile", default="LOCAL_ONLY", choices=["LOCAL_ONLY", "CONNECTED_EVIDENCE"]
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--enable-runs",
        action="store_true",
        help="let a person start a TinyFish run from the page (spends credit; needs "
        "TINYFISH_API_KEY, ABB_TEST_DSN, ABB_BIN and ABB_SIGNER_BIN in this environment)",
    )
    parser.add_argument(
        "--falkordb",
        default=os.environ.get("ABB_FALKORDB_URL", ""),
        help="FalkorDB on this computer, e.g. redis://127.0.0.1:6390 "
        "(default: ABB_FALKORDB_URL; empty draws the graph from the receipt)",
    )
    args = parser.parse_args()
    receipts = args.receipts.resolve()
    runner = None
    if args.enable_runs:
        from services.dashboard.runner import Runner

        runner = Runner(receipts)
    graph = None
    if args.falkordb:
        from services.graph.store import FalkorStore

        graph = FalkorStore(args.falkordb)  # refuses any address that is not this computer
    config = Config(
        receipts=receipts,
        keys=args.keys,
        abb=args.abb,
        profile=args.profile,
        runner=runner,
        graph=graph,
    )
    server = serve(config, args.port)
    print(f"dashboard on http://127.0.0.1:{server.server_address[1]}  (Ctrl+C to stop)")
    if args.keys is None:
        print("no --keys given: signatures cannot be judged and the page will say so")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
