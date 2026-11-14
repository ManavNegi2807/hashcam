"""Start the local service the HashCam Recorder browser extension talks to.

    python tools/recorder.py --dsn postgresql://abb@127.0.0.1:55432/postgres

It starts the signer and the ledger API (a fresh database on the PostgreSQL you name), then
serves the recorder API on 127.0.0.1. The pairing token is written to a file (its path is
printed, the token is not); paste it into the extension's side panel once.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from services.recorder.server import serve  # noqa: E402
from services.recorder.session import Recorder  # noqa: E402

DEFAULT_PORT = 8770


def write_token(path: Path) -> str:
    """A fresh pairing token in a file only this user can read."""
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(token)
    return token


def main() -> int:
    parser = argparse.ArgumentParser(description="The HashCam Recorder local service")
    parser.add_argument(
        "--dsn", default=os.environ.get("ABB_TEST_DSN", "postgresql://abb@127.0.0.1:5432/postgres")
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--receipts", type=Path, default=Path.home() / ".hashcam" / "receipts")
    parser.add_argument("--people-dir", type=Path, default=Path.home() / ".hashcam" / "people")
    parser.add_argument(
        "--token-file", type=Path, default=Path.home() / ".hashcam" / "recorder-token"
    )
    parser.add_argument("--approval-seconds", type=int, default=120)
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    token = write_token(args.token_file)
    work = Path(tempfile.mkdtemp(prefix="hashcam-rec-"))
    recorder = Recorder.start(
        admin_dsn=args.dsn,
        work=work,
        receipts=args.receipts,
        people=args.people_dir,
        approval_seconds=args.approval_seconds,
    )
    server = serve(recorder, token, args.port)
    print(f"HashCam Recorder on http://127.0.0.1:{args.port}", flush=True)
    print(f"pairing token written to {args.token_file} (paste it into the side panel)", flush=True)
    print(f"receipts are saved in {args.receipts}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        recorder.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
