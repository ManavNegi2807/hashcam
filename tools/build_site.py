"""Build the public HashCam site in site/ (a static folder, deployed as is).

    python tools/build_site.py [--samples --dsn postgresql://...]

1. Copies the shared files from ui/ (theme, styles, the nine animation styles, GSAP, the font),
   so ui/ stays the one source.
2. Builds the receipt verifier for the browser (`core/abb-wasm`, target wasm32-unknown-unknown)
   and copies it to site/verifier.wasm. Needs `rustup target add wasm32-unknown-unknown`.
3. With --samples: makes the sample receipts with the real recorder (signer, ledger, abb):
   one genuine receipt, the same with one event edited, and its key manifest. They hold only
   made-up addresses and demo keys made for that one run.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SITE = REPO / "site"
SHARED = ["theme.css", "console.css", "fx3d.js"]
VENDOR = ["gsap.min.js", "LICENSE-gsap.txt", "plus-jakarta-sans.woff2", "OFL-plus-jakarta-sans.txt"]


def copy_shared() -> None:
    for name in SHARED:
        shutil.copyfile(REPO / "ui" / name, SITE / name)
    (SITE / "vendor").mkdir(exist_ok=True)
    for name in VENDOR:
        shutil.copyfile(REPO / "ui" / "vendor" / name, SITE / "vendor" / name)


def build_wasm() -> None:
    target_dir = os.environ.get("CARGO_TARGET_DIR", str(REPO / "core" / "target"))
    subprocess.run(  # noqa: S603 - fixed argv
        [  # noqa: S607 - cargo comes from the developer's PATH
            "cargo",
            "build",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--manifest-path",
            str(REPO / "core" / "Cargo.toml"),
            "-p",
            "abb-wasm",
        ],
        check=True,
    )
    built = Path(target_dir) / "wasm32-unknown-unknown" / "release" / "abb_wasm.wasm"
    shutil.copyfile(built, SITE / "verifier.wasm")
    print(f"verifier.wasm: {built.stat().st_size // 1024} KB")


def make_samples(dsn: str) -> None:
    sys.path.insert(0, str(REPO))
    from services.recorder.session import Recorder

    work = Path(tempfile.mkdtemp(prefix="site-samples-"))
    recorder = Recorder.start(admin_dsn=dsn, work=work, receipts=work / "receipts")
    try:
        s = recorder.start_session(
            task="Order one notebook on shop.example",
            agent="Sample agent",
            passport={"hosts": ["shop.example"], "minutes": 30},
        )
        recorder.report(s, {"kind": "navigate", "url": "https://shop.example/"})
        recorder.report(s, {"kind": "navigate", "url": "https://bank.example/transfer"})  # blocked
        sealed = recorder.stop(s, killed=False)
        receipt = work / "receipts" / sealed["receipt"]
        out = SITE / "samples"
        out.mkdir(exist_ok=True)
        shutil.copyfile(receipt, out / "genuine.abbreceipt")
        shutil.copyfile(receipt.with_name(receipt.name + ".keys.json"), out / "sample.keys.json")
        edit_one_event(receipt, out / "edited.abbreceipt")
        print("samples:", sealed["verdict"]["overall"])
    finally:
        recorder.close()
        shutil.rmtree(work, ignore_errors=True)


def edit_one_event(src: Path, dst: Path) -> None:
    """Change one event's address, as someone editing the record afterwards would."""
    with zipfile.ZipFile(src) as archive:
        document = json.loads(archive.read("receipt.json"))
        others = {n: archive.read(n) for n in archive.namelist() if n != "receipt.json"}
    for item in document["events"]:
        event = json.loads(base64.b64decode(item["canonical_b64"]))
        if event["event_type"] == "ACTION_REQUESTED":
            event["payload"]["target"] = "https://shop.example/harmless"
            item["canonical_b64"] = base64.b64encode(
                json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
            ).decode()
            break
    with zipfile.ZipFile(dst, "w") as archive:
        archive.writestr("receipt.json", json.dumps(document))
        for name, data in others.items():
            archive.writestr(name, data)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", action="store_true")
    parser.add_argument("--no-wasm", action="store_true")
    parser.add_argument("--dsn", default=os.environ.get("ABB_TEST_DSN", ""))
    args = parser.parse_args()
    copy_shared()
    if not args.no_wasm:
        build_wasm()
    if args.samples:
        if not args.dsn:
            parser.error("--samples needs --dsn (or ABB_TEST_DSN)")
        make_samples(args.dsn)
    print(f"site ready in {SITE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
