"""Compare two runs of the same task and report how the second differs.

    python tools/replay_drift.py <first.abbreceipt> <second.abbreceipt>

Advisory only. It reads the two receipts' events; it does not verify them (use
`abb verify` for that) and it never changes anything. Drift is not wrongdoing.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from security.anomaly.drift import compare, trace_from_receipt  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    args = parser.parse_args()
    try:
        drift = compare(trace_from_receipt(args.first), trace_from_receipt(args.second))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile) as exc:
        print(f"cannot read a receipt: {exc.__class__.__name__}", file=sys.stderr)
        return 65
    if not drift.drifted:
        print("no drift: the same actions, hosts and outcome.")
        return 0
    print(f"drift (rule score {drift.score_ppm} ppm; a signal, not a probability):")
    for line in drift.describe():
        print("  " + line)
    print("This is advisory. A page may have changed, or the agent may simply vary.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
