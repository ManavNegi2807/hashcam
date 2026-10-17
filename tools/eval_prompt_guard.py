"""Measure the prompt guard on its small hand-written corpus and write the report.

    python tools/eval_prompt_guard.py            # prints the report
    python tools/eval_prompt_guard.py --write    # also writes docs/PROMPT_GUARD_EVAL.md

The report says what the numbers are (a measurement of this corpus, nothing more)
and lists every miss and every false alarm. `tests/security/test_prompt_guard.py`
fails if the file on disk no longer matches a fresh run.
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from security.prompt_guard import evaluate  # noqa: E402
from security.prompt_guard.guard import (  # noqa: E402
    BLOCK_AT,
    DETECTOR_ID,
    DETECTOR_VERSION,
    FLAG_AT,
)

HEADER = f"""# Prompt guard evaluation

**Status:** `MEASURED`, on the corpus named below and nowhere else.
**Detector:** `{DETECTOR_ID}` v{DETECTOR_VERSION} (deterministic rules, no classifier).
**Thresholds:** flag at {FLAG_AT} ppm, block signal at {BLOCK_AT} ppm.
**Recorded:** {datetime.date.today().isoformat()} by `python tools/eval_prompt_guard.py --write`.

## What this is, and is not

The corpus (`security/prompt_guard/corpus.py`) was written by the same person who
wrote the rules. It is a few dozen items, mostly English. A good score here shows
the rules do what their author intended on the author's own examples. It does
**not** show how the guard behaves on real pages, and the guard is **not** a
complete prompt-injection defence (`R-PIG-10`).

The six attacks marked "expected miss" are kept on purpose: other languages,
paraphrase and character substitution are outside what literal English rules can
catch, and leaving them out would flatter the recall.

## Why the false alarms are what they are

A pattern guard cannot tell a page that *discusses* "ignore previous instructions"
from one that *does it*. Wrapping text in a code block, quotes or "for example"
is something an attacker can do too, so the guard does **not** lower its score for
that framing; it adds a reason code (`IN_CODE_BLOCK`, `PRESENTED_AS_EXAMPLE`) for
the reviewer. The price is false alarms on security documentation. The verdict is a
signal to the policy gateway, not an authorization, and not proof of an attack.

"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write docs/PROMPT_GUARD_EVAL.md")
    args = parser.parse_args()
    body = evaluate.report(evaluate.run())
    text = HEADER + body
    print(text)
    if args.write:
        (REPO / "docs" / "PROMPT_GUARD_EVAL.md").write_text(text, encoding="utf-8")
        print("written docs/PROMPT_GUARD_EVAL.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
