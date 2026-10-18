"""Measure the endpoint rules and the Isolation Forest on labelled SYNTHETIC events.

    python tools/measure_endpoint.py                 # print the table
    python tools/measure_endpoint.py --write docs/MEASUREMENTS.md

Runs on several seeds and prints each, so nobody has to trust one lucky draw. The data is made up by
the same author as the rules: the numbers are optimistic and are NOT real-world performance.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from endpoint.measure import Result, measure  # noqa: E402
from endpoint.model import available, get_model  # noqa: E402

SEEDS = (11, 22, 33, 44, 55)


def table(results: list[Result]) -> str:
    lines = [
        "| Detector | Seed | Precision | Recall | F1 | False-alarm rate | Hard attacks caught |",
        "|---|---|---|---|---|---|---|",
    ]
    names = list(results[0].detectors)
    for name in names:
        for r in results:
            c = r.detectors[name]
            lines.append(
                f"| {name} | {r.seed} | {c.precision:.2f} | {c.recall:.2f} | {c.f1:.2f} | "
                f"{c.false_alarm_rate:.2f} | {r.hard_recall[name]:.2f} |"
            )
    return "\n".join(lines)


def families(results: list[Result]) -> str:
    names = list(results[0].detectors)
    first = results[0]
    lines = [
        f"| Attack family (seed {first.seed}) | " + " | ".join(names) + " |",
        "|---|" + "---|" * len(names),
    ]
    for family in sorted(first.recall_by_family[names[0]]):
        cells = " | ".join(f"{first.recall_by_family[n].get(family, 0):.2f}" for n in names)
        lines.append(f"| {family} | {cells} |")
    return "\n".join(lines)


INTRO = """# Detection measurements (synthetic data only)

Made by `python tools/measure_endpoint.py --write docs/MEASUREMENTS.md`. Each seed is a fresh
labelled set of {total} events ({malicious} attacks, about a quarter of them built to be hard; about
a tenth of the ordinary events look odd but are fine). The model is trained on separate ordinary
synthetic events.

**Read this first.** The events are made up by the author of the rules. The numbers are optimistic
and are **not** real-world performance. They show how the rules and the model compare on events
whose truth is known, and what each one misses. Precision is of the alerts raised; the false-alarm
rate is the share of ordinary events flagged. Thresholds are the ones the detectors already use;
nothing was tuned to improve a number.

"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", type=Path, help="write a markdown report here")
    args = parser.parse_args()
    for stream in (sys.stdout, sys.stderr):
        getattr(stream, "reconfigure", lambda **_: None)(encoding="utf-8", errors="replace")

    model = None
    train_seconds = 0.0
    if available():
        started = time.perf_counter()
        model = get_model()
        train_seconds = time.perf_counter() - started
    else:
        print("scikit-learn is not installed: measuring the rules only.")
    results = [measure(seed, model) for seed in SEEDS]
    body = table(results) + "\n\n" + families(results)
    speed = ", ".join(
        f"{k} {v:.0f} microseconds" for k, v in results[0].microseconds_per_event.items()
    )
    false_alarms = "; ".join(
        f"{n}: {', '.join(results[0].false_alarm_families[n]) or 'none'}"
        for n in results[0].detectors
    )
    footer = (
        f"\nPer event (this machine, one run): {speed}. "
        + (f"Training the model took {train_seconds:.1f} s.\n" if model else "\n")
        + f"Ordinary-looking events flagged anyway (seed {results[0].seed}): {false_alarms}.\n"
    )
    print(body + footer)
    if args.write:
        intro = INTRO.format(total=results[0].total, malicious=results[0].malicious)
        args.write.write_text(intro + body + "\n" + footer, encoding="utf-8")
        print(f"wrote {args.write}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
