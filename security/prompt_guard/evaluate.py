"""Score the guard on `corpus.py` and say plainly what that does and does not show."""

from __future__ import annotations

from dataclasses import dataclass

from .corpus import ALL, Sample
from .guard import DeterministicGuard


@dataclass(frozen=True)
class Outcome:
    sample: Sample
    verdict: str
    score_ppm: int
    reasons: tuple[str, ...]

    @property
    def flagged(self) -> bool:
        return self.verdict != "ALLOW"


@dataclass(frozen=True)
class Metrics:
    attacks: int
    benign: int
    true_positives: int
    false_negatives: int
    false_positives: int
    true_negatives: int

    @property
    def recall(self) -> float:
        return self.true_positives / self.attacks if self.attacks else 0.0

    @property
    def precision(self) -> float:
        flagged = self.true_positives + self.false_positives
        return self.true_positives / flagged if flagged else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign if self.benign else 0.0


def run(samples: tuple[Sample, ...] = ALL) -> list[Outcome]:
    guard = DeterministicGuard()
    outcomes = []
    for sample in samples:
        result = guard.classify(sample.text, source_kind="page_text")
        outcomes.append(Outcome(sample, result.verdict, result.score_ppm, result.reason_codes))
    return outcomes


def metrics(outcomes: list[Outcome]) -> Metrics:
    attacks = [o for o in outcomes if o.sample.is_attack]
    benign = [o for o in outcomes if not o.sample.is_attack]
    tp = sum(1 for o in attacks if o.flagged)
    fp = sum(1 for o in benign if o.flagged)
    return Metrics(
        attacks=len(attacks),
        benign=len(benign),
        true_positives=tp,
        false_negatives=len(attacks) - tp,
        false_positives=fp,
        true_negatives=len(benign) - fp,
    )


def report(outcomes: list[Outcome]) -> str:
    """Markdown for `docs/PROMPT_GUARD_EVAL.md`, with every miss and false alarm listed."""
    m = metrics(outcomes)
    lines = [
        "## Result",
        "",
        f"- attacks: {m.attacks}, benign: {m.benign}",
        f"- caught: {m.true_positives}, missed: {m.false_negatives}",
        f"- false alarms: {m.false_positives}, correctly allowed: {m.true_negatives}",
        f"- recall={m.recall:.3f}",
        f"- precision={m.precision:.3f}",
        f"- false_positive_rate={m.false_positive_rate:.3f}",
        "",
        "## Missed attacks (false negatives)",
        "",
    ]
    missed = [o for o in outcomes if o.sample.is_attack and not o.flagged]
    if not missed:
        lines.append("None.")
    for o in missed:
        expected = "expected miss" if o.sample.known_miss else "UNEXPECTED miss"
        lines.append(
            f"- `{o.sample.sample_id}` ({o.sample.language}, {o.sample.category or 'n/a'}): "
            f"{expected}"
        )
    lines += ["", "## False alarms (false positives)", ""]
    alarms = [o for o in outcomes if not o.sample.is_attack and o.flagged]
    if not alarms:
        lines.append("None.")
    for o in alarms:
        lines.append(
            f"- `{o.sample.sample_id}`: {o.verdict}, score {o.score_ppm} ppm, "
            f"reasons {', '.join(o.reasons)}"
        )
    return "\n".join(lines) + "\n"
