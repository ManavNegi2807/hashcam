"""Measure the rules and the model on labelled, SYNTHETIC events (slide 8's "detection baseline").

Reproducible from a seed. The labelled set is made by the same author as the rules, so every number
here is optimistic and none of it says anything about real traffic: it shows how the detectors
compare on events whose truth is known, and which hard cases each one misses. Nothing is tuned to
make a number look better: the thresholds are the ones the detectors already use.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from endpoint.model import Model
from endpoint.scoring import score
from endpoint.synthetic import Labelled, labelled_set


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, flagged: bool, malicious: bool) -> None:
        if flagged and malicious:
            self.tp += 1
        elif flagged:
            self.fp += 1
        elif malicious:
            self.fn += 1
        else:
            self.tn += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def false_alarm_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0


@dataclass
class Result:
    seed: int
    total: int
    malicious: int
    detectors: dict[str, Counts] = field(default_factory=dict)
    recall_by_family: dict[str, dict[str, float]] = field(default_factory=dict)
    hard_recall: dict[str, float] = field(default_factory=dict)
    false_alarm_families: dict[str, list[str]] = field(default_factory=dict)
    microseconds_per_event: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "seed": self.seed,
            "total": self.total,
            "malicious": self.malicious,
            "detectors": {
                name: {
                    "tp": c.tp,
                    "fp": c.fp,
                    "fn": c.fn,
                    "tn": c.tn,
                    "precision": round(c.precision, 3),
                    "recall": round(c.recall, 3),
                    "f1": round(c.f1, 3),
                    "false_alarm_rate": round(c.false_alarm_rate, 3),
                }
                for name, c in self.detectors.items()
            },
            "recall_by_family": self.recall_by_family,
            "hard_recall": self.hard_recall,
            "false_alarm_families": self.false_alarm_families,
        }


def measure(seed: int, model: Model | None) -> Result:
    data: list[Labelled] = labelled_set(seed)
    events = [d.event for d in data]
    started = time.perf_counter()
    rule_flags = [score(e).is_alert for e in events]
    rule_time = time.perf_counter() - started
    model_flags: list[bool] | None = None
    model_time = 0.0
    if model is not None:
        started = time.perf_counter()
        model_flags = [s.flagged for s in model.score_many(events)]
        model_time = time.perf_counter() - started

    names = ["rules"] + (["model", "rules or model"] if model_flags is not None else [])
    result = Result(seed, len(data), sum(d.malicious for d in data))
    result.detectors = {n: Counts() for n in names}
    hits: dict[str, dict[str, list[bool]]] = {n: {} for n in names}
    hard: dict[str, list[bool]] = {n: [] for n in names}
    false_alarms: dict[str, list[str]] = {n: [] for n in names}
    for i, item in enumerate(data):
        flags = {"rules": rule_flags[i]}
        if model_flags is not None:
            flags["model"] = model_flags[i]
            flags["rules or model"] = rule_flags[i] or model_flags[i]
        for name, flagged in flags.items():
            result.detectors[name].add(flagged, item.malicious)
            if item.malicious:
                hits[name].setdefault(item.family, []).append(flagged)
                if item.hard:
                    hard[name].append(flagged)
            elif flagged:
                false_alarms[name].append(item.family)
    for name in names:
        result.recall_by_family[name] = {
            fam: round(sum(v) / len(v), 3) for fam, v in sorted(hits[name].items())
        }
        result.hard_recall[name] = (
            round(sum(hard[name]) / len(hard[name]), 3) if hard[name] else 0.0
        )
        result.false_alarm_families[name] = sorted(set(false_alarms[name]))
    result.microseconds_per_event = {
        "rules": rule_time / len(events) * 1e6,
        **({"model": model_time / len(events) * 1e6} if model_flags is not None else {}),
    }
    return result
