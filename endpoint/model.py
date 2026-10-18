"""An optional Isolation Forest that learns what ordinary events look like and flags odd ones.

It is ADVISORY, like the rules: it cannot block or allow anything, and a flag is a signal for
a person, not proof. It is trained, every time, on SYNTHETIC ordinary events (`endpoint.synthetic`),
so what it learned is only as real as that made-up data. Nothing executable ever reaches a receipt:
only the model's identifiers, a score (parts per million), the threshold used and reason codes.

Its inputs are plain facts about the event (hour, size, address shape, who started a program). No
input is a policy decision or an allowlist outcome (`R-ANO-05`, no circularity), and none is a
rule's output. If scikit-learn is not installed the model simply does not exist (`available()` is
False) and everything else works without it.
"""

from __future__ import annotations

import importlib
import importlib.util
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from endpoint.events import EndpointEvent
from endpoint.synthetic import ordinary

MODEL_ID = "isolation-forest"
MODEL_VERSION = "1"
FEATURE_SCHEMA_ID = "endpoint-features.v1"
TRAIN_SEED = 20_261_018
TRAIN_COUNT = 1500
TREES = 100
THRESHOLD_PERCENTILE = 99  # of the ordinary training scores: about 1 in 100 ordinary events flags

COMPANY = "northwindbank.com"
LURE_WORDS = ("login", "verify", "secure", "account", "password", "signin")
OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

FEATURES = (
    "is_download",
    "is_click",
    "is_query",
    "is_launch",
    "hour",
    "size_mb_log",
    "query_count",
    "host_length",
    "host_dots",
    "host_hyphens",
    "host_digits",
    "company_host",
    "bare_ip_host",
    "path_length",
    "lure_words",
    "from_message",
    "is_shell",
    "office_parent",
)
#: What each feature means, in words, for the reason shown to a person.
FEATURE_TEXT = {
    "hour": "an unusual hour of the day",
    "size_mb_log": "an unusual file size",
    "query_count": "an unusual number of record queries",
    "host_length": "an unusually long address",
    "host_dots": "an unusual number of dots in the address",
    "host_hyphens": "an unusual number of hyphens in the address",
    "host_digits": "digits inside the address name",
    "company_host": "not the company's own address",
    "bare_ip_host": "a bare IP number as the address",
    "path_length": "an unusually long page path",
    "lure_words": "login or verification words in the address",
    "from_message": "a link opened from a chat or an email",
    "is_shell": "a script shell starting",
    "office_parent": "a program started by an office application",
}


def features(event: EndpointEvent) -> list[float]:
    parts = urlparse(event.target) if event.target.startswith(("http://", "https://")) else None
    host = (parts.hostname or "").lower() if parts else ""
    path = ((parts.path or "") + "?" + (parts.query or "")) if parts else ""
    return [
        float(event.kind == "file_download"),
        float(event.kind == "url_click"),
        float(event.kind == "record_query"),
        float(event.kind == "process_launch"),
        float(event.hour),
        math.log1p(event.size_mb),
        float(event.count if event.kind == "record_query" else 0),
        float(len(host)),
        float(host.count(".")),
        float(host.count("-")),
        float(sum(ch.isdigit() for ch in host)),
        float(bool(host) and (host == COMPANY or host.endswith("." + COMPANY))),
        float(bool(host) and all(ch.isdigit() or ch == "." for ch in host)),
        float(len(path)),
        float(sum(word in path.lower() for word in LURE_WORDS)),
        float(event.source in {"chat", "email"}),
        float(event.process.lower() in SHELLS),
        float(event.parent.lower() in OFFICE),
    ]


@dataclass(frozen=True)
class ModelScore:
    score_ppm: int
    threshold_ppm: int
    flagged: bool
    reasons: tuple[str, ...]  # reason codes: the features furthest from ordinary, most first

    @property
    def explanation(self) -> list[str]:
        return [FEATURE_TEXT[r.removeprefix("OUTLIER_").lower()] for r in self.reasons]


def available() -> bool:
    return importlib.util.find_spec("sklearn") is not None


class Model:
    def __init__(
        self, forest: Any, mean: list[float], spread: list[float], threshold: float
    ) -> None:
        self._forest = forest
        self._mean = mean
        self._spread = spread
        self._threshold = threshold

    def score_many(self, events: list[EndpointEvent]) -> list[ModelScore]:
        rows = [features(e) for e in events]
        raw = (-self._forest.score_samples(rows)).tolist()  # higher = stranger
        out: list[ModelScore] = []
        for row, value in zip(rows, raw, strict=True):
            flagged = value > self._threshold
            reasons: tuple[str, ...] = ()
            if flagged:
                far = sorted(
                    (
                        (abs(v - m) / s, name)
                        for v, m, s, name in zip(
                            row, self._mean, self._spread, FEATURES, strict=True
                        )
                        if name in FEATURE_TEXT
                    ),
                    reverse=True,
                )
                reasons = tuple("OUTLIER_" + name.upper() for z, name in far[:3] if z >= 2.0)
                reasons = reasons or ("OUTLIER_COMBINATION",)
            out.append(
                ModelScore(
                    score_ppm=max(0, min(1_000_000, int(value * 1_000_000))),
                    threshold_ppm=int(self._threshold * 1_000_000),
                    flagged=flagged,
                    reasons=reasons,
                )
            )
        return out

    def score(self, event: EndpointEvent) -> ModelScore:
        return self.score_many([event])[0]


@lru_cache(maxsize=1)
def get_model() -> Model:
    """Train on ordinary synthetic events. Deterministic: the same seed gives the same model."""
    # Imported by name so the optional libraries are never needed (or type-checked) unless used.
    np = importlib.import_module("numpy")
    forest_class = importlib.import_module("sklearn.ensemble").IsolationForest

    train = ordinary(TRAIN_COUNT, TRAIN_SEED)
    rows = np.array([features(e) for e in train])
    forest = forest_class(n_estimators=TREES, random_state=0, contamination="auto")
    forest.fit(rows)
    scores = -forest.score_samples(rows)
    threshold = float(np.percentile(scores, THRESHOLD_PERCENTILE))
    spread = np.where(rows.std(axis=0) < 1e-9, 1.0, rows.std(axis=0))
    return Model(forest, rows.mean(axis=0).tolist(), spread.tolist(), threshold)
