"""The optional Isolation Forest and the measurement harness.

Skipped when scikit-learn is not installed (it is optional). The model is advisory: nothing here (or
in the code) lets it block or allow anything, and the receipt may only carry its identifiers, a
score and reason codes.
"""

from __future__ import annotations

import importlib.util
import inspect
import json
from typing import Any

import pytest

pytest.importorskip("sklearn")

import endpoint.model as model_module
from endpoint.events import BASELINE, OFFHOURS_DOWNLOAD, PHISHING_CHAT, EndpointEvent
from endpoint.measure import measure
from endpoint.model import (
    FEATURE_TEXT,
    FEATURES,
    available,
    features,
    get_model,
)
from endpoint.synthetic import labelled_set, ordinary

#: What the verifier lets an analysis record carry (core/abb-receipt/src/advisory.rs).
ALLOWED_RECORD_FIELDS = {
    "model_id",
    "model_version",
    "feature_schema_id",
    "score_ppm",
    "reason_codes",
    "score_kind",
    "threshold_ppm",
}


def test_the_model_is_available_and_trains_deterministically() -> None:
    assert available()
    first = get_model().score(PHISHING_CHAT[0])
    get_model.cache_clear()
    again = get_model().score(PHISHING_CHAT[0])
    assert first == again  # the same seed gives the same model, so the same answer


def test_it_flags_the_phishing_link_and_the_night_zip_but_not_ordinary_events() -> None:
    model = get_model()
    assert model.score(PHISHING_CHAT[0]).flagged
    assert model.score(OFFHOURS_DOWNLOAD[0]).flagged
    assert not any(model.score(e).flagged for e in BASELINE)


def test_about_one_in_a_hundred_ordinary_training_like_events_is_flagged() -> None:
    fresh = ordinary(1000, seed=424_242)  # events the model never saw
    flagged = sum(s.flagged for s in get_model().score_many(fresh))
    assert flagged <= 40  # a rough ceiling around 1 percent; far from "alarm on everything"


def test_every_flag_comes_with_reasons_in_words() -> None:
    score = get_model().score(PHISHING_CHAT[0])
    assert score.reasons and all(r.startswith("OUTLIER_") for r in score.reasons)
    assert all(isinstance(t, str) and t for t in score.explanation)
    assert all(name in FEATURES for name in FEATURE_TEXT)


def test_a_record_built_from_a_score_carries_only_what_a_receipt_may_hold() -> None:
    score = get_model().score(PHISHING_CHAT[0])
    record: dict[str, Any] = {
        "model_id": model_module.MODEL_ID,
        "model_version": model_module.MODEL_VERSION,
        "feature_schema_id": model_module.FEATURE_SCHEMA_ID,
        "score_ppm": score.score_ppm,
        "reason_codes": list(score.reasons),
        "score_kind": "ANOMALY_SCORE",
        "threshold_ppm": score.threshold_ppm,
    }
    assert set(record) <= ALLOWED_RECORD_FIELDS
    assert 0 <= record["score_ppm"] <= 1_000_000
    json.dumps(record)  # plain numbers and text: nothing executable, nothing pickled


def test_the_model_reads_only_plain_facts_never_a_policy_decision_or_a_rule_output() -> None:
    source = inspect.getsource(model_module)
    for forbidden in (
        "Policy",
        "allowed_hosts",
        "ACTION_BLOCKED",
        "REQUIRE_APPROVAL",
        "endpoint.scoring",
        "score(",
    ):
        assert forbidden not in source.replace("score_samples", "").replace("def score", ""), (
            forbidden
        )


def test_the_feature_vector_has_one_number_for_each_named_feature() -> None:
    row = features(
        EndpointEvent("file_download", "u", 3, target="https://a.example/x.zip", size_mb=9)
    )
    assert len(row) == len(FEATURES) and all(isinstance(v, float) for v in row)


def test_without_scikit_learn_the_model_simply_does_not_exist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(importlib.util, "find_spec", lambda _name: None)
    assert model_module.available() is False


# ---- the measurement harness -----------------------------------------------------------------


def test_measuring_twice_on_one_seed_gives_identical_numbers() -> None:
    model = get_model()
    assert measure(5, model).as_dict() == measure(5, model).as_dict()


def test_the_counts_add_up_to_every_event_for_every_detector() -> None:
    result = measure(6, get_model())
    for counts in result.detectors.values():
        assert counts.tp + counts.fp + counts.fn + counts.tn == result.total
        assert counts.tp + counts.fn == result.malicious


def test_the_labelled_set_is_reproducible_and_contains_hard_cases() -> None:
    a, b = labelled_set(9), labelled_set(9)
    assert [x.event for x in a] == [x.event for x in b]
    assert sum(x.hard and x.malicious for x in a) > 20
    assert sum(x.hard and not x.malicious for x in a) > 20


def test_combining_the_detectors_never_loses_an_attack_the_rules_caught() -> None:
    result = measure(7, get_model())
    assert result.detectors["rules or model"].recall >= result.detectors["rules"].recall


def test_hard_attacks_really_are_hard_for_the_rules() -> None:
    """If the 'hard' cases were easy, the measurement would be flattering for no reason."""
    result = measure(8, get_model())
    assert result.hard_recall["rules"] < 0.5


def test_without_the_model_only_the_rules_are_measured() -> None:
    result = measure(3, None)
    assert list(result.detectors) == ["rules"]


def test_the_written_report_says_it_is_synthetic_and_not_real_world() -> None:
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "docs" / "MEASUREMENTS.md").read_text(
        encoding="utf-8"
    )
    assert "synthetic" in text.lower() and "not** real-world performance" in text
