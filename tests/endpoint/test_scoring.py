"""The explainable rules: what fires, why, and what must not.

These are plain unit tests. They check the rules against hand-made events. They say nothing about
how well the rules would do on real traffic: that is a measurement (`tests/endpoint/test_measure.py`
and `docs/DEMO.md`), and it is made on simulated, labelled events only.
"""

from __future__ import annotations

import pytest

from endpoint.events import (
    BASELINE,
    OFFHOURS_DOWNLOAD,
    OFFICE_SPAWNS_SHELL,
    PHISHING_CHAT,
    RECORDS_ACCESS,
    SCENARIOS,
    EndpointEvent,
    scenario_for,
)
from endpoint.scoring import HIGH_PPM, MEDIUM_PPM, RULES, explain, score


@pytest.mark.parametrize("event", BASELINE, ids=lambda e: f"{e.kind}-{e.hour}")
def test_ordinary_events_raise_no_alert(event: EndpointEvent) -> None:
    assert not score(event).is_alert


def test_a_lookalike_login_link_from_chat_is_high() -> None:
    result = score(PHISHING_CHAT[0])
    assert result.severity == "HIGH"
    assert {"LOOKALIKE_DOMAIN", "SUSPICIOUS_TLD", "LOGIN_LURE", "LINK_FROM_MESSAGE"} <= set(
        result.rule_ids
    )


def test_a_big_zip_from_unknown_storage_at_night_is_high() -> None:
    result = score(OFFHOURS_DOWNLOAD[0])
    assert result.severity == "HIGH"
    assert {"OFF_HOURS", "LARGE_DOWNLOAD", "ARCHIVE_FILE", "UNKNOWN_STORAGE_HOST"} == set(
        result.rule_ids
    )


def test_a_burst_of_record_queries_in_the_evening_is_high() -> None:
    assert score(RECORDS_ACCESS[0]).severity == "HIGH"


def test_a_script_shell_started_by_an_office_program_is_medium() -> None:
    result = score(OFFICE_SPAWNS_SHELL[0])
    assert result.severity == "MEDIUM" and result.rule_ids == ("SCRIPT_FROM_OFFICE_APP",)


def test_the_same_shell_started_by_the_desktop_is_not_an_alert() -> None:
    event = EndpointEvent(
        "process_launch", "mkhan", 15, process="powershell.exe", parent="explorer.exe"
    )
    assert not score(event).is_alert


def test_a_link_on_the_companys_own_domain_is_not_a_lookalike() -> None:
    event = EndpointEvent(
        "url_click", "asha", 15, target="https://login.northwindbank.com/verify", source="email"
    )
    assert "LOOKALIKE_DOMAIN" not in score(event).rule_ids
    assert "LOGIN_LURE" not in score(event).rule_ids  # a login page on the company's own site


def test_a_bare_ip_address_and_look_alike_characters_are_noticed() -> None:
    ip = EndpointEvent("url_click", "a", 12, target="http://203.0.113.9/login", source="chat")
    assert "IP_ADDRESS_HOST" in score(ip).rule_ids
    puny = EndpointEvent(
        "url_click", "a", 12, target="https://xn--nrthwind-9db.com/", source="chat"
    )
    assert "PUNYCODE_HOST" in score(puny).rule_ids


def test_working_hours_decide_off_hours_exactly() -> None:
    def off(hour: int) -> bool:
        event = EndpointEvent(
            "file_download", "a", hour, target="https://x.example/a.pdf", size_mb=1
        )
        return "OFF_HOURS" in score(event).rule_ids

    assert [off(h) for h in (7, 8, 18, 19)] == [True, False, False, True]


def test_the_query_burst_threshold_is_three_times_the_usual_hour() -> None:
    def burst(count: int) -> bool:
        event = EndpointEvent("record_query", "a", 12, target="t", count=count)
        return "QUERY_BURST" in score(event).rule_ids

    assert [burst(18), burst(19)] == [False, True]


def test_the_score_is_the_sum_of_the_fired_weights_and_capped() -> None:
    result = score(PHISHING_CHAT[0])
    assert result.score_ppm == sum(RULES[r].weight_ppm for r in result.rule_ids)
    assert result.score_ppm <= 1_000_000
    assert MEDIUM_PPM < HIGH_PPM


def test_every_fired_rule_comes_with_a_reason_in_plain_words() -> None:
    result = score(PHISHING_CHAT[0])
    reasons = explain(result.rule_ids)
    assert [r["rule_id"] for r in reasons] == list(result.rule_ids)
    assert all(isinstance(r["text"], str) and len(str(r["text"])) > 10 for r in reasons)


def test_scoring_is_deterministic() -> None:
    assert score(PHISHING_CHAT[0]) == score(PHISHING_CHAT[0])


def test_no_rule_reads_the_gateways_policy_or_an_allowlist() -> None:
    """No circularity: the rules must not be fed policy outcomes (`R-ANO-05`)."""
    import inspect

    import endpoint.scoring as module

    source = inspect.getsource(module)
    for forbidden in ("policy", "allowed_hosts", "ACTION_BLOCKED", "REQUIRE_APPROVAL"):
        assert forbidden not in source.replace("policy decisions", ""), forbidden


def test_scenarios_pick_by_a_few_plain_words() -> None:
    assert scenario_for("phishing link in chat")[0] == "phishing_chat"
    assert scenario_for("a big download at night")[0] == "offhours_download"
    assert scenario_for("many record queries")[0] == "records_access"
    assert scenario_for("")[0] == "all" and scenario_for("zzz")[0] == "all"


def test_the_full_scenario_holds_exactly_the_expected_alerts() -> None:
    flagged = [e for e in SCENARIOS["all"] if score(e).is_alert]
    assert [e.kind for e in flagged] == [
        "url_click",
        "file_download",
        "record_query",
        "process_launch",
    ]


def test_an_event_with_an_impossible_hour_or_kind_is_refused() -> None:
    with pytest.raises(ValueError):
        EndpointEvent("file_download", "a", 24)
    with pytest.raises(ValueError):
        EndpointEvent("keylog", "a", 1)
