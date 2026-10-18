"""Explainable scoring: a sum of named rules, each with a plain-words reason.

A score is the sum of the weights of the rules that fired (parts per million, capped at a million).
It is NOT a probability and not a verdict: it says which rules matched, so an analyst can judge.
No rule reads the gateway's policy decisions or an allowlist (`R-ANO-05`, no circularity): every
rule looks only at the reported event itself.

An optional learned model (the deck mentions an Isolation Forest) is NOT built.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse

from endpoint.events import EndpointEvent

MODEL_ID = "endpoint-rules"
MODEL_VERSION = "1"
FEATURE_SCHEMA_ID = "endpoint-events.v1"
MEDIUM_PPM = 300_000
HIGH_PPM = 600_000

COMPANY_DOMAIN = "northwindbank.com"
WORK_HOURS = range(8, 19)
BASELINE_QUERIES_PER_HOUR = 6
SUSPICIOUS_TLDS = {"top", "xyz", "click", "icu", "rest", "work", "cfd", "sbs"}
LURE_WORDS = ("login", "verify", "secure", "account", "password", "signin")
ARCHIVES = (".zip", ".7z", ".rar", ".tar.gz")
SHELLS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    weight_ppm: int
    text: str


RULES: dict[str, Rule] = {
    r.rule_id: r
    for r in (
        Rule("OFF_HOURS", 200_000, "It happened outside working hours (08:00 to 19:00)."),
        Rule("LARGE_DOWNLOAD", 250_000, "The download is large (100 MB or more)."),
        Rule("ARCHIVE_FILE", 100_000, "The file is a compressed archive, easy to carry away."),
        Rule(
            "UNKNOWN_STORAGE_HOST", 200_000, "The file came from a host that is not the company's."
        ),
        Rule(
            "LOOKALIKE_DOMAIN",
            350_000,
            "The address imitates the company's name on another domain.",
        ),
        Rule("PUNYCODE_HOST", 300_000, "The address uses look-alike characters (punycode)."),
        Rule("IP_ADDRESS_HOST", 300_000, "The address is a bare IP number, not a name."),
        Rule(
            "SUSPICIOUS_TLD", 150_000, "The domain ends in a suffix often used for throwaway sites."
        ),
        Rule("LOGIN_LURE", 150_000, "The address asks for a login, verification or account step."),
        Rule("LINK_FROM_MESSAGE", 50_000, "The link was opened from a chat or an email."),
        Rule("SCRIPT_FROM_OFFICE_APP", 450_000, "A script shell was started by an office program."),
        Rule("QUERY_BURST", 400_000, "Far more record queries than this user's usual hour (6)."),
    )
}


@dataclass(frozen=True)
class Score:
    score_ppm: int
    rule_ids: tuple[str, ...]

    @property
    def severity(self) -> str:
        if self.score_ppm >= HIGH_PPM:
            return "HIGH"
        if self.score_ppm >= MEDIUM_PPM:
            return "MEDIUM"
        return "LOW"

    @property
    def is_alert(self) -> bool:
        return self.score_ppm >= MEDIUM_PPM


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _is_company(host: str) -> bool:
    return host == COMPANY_DOMAIN or host.endswith("." + COMPANY_DOMAIN)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def score(event: EndpointEvent) -> Score:
    fired: list[str] = []
    host = host_of(event.target)
    path = urlparse(event.target).path.lower() + "?" + urlparse(event.target).query.lower()

    if event.hour not in WORK_HOURS and event.kind in {
        "file_download",
        "record_query",
        "url_click",
    }:
        fired.append("OFF_HOURS")
    if event.kind == "file_download":
        if event.size_mb >= 100:
            fired.append("LARGE_DOWNLOAD")
        if path.split("?")[0].endswith(ARCHIVES):
            fired.append("ARCHIVE_FILE")
        if host and not _is_company(host):
            fired.append("UNKNOWN_STORAGE_HOST")
    if event.kind == "url_click" and host:
        if "northwind" in host and not _is_company(host):
            fired.append("LOOKALIKE_DOMAIN")
        if "xn--" in host:
            fired.append("PUNYCODE_HOST")
        if _is_ip(host):
            fired.append("IP_ADDRESS_HOST")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            fired.append("SUSPICIOUS_TLD")
        if any(word in path for word in LURE_WORDS) and not _is_company(host):
            fired.append("LOGIN_LURE")
        if event.source in {"chat", "email"}:
            fired.append("LINK_FROM_MESSAGE")
    if event.kind == "process_launch":
        if event.process.lower() in SHELLS and event.parent.lower() in OFFICE:
            fired.append("SCRIPT_FROM_OFFICE_APP")
    if event.kind == "record_query" and event.count > 3 * BASELINE_QUERIES_PER_HOUR:
        fired.append("QUERY_BURST")

    total = min(1_000_000, sum(RULES[r].weight_ppm for r in fired))
    return Score(total, tuple(sorted(fired)))


def explain(rule_ids: list[str] | tuple[str, ...]) -> list[dict[str, object]]:
    """Each rule that fired, with its weight and its reason, for people to read."""
    return [
        {"rule_id": r, "weight_ppm": RULES[r].weight_ppm, "text": RULES[r].text}
        for r in rule_ids
        if r in RULES
    ]
