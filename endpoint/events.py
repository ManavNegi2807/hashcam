"""The simulated collector's events and the scenarios built from them.

Every event here is made up (people, companies, domains). `northwindbank.com` is this demo's
imaginary bank. Nothing is read from a real computer.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

KINDS = ("file_download", "process_launch", "url_click", "record_query")


@dataclass(frozen=True)
class EndpointEvent:
    kind: str  # one of KINDS
    user: str
    hour: int  # local hour of day, 0 to 23
    target: str = ""  # a URL for downloads and clicks; a record set for queries
    size_mb: int = 0  # downloads
    process: str = ""  # process launches
    parent: str = ""  # process launches
    source: str = ""  # url clicks: where the link came from (chat, email, browser)
    count: int = 1  # record queries in that hour

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown event kind {self.kind}")
        if not 0 <= self.hour <= 23:
            raise ValueError("hour must be 0 to 23")

    def as_json(self) -> bytes:
        """The collector's report, as bytes that are sealed into the receipt by digest."""
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode("utf-8")


# A few ordinary events: they must NOT raise an alert.
BASELINE = (
    EndpointEvent("process_launch", "asha", 10, process="excel.exe", parent="explorer.exe"),
    EndpointEvent(
        "file_download",
        "asha",
        11,
        target="https://files.northwindbank.com/reports/q3.pdf",
        size_mb=2,
    ),
    EndpointEvent("record_query", "asha", 11, target="customer_balances", count=4),
    EndpointEvent(
        "url_click", "asha", 12, target="https://intranet.northwindbank.com/news", source="chat"
    ),
)

PHISHING_CHAT = (
    EndpointEvent(
        "url_click",
        "asha",
        15,
        target="https://northwind-bank.secure-login.top/verify/account?session=1",
        source="chat",
    ),
)
OFFHOURS_DOWNLOAD = (
    EndpointEvent(
        "file_download",
        "jsmith",
        2,
        target="https://files.randomstorage.io/exports/customers_q3.zip",
        size_mb=520,
    ),
)
RECORDS_ACCESS = (
    EndpointEvent("record_query", "jsmith", 21, target="customer_balances", count=42),
)
OFFICE_SPAWNS_SHELL = (
    EndpointEvent("process_launch", "mkhan", 15, process="powershell.exe", parent="winword.exe"),
)

SCENARIOS: dict[str, tuple[EndpointEvent, ...]] = {
    "phishing_chat": BASELINE[:2] + PHISHING_CHAT,
    "offhours_download": BASELINE[:2] + OFFHOURS_DOWNLOAD,
    "records_access": BASELINE[:3] + RECORDS_ACCESS,
    "all": BASELINE + PHISHING_CHAT + OFFHOURS_DOWNLOAD + RECORDS_ACCESS + OFFICE_SPAWNS_SHELL,
}


def scenario_for(text: str) -> tuple[str, tuple[EndpointEvent, ...]]:
    """Pick a scenario from a few plain words. Anything unclear runs the full set."""
    lowered = text.lower()
    for name, words in (
        ("phishing_chat", ("phish", "link", "chat")),
        ("offhours_download", ("download", "zip", "exfil")),
        ("records_access", ("record", "quer", "balance")),
    ):
        if any(w in lowered for w in words):
            return name, SCENARIOS[name]
    return "all", SCENARIOS["all"]


MAX_LINKS = 5


def events_from_links(
    text: str, user: str = "reporter", hour: int | None = None
) -> list[EndpointEvent]:
    """Links a person pasted ("is this safe?") as clicked-link events, up to five.

    The link is never opened from this computer: it is only scored, and (with a TinyFish key)
    sent to TinyFish as a question and a fetch."""
    import re
    import time

    now = time.localtime().tm_hour if hour is None else hour
    found = re.findall(r"https?://[^\s<>\"']{3,500}", text)
    return [
        EndpointEvent("url_click", user, now, target=link.rstrip(".,;)"), source="reported")
        for link in found[:MAX_LINKS]
    ]
