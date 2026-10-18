"""Made-up endpoint events: ordinary ones to train on, and labelled ones to measure with.

Everything here is SYNTHETIC. The author of the rules also wrote these generators, so the numbers
measured on them are optimistic and say nothing about real traffic. They exist so that the model and
the rules can be compared, repeatably, on events whose truth is known, including hard cases each
one should get wrong.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from endpoint.events import EndpointEvent

COMPANY = "northwindbank.com"
KNOWN_GOOD = ["github.com", "python.org", "microsoft.com", "docs.google.com", "slack.com"]
NEWS = ["news.example.org", "weather.example.net", "intranet.northwindbank.com", "wiki.example.org"]
OFFICE_PARENTS = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"]
DESKTOP_PARENTS = ["explorer.exe", "code.exe", "windowsterminal.exe", "devenv.exe"]
SHELLS = ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"]
FILES = ["report", "invoice", "notes", "q3-summary", "template", "readme", "slides", "export"]
EXTENSIONS = [".pdf", ".docx", ".xlsx", ".csv", ".txt", ".png"]
SUSPICIOUS_TLDS = ["top", "xyz", "click", "icu", "rest", "work"]


@dataclass(frozen=True)
class Labelled:
    event: EndpointEvent
    malicious: bool
    family: str
    hard: bool = False  # built to be a case the rules should get wrong


def _day_hour(rng: random.Random) -> int:
    return rng.randint(8, 18)


def _benign_download(rng: random.Random) -> EndpointEvent:
    host = rng.choice([f"files.{COMPANY}", *KNOWN_GOOD])
    name = rng.choice(FILES) + rng.choice(EXTENSIONS)
    return EndpointEvent(
        "file_download",
        "u",
        _day_hour(rng),
        target=f"https://{host}/{name}",
        size_mb=rng.choice([0, 1, 1, 2, 3, 5, 8, 12, 20, 35, 48]),
    )


def _benign_click(rng: random.Random) -> EndpointEvent:
    if rng.random() < 0.15:  # a real sign-in page on a well-known site
        target = rng.choice(
            ["https://accounts.google.com/signin", "https://login.microsoftonline.com/"]
        )
    else:
        target = f"https://{rng.choice(NEWS)}/{rng.choice(FILES)}"
    return EndpointEvent(
        "url_click",
        "u",
        _day_hour(rng),
        target=target,
        source=rng.choice(["chat", "email", "browser"]),
    )


def _benign_queries(rng: random.Random) -> EndpointEvent:
    return EndpointEvent(
        "record_query",
        "u",
        rng.choice([8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19]),
        target="customer_balances",
        count=rng.randint(0, 12),
    )


def _benign_shell(rng: random.Random) -> EndpointEvent:
    return EndpointEvent(
        "process_launch",
        "u",
        _day_hour(rng),
        process=rng.choice(SHELLS),
        parent=rng.choice(DESKTOP_PARENTS),
    )


def ordinary(count: int, seed: int) -> list[EndpointEvent]:
    """Events a normal working day produces. Used to teach the model what normal looks like."""
    rng = random.Random(seed)  # noqa: S311 - made-up data for measuring, not security
    makers = [_benign_download] * 3 + [_benign_click] * 4 + [_benign_queries] * 2 + [_benign_shell]
    return [rng.choice(makers)(rng) for _ in range(count)]


# ---- the labelled set ------------------------------------------------------------------------


def _hard_benign(rng: random.Random) -> Labelled:
    """Legitimate things that LOOK odd: a nightly backup, a month-end analyst burst."""
    if rng.random() < 0.5:
        event = EndpointEvent(
            "file_download",
            "backup",
            rng.randint(1, 3),
            target=f"https://files.{COMPANY}/backup.zip",
            size_mb=rng.randint(200, 800),
        )
        return Labelled(event, False, "nightly_backup", hard=True)
    event = EndpointEvent(
        "record_query",
        "analyst",
        rng.randint(14, 17),
        target="customer_balances",
        count=rng.randint(25, 40),
    )
    return Labelled(event, False, "month_end_burst", hard=True)


def _phishing(rng: random.Random, hard: bool) -> Labelled:
    tld = rng.choice(SUSPICIOUS_TLDS)
    if hard:  # no company name inside the address: the rules cannot see the imitation
        host = rng.choice(
            [
                f"n0rthwindbank.{tld}",
                "nrthwindb-ank.com",
                f"login-portal-{rng.randint(10, 99)}.{tld}",
            ]
        )
    else:
        host = rng.choice(
            [
                f"northwind-bank.secure-login.{tld}",
                f"northwindbank-secure.{tld}",
                f"support-northwind.{tld}",
            ]
        )
    page = rng.choice(["verify", "login", "account/update", "signin"])
    event = EndpointEvent(
        "url_click",
        "u",
        rng.randint(7, 20),
        target=f"https://{host}/{page}?id={rng.randint(1000, 9999)}",
        source=rng.choice(["chat", "email"]),
    )
    return Labelled(event, True, "phishing_hard" if hard else "phishing", hard=hard)


def _exfil(rng: random.Random, hard: bool) -> Labelled:
    host = rng.choice(
        ["files.randomstorage.io", "dl.fileshare.top", "cdn.sendbox.xyz", "198.51.100.23"]
    )
    if hard:  # in working hours, modest size, not an archive: easy to miss
        event = EndpointEvent(
            "file_download",
            "u",
            _day_hour(rng),
            target=f"http://{host}/customers_export.csv",
            size_mb=rng.randint(15, 60),
        )
        return Labelled(event, True, "exfil_hard", hard=True)
    event = EndpointEvent(
        "file_download",
        "u",
        rng.choice([0, 1, 2, 3, 4, 5, 22, 23]),
        target=f"https://{host}/exports/{rng.choice(FILES)}.{rng.choice(['zip', '7z', 'rar'])}",
        size_mb=rng.randint(120, 900),
    )
    return Labelled(event, True, "exfil")


def _burst(rng: random.Random, hard: bool) -> Labelled:
    if hard:  # a quiet probe in the evening: not far above normal, only slightly off hours
        event = EndpointEvent(
            "record_query",
            "u",
            rng.randint(19, 21),
            target="customer_balances",
            count=rng.randint(14, 18),
        )
        return Labelled(event, True, "burst_hard", hard=True)
    event = EndpointEvent(
        "record_query",
        "u",
        rng.choice([6, 7, 19, 20, 21, 22, 23]),
        target="customer_balances",
        count=rng.randint(30, 120),
    )
    return Labelled(event, True, "burst")


def _shell(rng: random.Random, hard: bool) -> Labelled:
    if hard:  # started by a browser or reader, not an office program: the rule does not look there
        event = EndpointEvent(
            "process_launch",
            "u",
            _day_hour(rng),
            process=rng.choice(SHELLS),
            parent=rng.choice(["acrord32.exe", "chrome.exe", "msedge.exe"]),
        )
        return Labelled(event, True, "shell_hard", hard=True)
    event = EndpointEvent(
        "process_launch",
        "u",
        _day_hour(rng),
        process=rng.choice(SHELLS),
        parent=rng.choice(OFFICE_PARENTS),
    )
    return Labelled(event, True, "shell")


def labelled_set(seed: int, benign: int = 600, malicious: int = 200) -> list[Labelled]:
    """A labelled set: mostly ordinary traffic (10% looks odd but is fine) and four kinds of attack
    (about a quarter of them built to be hard). Reproducible from the seed."""
    rng = random.Random(seed)  # noqa: S311 - made-up data for measuring, not security
    out: list[Labelled] = []
    plain = ordinary(benign - benign // 10, seed + 1)
    out.extend(Labelled(e, False, e.kind) for e in plain)
    out.extend(_hard_benign(rng) for _ in range(benign // 10))
    makers = [_phishing, _exfil, _burst, _shell]
    for i in range(malicious):
        out.append(makers[i % 4](rng, rng.random() < 0.25))
    rng.shuffle(out)
    return out
