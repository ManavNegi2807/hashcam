"""Ask TinyFish about a URL, only when there is one and the run is allowed to.

Two questions, both through the gateway: **Search** (what do web reports say about this domain?) and
**Fetch** (what does the page itself say? TinyFish's servers read it, not this computer). Context,
not a verdict: whatever TinyFish returns is the provider's own claim, stored as an artifact and
shown as such. If it cannot be asked (no key, budget stopped, an error) the alert says so: missing
evidence is UNKNOWN, never "safe". The policy decides before each call and the receipt records it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from endpoint.scoring import host_of
from policy.engine import Action

SEARCH_URL = "https://api.search.tinyfish.ai"


@dataclass(frozen=True)
class Part:
    status: str  # DONE, NOT_RUN, NOT_ASKED, or a TinyFish adapter status such as OUTCOME_UNKNOWN
    text: str = ""


@dataclass(frozen=True)
class Enrichment:
    search: Part
    fetch: Part


def question_for(url: str) -> str:
    host = host_of(url) or url[:80]
    return (
        f"Is the website {host} a phishing, scam or malware site? "
        "What do web reports say about this domain?"
    )


def _part(outcome: Any) -> Part:
    return Part("DONE" if outcome.status == "SUCCEEDED" else outcome.status, outcome.detail)


def enrich(gateway: Any, adapter: Any, url: str, number: int) -> Enrichment:
    """`adapter` is a TinyFishAdapter on this gateway, or None when TinyFish is not available."""
    if adapter is None:
        skipped = Action(
            action_id=f"enrich-{number}",
            action_type="api_call",
            target=SEARCH_URL,
            params={"kind": "search and fetch", "not_run": "TinyFish is not available"},
        )
        gateway.deny(skipped, "ENRICHMENT_NOT_RUN")
        said = Part("NOT_RUN", "TinyFish was not asked: no key is set for this run.")
        return Enrichment(said, said)
    question = question_for(url)
    return Enrichment(_part(adapter.search(question)), _part(adapter.fetch(url, question)))
