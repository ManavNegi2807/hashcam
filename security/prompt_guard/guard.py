"""A deterministic screen for untrusted text on its way to an agent (`R-PIG-*`).

What it is: a handful of readable rules for common injection shapes (an override
of earlier instructions, role-confusion markers, attempts to reveal the system
prompt, tool-use hijacking, hidden or encoded instructions). Same input, same
answer; no model, no network, no clock.

What it is **not**: a complete prompt-injection defence (`R-PIG-10`). It misses
paraphrases, other languages and anything clever. `corpus.py` and
`docs/PROMPT_GUARD_EVAL.md` report what it caught and missed on a small
hand-written set; that is a measurement of that set only.

Its verdict is a **signal** to the policy gateway (`R-PIG-05`). `ALLOW`,
`FLAG_FOR_REVIEW` and `BLOCK_BY_POLICY` authorize nothing; only deterministic
policy can block or allow an action. A high score is not proof of an attack
(`R-UI-05`).

No Prompt Chainmail code or model is used (`R-PIG-08`): that repository lists a
Business Source License and has not been reviewed. Only the interface in
`Classifier` is kept, so a reviewed classifier could be plugged in later.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

Verdict = Literal["ALLOW", "FLAG_FOR_REVIEW", "BLOCK_BY_POLICY"]

DETECTOR_ID = "abb-deterministic-guard"
DETECTOR_VERSION = "1"

#: Larger inputs are cut here and the cut is recorded (`R-PIG-02`). The digest
#: still covers the whole original.
MAX_INPUT_BYTES = 256 * 1024

FLAG_AT = 300_000
BLOCK_AT = 700_000

#: Format characters used to hide text from a human reader (zero-width and bidi).
HIDDEN_CHARS = re.compile("[​‌‍⁠﻿‪‫‬‭‮⁦⁧⁨⁩]")
FENCE = re.compile(r"```.*?```", re.DOTALL)
INLINE_CODE = re.compile(r"`[^`\n]{1,200}`")

OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}"
    r"\b(previous|prior|above|earlier|all|any|your|the)\b[^.\n]{0,30}"
    r"\b(instructions?|rules?|prompts?|guidelines?|directions?|restrictions?)\b",
    re.IGNORECASE,
)
NEW_INSTRUCTIONS = re.compile(r"\bnew\s+(?:system\s+)?instructions?\s*:", re.IGNORECASE)
FROM_NOW_ON = re.compile(r"\bfrom\s+now\s+on\s*,?\s+you\s+(?:are|will|must)", re.IGNORECASE)
ROLE_MARKERS = re.compile(
    r"(<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|<</SYS>>|(?:^|\n)\s*#{1,3}\s*system\b)",
    re.IGNORECASE,
)
# A bare "system:" or "assistant:" line start also appears in logs and YAML, so
# on its own it stays below the flag threshold.
ROLE_LABEL = re.compile(r"(?:^|\n)\s*(?:system|assistant)\s*:\s*\S", re.IGNORECASE)
AUTH_CLAIM = re.compile(
    r"\byou\s+(?:are|have\s+been)\s+(?:now\s+)?(?:authori[sz]ed|allowed|permitted|cleared)"
    r"\s+to\s+(?:skip|bypass|ignore|disable|override)",
    re.IGNORECASE,
)
PERSONA = re.compile(
    r"\byou\s+are\s+now\b[^.\n]{0,40}\b(unrestricted|jailbroken|dan\b|developer\s+mode|"
    r"without\s+(?:any\s+)?(?:rules|restrictions|limits))",
    re.IGNORECASE,
)
EXFIL_PROMPT = re.compile(
    r"\b(reveal|print|show|repeat|output|leak|display)\b[^.\n]{0,30}"
    r"\b(system\s+prompt|your\s+instructions|hidden\s+prompt|initial\s+prompt|"
    r"the\s+instructions\s+above)",
    re.IGNORECASE,
)
_SECRETISH = (
    r"(?:data|tokens?|cookies?|passwords?|credentials?|contents?|sessions?|secrets?|keys?|"
    r"invoices?|customer\s+list|account\s+numbers?|details|files?|information|history)"
)
SEND_DATA = re.compile(
    r"\b(send|post|upload|forward|email|exfiltrate|transmit)\b[^.\n]{0,50}\b"
    + _SECRETISH
    + r"\b[^.\n]{0,40}\b(?:to|at)\b[^.\n]{0,30}(https?://|[\w.+-]+@[\w-]+\.[\w.-]+)",
    re.IGNORECASE,
)
TOOL_CALL = re.compile(
    r"\b(call|invoke|use|run|execute)\b\s+(?:the\s+)?(?:\w+\s+){0,2}"
    r"(tool|function|command|api)\b[^.\n]{0,40}"
    r"\b(now|immediately|without\s+(?:asking|telling|confirm))",
    re.IGNORECASE,
)
HIDDEN_STYLE = re.compile(
    r"(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0|"
    r"color\s*:\s*(?:white|#fff(?:fff)?)\b)",
    re.IGNORECASE,
)
INSTRUCTION_WORDS = re.compile(
    r"\b(ignore|disregard|instructions?|assistant|system\s+prompt|you\s+must|send\s+the)\b",
    re.IGNORECASE,
)
HTML_COMMENT = re.compile(r"<!--(.{0,300}?)-->", re.DOTALL)
BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
EXAMPLE_CONTEXT = re.compile(
    r"(for\s+example|e\.g\.|such\s+as|an?\s+attacker|attackers?\s+(?:may|can|often)|"
    r"prompt\s+injection|injection\s+attack|a\s+common\s+attack|known\s+phrase|"
    r"don'?t\s+(?:ever\s+)?(?:follow|obey)|never\s+(?:follow|obey)|training\s+data|"
    r"security\s+(?:advisory|research|blog))",
    re.IGNORECASE,
)

#: Parts per million added when a category matches.
WEIGHTS = {
    "INSTRUCTION_OVERRIDE": 400_000,
    "NEW_INSTRUCTIONS": 250_000,
    "FROM_NOW_ON": 250_000,
    "ROLE_CONFUSION": 350_000,
    "ROLE_LABEL": 250_000,
    "AUTHORIZATION_CLAIM": 300_000,
    "PERSONA_SWITCH": 350_000,
    "PROMPT_EXFILTRATION": 300_000,
    "TOOL_USE_HIJACK": 300_000,
    "SEND_DATA_OUT": 300_000,
    "HIDDEN_INSTRUCTION": 400_000,
    "ENCODED_INSTRUCTION": 300_000,
    "HIDDEN_CHARACTERS": 150_000,
}
# A match inside a code block, or introduced as an example, is NOT discounted: the
# attacker controls that framing, so a discount would be a bypass. The guard says
# so in the reason codes instead, and the verdict stays a review signal.


class Classifier(Protocol):
    """The slot a reviewed classifier would fill. Nothing implements it today."""

    detector_id: str
    detector_version: str

    def classify(self, text: str) -> tuple[int, list[str]]:
        """Return `(score_ppm, reason_codes)`."""
        ...


@dataclass(frozen=True)
class GuardResult:
    verdict: Verdict
    score_ppm: int
    reason_codes: tuple[str, ...]
    source_digest: str
    source_kind: str
    truncated: bool
    classifier_available: bool
    detector_id: str = DETECTOR_ID
    detector_version: str = DETECTOR_VERSION

    def to_payload(self) -> dict[str, object]:
        """The `PROMPT_SECURITY_ANALYSIS_COMPLETED` payload (`R-PIG-06`)."""
        return {
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "verdict": self.verdict,
            "score_ppm": self.score_ppm,
            "reason_codes": list(self.reason_codes),
            "source_digest": self.source_digest,
            "classifier_available": self.classifier_available,
            "source_kind": self.source_kind,
            "truncated": self.truncated,
            "coverage": "DETERMINISTIC_ONLY",
        }


def _spans(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in pattern.finditer(text)]


def _inside(position: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in spans)


def _framing(text: str, start: int, code: list[tuple[int, int]]) -> str | None:
    """Is this match inside a code block or introduced as an example? (information only)"""
    if _inside(start, code):
        return "IN_CODE_BLOCK"
    if EXAMPLE_CONTEXT.search(text[max(0, start - 200) : start]):
        return "PRESENTED_AS_EXAMPLE"
    return None


class DeterministicGuard:
    """Screens text. Holds no state between calls."""

    def __init__(self, classifier: Classifier | None = None) -> None:
        self._classifier = classifier

    @staticmethod
    def _scan(plain: str, hit: Callable[[str], None], notes: set[str]) -> None:
        code = _spans(FENCE, plain) + _spans(INLINE_CODE, plain)
        for pattern, name in (
            (OVERRIDE, "INSTRUCTION_OVERRIDE"),
            (NEW_INSTRUCTIONS, "NEW_INSTRUCTIONS"),
            (FROM_NOW_ON, "FROM_NOW_ON"),
            (ROLE_MARKERS, "ROLE_CONFUSION"),
            (ROLE_LABEL, "ROLE_LABEL"),
            (AUTH_CLAIM, "AUTHORIZATION_CLAIM"),
            (PERSONA, "PERSONA_SWITCH"),
            (EXFIL_PROMPT, "PROMPT_EXFILTRATION"),
            (TOOL_CALL, "TOOL_USE_HIJACK"),
            (SEND_DATA, "SEND_DATA_OUT"),
        ):
            for match in pattern.finditer(plain):
                hit(name)
                framing = _framing(plain, match.start(), code)
                if framing:
                    notes.add(framing)

        for comment in HTML_COMMENT.finditer(plain):
            if INSTRUCTION_WORDS.search(comment.group(1)):
                hit("HIDDEN_INSTRUCTION")
        for style in HIDDEN_STYLE.finditer(plain):
            near = plain[style.start() : style.end() + 300]
            if INSTRUCTION_WORDS.search(near):
                hit("HIDDEN_INSTRUCTION")

        for run in BASE64_RUN.finditer(plain):
            try:
                decoded = base64.b64decode(run.group(0), validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if OVERRIDE.search(decoded) or INSTRUCTION_WORDS.search(decoded):
                hit("ENCODED_INSTRUCTION")

    def classify(self, data: str | bytes, *, source_kind: str = "page_text") -> GuardResult:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        # The digest names the whole original, even when only a part is read.
        digest = hashlib.sha256(raw).hexdigest()
        truncated = len(raw) > MAX_INPUT_BYTES
        text = raw[:MAX_INPUT_BYTES].decode("utf-8", "replace")

        reasons: dict[str, float] = {}
        notes: set[str] = set()

        def hit(code: str) -> None:
            reasons[code] = max(reasons.get(code, 0.0), float(WEIGHTS[code]))

        hidden_count = len(HIDDEN_CHARS.findall(text))
        if hidden_count >= 3:
            hit("HIDDEN_CHARACTERS")
        # What a model would read, two ways: with format characters removed (this
        # rebuilds "ig<ZWSP>nore") and with them turned into a space (a separator
        # hidden between words). A hit in either view counts.
        views = [
            unicodedata.normalize("NFKC", HIDDEN_CHARS.sub("", text)),
            unicodedata.normalize("NFKC", HIDDEN_CHARS.sub(" ", text)),
        ]
        for plain in dict.fromkeys(views):
            self._scan(plain, hit, notes)

        score = int(sum(reasons.values()))
        codes = sorted(reasons) + sorted(notes)

        classifier_available = False
        if self._classifier is not None:
            try:
                extra_score, extra_reasons = self._classifier.classify(plain)
            except Exception:  # a broken classifier must never take the guard down
                codes.append("CLASSIFIER_UNAVAILABLE")
            else:
                classifier_available = True
                score = max(score, int(extra_score))
                codes.extend(extra_reasons)
        if truncated:
            codes.append("INPUT_TRUNCATED")

        score = min(score, 1_000_000)
        if score >= BLOCK_AT:
            verdict: Verdict = "BLOCK_BY_POLICY"
        elif score >= FLAG_AT:
            verdict = "FLAG_FOR_REVIEW"
        else:
            verdict = "ALLOW"
        return GuardResult(
            verdict=verdict,
            score_ppm=score,
            reason_codes=tuple(sorted(set(codes))),
            source_digest=digest,
            source_kind=source_kind,
            truncated=truncated,
            classifier_available=classifier_available,
        )
