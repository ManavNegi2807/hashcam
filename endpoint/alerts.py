"""Alerts, read back out of a receipt.

An alert is a flagged score record (`ML_ANALYSIS_COMPLETED`, model `endpoint-rules`) together with
what the ledger recorded around it: the reported event (sealed as an artifact), what TinyFish said
(or that it was not asked), and whether a person approved isolating the account. Everything here is
read from the receipt; nothing is scored again and nothing is decided. Whether the receipt itself is
unaltered is the offline verifier's answer, not this module's.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pathsafe
from endpoint.model import FEATURE_TEXT
from endpoint.model import MODEL_ID as FOREST_ID
from endpoint.scoring import MODEL_ID, explain
from endpoint.scoring import Score as _Score

MAX_ARTIFACT_BYTES = 200_000
COLLECTOR = "endpoint-collector-report"
SEARCH_EVIDENCE = "tinyfish-search-result"
FETCH_EVIDENCE = "tinyfish-fetch-result"


def _artifact(archive: zipfile.ZipFile, digest: str) -> bytes | None:
    """The bytes of an artifact inside the receipt, found by its digest. None if absent."""
    wanted = digest.split(":")[-1]
    for name in archive.namelist():
        if name.startswith("artifacts/") and name.rsplit("/", 1)[-1].split(":")[-1] == wanted:
            info = archive.getinfo(name)
            if info.file_size > MAX_ARTIFACT_BYTES:
                return None
            return archive.read(name)
    return None


def alerts_from(path: Path, summary: dict[str, Any]) -> list[dict[str, Any]]:
    """Alerts for one receipt. `summary` is `services.dashboard.server.summarize(path)`."""
    found: list[dict[str, Any]] = []
    subject: dict[str, Any] | None = None
    asked: dict[str, str] = {}
    current: dict[str, Any] | None = None
    with zipfile.ZipFile(pathsafe.extended(path)) as archive:
        for event in summary.get("events", []):
            kind = event["event_type"]
            payload = event.get("payload", {}) or {}
            action = str(payload.get("action_id", ""))

            if kind == "ACTION_REQUESTED" and action.startswith("ev-"):
                subject = {
                    "action_id": action,
                    "kind": payload.get("action_type", ""),
                    "target": payload.get("target", ""),
                    "report": None,
                }
                current = None
            elif kind == "ARTIFACT_CAPTURED" and payload.get("capture_method") == COLLECTOR:
                raw = _artifact(archive, str(payload.get("artifact_digest", "")))
                if subject is not None and raw is not None:
                    try:
                        subject["report"] = json.loads(raw)
                    except ValueError:
                        pass
            elif kind == "ML_ANALYSIS_COMPLETED" and payload.get("model_id") == FOREST_ID:
                opinion = _opinion(payload)
                if current is not None and current["subject"].get("action_id") == (
                    subject or {}
                ).get("action_id"):
                    current["model"] = opinion
                else:  # only the learned model flagged this one: a lower tier to look at
                    current = _new_alert(len(found) + 1, subject, 0, [], event)
                    current["severity"] = "REVIEW"
                    current["model"] = opinion
                    found.append(current)
            elif kind == "ML_ANALYSIS_COMPLETED" and payload.get("model_id") == MODEL_ID:
                score = int(payload.get("score_ppm", 0))
                reasons = [str(r) for r in payload.get("reason_codes", [])]
                current = _new_alert(len(found) + 1, subject, score, reasons, event)
                found.append(current)
            elif current is not None:
                _attach(current, kind, payload, action, archive, asked)
    return found


def _new_alert(
    number: int,
    subject: dict[str, Any] | None,
    score: int,
    reasons: list[str],
    event: dict[str, Any],
) -> dict[str, Any]:
    return {
        "alert_id": f"alert-{number}",
        "subject": dict(subject or {}),
        "score_ppm": score,
        "severity": _Score(score, tuple(reasons)).severity,
        "signals": explain(reasons),
        "model": None,
        "web_evidence": {
            "status": "NOT_ASKED",
            "search": {"status": "NOT_ASKED", "text": ""},
            "fetch": {"status": "NOT_ASKED", "text": ""},
        },
        "isolation": {"status": "NOT_PROPOSED"},
        "sequence": event.get("sequence"),
    }


def _opinion(payload: dict[str, Any]) -> dict[str, Any]:
    """The learned model's record, with each reason code turned into words."""
    reasons = []
    for code in payload.get("reason_codes", []):
        key = str(code).removeprefix("OUTLIER_").lower()
        reasons.append(
            {
                "code": str(code),
                "text": FEATURE_TEXT.get(key, "a combination of small differences"),
            }
        )
    return {
        "score_ppm": int(payload.get("score_ppm", 0)),
        "threshold_ppm": int(payload.get("threshold_ppm", 0)),
        "reasons": reasons,
    }


def _overall(web: dict[str, Any]) -> str:
    """One word for the whole web-evidence block. Anything missing stays visible as missing."""
    parts = [web["search"]["status"], web["fetch"]["status"]]
    if all(p == "NOT_ASKED" for p in parts):
        return "NOT_ASKED"
    if "DONE" in parts:
        return "DONE"
    for word in ("NOT_RUN", "UNKNOWN", "FAILED", "BLOCKED"):
        if word in parts:
            return word
    return str(next(p for p in parts if p != "NOT_ASKED"))


def _attach(
    alert: dict[str, Any],
    kind: str,
    payload: dict[str, Any],
    action: str,
    archive: zipfile.ZipFile,
    asked: dict[str, str],
) -> None:
    """Fold the events after a score record into that alert."""
    web = alert["web_evidence"]
    if action.startswith("enrich-") and kind == "ACTION_BLOCKED":
        said = {"status": "NOT_RUN", "text": "TinyFish was not asked: no key."}
        web["search"], web["fetch"] = dict(said), dict(said)
    elif action.startswith("tf-"):
        if kind == "ACTION_REQUESTED":
            asked[action] = "fetch" if "fetch" in str(payload.get("target", "")) else "search"
            web[asked[action]]["status"] = "WAITING"
        part = web.get(asked.get(action, ""))
        if part is not None:
            word = {
                "ACTION_SUCCEEDED": "DONE",
                "ACTION_FAILED": "FAILED",
                "OUTCOME_UNKNOWN": "UNKNOWN",
                "ACTION_BLOCKED": "BLOCKED",
            }.get(kind)
            if word:
                part["status"] = word
    if kind == "ARTIFACT_CAPTURED":
        part_name = {SEARCH_EVIDENCE: "search", FETCH_EVIDENCE: "fetch"}.get(
            str(payload.get("capture_method"))
        )
        if part_name:
            raw = _artifact(archive, str(payload.get("artifact_digest", "")))
            if raw is not None:
                web[part_name]["text"] = raw.decode("utf-8", "replace")[:4000]
    web["status"] = _overall(web)
    if action.startswith("iso-"):
        state = alert["isolation"]
        if kind == "ACTION_REQUESTED":
            state["status"] = "WAITING_FOR_APPROVAL"
        elif kind == "HUMAN_APPROVAL_GRANTED":
            state["status"] = "APPROVED"
        elif kind == "HUMAN_APPROVAL_DENIED":
            state["status"] = "DENIED"
        elif kind == "ACTION_SUCCEEDED":
            state["status"] = "ISOLATED_SIMULATED"
