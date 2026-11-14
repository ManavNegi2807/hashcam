"""What the website's read-only viewer may see of a session.

The extension and the local console are the person's own tools and see everything. The public
HashCam site reads a session over the viewer key from a browser tab, so it gets less:

* Always: addresses lose their query string, fragment and user:password part (those carry tokens),
  and the text of a step that is waiting for approval is replaced by a plain notice (it names form
  fields). The page that reads this is not where a person approves anything.
* For a session marked **sensitive**: also no task text, no passport sites, only the host of each
  address, no screenshots, and no list of the sites a task names.

Pure functions over the dict that `Recorder.view` returns, so they are tested without a stack.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

WITHHELD_TASK = "Withheld: this agent is marked sensitive."
WAITING_NOTICE = "A step is waiting for a person to approve it."
HIDDEN_HOST = "(hidden)"


def strip_url(url: object, *, keep_path: bool) -> str:
    """`https://host/path` with no query, fragment or credentials; the host alone if asked."""
    try:
        parts = urlsplit(str(url))
        host = parts.hostname
        port = parts.port
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not host:
        return ""
    shown = f"{parts.scheme}://{host}" + (f":{port}" if port else "")
    if keep_path and parts.path and parts.path != "/":
        shown += parts.path[:200]
    return shown


def _entry(entry: dict[str, Any], sensitive: bool) -> dict[str, Any]:
    out = dict(entry)
    if out.get("target"):
        out["target"] = strip_url(out["target"], keep_path=not sensitive)
    drift = out.get("drift")
    if isinstance(drift, dict):
        out["drift"] = {k: v for k, v in drift.items() if k != "task_hosts"}
    if sensitive:
        out.pop("snapshot", None)
    return out


def public_view(view: dict[str, Any]) -> dict[str, Any]:
    """A copy of one session's view that is safe to hand to the website."""
    sensitive = bool(view.get("sensitive"))
    out = dict(view)
    out["timeline"] = [_entry(e, sensitive) for e in view.get("timeline", [])]
    out["waiting"] = [
        {"action_id": w["action_id"], "summary": WAITING_NOTICE, "seconds_left": w["seconds_left"]}
        for w in view.get("waiting", [])
    ]
    passport = dict(view.get("passport") or {})
    passport.pop("mandate_id", None)
    if sensitive:
        out["task"] = WITHHELD_TASK
        passport["hosts"] = [HIDDEN_HOST]
        passport.pop("max_spend_minor_units", None)
    out["passport"] = passport
    return out


def public_row(row: dict[str, Any]) -> dict[str, Any]:
    """One entry of the session list, for the website."""
    if not row.get("sensitive"):
        return row
    return {**row, "task": WITHHELD_TASK}
