"""How the worker hands a signed approval to the control plane.

Same shape as the event sink: standard library only, over the real HTTP API.
The worker only *relays* what an approver signed on their own device. It never
sees the approver's key, and what it relays is checked again by the API and then
again by the verifier.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from .event_sink import SinkError


class HttpApprovalClient:
    """Posts to `POST /api/v1/runs/{run_id}/approvals`."""

    def __init__(
        self, *, base_url: str, run_id: str, token: str, timeout_seconds: float = 30.0
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._run_id = run_id
        self._token = token
        self._timeout = timeout_seconds

    def submit(
        self, *, approval_id: str, statement_b64: str, key_id: str, signature: str
    ) -> dict[str, Any]:
        request = urllib.request.Request(  # noqa: S310 - fixed http(s) base URL
            f"{self._base_url}/api/v1/runs/{self._run_id}/approvals",
            data=json.dumps(
                {
                    "approval_id": approval_id,
                    "statement_b64": statement_b64,
                    "key_id": key_id,
                    "signature": signature,
                }
            ).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self._token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                answer = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode("utf-8"))
                raise SinkError(
                    str(body.get("code", "INTERNAL")), str(body.get("detail", ""))
                ) from exc
            except (ValueError, OSError):
                raise SinkError("INTERNAL", f"HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SinkError("DEPENDENCY_UNAVAILABLE", "the control plane is not reachable") from exc
        if not isinstance(answer, dict) or "decision" not in answer:
            raise SinkError("INTERNAL", "the control plane's answer was not an approval")
        return answer
