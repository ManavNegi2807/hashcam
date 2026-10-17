"""How the worker gets an event into the ledger: over the real HTTP API.

The worker is untrusted for ledger integrity (`DESIGN.md` 5, `R-SVC-05`), so it
does not write rows. It posts proposed events to the ingestion endpoint, which
assigns the sequence, canonicalizes through the Rust core and commits.

Only the standard library is used, so the worker needs no HTTP dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class SinkError(RuntimeError):
    """The ledger refused an event. The run must stop rather than continue blind."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class HttpEventSink:
    """Posts events to `POST /api/v1/runs/{run_id}/events`."""

    def __init__(
        self,
        *,
        base_url: str,
        run_id: str,
        token: str,
        fencing_token: int,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._run_id = run_id
        self._token = token
        self._fencing_token = fencing_token
        self._timeout = timeout_seconds

    def emit(
        self,
        *,
        event_type: str,
        source: str,
        provenance: dict[str, Any],
        payload: dict[str, Any],
        idempotency_key: str | None = None,
        policy_ref: dict[str, Any] | None = None,
        artifact_refs: list[str] | None = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "event_type": event_type,
            "source": source,
            "provenance": provenance,
            "payload": payload,
        }
        if policy_ref is not None:
            body["policy_ref"] = policy_ref
        if artifact_refs:
            body["artifact_refs"] = artifact_refs

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "X-Fencing-Token": str(self._fencing_token),
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key

        request = urllib.request.Request(  # noqa: S310 - fixed http(s) base URL
            f"{self._base_url}/api/v1/runs/{self._run_id}/events",
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                answer = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise _sink_error(exc) from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            raise SinkError("DEPENDENCY_UNAVAILABLE", "the ledger is not reachable") from exc

        if not isinstance(answer, dict) or "event_id" not in answer:
            raise SinkError("INTERNAL", "the ledger's answer was not an event")
        return answer

    def fetch_events(self) -> list[dict[str, Any]]:
        """Every committed event of this run, read back from the ledger.

        Advisory monitors must judge what the ledger holds, not a private copy:
        the control plane commits events too (an approval, for one), and a copy
        kept by the worker would not contain them.
        """
        events: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            query = "limit=200" + (f"&cursor={cursor}" if cursor else "")
            request = urllib.request.Request(  # noqa: S310 - fixed http(s) base URL
                f"{self._base_url}/api/v1/runs/{self._run_id}/events?{query}",
                headers={"Authorization": f"Bearer {self._token}"},
            )
            try:
                with urllib.request.urlopen(request, timeout=self._timeout) as response:  # noqa: S310
                    page = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                raise _sink_error(exc) from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                raise SinkError("DEPENDENCY_UNAVAILABLE", "the ledger is not reachable") from exc
            for item in page["items"]:
                body = json.loads(item["canonical"])
                events.append(
                    {
                        "event_id": item["event_id"],
                        "sequence": item["sequence"],
                        "event_type": item["event_type"],
                        "payload": body.get("payload", {}),
                    }
                )
            cursor = page.get("next_cursor")
            if not cursor:
                return events


def _sink_error(exc: urllib.error.HTTPError) -> SinkError:
    try:
        body = json.loads(exc.read().decode("utf-8"))
        return SinkError(str(body.get("code", "INTERNAL")), str(body.get("detail", "")))
    except (ValueError, OSError):
        return SinkError("INTERNAL", f"HTTP {exc.code}")
