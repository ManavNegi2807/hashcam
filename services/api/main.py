"""The one FastAPI service: control plane, ingestion module and SSE.

Hackathon cut (`D-13`, `R-HKC-01`): ingestion lives inside this service instead
of a separate Litestar process. The split waits for a benchmark that shows it is
needed (`R-SVC-04`).

Trust boundaries this file must respect (`DESIGN.md` 5):

* it holds **no** signer key and never signs anything (`R-SIG-01`);
* it is the only normal writer of committed event rows (`R-SVC-03`);
* the worker and adapters that call it are untrusted for ledger integrity, so
  every field they may not choose is assigned here and validated by the Rust
  core (`R-SVC-05`).

Routes follow `DATABASE_AND_API_CONTRACTS.md` Part B. Only the endpoints Step 3
needs exist; the rest arrive with their steps and are absent rather than
stubbed, so nothing reports a result it did not compute.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from .approvals import ApprovalRelay
from .canonical import Canonicalizer
from .errors import AbbError
from .mandates import register_mandate as store_signed_mandate
from .repository import Principal, Repository

API = "/api/v1"
MAX_EVENT_BYTES = 65_536  # PROTOCOL.md 3.3; the core enforces it again
MAX_PAGE = 200


def build_app(
    *,
    dsn: str,
    abb_path: str,
    sse_poll_seconds: float = 0.05,
    key_manifest_path: str | None = None,
) -> FastAPI:
    """Build the service. `dsn` and `abb_path` are injected so tests can run it.

    `key_manifest_path` is the out-of-band key list approvals and mandates are
    checked against. Without it those endpoints fail closed.
    """
    import psycopg

    @contextmanager
    def connect() -> Iterator[Any]:
        with psycopg.connect(dsn) as conn:
            yield conn

    repo = Repository(connect=connect, canonicalizer=Canonicalizer(abb_path))

    app = FastAPI(
        title="Agent Black Box API",
        version="0.1.0",
        docs_url=None,  # no docs surface in the hackathon cut
        redoc_url=None,
    )
    app.state.repository = repo
    relay = ApprovalRelay(repository=repo, abb_path=abb_path, key_manifest_path=key_manifest_path)
    policy_cache: dict[tuple[str, int], dict[str, list[str]]] = {}

    def redaction_for(run_id: str) -> dict[str, list[str]]:
        """The run's policy redaction rules (`D-11`); empty for most policies."""
        from policy.engine import Policy

        run = repo.get_run(run_id)
        if run is None:
            return {}
        key = (str(run["policy_id"]), int(run["policy_version"]))
        if key not in policy_cache:
            try:
                policy_cache[key] = Policy.load(*key).redaction_rules()
            except (OSError, ValueError):
                # A policy we cannot load must not silently turn redaction off.
                raise AbbError("INTERNAL", "the run's policy could not be loaded") from None
        return policy_cache[key]

    # ------------------------------------------- request id and error shape

    # Error mapping lives in exception handlers, not in middleware: Starlette's
    # BaseHTTPMiddleware propagates downstream failures through a task group,
    # so an `except AbbError` there does not match and every error would come
    # back as 500 INTERNAL. Handlers run below that boundary.

    @app.middleware("http")
    async def attach_request_id(request: Request, call_next: Any) -> Response:
        request_id = request.headers.get("X-Request-Id") or uuid.uuid4().hex
        request.state.request_id = request_id
        response: Response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        return response

    def request_id_of(request: Request) -> str:
        return getattr(request.state, "request_id", uuid.uuid4().hex)

    @app.exception_handler(AbbError)
    async def abb_error_handler(request: Request, exc: AbbError) -> Response:
        request_id = request_id_of(request)
        return JSONResponse(
            status_code=exc.status,
            content=exc.body(request_id),
            media_type="application/problem+json",
            headers={"X-Request-Id": request_id},
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, exc: Exception) -> Response:
        """Never leak a traceback, a path or SQL to a client (ERROR_HANDLING.md 3)."""
        request_id = request_id_of(request)
        return JSONResponse(
            status_code=500,
            content=AbbError("INTERNAL", "unexpected error").body(request_id),
            media_type="application/problem+json",
            headers={"X-Request-Id": request_id},
        )

    # ------------------------------------------------------------- auth deps

    def principal(authorization: str | None = Header(default=None)) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise AbbError("UNAUTHENTICATED", "a bearer token is required")
        found = repo.principal_for_token(authorization.removeprefix("Bearer ").strip())
        if found is None:
            raise AbbError("UNAUTHENTICATED", "unknown or expired token")
        return found

    def require_role(*roles: str) -> Any:
        def dependency(who: Principal = Depends(principal)) -> Principal:
            if who.role not in roles:
                raise AbbError("FORBIDDEN", f"this endpoint needs one of: {', '.join(roles)}")
            return who

        return dependency

    def reachable_run(run_id: str, who: Principal) -> str:
        """Check scope before existence, so a scoped token learns nothing."""
        if not who.may_reach_run(run_id):
            raise AbbError("FORBIDDEN", "this token is scoped to another run")
        if not repo.run_exists(run_id):
            raise AbbError("NOT_FOUND", "unknown run")
        return run_id

    # --------------------------------------------------------------- health

    @app.get(f"{API}/health")
    def health() -> dict[str, str]:
        """Liveness. Never reports configuration, a DSN or a token."""
        return {"status": "ok", "protocol_version": "abb/1"}

    @app.get(f"{API}/ready")
    def ready() -> Response:
        try:
            with connect() as conn:
                conn.execute("SELECT 1")
        except Exception:
            raise AbbError("DEPENDENCY_UNAVAILABLE", "the database is not reachable") from None
        return JSONResponse({"status": "ready"})

    # ----------------------------------------------------------------- runs

    @app.post(f"{API}/runs", status_code=201)
    def create_run(
        body: dict[str, Any], who: Principal = Depends(require_role("operator", "admin"))
    ) -> dict[str, Any]:
        for field in (
            "task",
            "adapter",
            "profile",
            "requested_coverage",
            "policy_id",
            "policy_version",
        ):
            if field not in body:
                raise AbbError("VALIDATION_FAILED", f"{field} is required")
        if body["profile"] not in {"LOCAL_ONLY", "CONNECTED_EVIDENCE"}:
            raise AbbError("VALIDATION_FAILED", "unknown profile")
        if body["requested_coverage"] not in {"TASK_LEVEL", "STEP_OBSERVED", "STEP_GATED"}:
            raise AbbError("VALIDATION_FAILED", "unknown requested_coverage")
        if not isinstance(body["policy_version"], int) or isinstance(body["policy_version"], bool):
            raise AbbError("VALIDATION_FAILED", "policy_version must be an integer")
        return repo.create_run(
            task=str(body["task"]),
            adapter=str(body["adapter"]),
            profile=str(body["profile"]),
            requested_coverage=str(body["requested_coverage"]),
            policy_id=str(body["policy_id"]),
            policy_version=int(body["policy_version"]),
            mandate_id=body.get("mandate_id"),
            created_by=who.user_id,
        )

    @app.get(f"{API}/runs/{{run_id}}")
    def get_run(run_id: str, who: Principal = Depends(principal)) -> dict[str, Any]:
        reachable_run(run_id, who)
        run = repo.get_run(run_id)
        if run is None:  # pragma: no cover - reachable_run already checked
            raise AbbError("NOT_FOUND", "unknown run")
        return run

    # ------------------------------------------------------------ ingestion

    @app.post(f"{API}/runs/{{run_id}}/events")
    async def propose_event(
        run_id: str,
        request: Request,
        who: Principal = Depends(require_role("adapter", "operator", "admin")),
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        fencing_token: str | None = Header(default=None, alias="X-Fencing-Token"),
    ) -> Response:
        reachable_run(run_id, who)
        # The raw body goes to the Rust core untouched: see canonical.py.
        body = await request.body()
        if len(body) > MAX_EVENT_BYTES:
            raise AbbError("PAYLOAD_TOO_LARGE", "over the event size limit")
        if idempotency_key is not None and not 1 <= len(idempotency_key) <= 128:
            raise AbbError("VALIDATION_FAILED", "Idempotency-Key must be 1 to 128 characters")

        token_value: int | None = None
        if fencing_token is not None:
            try:
                token_value = int(fencing_token)
            except ValueError:
                raise AbbError("VALIDATION_FAILED", "X-Fencing-Token must be an integer") from None

        committed = repo.ingest_event(
            run_id=run_id,
            body=body,
            idempotency_key=idempotency_key,
            fencing_token=token_value,
            redact=redaction_for(run_id),
        )
        event = committed.event
        payload: dict[str, Any] = {
            "event_id": event.event_id,
            "run_id": event.run_id,
            "sequence": event.sequence,
            "leaf_hash": event.leaf_hash.hex(),
            "committed": True,
        }
        if committed.replayed:
            # Documented as 200 with this code (ERROR_HANDLING.md 4.1).
            payload["code"] = "IDEMPOTENT_REPLAY"
            return JSONResponse(payload, status_code=200)
        return JSONResponse(payload, status_code=201)

    # ------------------------------------------------- approvals, mandates

    @app.post(f"{API}/runs/{{run_id}}/approvals", status_code=201)
    def submit_approval(
        run_id: str,
        body: dict[str, Any],
        who: Principal = Depends(require_role("adapter", "approver", "operator", "admin")),
    ) -> dict[str, Any]:
        """Relay a signed approval. The signature is the authority, not the caller."""
        reachable_run(run_id, who)
        for field in ("approval_id", "statement_b64", "key_id", "signature"):
            if not isinstance(body.get(field), str) or not body[field]:
                raise AbbError("VALIDATION_FAILED", f"{field} is required")
        return relay.submit(
            run_id,
            approval_id=body["approval_id"],
            statement_b64=body["statement_b64"],
            key_id=body["key_id"],
            signature=body["signature"],
        )

    @app.post(f"{API}/mandates", status_code=201)
    def register_mandate(
        body: dict[str, Any], who: Principal = Depends(require_role("operator", "admin"))
    ) -> dict[str, Any]:
        """Register a signed mandate. Checked by the core against the manifest."""
        del who
        for field in ("document_b64", "signature"):
            if not isinstance(body.get(field), str) or not body[field]:
                raise AbbError("VALIDATION_FAILED", f"{field} is required")
        return store_signed_mandate(
            repo,
            abb_path=abb_path,
            key_manifest_path=key_manifest_path,
            document_b64=body["document_b64"],
            signature=body["signature"],
        )

    @app.get(f"{API}/runs/{{run_id}}/events")
    def list_events(
        run_id: str,
        limit: int = 50,
        cursor: str | None = None,
        who: Principal = Depends(principal),
    ) -> dict[str, Any]:
        reachable_run(run_id, who)
        if limit < 1 or limit > MAX_PAGE:
            raise AbbError("VALIDATION_FAILED", f"limit must be 1 to {MAX_PAGE}")
        after: int | None = None
        if cursor is not None:
            try:
                after = int(cursor)
            except ValueError:
                raise AbbError("VALIDATION_FAILED", "cursor is not a sequence number") from None
        items = repo.list_events(run_id, after=after, limit=limit)
        next_cursor = str(items[-1]["sequence"]) if len(items) == limit and items else None
        return {"items": items, "next_cursor": next_cursor}

    # ------------------------------------------------------------------ SSE

    @app.get(f"{API}/runs/{{run_id}}/stream")
    def stream(
        run_id: str,
        request: Request,
        who: Principal = Depends(principal),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> StreamingResponse:
        """Committed events only, resumable with `Last-Event-ID` (`R-DAT-05`)."""
        reachable_run(run_id, who)
        after: int | None = None
        if last_event_id is not None:
            try:
                after = int(last_event_id)
            except ValueError:
                raise AbbError("VALIDATION_FAILED", "Last-Event-ID must be a sequence") from None

        async def events() -> AsyncIterator[bytes]:
            import asyncio

            cursor = after
            idle = 0.0
            while True:
                if await request.is_disconnected():
                    return
                batch = repo.list_events(run_id, after=cursor, limit=MAX_PAGE)
                for item in batch:
                    cursor = item["sequence"]
                    # id: is the sequence, so Last-Event-ID resumes exactly.
                    yield (
                        f"id: {item['sequence']}\n"
                        f"event: {item['event_type']}\n"
                        f"data: {item['canonical']}\n\n"
                    ).encode()
                    if item["event_type"] == "RUN_FINISHED":
                        # The contract closes the stream on RUN_FINISHED.
                        return
                if batch:
                    idle = 0.0
                    continue
                await asyncio.sleep(sse_poll_seconds)
                idle += sse_poll_seconds
                if idle >= 15.0:
                    idle = 0.0
                    yield b": keepalive\n\n"

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return app


def build() -> FastAPI:
    """Entry point for `uvicorn services.api.main:build --factory`.

    Configuration comes from the environment; nothing is defaulted to a
    password, and a missing value is an error rather than a guess.
    """
    import os

    dsn = os.environ.get("ABB_DB_DSN")
    abb_path = os.environ.get("ABB_BIN")
    if not dsn or not abb_path:
        raise RuntimeError("ABB_DB_DSN and ABB_BIN must be set")
    return build_app(
        dsn=dsn, abb_path=abb_path, key_manifest_path=os.environ.get("ABB_KEY_MANIFEST")
    )


__all__ = ["build", "build_app"]
