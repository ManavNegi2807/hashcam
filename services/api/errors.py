"""The one error shape, from `ERROR_HANDLING.md` sections 3 and 4.

Every HTTP error carries a stable `code`, a human message and a `request_id`.
A client branches on `code`, never on `detail`. `detail` never contains a
stack trace, a file path, SQL or a secret (`ERROR_HANDLING.md` 1.7, 3).
"""

from __future__ import annotations

# Ingestion and API codes (ERROR_HANDLING.md 4.1). Each entry is
# (HTTP status, retryable).
CODES: dict[str, tuple[int, bool]] = {
    "UNAUTHENTICATED": (401, False),
    "FORBIDDEN": (403, False),
    "NOT_FOUND": (404, False),
    "VALIDATION_FAILED": (422, False),
    "CANONICAL_FORM_INVALID": (422, False),
    "PAYLOAD_TOO_LARGE": (413, False),
    "UNKNOWN_EVENT_TYPE": (422, False),
    "SEQUENCE_CONFLICT": (409, False),
    "IDEMPOTENT_REPLAY": (200, False),
    "RUN_FINISHED": (409, False),
    "ILLEGAL_TRANSITION": (409, False),
    "STALE_FENCING_TOKEN": (409, False),
    "RATE_LIMITED": (429, True),
    "BACKPRESSURE": (503, True),
    "DEPENDENCY_UNAVAILABLE": (503, True),
    "INTERNAL": (500, False),
    # The signer refused on integrity grounds (fork, root mismatch, not
    # extending). Its own code travels in `detail`, because flattening an
    # integrity answer into a generic failure would hide an alert
    # (ERROR_HANDLING.md 11).
    "SIGNER_REFUSED": (409, False),
    # Signed approvals and mandates (ERROR_HANDLING.md 4.3).
    "BAD_SIGNATURE": (422, False),
    "UNKNOWN_APPROVER": (403, False),
    "UNKNOWN_ISSUER": (403, False),
    "APPROVAL_REQUIRED": (409, False),
    "APPROVAL_EXPIRED": (409, False),
    "APPROVAL_MISMATCH": (409, False),
    "APPROVAL_ALREADY_DECIDED": (409, False),
    "MANDATE_VIOLATION": (403, False),
    # Protocol-level rejections surfaced from the Rust core. They are all
    # client errors: the producer sent something the protocol forbids.
    "UNSUPPORTED": (422, False),
    "FLOAT_NOT_ALLOWED": (422, False),
    "NAN_OR_INFINITY": (422, False),
    "MINUS_ZERO": (422, False),
    "LEADING_ZERO": (422, False),
    "NUMBER_FORM_INVALID": (422, False),
    "INT_OUT_OF_RANGE": (422, False),
    "DUPLICATE_KEY": (422, False),
    "LONE_SURROGATE": (422, False),
    "INVALID_UTF8": (422, False),
    "STRING_TOO_LONG": (413, False),
    "SIZE_EXCEEDED": (413, False),
    "DEPTH_EXCEEDED": (422, False),
    "TRAILING_DATA": (422, False),
    "SYNTAX_ERROR": (422, False),
}

TITLES: dict[str, str] = {
    "SEQUENCE_CONFLICT": "Sequence conflict",
    "RUN_FINISHED": "Run already finished",
    "STALE_FENCING_TOKEN": "Worker lease was taken over",
    "CANONICAL_FORM_INVALID": "Not strict canonical JSON",
    "ILLEGAL_TRANSITION": "Run-state transition not allowed",
    "SIGNER_REFUSED": "The signer refused to sign",
}


class AbbError(Exception):
    """An error with a stable code, ready to render as problem+json.

    Deliberately **not** a frozen dataclass: `contextlib` and `psycopg` assign
    `__traceback__` while an exception travels out of a `with` block, and a
    frozen dataclass refuses that, replacing this error with a
    `FrozenInstanceError` so every mapped error would surface as 500 INTERNAL.
    """

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code, detail)
        self.code = code
        self.detail = detail

    def __repr__(self) -> str:
        return f"AbbError(code={self.code!r}, detail={self.detail!r})"

    @property
    def status(self) -> int:
        return CODES.get(self.code, (500, False))[0]

    @property
    def retryable(self) -> bool:
        return CODES.get(self.code, (500, False))[1]

    @property
    def title(self) -> str:
        return TITLES.get(self.code, self.code.replace("_", " ").capitalize())

    def body(self, request_id: str) -> dict[str, object]:
        """The RFC 9457 style body of `ERROR_HANDLING.md` section 3."""
        return {
            # Placeholder base URL until a docs site exists.
            "type": f"https://abb.invalid/errors/{self.code}",
            "title": self.title,
            "status": self.status,
            "code": self.code,
            "detail": self.detail,
            "request_id": request_id,
            "retryable": self.retryable,
        }
