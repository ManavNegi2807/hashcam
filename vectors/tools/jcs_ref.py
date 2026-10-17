"""RFC 8785 (JCS) serializer and strict parser — test-vector use only.

AGENTS.md rule 3.10 allows exactly one other implementation of the
cryptographic rules: the test-vector cross-check. This module is that
implementation. It generates and checks `vectors/`, and it must never be
imported by a service, an adapter or the signer. The Rust core in `core/`
(Step 2) is the implementation that ships.

Restrictions this module enforces, from PROTOCOL.md section 3:

* numbers are integers in [-(2^53-1), 2^53-1]; floats, exponents, fractions,
  `-0`, leading zeros, `NaN` and `Infinity` are rejected;
* duplicate object keys are rejected;
* object keys are sorted by UTF-16 code unit, not by code point;
* lone surrogates and invalid UTF-8 are rejected;
* canonical size <= 65536 bytes, nesting depth <= 16, single string <= 16384 bytes.
"""

from __future__ import annotations

import json
import re
from typing import Any

MAX_INT = 2**53 - 1
MIN_INT = -(2**53 - 1)
MAX_CANONICAL_BYTES = 65_536
MAX_DEPTH = 16
MAX_STRING_BYTES = 16_384


class CanonicalError(ValueError):
    """Rejection with a stable reason code, so vectors can pin the reason."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# --------------------------------------------------------------------------- #
# serializing
# --------------------------------------------------------------------------- #


def _sort_key(key: str) -> bytes:
    # UTF-16 big-endian bytes compare in UTF-16 code-unit order, which is what
    # RFC 8785 requires. Plain `sorted()` compares code points and differs
    # above U+FFFF.
    return key.encode("utf-16-be", errors="strict")


def _check_string(value: str) -> None:
    # PROTOCOL.md 3.3 limits a single string in BYTES, not characters, so a
    # long non-ASCII string is judged the same way the Rust core judges it.
    encoded_length = len(value.encode("utf-8", errors="surrogatepass"))
    if encoded_length > MAX_STRING_BYTES:
        raise CanonicalError("STRING_TOO_LONG", f"{encoded_length} bytes")
    for ch in value:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise CanonicalError("LONE_SURROGATE", f"U+{ord(ch):04X}")


def _serialize(value: Any, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise CanonicalError("DEPTH_EXCEEDED", f"depth {depth}")
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if not MIN_INT <= value <= MAX_INT:
            raise CanonicalError("INT_OUT_OF_RANGE", str(value))
        return str(value)
    if isinstance(value, float):
        raise CanonicalError("FLOAT_NOT_ALLOWED", repr(value))
    if isinstance(value, str):
        _check_string(value)
        # ensure_ascii=False gives JCS escaping: only ", \ and the control
        # characters are escaped, with the short forms where they exist.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item, depth + 1) for item in value) + "]"
    if isinstance(value, dict):
        parts = []
        for key in sorted(value, key=_sort_key):
            if not isinstance(key, str):
                raise CanonicalError("NON_STRING_KEY", repr(key))
            _check_string(key)
            parts.append(
                json.dumps(key, ensure_ascii=False) + ":" + _serialize(value[key], depth + 1)
            )
        return "{" + ",".join(parts) + "}"
    raise CanonicalError("UNSUPPORTED_TYPE", type(value).__name__)


def serialize(value: Any) -> str:
    """Return the JCS text for `value`."""
    text = _serialize(value, 1)
    if len(text.encode("utf-8")) > MAX_CANONICAL_BYTES:
        raise CanonicalError("SIZE_EXCEEDED", f"{len(text.encode('utf-8'))} bytes")
    return text


def canonical_bytes(value: Any) -> bytes:
    return serialize(value).encode("utf-8")


# --------------------------------------------------------------------------- #
# strict parsing
# --------------------------------------------------------------------------- #

# A number token that JCS and PROTOCOL.md section 3.2 accept: an optional
# minus, then 0 or a non-zero digit run. Nothing else.
_GOOD_NUMBER = re.compile(r"^-?(0|[1-9][0-9]*)$")


def _scan_number_tokens(text: str) -> list[str]:
    """Collect number tokens that sit outside string literals."""
    tokens: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        # `+` starts a token too, so that `+1` is reported as a bad number form
        # rather than falling through to a generic syntax error.
        if ch in "-+" or ch.isdigit():
            start = i
            while i < n and (text[i].isdigit() or text[i] in "-+.eE"):
                i += 1
            tokens.append(text[start:i])
            continue
        i += 1
    return tokens


def _reject_bad_number_forms(text: str) -> None:
    for number in _scan_number_tokens(text):
        # Order matters: `-0` and `01` are well-formed for the regex below but
        # are not canonical forms (PROTOCOL.md 3.2).
        if number == "-0":
            raise CanonicalError("MINUS_ZERO", number)
        if re.match(r"^-?0[0-9]", number):
            raise CanonicalError("LEADING_ZERO", number)
        if _GOOD_NUMBER.match(number):
            continue
        if "." in number or "e" in number or "E" in number:
            raise CanonicalError("FLOAT_NOT_ALLOWED", number)
        raise CanonicalError("NUMBER_FORM_INVALID", number)


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise CanonicalError("DUPLICATE_KEY", key)
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise CanonicalError("NAN_OR_INFINITY", name)


def _reject_float(raw: str) -> Any:
    raise CanonicalError("FLOAT_NOT_ALLOWED", raw)


def _walk_checks(node: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalError("DEPTH_EXCEEDED", f"depth {depth}")
    if isinstance(node, str):
        _check_string(node)
    elif isinstance(node, bool):
        return
    elif isinstance(node, int):
        if not MIN_INT <= node <= MAX_INT:
            raise CanonicalError("INT_OUT_OF_RANGE", str(node))
    elif isinstance(node, list):
        for item in node:
            _walk_checks(item, depth + 1)
    elif isinstance(node, dict):
        for key, value in node.items():
            _check_string(key)
            _walk_checks(value, depth + 1)


def parse_strict(data: str | bytes) -> Any:
    """Parse `data` under the protocol's rules, or raise `CanonicalError`."""
    if isinstance(data, bytes):
        if len(data) > MAX_CANONICAL_BYTES:
            raise CanonicalError("SIZE_EXCEEDED", f"{len(data)} bytes")
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalError("INVALID_UTF8", str(exc)) from exc
    else:
        text = data
        if len(text.encode("utf-8", errors="surrogatepass")) > MAX_CANONICAL_BYTES:
            raise CanonicalError("SIZE_EXCEEDED", "over limit")

    _reject_bad_number_forms(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicate_keys,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalError:
        raise
    except json.JSONDecodeError as exc:
        if exc.msg.startswith("Extra data"):
            raise CanonicalError("TRAILING_DATA", exc.msg) from exc
        raise CanonicalError("SYNTAX_ERROR", exc.msg) from exc
    except RecursionError as exc:
        raise CanonicalError("DEPTH_EXCEEDED", "recursion") from exc

    _walk_checks(value, 1)
    return value


def is_canonical(data: str | bytes) -> bool:
    """True when `data` is already exactly the canonical form of its own value."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    try:
        return serialize(parse_strict(text)) == text
    except CanonicalError:
        return False
