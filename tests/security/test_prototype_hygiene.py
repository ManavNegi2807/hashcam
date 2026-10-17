"""Step 0 checks on the prototype tree: ignore rules, compose wiring, secret-free logs."""

import contextlib
import io
import sys
from pathlib import Path
from typing import Any, ClassVar

import pytest

PROTO = Path(__file__).resolve().parents[2] / "prototype"
pytestmark = pytest.mark.skipif(not PROTO.exists(), reason="prototype tree not present")

FAKE_KEY_MARK = "FAKE-SIGNING-KEY-DO-NOT-USE-0123456789"


def test_dockerignore_keeps_secrets_out_of_the_image() -> None:
    lines = {x.strip() for x in (PROTO / ".dockerignore").read_text().splitlines()}
    for must in ("secrets/", "*.db", "*.pem", ".env", "shots/", "__pycache__/", ".git/"):
        assert must in lines, f"{must} missing from .dockerignore"


def test_compose_gives_the_signing_key_only_to_the_ledger_service() -> None:
    import yaml

    doc = yaml.safe_load((PROTO / "docker-compose.yml").read_text())
    services = doc["services"]
    assert "ledger" in services
    for name, svc in services.items():
        secrets = [s if isinstance(s, str) else s["source"] for s in svc.get("secrets", [])]
        if name == "ledger":
            assert "signing_key" in secrets
        else:
            assert "signing_key" not in secrets, f"{name} must not hold the signing key"
        for port in svc.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} port not local-only: {port}"
    ledger = services["ledger"]
    assert ledger.get("user"), "ledger must run as a non-root user"
    assert "healthcheck" in ledger


def test_dockerfile_runs_as_non_root() -> None:
    text = (PROTO / "Dockerfile").read_text()
    assert "USER " in text
    assert "USER root" not in text


class _Store:
    rows: ClassVar[list[Any]] = []

    def append(self, run_id: str, entry: Any) -> None:
        self.rows.append(entry)

    def save_shot(self, png: bytes) -> str:
        return ""


class _Guard:
    def check(self, url: str, action: str, params: Any) -> tuple[str, str]:
        return "allow", ""


class _Fish:
    def run(self, url: str, action: str, params: Any) -> tuple[str, bytes]:
        return "done", b""


def test_a_step_with_a_fake_key_leaks_nothing_to_stdout_or_the_log() -> None:
    sys.path.insert(0, str(PROTO))
    try:
        from agent.run_step import RunStep  # type: ignore[import-not-found]
        from ledger.chain import Chain, new_key  # type: ignore[import-not-found]
    finally:
        sys.path.remove(str(PROTO))

    store = _Store()
    store.rows.clear()
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        step = RunStep(Chain(new_key()), store, "r", _Guard(), _Fish())
        step("shop", "type", {"note": "visit", "api_key": FAKE_KEY_MARK})
    blob = out.getvalue() + repr(store.rows)
    assert "-----BEGIN" not in blob
    assert FAKE_KEY_MARK not in blob
