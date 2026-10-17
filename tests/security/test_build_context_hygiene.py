"""Step 0b: the build context and the working tree must never carry secrets.

Covers R-OPS-05, AGENTS.md 3.14-3.16. A `COPY . .` in a Dockerfile must not be
able to pull `secrets/`, a key, a database or an environment file into an image.
These tests read the ignore files only; they never read key material.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]

# Patterns that must be excluded from any Docker build context (deploy/.dockerignore)
# and from version control (.gitignore).
REQUIRED_PATTERNS = [
    "secrets/",
    "*.pem",
    "*.key",
    ".env",
    "*.db",
    "__pycache__/",
]

DOCKER_ONLY_PATTERNS = [
    ".git/",
    "target/",
    "node_modules/",
]


def _rules(path: Path) -> list[str]:
    assert path.is_file(), f"{path.relative_to(REPO)} is missing"
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


@pytest.mark.parametrize("pattern", REQUIRED_PATTERNS + DOCKER_ONLY_PATTERNS)
def test_dockerignore_excludes_pattern(pattern: str) -> None:
    assert pattern in _rules(REPO / "deploy" / ".dockerignore")


@pytest.mark.parametrize("pattern", REQUIRED_PATTERNS)
def test_gitignore_excludes_pattern(pattern: str) -> None:
    assert pattern in _rules(REPO / ".gitignore")


def test_dockerignore_has_no_negation_that_readmits_secrets() -> None:
    # A later `!secrets/...` line would undo the exclusion.
    for line in _rules(REPO / "deploy" / ".dockerignore"):
        assert not re.match(r"^!.*(secret|\.pem|\.key|\.env)", line, re.IGNORECASE), line


def test_no_key_or_env_file_in_the_working_tree() -> None:
    """Nothing that looks like key material may sit in the repository."""
    # Dot-directories are tool caches and vendored dependency trees. A CA
    # bundle inside one of those is not a secret of this project, and the
    # ignore files keep them out of git and out of every build context.
    offenders = [
        p.relative_to(REPO).as_posix()
        for p in REPO.rglob("*")
        if p.is_file()
        and not any(part.startswith(".") for part in p.relative_to(REPO).parts)
        and (
            p.suffix in {".pem", ".key", ".p12", ".pfx"}
            or p.name in {".env", "id_rsa", "id_ed25519"}
            or "secrets" in p.relative_to(REPO).parts[:-1]
        )
    ]
    assert offenders == [], f"key-like files present: {offenders}"


def test_skeleton_directories_exist() -> None:
    """The v10 layout from the plan, section 2."""
    expected = [
        "core",
        "signer",
        "services/api",
        "services/worker",
        "adapters/replay",
        "adapters/playwright",
        "adapters/tinyfish",
        "policy",
        "security/semantic",
        "security/prompt_guard",
        "security/anomaly",
        "vectors",
        "deploy",
        "docs",
        "tests/contract",
        "tests/integration",
        "tests/tamper",
        "tests/fault",
        "tests/security",
    ]
    missing = [d for d in expected if not (REPO / d).is_dir()]
    assert missing == [], f"missing skeleton directories: {missing}"


def test_every_skeleton_directory_states_its_status() -> None:
    """Each stub README must say the slice is not implemented (R-CLM-01, R-CLM-02)."""
    stubs = sorted(REPO.glob("*/README.md")) + sorted(REPO.glob("*/*/README.md"))
    # Skip docs/ (real documents) and tool caches such as .pytest_cache/.
    stubs = [
        p
        for p in stubs
        if p.parts[-2] != "docs" and not any(part.startswith(".") for part in p.parts)
    ]
    assert stubs, "no stub READMEs found"
    statuses = ("SPECIFIED", "IMPLEMENTED", "TESTED", "MEASURED", "UNVERIFIED")
    for stub in stubs:
        text = stub.read_text(encoding="utf-8")
        assert any(s in text for s in statuses), (
            f"{stub.relative_to(REPO)} carries no claim status (R-CLM-01)"
        )
