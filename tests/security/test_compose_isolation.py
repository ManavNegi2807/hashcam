"""The signer's key volume is not shared, and the signer is not reachable.

`R-OPS-03`, `R-OPS-04` and `R-SIG-02` are properties of the deployment file, so
they are tested as such. `tools/check_key_volume_isolation.py` holds the rules;
this file makes them part of the suite, and proves the check can fail.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

COMPOSE = REPO / "deploy" / "docker-compose.yml"


def checker():  # noqa: ANN201
    pytest.importorskip("yaml")
    from tools.check_key_volume_isolation import check

    return check


def test_the_compose_file_passes_the_isolation_rules() -> None:
    assert COMPOSE.is_file()
    problems = checker()(COMPOSE)
    assert problems == [], problems


@pytest.mark.parametrize(
    ("extra_mount", "expected"),
    [
        # The api mounting the signer's keys is the mistake this check exists for.
        ("      - signer_keys:/keys:ro", "mounted by"),
        # A writable key mount is also wrong.
        ("      - signer_keys:/keys", "writable"),
    ],
)
def test_the_check_catches_a_shared_key_volume(
    tmp_path: Path, extra_mount: str, expected: str
) -> None:
    """A negative control: the rules must be able to fail."""
    text = COMPOSE.read_text(encoding="utf-8")
    marker = "      - ingestion_keys:/ingestion:ro"
    assert marker in text, "the api's volume block moved; update this test"
    broken = text.replace(marker, f"{marker}\n{extra_mount}", 1)
    path = tmp_path / "docker-compose.yml"
    path.write_text(broken, encoding="utf-8")

    problems = checker()(path)
    assert any(expected in problem for problem in problems), problems


def test_the_signer_publishes_no_ports_and_avoids_the_database_network() -> None:
    pytest.importorskip("yaml")
    import yaml

    document = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    signer = document["services"]["signer"]
    assert "ports" not in signer
    assert "data" not in (signer.get("networks") or [])
    # And it is the only service on the signer network besides the api.
    on_signer_network = [
        name
        for name, service in document["services"].items()
        if "signer" in (service.get("networks") or [])
    ]
    assert sorted(on_signer_network) == ["api", "signer"]
