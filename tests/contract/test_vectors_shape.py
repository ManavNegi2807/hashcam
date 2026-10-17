"""Step 1: structural rules every conformance vector file must obey.

Covers R-PRO-01, R-PRO-03, R-TST-01 and PROTOCOL.md section 17. These tests say
nothing about whether the expected values are *correct* — that is
`test_vectors_selfcheck.py`. They only guard the file format, so that the Rust
core (Step 2) and the Python cross-check read the same shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "vectors"

# Sets frozen in Step 1 (DESIGN.md 20.1 item 1: JCS, tree, checkpoints, global log).
REQUIRED_SETS = {
    "jcs/canonical.json",
    "jcs/invalid.json",
    "hashing/domain_tags.json",
    "hashing/tree_hashes.json",
    "merkle/roots.json",
    "merkle/inclusion.json",
    "merkle/consistency.json",
    "merkle/malformed.json",
    "checkpoint/checkpoints.json",
    "global/global_log.json",
    "approval/approvals.json",
    "mandate/mandates.json",
    "commitment/commitments.json",
}

REQUIRED_TREE_SIZES = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17]

# PROTOCOL.md section 4. Every tag must appear in the hashing vectors.
DOMAIN_TAGS = [
    "ABB1-EVENT",
    "ABB1-CHECKPOINT",
    "ABB1-MANIFEST",
    "ABB1-WITNESS",
    "ABB1-KEYROTATE",
    "ABB1-RUNROOT",
    "ABB1-FIELD",
    "ABB1-APPROVAL",
    "ABB1-MANDATE",
]


def _no_float(_: str) -> Any:
    raise AssertionError("a vector file contains a float; protocol numbers are integers only")


def vector_files() -> list[Path]:
    return sorted(VECTORS.rglob("*.json"))


def load(path: Path) -> dict[str, Any]:
    # parse_float raises: R-PRO-03 forbids floats anywhere in hashed material.
    loaded = json.loads(path.read_text(encoding="utf-8"), parse_float=_no_float)
    return cast("dict[str, Any]", loaded)


def test_vectors_directory_exists() -> None:
    assert VECTORS.is_dir(), "vectors/ is missing"
    assert (VECTORS / "README.md").is_file(), "vectors/README.md is missing"


def test_all_required_sets_are_present() -> None:
    present = {p.relative_to(VECTORS).as_posix() for p in vector_files()}
    missing = sorted(REQUIRED_SETS - present)
    assert missing == [], f"missing vector sets: {missing}"


@pytest.mark.parametrize("rel", sorted(REQUIRED_SETS))
def test_file_header(rel: str) -> None:
    doc = load(VECTORS / rel)
    assert doc["protocol_version"] == "abb/1"
    assert doc["set"], "set name missing"
    assert doc["generator"], "generator provenance missing"
    assert isinstance(doc["cases"], list) and doc["cases"], "no cases"


def test_case_ids_are_unique_across_all_files() -> None:
    seen: dict[str, str] = {}
    for path in vector_files():
        doc = load(path)
        if "cases" not in doc:
            continue
        for case in doc["cases"]:
            cid = case["id"]
            assert cid not in seen, f"duplicate case id {cid} in {path.name} and {seen[cid]}"
            seen[cid] = path.name
    assert len(seen) >= 80, f"only {len(seen)} cases; the frozen sets need more"


def test_every_case_has_an_id_a_description_and_an_expectation() -> None:
    for path in vector_files():
        doc = load(path)
        for case in doc.get("cases", []):
            assert case.get("id"), f"case without id in {path.name}"
            assert case.get("desc"), f"case {case.get('id')} has no description"
            assert "expect" in case, f"case {case['id']} has no expect block"


def test_hex_fields_are_lowercase_and_the_right_length() -> None:
    """PROTOCOL.md section 1: hex is lowercase, no prefix, no separators."""
    for path in vector_files():
        doc = load(path)
        for case in doc.get("cases", []):
            for field, value in _walk(case):
                if not isinstance(value, str):
                    continue
                if field.endswith(("_hash", "_digest", "digest", "commitment")):
                    assert value == value.lower(), f"{case['id']}.{field} is not lowercase"
                    assert len(value) == 64, f"{case['id']}.{field} is not 64 hex chars"
                    int(value, 16)
                if field.endswith("signature"):
                    assert value == value.lower(), f"{case['id']}.{field} is not lowercase"
                    assert len(value) == 128, f"{case['id']}.{field} is not 128 hex chars"
                    int(value, 16)


def _walk(node: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(_walk(value, key))
    elif isinstance(node, list):
        for item in node:
            out.extend(_walk(item, prefix))
    else:
        out.append((prefix, node))
    return out


def test_merkle_roots_cover_every_required_size() -> None:
    doc = load(VECTORS / "merkle" / "roots.json")
    sizes = sorted(case["input"]["leaf_count"] for case in doc["cases"])
    missing = [n for n in REQUIRED_TREE_SIZES if n not in sizes]
    assert missing == [], f"tree sizes not covered: {missing}"


def test_inclusion_and_consistency_cover_every_required_size() -> None:
    inc = load(VECTORS / "merkle" / "inclusion.json")
    con = load(VECTORS / "merkle" / "consistency.json")
    inc_sizes = {case["input"]["tree_size"] for case in inc["cases"]}
    con_sizes = {case["input"]["second_size"] for case in con["cases"]}
    for n in REQUIRED_TREE_SIZES:
        if n >= 1:
            assert n in inc_sizes, f"no inclusion proof for tree size {n}"
        if n >= 2:
            assert n in con_sizes, f"no consistency proof for second_size {n}"


def test_every_domain_tag_has_a_hashing_vector() -> None:
    doc = load(VECTORS / "hashing" / "domain_tags.json")
    tagged = {case["input"]["tag"] for case in doc["cases"]}
    missing = [t for t in DOMAIN_TAGS if t not in tagged]
    assert missing == [], f"domain tags without a vector: {missing}"


def test_artifact_digest_vector_is_untagged() -> None:
    """D-03: the artifact digest has no domain tag."""
    doc = load(VECTORS / "hashing" / "domain_tags.json")
    untagged = [c for c in doc["cases"] if c["input"].get("tag") is None]
    assert untagged, "no untagged artifact-digest vector (D-03)"


def test_invalid_jcs_cases_state_a_rejection_reason() -> None:
    doc = load(VECTORS / "jcs" / "invalid.json")
    for case in doc["cases"]:
        assert case["expect"]["result"] == "REJECT"
        assert case["expect"]["reason"], f"{case['id']} has no rejection reason"


def test_malformed_proof_cases_all_expect_rejection() -> None:
    doc = load(VECTORS / "merkle" / "malformed.json")
    for case in doc["cases"]:
        assert case["expect"]["result"] == "REJECT"
        assert case["expect"]["reason"]
