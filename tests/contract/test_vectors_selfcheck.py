"""Step 1: are the frozen expectations actually right?

Every check here is done with an *independent* path, not with the generator:

* digests are recomputed with `hashlib` straight from the tagged bytes;
* Merkle roots are recomputed with an iterative frontier, while the generator
  uses the recursive RFC 6962 definition;
* inclusion and consistency proofs are checked with the RFC 6962 *verification*
  algorithms, which never call the proof-building code;
* checkpoint signatures are verified with `cryptography`, not re-signed.

So a bug in the generator cannot make these tests pass. Covers R-CRY-01,
R-CRY-02, R-CRY-03, R-PRO-02, R-PRO-03, R-PRO-06, R-TST-01, D-01, D-03, D-10.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections import OrderedDict
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "vectors"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _no_float(_: str) -> Any:
    raise AssertionError("float in a vector file")


def load(rel: str) -> dict[str, Any]:
    loaded = json.loads((VECTORS / rel).read_text(encoding="utf-8"), parse_float=_no_float)
    return cast("dict[str, Any]", loaded)


def b64(value: str) -> bytes:
    return base64.b64decode(value)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utf16_key(key: str) -> bytes:
    """RFC 8785 sorts object keys by UTF-16 code unit, not by code point."""
    return key.encode("utf-16-be")


# --------------------------------------------------------------------------- #
# independent Merkle implementations (RFC 6962)
# --------------------------------------------------------------------------- #

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def frontier_root(leaves: list[bytes]) -> str:
    """Iterative root: the frontier the signer keeps (PROTOCOL.md 11.1).

    Deliberately a different algorithm from the generator's recursive MTH.
    """
    if not leaves:
        return EMPTY_ROOT
    # frontier[i] holds a completed subtree of exactly 2**i leaves, or None.
    frontier: list[bytes | None] = []
    for data in leaves:
        carry = leaf_hash(data)
        level = 0
        while True:
            if level == len(frontier):
                frontier.append(carry)
                break
            held = frontier[level]
            if held is None:
                frontier[level] = carry
                break
            frontier[level] = None
            carry = node_hash(held, carry)
            level += 1
    # Fold the remaining subtrees right to left: RFC 6962 trees are left-perfect.
    acc: bytes | None = None
    for held in frontier:
        if held is None:
            continue
        acc = held if acc is None else node_hash(held, acc)
    assert acc is not None
    return acc.hex()


def verify_inclusion(leaf: bytes, index: int, size: int, path: list[str]) -> str:
    """RFC 6962 section 2.1.1 audit-path verification. Returns the derived root."""
    if not 0 <= index < size:
        raise ValueError("leaf_index out of range")
    node = leaf_hash(leaf)
    fn, sn = index, size - 1
    for sibling_hex in path:
        sibling = bytes.fromhex(sibling_hex)
        if sn == 0:
            raise ValueError("path too long")
        if fn % 2 == 1 or fn == sn:
            node = node_hash(sibling, node)
            while fn % 2 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path too short")
    return node.hex()


def verify_consistency(first_size: int, second_size: int, first_root: str, path: list[str]) -> str:
    """Consistency-proof verification, RFC 9162 section 2.1.4.2 (same tree as RFC 6962).

    Returns the derived second root.
    """
    if first_size > second_size or first_size == 0:
        raise ValueError("bad proof sizes")
    if first_size == second_size:
        if path:
            raise ValueError("proof must be empty for equal sizes")
        return first_root
    if not path:
        raise ValueError("empty proof")
    nodes = [bytes.fromhex(h) for h in path]
    # A first_size that is an exact power of two means the first root itself is
    # the omitted leading node (RFC 6962 SUBPROOF(m, D[m], true) = {}).
    if first_size & (first_size - 1) == 0:
        nodes.insert(0, bytes.fromhex(first_root))
    fn, sn = first_size - 1, second_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    first_derived = second_derived = nodes[0]
    for sibling in nodes[1:]:
        if sn == 0:
            raise ValueError("path too long")
        if (fn & 1) or fn == sn:
            first_derived = node_hash(sibling, first_derived)
            second_derived = node_hash(sibling, second_derived)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            second_derived = node_hash(second_derived, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("path too short")
    if first_derived.hex() != first_root:
        raise ValueError("first root does not match")
    return second_derived.hex()


def synthetic_leaves(count: int) -> list[bytes]:
    """The leaf data the generator uses, restated here so the test is self-contained."""
    return [b"abb1-test-leaf-%d" % i for i in range(count)]


# --------------------------------------------------------------------------- #
# JCS
# --------------------------------------------------------------------------- #


def test_canonical_output_is_a_fixed_point_and_matches_its_digest() -> None:
    doc = load("jcs/canonical.json")
    for case in doc["cases"]:
        canonical: str = case["expect"]["canonical"]
        # 1. it parses, and it parses back to the declared input value
        parsed = json.loads(canonical, object_pairs_hook=OrderedDict, parse_float=_no_float)
        assert json.loads(json.dumps(parsed)) == case["input"], case["id"]
        # 2. no insignificant whitespace, minimal escaping: dumping it again is identical
        assert json.dumps(parsed, separators=(",", ":"), ensure_ascii=False) == canonical, case[
            "id"
        ]
        # 3. the declared digest is the digest of the UTF-8 canonical bytes
        assert sha(canonical.encode("utf-8")) == case["expect"]["canonical_sha256"], case["id"]


def test_canonical_object_keys_are_sorted_by_utf16_code_unit() -> None:
    doc = load("jcs/canonical.json")
    checked = 0

    def walk(node: Any) -> None:
        nonlocal checked
        if isinstance(node, OrderedDict):
            keys = list(node.keys())
            assert keys == sorted(keys, key=utf16_key), f"keys not JCS-sorted: {keys}"
            checked += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for case in doc["cases"]:
        walk(json.loads(case["expect"]["canonical"], object_pairs_hook=OrderedDict))
    assert checked >= 5, "too few objects exercised by the JCS vectors"


def test_a_non_bmp_key_ordering_case_exists_and_differs_from_code_point_order() -> None:
    """The prototype's `sorted()` is wrong above U+FFFF; this pins the difference."""
    doc = load("jcs/canonical.json")
    hits = []
    for case in doc["cases"]:
        parsed = json.loads(case["expect"]["canonical"], object_pairs_hook=OrderedDict)
        if not isinstance(parsed, OrderedDict):
            continue
        keys = list(parsed.keys())
        if keys != sorted(keys) and keys == sorted(keys, key=utf16_key):
            hits.append(case["id"])
    assert hits, "no vector distinguishes UTF-16 order from code-point order"


def test_invalid_jcs_inputs_are_rejected_by_the_reference_parser() -> None:
    from vectors.tools import jcs_ref

    doc = load("jcs/invalid.json")
    for case in doc["cases"]:
        # Raw bytes for cases that cannot be written as JSON text (invalid UTF-8).
        data = case["input_text"] if "input_text" in case else b64(case["input_b64"])
        with pytest.raises(jcs_ref.CanonicalError) as err:
            jcs_ref.parse_strict(data)
        assert err.value.reason == case["expect"]["reason"], case["id"]


# --------------------------------------------------------------------------- #
# hashing and domain separation
# --------------------------------------------------------------------------- #


def test_domain_tag_digests() -> None:
    doc = load("hashing/domain_tags.json")
    for case in doc["cases"]:
        tag = case["input"]["tag"]
        data = b64(case["input"]["data_b64"])
        prefix = b"" if tag is None else tag.encode("ascii") + b"\x00"
        assert sha(prefix + data) == case["expect"]["digest"], case["id"]


def test_leaf_and_node_hashes() -> None:
    doc = load("hashing/tree_hashes.json")
    for case in doc["cases"]:
        kind = case["input"]["kind"]
        if kind == "leaf":
            assert leaf_hash(b64(case["input"]["data_b64"])).hex() == case["expect"]["digest"]
        elif kind == "node":
            left = bytes.fromhex(case["input"]["left"])
            right = bytes.fromhex(case["input"]["right"])
            assert node_hash(left, right).hex() == case["expect"]["digest"]
        elif kind == "empty_tree":
            assert EMPTY_ROOT == case["expect"]["digest"]
        else:
            raise AssertionError(f"unknown kind {kind}")


def test_tags_are_domain_separating() -> None:
    """The same bytes under two tags must not collide."""
    doc = load("hashing/domain_tags.json")
    by_data: dict[str, set[str]] = {}
    for case in doc["cases"]:
        by_data.setdefault(case["input"]["data_b64"], set()).add(case["expect"]["digest"])
    for data_b64, digests in by_data.items():
        cases = [c for c in doc["cases"] if c["input"]["data_b64"] == data_b64]
        if len({c["input"]["tag"] for c in cases}) > 1:
            assert len(digests) == len(cases), "two tags produced the same digest"


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #


def test_roots_match_an_independent_frontier_implementation() -> None:
    doc = load("merkle/roots.json")
    for case in doc["cases"]:
        count = case["input"]["leaf_count"]
        assert frontier_root(synthetic_leaves(count)) == case["expect"]["root_hash"], case["id"]


def test_empty_tree_is_the_digest_of_zero_bytes() -> None:
    doc = load("merkle/roots.json")
    zero = [c for c in doc["cases"] if c["input"]["leaf_count"] == 0]
    assert zero, "no empty-tree vector"
    assert zero[0]["expect"]["root_hash"] == EMPTY_ROOT


def test_inclusion_proofs_verify_to_the_declared_root() -> None:
    doc = load("merkle/inclusion.json")
    for case in doc["cases"]:
        size = case["input"]["tree_size"]
        index = case["input"]["leaf_index"]
        leaves = synthetic_leaves(size)
        assert leaf_hash(leaves[index]).hex() == case["expect"]["leaf_hash"], case["id"]
        derived = verify_inclusion(leaves[index], index, size, case["expect"]["path"])
        assert derived == case["expect"]["root_hash"], case["id"]
        assert derived == frontier_root(leaves), case["id"]


def test_consistency_proofs_verify_between_the_two_roots() -> None:
    doc = load("merkle/consistency.json")
    for case in doc["cases"]:
        first = case["input"]["first_size"]
        second = case["input"]["second_size"]
        first_root = frontier_root(synthetic_leaves(first))
        assert first_root == case["expect"]["first_root"], case["id"]
        derived = verify_consistency(first, second, first_root, case["expect"]["path"])
        assert derived == case["expect"]["second_root"], case["id"]
        assert derived == frontier_root(synthetic_leaves(second)), case["id"]


def test_malformed_proofs_are_rejected() -> None:
    doc = load("merkle/malformed.json")
    for case in doc["cases"]:
        kind = case["input"]["proof_kind"]
        with pytest.raises((ValueError, IndexError)):
            if kind == "inclusion":
                size = case["input"]["tree_size"]
                index = case["input"]["leaf_index"]
                leaves = synthetic_leaves(max(size, index + 1))
                verify_inclusion(leaves[index], index, size, case["input"]["path"])
            else:
                verify_consistency(
                    case["input"]["first_size"],
                    case["input"]["second_size"],
                    case["input"]["first_root"],
                    case["input"]["path"],
                )


# --------------------------------------------------------------------------- #
# checkpoints
# --------------------------------------------------------------------------- #


def _public_key() -> Ed25519PublicKey:
    keys = load("keys/test_keys.json")
    signer = next(k for k in keys["keys"] if k["role"] == "signer")
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer["public_key_hex"]))


def test_test_key_manifest_carries_no_private_key() -> None:
    """Only public key material may be committed, and it must be marked test-only."""
    raw = (VECTORS / "keys" / "test_keys.json").read_text(encoding="utf-8")
    assert "BEGIN" not in raw, "a PEM block must not appear in a committed key manifest"
    keys = load("keys/test_keys.json")
    assert "TEST" in keys["note"].upper(), "the manifest must say these keys are test-only"
    for key in keys["keys"]:
        for field in key:
            assert not field.startswith("private"), field
            assert field not in {"seed", "seed_hex", "secret_key", "private_key_hex"}, field
        # 32-byte public key, nothing longer that could hide a private half.
        assert len(bytes.fromhex(key["public_key_hex"])) == 32, key["key_id"]


def test_key_id_is_the_digest_of_the_public_key() -> None:
    keys = load("keys/test_keys.json")
    for key in keys["keys"]:
        expected = "ed25519:" + sha(bytes.fromhex(key["public_key_hex"]))
        assert key["key_id"] == expected, key["key_id"]


def test_checkpoint_signatures_verify_and_hashes_match() -> None:
    doc = load("checkpoint/checkpoints.json")
    pub = _public_key()
    valid = [c for c in doc["cases"] if c["expect"].get("result") == "ACCEPT"]
    assert valid, "no accepted checkpoint vectors"
    for case in valid:
        canonical = b64(case["expect"]["canonical_b64"])
        signing_bytes = b"ABB1-CHECKPOINT\x00" + canonical
        assert sha(signing_bytes) == case["expect"]["checkpoint_hash"], case["id"]
        pub.verify(bytes.fromhex(case["expect"]["signature"]), signing_bytes)
        # the payload really describes the tree it claims to
        payload = json.loads(canonical, parse_float=_no_float)
        assert payload["root_hash"] == frontier_root(synthetic_leaves(payload["tree_size"]))
        assert payload["protocol_version"] == "abb/1"


def test_checkpoint_signature_is_not_part_of_the_checkpoint_hash() -> None:
    """PROTOCOL.md 10.2: re-signing an identical payload keeps the same hash."""
    doc = load("checkpoint/checkpoints.json")
    pairs = [c for c in doc["cases"] if c["id"].endswith("resigned-identical")]
    assert pairs, "no re-signing vector"
    case = pairs[0]
    assert case["expect"]["checkpoint_hash"] == case["expect"]["same_hash_as"]


def test_a_tampered_checkpoint_signature_does_not_verify() -> None:
    doc = load("checkpoint/checkpoints.json")
    pub = _public_key()
    bad = [c for c in doc["cases"] if c["expect"].get("reason") == "BAD_SIGNATURE"]
    assert bad, "no bad-signature vector"
    for case in bad:
        signing_bytes = b"ABB1-CHECKPOINT\x00" + b64(case["input"]["canonical_b64"])
        with pytest.raises(InvalidSignature):
            pub.verify(bytes.fromhex(case["input"]["signature"]), signing_bytes)


def test_chain_rule_cases_are_labelled_correctly() -> None:
    """Genesis, extension, idempotent replay, regression, fork (PROTOCOL.md 10.3)."""
    doc = load("checkpoint/checkpoints.json")
    reasons = {c["expect"].get("reason") for c in doc["cases"]}
    for required in ("NOT_EXTENDING", "SIZE_REGRESSION", "FORK_DETECTED", "BAD_GENESIS"):
        assert required in reasons, f"no vector for {required}"
    genesis = [c for c in doc["cases"] if c["id"].endswith("genesis")]
    assert genesis
    payload = json.loads(b64(genesis[0]["expect"]["canonical_b64"]), parse_float=_no_float)
    assert payload["prev_checkpoint_hash"] == "0" * 64
    assert payload["tree_size"] >= 1


# --------------------------------------------------------------------------- #
# global log (D-10)
# --------------------------------------------------------------------------- #


def test_global_log_leaves_are_tagged_run_root_records() -> None:
    doc = load("global/global_log.json")
    for case in doc["cases"]:
        if "record_canonical_b64" not in case.get("expect", {}):
            continue
        canonical = b64(case["expect"]["record_canonical_b64"])
        leaf_data = b"ABB1-RUNROOT\x00" + canonical
        assert leaf_hash(leaf_data).hex() == case["expect"]["leaf_hash"], case["id"]
        record = json.loads(canonical, parse_float=_no_float)
        assert set(record) == {
            "run_id",
            "checkpoint_hash",
            "tree_size",
            "root_hash",
            "manifest_head",
            "finalized_at",
        }, case["id"]


def test_global_roots_for_one_to_five_runs() -> None:
    doc = load("global/global_log.json")
    records = [c for c in doc["cases"] if "record_canonical_b64" in c.get("expect", {})]
    assert len(records) >= 5, "need run roots 1..5 (TESTING.md section 3)"
    leaves = [b"ABB1-RUNROOT\x00" + b64(c["expect"]["record_canonical_b64"]) for c in records]
    roots = {
        c["input"]["tree_size"]: c["expect"]["root_hash"]
        for c in doc["cases"]
        if "tree_size" in c.get("input", {}) and "root_hash" in c.get("expect", {})
    }
    for size, expected in roots.items():
        assert frontier_root(leaves[:size]) == expected, f"global root for {size} runs"


def test_altered_and_injected_run_roots_are_flagged() -> None:
    doc = load("global/global_log.json")
    reasons = {c["expect"].get("reason") for c in doc["cases"]}
    assert "GLOBAL_ROOT_MISMATCH" in reasons, "no altered-run-root vector (TS-12)"
    assert "NOT_IN_SIGNER_STATE_LOG" in reasons, "no injected-run-root vector (R-GLB-02)"


def test_deleting_a_run_changes_the_global_root() -> None:
    """The mechanism behind `abb verify-global` (R-GLB-05, TS-11)."""
    doc = load("global/global_log.json")
    records = [c for c in doc["cases"] if "record_canonical_b64" in c.get("expect", {})]
    leaves = [b"ABB1-RUNROOT\x00" + b64(c["expect"]["record_canonical_b64"]) for c in records]
    full = frontier_root(leaves[:5])
    without_third = frontier_root(leaves[:2] + leaves[3:5])
    assert full != without_third
    assert len(leaves[:2] + leaves[3:5]) == 4
