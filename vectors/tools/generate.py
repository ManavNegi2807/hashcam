"""Generate the frozen conformance vectors for `abb/1`.

Run from the repository root:

    python vectors/tools/generate.py

Deterministic: the same inputs and the same documented test key produce the
same files byte for byte, so a regenerated file that differs is a real change
and shows up in the diff. Once a vector is frozen it is not edited silently
(AGENTS.md 3.24); a protocol change needs a new decision, new vectors and a
`protocol_version` bump.

Covers the Step 1 sets of docs/IMPLEMENTATION_PLAN.md: JCS, hashing and domain
tags, Merkle tree and proofs, checkpoints, global log.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vectors.tools import jcs_ref, merkle_ref

VECTORS = Path(__file__).resolve().parents[1]
GENERATOR = "vectors/tools/generate.py (Python reference, cross-check only)"
PV = "abb/1"

# Test-only keys. The seed is derived from a published label so that anyone can
# rebuild the exact key pair; it is therefore PUBLIC and must never be used for
# anything real (TESTING.md section 16).
KEY_LABELS = {
    "signer": b"abb/1 test key v1 signer",
    "witness": b"abb/1 test key v1 witness",
    "approver": b"abb/1 test key v1 approver",
    "mandate_issuer": b"abb/1 test key v1 mandate_issuer",
}
FAILURE_DOMAINS = {
    "signer": "host:vector-generator/admin:test",
    "witness": "host:vector-generator/admin:test",
    "approver": "host:vector-generator/admin:test",
    "mandate_issuer": "host:vector-generator/admin:test",
}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_key(role: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(KEY_LABELS[role]).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_hex(role: str) -> str:
    from cryptography.hazmat.primitives import serialization

    return (
        test_key(role)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def key_id(role: str) -> str:
    return "ed25519:" + sha_hex(bytes.fromhex(public_hex(role)))


def write(rel: str, set_name: str, note: str, cases: list[dict[str, Any]]) -> None:
    path = VECTORS / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "set": set_name,
        "protocol_version": PV,
        "generator": GENERATOR,
        "note": note,
        "cases": cases,
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{rel}: {len(cases)} cases")


# --------------------------------------------------------------------------- #
# JCS
# --------------------------------------------------------------------------- #

EXAMPLE_EVENT = {
    "protocol_version": "abb/1",
    "schema_version": 1,
    "run_id": "00000000-0000-4000-8000-000000000001",
    "event_id": "00000000-0000-4000-8000-0000000000a1",
    "sequence": 3,
    "event_type": "ACTION_BLOCKED",
    "created_at": 1760000000000,
    "source": "observed_by_local_gateway",
    "provenance": {
        "adapter_name": "replay",
        "adapter_version": "0.1.0",
        "execution_id": "replay-1",
        "mode": "REPLAY",
        "observed_coverage": "STEP_GATED",
    },
    "payload": {
        "action_id": "act-2",
        "policy_id": "default",
        "policy_version": "1",
        "reason_codes": ["DOMAIN_NOT_ALLOWED"],
    },
    "policy_ref": {"policy_id": "default", "policy_version": "1"},
    "idempotency_key": "run1-act2-blocked",
}


def jcs_canonical_cases() -> list[dict[str, Any]]:
    inputs: list[tuple[str, str, Any]] = [
        ("jcs-empty-object", "empty object", {}),
        ("jcs-empty-array", "empty array", []),
        ("jcs-key-order-ascii", "ASCII keys are reordered", {"b": 1, "a": 2, "C": 3}),
        (
            "jcs-nested",
            "nested objects and arrays keep array order and sort object keys",
            {"z": [3, 2, 1], "a": {"y": 1, "b": {"x": 0}}},
        ),
        (
            "jcs-key-order-non-bmp",
            "U+10000 sorts before U+FFFF by UTF-16 code unit, the opposite of code-point order",
            {"￿": 1, "\U00010000": 2, "a": 3},
        ),
        (
            "jcs-key-order-latin-vs-combining",
            "precomposed and other non-ASCII keys; no normalisation is applied",
            {"é": 1, "é": 2, "f": 3},
        ),
        (
            "jcs-integer-extremes",
            "largest and smallest allowed integers",
            {"max": 2**53 - 1, "min": -(2**53 - 1), "zero": 0},
        ),
        (
            "jcs-escaping",
            "only quote, backslash and control characters are escaped",
            {"q": 'a"b', "bs": "a\\b", "ctl": "a\u0000\u001f\bb", "tabnl": "a\t\nb"},
        ),
        (
            "jcs-literals",
            "true, false and null are preserved",
            {"t": True, "f": False, "n": None},
        ),
        (
            "jcs-unicode-literal",
            "non-ASCII characters are emitted literally as UTF-8, not escaped",
            {"text": "é中\U0001f600"},
        ),
        (
            "jcs-event-envelope",
            "the illustrative event from PROTOCOL.md section 20",
            EXAMPLE_EVENT,
        ),
    ]
    cases = []
    for case_id, desc, value in inputs:
        canonical = jcs_ref.serialize(value)
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": value,
                "expect": {
                    "canonical": canonical,
                    "canonical_sha256": sha_hex(canonical.encode("utf-8")),
                },
            }
        )
    return cases


def jcs_invalid_cases() -> list[dict[str, Any]]:
    raw: list[tuple[str, str, str, str]] = [
        ("jcs-bad-float", "fractional number", '{"a":1.5}', "FLOAT_NOT_ALLOWED"),
        ("jcs-bad-exponent", "exponent notation", '{"a":1e2}', "FLOAT_NOT_ALLOWED"),
        ("jcs-bad-nan", "NaN literal", '{"a":NaN}', "NAN_OR_INFINITY"),
        ("jcs-bad-infinity", "Infinity literal", '{"a":Infinity}', "NAN_OR_INFINITY"),
        ("jcs-bad-minus-zero", "minus zero", '{"a":-0}', "MINUS_ZERO"),
        ("jcs-bad-leading-zero", "leading zero", '{"a":01}', "LEADING_ZERO"),
        ("jcs-bad-plus", "explicit plus sign", '{"a":+1}', "NUMBER_FORM_INVALID"),
        ("jcs-bad-duplicate-key", "duplicate object key", '{"a":1,"a":2}', "DUPLICATE_KEY"),
        (
            "jcs-bad-int-too-large",
            "integer above 2^53-1",
            '{"a":9007199254740992}',
            "INT_OUT_OF_RANGE",
        ),
        (
            "jcs-bad-lone-surrogate",
            "lone high surrogate in a string",
            '{"a":"\\ud800"}',
            "LONE_SURROGATE",
        ),
        ("jcs-bad-trailing-data", "two documents in one input", "{} {}", "TRAILING_DATA"),
        ("jcs-bad-syntax", "unterminated object", "{", "SYNTAX_ERROR"),
        (
            "jcs-bad-depth",
            "nesting deeper than 16",
            "[" * 17 + "]" * 17,
            "DEPTH_EXCEEDED",
        ),
        (
            "jcs-bad-string-too-long",
            "single string longer than 16384 characters",
            '{"a":"' + "x" * 16_385 + '"}',
            "STRING_TOO_LONG",
        ),
    ]
    cases = []
    for case_id, desc, text, reason in raw:
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input_text": text,
                "expect": {"result": "REJECT", "reason": reason},
            }
        )
    # Raw invalid UTF-8 cannot be written as JSON text, so it travels as base64.
    cases.append(
        {
            "id": "jcs-bad-invalid-utf8",
            "desc": "invalid UTF-8 byte sequence inside a string",
            "input_b64": b64(b'{"a":"\xff\xfe"}'),
            "expect": {"result": "REJECT", "reason": "INVALID_UTF8"},
        }
    )
    return cases


# --------------------------------------------------------------------------- #
# hashing
# --------------------------------------------------------------------------- #

TAGS = [
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
TAG_INPUT = b"abb1 vector input"


def hashing_tag_cases() -> list[dict[str, Any]]:
    cases = []
    for tag in TAGS:
        digest = sha_hex(tag.encode("ascii") + b"\x00" + TAG_INPUT)
        cases.append(
            {
                "id": f"hash-tag-{tag.lower()}",
                "desc": f"{tag} over the shared vector input; the same bytes under a "
                f"different tag must give a different digest",
                "input": {"tag": tag, "data_b64": b64(TAG_INPUT)},
                "expect": {"digest": digest},
            }
        )
    cases.append(
        {
            "id": "hash-artifact-untagged",
            "desc": "D-03: an artifact digest is SHA-256 of the raw bytes with no tag, "
            "because the object key equals the digest",
            "input": {"tag": None, "data_b64": b64(TAG_INPUT)},
            "expect": {"digest": sha_hex(TAG_INPUT)},
        }
    )
    return cases


def hashing_tree_cases() -> list[dict[str, Any]]:
    leaf0 = merkle_ref.synthetic_leaves(1)[0]
    left = merkle_ref.leaf_hash(b"abb1-test-leaf-0")
    right = merkle_ref.leaf_hash(b"abb1-test-leaf-1")
    return [
        {
            "id": "hash-empty-tree",
            "desc": "empty tree root is the digest of zero bytes",
            "input": {"kind": "empty_tree"},
            "expect": {"digest": sha_hex(b"")},
        },
        {
            "id": "hash-leaf-prefix",
            "desc": "leaf hash uses the 0x00 prefix",
            "input": {"kind": "leaf", "data_b64": b64(leaf0)},
            "expect": {"digest": merkle_ref.leaf_hash(leaf0).hex()},
        },
        {
            "id": "hash-leaf-tagged-event",
            "desc": "leaf hash over tagged event bytes, as an event stream builds it",
            "input": {"kind": "leaf", "data_b64": b64(b"ABB1-EVENT\x00" + TAG_INPUT)},
            "expect": {"digest": merkle_ref.leaf_hash(b"ABB1-EVENT\x00" + TAG_INPUT).hex()},
        },
        {
            "id": "hash-node-prefix",
            "desc": "node hash uses the 0x01 prefix and is order sensitive",
            "input": {"kind": "node", "left": left.hex(), "right": right.hex()},
            "expect": {"digest": merkle_ref.node_hash(left, right).hex()},
        },
        {
            "id": "hash-node-swapped",
            "desc": "swapping the children gives a different digest",
            "input": {"kind": "node", "left": right.hex(), "right": left.hex()},
            "expect": {"digest": merkle_ref.node_hash(right, left).hex()},
        },
    ]


# --------------------------------------------------------------------------- #
# Merkle
# --------------------------------------------------------------------------- #

SIZES = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17]


def merkle_root_cases() -> list[dict[str, Any]]:
    cases = []
    for n in SIZES:
        leaves = merkle_ref.synthetic_leaves(n)
        cases.append(
            {
                "id": f"merkle-root-{n}",
                "desc": f"RFC 6962 tree hash over {n} synthetic leaves",
                "input": {"leaf_count": n, "leaf_data_pattern": "abb1-test-leaf-<i>"},
                "expect": {"root_hash": merkle_ref.mth(leaves).hex()},
            }
        )
    return cases


def merkle_inclusion_cases() -> list[dict[str, Any]]:
    cases = []
    for n in [s for s in SIZES if s >= 1]:
        leaves = merkle_ref.synthetic_leaves(n)
        root = merkle_ref.mth(leaves).hex()
        for index in sorted({0, n // 2, n - 1}):
            path = [h.hex() for h in merkle_ref.inclusion_path(index, leaves)]
            cases.append(
                {
                    "id": f"merkle-incl-{n}-{index}",
                    "desc": f"audit path for leaf {index} of {n}",
                    "input": {"tree_size": n, "leaf_index": index},
                    "expect": {
                        "leaf_hash": merkle_ref.leaf_hash(leaves[index]).hex(),
                        "path": path,
                        "root_hash": root,
                    },
                }
            )
    return cases


def merkle_consistency_cases() -> list[dict[str, Any]]:
    cases = []
    for second in [s for s in SIZES if s >= 2]:
        firsts = sorted({1, second // 2, second - 1})
        for first in firsts:
            if first < 1:
                continue
            leaves = merkle_ref.synthetic_leaves(second)
            path = [h.hex() for h in merkle_ref.consistency_path(first, leaves)]
            cases.append(
                {
                    "id": f"merkle-cons-{first}-{second}",
                    "desc": f"consistency proof from {first} leaves to {second}",
                    "input": {"first_size": first, "second_size": second},
                    "expect": {
                        "first_root": merkle_ref.mth(merkle_ref.synthetic_leaves(first)).hex(),
                        "second_root": merkle_ref.mth(leaves).hex(),
                        "path": path,
                    },
                }
            )
    return cases


def merkle_malformed_cases() -> list[dict[str, Any]]:
    leaves7 = merkle_ref.synthetic_leaves(7)
    good7 = [h.hex() for h in merkle_ref.inclusion_path(3, leaves7)]
    root4 = merkle_ref.mth(merkle_ref.synthetic_leaves(4)).hex()
    cons = [h.hex() for h in merkle_ref.consistency_path(4, leaves7)]
    return [
        {
            "id": "merkle-bad-index-out-of-range",
            "desc": "leaf_index equal to tree_size",
            "input": {"proof_kind": "inclusion", "tree_size": 7, "leaf_index": 7, "path": good7},
            "expect": {"result": "REJECT", "reason": "LEAF_INDEX_OUT_OF_RANGE"},
        },
        {
            "id": "merkle-bad-path-too-short",
            "desc": "audit path with an element removed",
            "input": {
                "proof_kind": "inclusion",
                "tree_size": 7,
                "leaf_index": 3,
                "path": good7[:-1],
            },
            "expect": {"result": "REJECT", "reason": "PATH_TOO_SHORT"},
        },
        {
            "id": "merkle-bad-path-too-long",
            "desc": "audit path with an extra element",
            "input": {
                "proof_kind": "inclusion",
                "tree_size": 7,
                "leaf_index": 3,
                "path": [*good7, "00" * 32],
            },
            "expect": {"result": "REJECT", "reason": "PATH_TOO_LONG"},
        },
        {
            "id": "merkle-bad-path-not-hex",
            "desc": "audit path element that is not hex",
            "input": {
                "proof_kind": "inclusion",
                "tree_size": 7,
                "leaf_index": 3,
                "path": ["zz" * 32, *good7[1:]],
            },
            "expect": {"result": "REJECT", "reason": "NOT_HEX"},
        },
        {
            "id": "merkle-bad-first-size-zero",
            "desc": "consistency proof with first_size 0",
            "input": {
                "proof_kind": "consistency",
                "first_size": 0,
                "second_size": 7,
                "first_root": root4,
                "path": cons,
            },
            "expect": {"result": "REJECT", "reason": "FIRST_SIZE_ZERO"},
        },
        {
            "id": "merkle-bad-first-larger-than-second",
            "desc": "consistency proof with first_size greater than second_size",
            "input": {
                "proof_kind": "consistency",
                "first_size": 9,
                "second_size": 7,
                "first_root": root4,
                "path": cons,
            },
            "expect": {"result": "REJECT", "reason": "SIZE_REGRESSION"},
        },
        {
            "id": "merkle-bad-consistency-empty-path",
            "desc": "consistency proof between different sizes with an empty path",
            "input": {
                "proof_kind": "consistency",
                "first_size": 4,
                "second_size": 7,
                "first_root": root4,
                "path": [],
            },
            "expect": {"result": "REJECT", "reason": "EMPTY_PROOF"},
        },
    ]


# --------------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------------- #


def key_cases() -> dict[str, Any]:
    return {
        "set": "key manifest (test only)",
        "protocol_version": PV,
        "generator": GENERATOR,
        "note": (
            "PUBLIC TEST KEYS ONLY. The private seed is SHA-256 of the label in "
            "vectors/tools/generate.py, so the key pair is reproducible by anyone and "
            "offers no security. Never use these keys outside the vectors "
            "(TESTING.md section 16). No private material is stored in this file."
        ),
        "keys": [
            {
                "key_id": key_id(role),
                "public_key_hex": public_hex(role),
                "role": role,
                "failure_domain": FAILURE_DOMAINS[role],
                "valid_from": 1_760_000_000_000,
                "status": "active",
            }
            for role in ("signer", "witness", "approver", "mandate_issuer")
        ],
    }


# --------------------------------------------------------------------------- #
# checkpoints
# --------------------------------------------------------------------------- #

ZERO64 = "0" * 64
RUN_STREAM = "11111111-1111-4111-8111-111111111111"


def checkpoint_payload(
    tree_size: int,
    prev: str,
    *,
    stream_id: str = RUN_STREAM,
    manifest_size: int = 0,
    manifest_head: str = ZERO64,
    created_at: int = 1_760_000_100_000,
    root_override: str | None = None,
) -> dict[str, Any]:
    leaves = merkle_ref.synthetic_leaves(tree_size)
    return {
        "protocol_version": PV,
        "stream_id": stream_id,
        "tree_size": tree_size,
        "root_hash": root_override or merkle_ref.mth(leaves).hex(),
        "manifest_size": manifest_size,
        "manifest_head": manifest_head,
        "prev_checkpoint_hash": prev,
        "key_id": key_id("signer"),
        "created_at": created_at,
    }


def sign_checkpoint(payload: dict[str, Any], role: str = "signer") -> tuple[bytes, str, str]:
    canonical = jcs_ref.canonical_bytes(payload)
    signing_bytes = b"ABB1-CHECKPOINT\x00" + canonical
    signature = test_key(role).sign(signing_bytes).hex()
    return canonical, sha_hex(signing_bytes), signature


def checkpoint_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []

    genesis = checkpoint_payload(4, ZERO64)
    g_canon, g_hash, g_sig = sign_checkpoint(genesis)
    cases.append(
        {
            "id": "cp-accept-genesis",
            "desc": "genesis checkpoint: previous hash is 64 zeros and tree_size >= 1",
            "input": {"payload": genesis},
            "expect": {
                "result": "ACCEPT",
                "canonical_b64": b64(g_canon),
                "checkpoint_hash": g_hash,
                "signature": g_sig,
                "key_id": key_id("signer"),
            },
        }
    )

    ext = checkpoint_payload(8, g_hash, created_at=1_760_000_200_000)
    e_canon, e_hash, e_sig = sign_checkpoint(ext)
    cases.append(
        {
            "id": "cp-accept-extension",
            "desc": "later checkpoint extends the genesis: larger tree_size, prev hash links",
            "input": {"payload": ext, "prev_checkpoint_hash": g_hash},
            "expect": {
                "result": "ACCEPT",
                "canonical_b64": b64(e_canon),
                "checkpoint_hash": e_hash,
                "signature": e_sig,
                "key_id": key_id("signer"),
            },
        }
    )

    # Re-signing the identical payload: the signature is not part of the hash,
    # so the checkpoint hash is unchanged (PROTOCOL.md 10.2).
    r_canon, r_hash, r_sig = sign_checkpoint(ext)
    cases.append(
        {
            "id": "cp-accept-resigned-identical",
            "desc": "the same payload signed again keeps the same checkpoint_hash",
            "input": {"payload": ext},
            "expect": {
                "result": "ACCEPT",
                "canonical_b64": b64(r_canon),
                "checkpoint_hash": r_hash,
                "signature": r_sig,
                "same_hash_as": e_hash,
                "key_id": key_id("signer"),
            },
        }
    )

    cases.append(
        {
            "id": "cp-accept-equal-size-idempotent",
            "desc": "an equal tree_size request is only legal as the identical checkpoint",
            "input": {"payload": ext, "resubmitted": True},
            "expect": {
                "result": "ACCEPT",
                "canonical_b64": b64(e_canon),
                "checkpoint_hash": e_hash,
                "signature": e_sig,
                "key_id": key_id("signer"),
            },
        }
    )

    not_extending = checkpoint_payload(16, ZERO64, created_at=1_760_000_300_000)
    ne_canon, ne_hash, ne_sig = sign_checkpoint(not_extending)
    cases.append(
        {
            "id": "cp-reject-not-extending",
            "desc": "tree grows but prev_checkpoint_hash does not point at the last checkpoint",
            "input": {
                "payload": not_extending,
                "canonical_b64": b64(ne_canon),
                "signature": ne_sig,
                "signer_last_checkpoint_hash": e_hash,
            },
            "expect": {"result": "REJECT", "reason": "NOT_EXTENDING", "checkpoint_hash": ne_hash},
        }
    )

    regression = checkpoint_payload(2, e_hash, created_at=1_760_000_400_000)
    rg_canon, rg_hash, rg_sig = sign_checkpoint(regression)
    cases.append(
        {
            "id": "cp-reject-size-regression",
            "desc": "tree_size smaller than the last signed checkpoint",
            "input": {
                "payload": regression,
                "canonical_b64": b64(rg_canon),
                "signature": rg_sig,
                "signer_last_tree_size": 8,
            },
            "expect": {"result": "REJECT", "reason": "SIZE_REGRESSION", "checkpoint_hash": rg_hash},
        }
    )

    fork = checkpoint_payload(8, g_hash, created_at=1_760_000_200_000, root_override="ab" * 32)
    fk_canon, fk_hash, fk_sig = sign_checkpoint(fork)
    cases.append(
        {
            "id": "cp-reject-fork",
            "desc": "same tree_size as an already signed checkpoint but a different root",
            "input": {
                "payload": fork,
                "canonical_b64": b64(fk_canon),
                "signature": fk_sig,
                "conflicts_with_checkpoint_hash": e_hash,
            },
            "expect": {"result": "REJECT", "reason": "FORK_DETECTED", "checkpoint_hash": fk_hash},
        }
    )

    bad_genesis = checkpoint_payload(4, "cd" * 32, created_at=1_760_000_050_000)
    bg_canon, bg_hash, bg_sig = sign_checkpoint(bad_genesis)
    cases.append(
        {
            "id": "cp-reject-bad-genesis",
            "desc": "first checkpoint of an unknown stream with a non-zero previous hash",
            "input": {
                "payload": bad_genesis,
                "canonical_b64": b64(bg_canon),
                "signature": bg_sig,
                "signer_has_state": False,
            },
            "expect": {"result": "REJECT", "reason": "BAD_GENESIS", "checkpoint_hash": bg_hash},
        }
    )

    # Flip the last byte of a valid signature.
    flipped = bytearray(bytes.fromhex(e_sig))
    flipped[-1] ^= 0x01
    cases.append(
        {
            "id": "cp-reject-bad-signature",
            "desc": "valid payload, one bit flipped in the signature",
            "input": {
                "payload": ext,
                "canonical_b64": b64(e_canon),
                "signature": bytes(flipped).hex(),
            },
            "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
        }
    )

    w_canon, w_hash, w_sig = sign_checkpoint(ext, role="witness")
    cases.append(
        {
            "id": "cp-reject-wrong-key-role",
            "desc": "checkpoint signed by the witness key, which has no signer role",
            "input": {
                "payload": ext,
                "canonical_b64": b64(w_canon),
                "signature": w_sig,
                "signed_by_key_id": key_id("witness"),
            },
            "expect": {
                "result": "REJECT",
                "reason": "WRONG_KEY_ROLE",
                "checkpoint_hash": w_hash,
            },
        }
    )

    return cases


# --------------------------------------------------------------------------- #
# global log (D-10)
# --------------------------------------------------------------------------- #


def run_root_record(index: int) -> dict[str, Any]:
    """A run-root record as PROTOCOL.md 8.5 defines it, built from a run's final checkpoint."""
    tree_size = 4 + index  # each run has a slightly different final tree
    payload = checkpoint_payload(
        tree_size,
        ZERO64,
        stream_id=f"00000000-0000-4000-8000-00000000000{index + 1}",
        created_at=1_760_000_000_000 + index * 1_000,
    )
    _, cp_hash, _ = sign_checkpoint(payload)
    return {
        "run_id": f"00000000-0000-4000-8000-00000000000{index + 1}",
        "checkpoint_hash": cp_hash,
        "tree_size": tree_size,
        "root_hash": payload["root_hash"],
        "manifest_head": ZERO64,
        "finalized_at": 1_760_000_000_000 + index * 1_000,
    }


def global_cases() -> list[dict[str, Any]]:
    records = [run_root_record(i) for i in range(5)]
    leaves = [b"ABB1-RUNROOT\x00" + jcs_ref.canonical_bytes(r) for r in records]

    cases: list[dict[str, Any]] = []
    for i, record in enumerate(records):
        canonical = jcs_ref.canonical_bytes(record)
        cases.append(
            {
                "id": f"glb-record-{i + 1}",
                "desc": f"run-root record at global position {i}",
                "input": {"position": i, "run_id": record["run_id"]},
                "expect": {
                    "record_canonical_b64": b64(canonical),
                    "leaf_hash": merkle_ref.leaf_hash(b"ABB1-RUNROOT\x00" + canonical).hex(),
                },
            }
        )

    for size in range(1, 6):
        cases.append(
            {
                "id": f"glb-root-{size}",
                "desc": f"global root after {size} finalised runs",
                "input": {"tree_size": size},
                "expect": {"root_hash": merkle_ref.mth(leaves[:size]).hex()},
            }
        )

    # Global checkpoint over the 5 runs: stream_id "global", manifest empty.
    global_payload = {
        "protocol_version": PV,
        "stream_id": "global",
        "tree_size": 5,
        "root_hash": merkle_ref.mth(leaves).hex(),
        "manifest_size": 0,
        "manifest_head": ZERO64,
        "prev_checkpoint_hash": ZERO64,
        "key_id": key_id("signer"),
        "created_at": 1_760_000_500_000,
    }
    gp_canon = jcs_ref.canonical_bytes(global_payload)
    gp_signing = b"ABB1-CHECKPOINT\x00" + gp_canon
    cases.append(
        {
            "id": "glb-checkpoint-5",
            "desc": "global checkpoint covering five runs; manifest_size 0 and 64 zero bytes head",
            "input": {"tree_size": 5, "stream_id": "global"},
            "expect": {
                "result": "ACCEPT",
                "canonical_b64": b64(gp_canon),
                "checkpoint_hash": sha_hex(gp_signing),
                "signature": test_key("signer").sign(gp_signing).hex(),
            },
        }
    )

    # TS-11: a run deleted from the database changes the recomputed root.
    without_third = merkle_ref.mth(leaves[:2] + leaves[3:5]).hex()
    cases.append(
        {
            "id": "glb-reject-deleted-run",
            "desc": "run 3 deleted: the recomputed global root no longer matches the anchored "
            "checkpoint, and the tree is one leaf shorter (TS-11)",
            "input": {
                "deleted_run_id": records[2]["run_id"],
                "remaining_positions": [0, 1, 3, 4],
                "anchored_tree_size": 5,
                "anchored_root_hash": merkle_ref.mth(leaves).hex(),
            },
            "expect": {
                "result": "REJECT",
                "reason": "GLOBAL_ROOT_MISMATCH",
                "recomputed_root_hash": without_third,
                "recomputed_tree_size": 4,
            },
        }
    )

    # TS-12: a run root altered in place.
    altered = dict(records[1])
    altered["root_hash"] = "ef" * 32
    altered_leaves = list(leaves)
    altered_leaves[1] = b"ABB1-RUNROOT\x00" + jcs_ref.canonical_bytes(altered)
    cases.append(
        {
            "id": "glb-reject-altered-run-root",
            "desc": "run 2's root_hash edited in the global log (TS-12)",
            "input": {
                "position": 1,
                "altered_record_canonical_b64": b64(jcs_ref.canonical_bytes(altered)),
                "anchored_root_hash": merkle_ref.mth(leaves).hex(),
            },
            "expect": {
                "result": "REJECT",
                "reason": "GLOBAL_ROOT_MISMATCH",
                "recomputed_root_hash": merkle_ref.mth(altered_leaves).hex(),
            },
        }
    )

    # R-GLB-02: a run root the signer never signed must not be appendable.
    injected = run_root_record(9)
    injected["checkpoint_hash"] = "ba" * 32
    cases.append(
        {
            "id": "glb-reject-injected-run-root",
            "desc": "run root whose checkpoint_hash is not in the signer's own state log "
            "(R-GLB-02)",
            "input": {
                "record_canonical_b64": b64(jcs_ref.canonical_bytes(injected)),
                "signer_state_log_checkpoint_hashes": [r["checkpoint_hash"] for r in records],
            },
            "expect": {"result": "REJECT", "reason": "NOT_IN_SIGNER_STATE_LOG"},
        }
    )

    return cases


# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# approvals, mandates, field commitments (Step 9; PROTOCOL.md 5.5 to 5.7)
# --------------------------------------------------------------------------- #

APPROVAL_RUN = "11111111-1111-4111-8111-111111111111"
SUMMARY_TEXT = "CLICK https://bank.example/payee params=3f5a"


def signing_digest_and_signature(tag: bytes, canonical: bytes, role: str) -> tuple[str, str]:
    """Digest of the signing bytes, and the Ed25519 signature over them."""
    signing_bytes = tag + b"\x00" + canonical
    return sha_hex(signing_bytes), test_key(role).sign(signing_bytes).hex()


def approval_statement(**changes: Any) -> dict[str, Any]:
    statement: dict[str, Any] = {
        "approval_id": "approval-act-7",
        "run_id": APPROVAL_RUN,
        "action_id": "act-7",
        "summary_digest": sha_hex(SUMMARY_TEXT.encode()),
        "decision": "GRANTED",
        "expires_at": 1_760_000_900_000,
    }
    statement.update(changes)
    return statement


def approval_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    approver = key_id("approver")

    def accept(case_id: str, desc: str, statement: dict[str, Any]) -> None:
        canonical = jcs_ref.canonical_bytes(statement)
        digest, signature = signing_digest_and_signature(b"ABB1-APPROVAL", canonical, "approver")
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {"statement": statement, "key_id": approver, "signature": signature},
                "expect": {
                    "result": "ACCEPT",
                    "canonical_b64": b64(canonical),
                    "signing_digest": digest,
                },
            }
        )

    accept(
        "approval-accept-granted",
        "a granted approval signed by the approver key",
        approval_statement(),
    )
    accept(
        "approval-accept-denied",
        "a denial is signed the same way",
        approval_statement(decision="DENIED", approval_id="approval-act-8", action_id="act-8"),
    )

    original = approval_statement()
    canonical = jcs_ref.canonical_bytes(original)
    _, good_signature = signing_digest_and_signature(b"ABB1-APPROVAL", canonical, "approver")

    def altered(case_id: str, desc: str, **changes: Any) -> None:
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {
                    "statement": approval_statement(**changes),
                    "key_id": approver,
                    "signature": good_signature,
                },
                "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
            }
        )

    altered("approval-reject-action-changed", "action_id changed after signing", action_id="act-9")
    altered(
        "approval-reject-summary-changed",
        "the approver signed a different summary than the one now claimed",
        summary_digest=sha_hex(b"CLICK https://evil.example/payee params=3f5a"),
    )
    altered("approval-reject-decision-flipped", "DENIED rewritten as GRANTED", decision="DENIED")
    altered(
        "approval-reject-expiry-extended", "expires_at pushed later", expires_at=1_760_009_999_999
    )
    altered(
        "approval-reject-other-run",
        "the statement is replayed into a different run",
        run_id="22222222-2222-4222-8222-222222222222",
    )

    # Signed by a key that is not the approver's.
    _, forged = signing_digest_and_signature(b"ABB1-APPROVAL", canonical, "witness")
    cases.append(
        {
            "id": "approval-reject-forged-signature",
            "desc": "signature made by a different key than the one named",
            "input": {"statement": original, "key_id": approver, "signature": forged},
            "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
        }
    )
    # Domain separation: right key, wrong tag.
    _, other_domain = signing_digest_and_signature(b"ABB1-MANDATE", canonical, "approver")
    cases.append(
        {
            "id": "approval-reject-wrong-domain-tag",
            "desc": "the same bytes signed under the mandate tag must not count as an approval",
            "input": {"statement": original, "key_id": approver, "signature": other_domain},
            "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
        }
    )
    # A key that holds another role.
    _, by_witness = signing_digest_and_signature(b"ABB1-APPROVAL", canonical, "witness")
    cases.append(
        {
            "id": "approval-reject-key-is-not-an-approver",
            "desc": "a valid signature by a witness key is not an approval",
            "input": {"statement": original, "key_id": key_id("witness"), "signature": by_witness},
            "expect": {"result": "REJECT", "reason": "WRONG_KEY_ROLE"},
        }
    )

    # Statement-level validation, from raw text so the exact bytes are explicit.
    base_text = jcs_ref.canonical_bytes(original).decode()
    raw = [
        (
            "approval-reject-extra-field",
            "an undefined field is refused",
            base_text[:-1] + ',"note":"hi"}',
        ),
        (
            "approval-reject-bad-decision",
            "decision must be GRANTED or DENIED",
            base_text.replace("GRANTED", "MAYBE"),
        ),
        (
            "approval-reject-uppercase-digest",
            "hex must be lowercase",
            base_text.replace(original["summary_digest"], original["summary_digest"].upper()),
        ),
        (
            "approval-reject-not-canonical",
            "whitespace makes it non-canonical",
            base_text.replace(":", ": ", 1),
        ),
        (
            "approval-reject-float-expiry",
            "protocol numbers are integers",
            base_text.replace("1760000900000", "1760000900000.5"),
        ),
    ]
    for case_id, desc, text in raw:
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {"statement_text": text, "key_id": approver},
                "expect": {"result": "REJECT", "reason": "VALIDATION_FAILED"},
            }
        )
    return cases


def mandate_document(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "mandate_id": "mandate-1",
        "issuer_key_id": key_id("mandate_issuer"),
        "subject": "replay",
        "allowed_hosts": ["vendor.example", "*.bank.example"],
        "allowed_action_types": ["NAVIGATE", "CLICK", "TYPE"],
        "max_actions": 12,
        "not_before": 1_760_000_000_000,
        "not_after": 1_760_086_400_000,
        "max_spend_minor_units": 50_000,
        "currency": "INR",
    }
    document.update(changes)
    return {k: v for k, v in document.items() if v is not None}


def mandate_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    issuer = key_id("mandate_issuer")

    def accept(case_id: str, desc: str, document: dict[str, Any]) -> None:
        canonical = jcs_ref.canonical_bytes(document)
        digest, signature = signing_digest_and_signature(
            b"ABB1-MANDATE", canonical, "mandate_issuer"
        )
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {"mandate": document, "key_id": issuer, "signature": signature},
                "expect": {
                    "result": "ACCEPT",
                    "canonical_b64": b64(canonical),
                    "mandate_digest": digest,
                },
            }
        )

    accept("mandate-accept-with-spend-bound", "a mandate with a spend bound", mandate_document())
    accept(
        "mandate-accept-without-spend-bound",
        "the two spend fields are omitted together",
        mandate_document(max_spend_minor_units=None, currency=None, mandate_id="mandate-2"),
    )
    accept(
        "mandate-accept-no-actions-allowed",
        "max_actions of zero is a legal, if useless, mandate",
        mandate_document(max_actions=0, mandate_id="mandate-3"),
    )

    original = mandate_document()
    canonical = jcs_ref.canonical_bytes(original)
    _, good = signing_digest_and_signature(b"ABB1-MANDATE", canonical, "mandate_issuer")

    def tampered(case_id: str, desc: str, **changes: Any) -> None:
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {
                    "mandate": mandate_document(**changes),
                    "key_id": issuer,
                    "signature": good,
                },
                "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
            }
        )

    tampered(
        "mandate-reject-max-actions-raised", "max_actions raised after signing", max_actions=500
    )
    tampered(
        "mandate-reject-host-added",
        "a host added after signing",
        allowed_hosts=["vendor.example", "*.bank.example", "evil.example"],
    )
    tampered(
        "mandate-reject-spend-raised",
        "spend bound raised after signing",
        max_spend_minor_units=5_000_000,
    )
    tampered(
        "mandate-reject-window-extended", "not_after pushed later", not_after=1_999_999_999_999
    )

    _, other_domain = signing_digest_and_signature(b"ABB1-APPROVAL", canonical, "mandate_issuer")
    cases.append(
        {
            "id": "mandate-reject-wrong-domain-tag",
            "desc": "the same bytes signed under the approval tag are not a mandate",
            "input": {"mandate": original, "key_id": issuer, "signature": other_domain},
            "expect": {"result": "REJECT", "reason": "BAD_SIGNATURE"},
        }
    )
    _, by_approver = signing_digest_and_signature(b"ABB1-MANDATE", canonical, "approver")
    cases.append(
        {
            "id": "mandate-reject-signed-by-an-approver-key",
            "desc": "only a mandate_issuer key can issue a mandate",
            "input": {"mandate": original, "key_id": key_id("approver"), "signature": by_approver},
            "expect": {"result": "REJECT", "reason": "WRONG_KEY_ROLE"},
        }
    )

    base_text = canonical.decode()
    raw = [
        (
            "mandate-reject-window-reversed",
            "not_after before not_before",
            base_text.replace("1760086400000", "1759999999999"),
        ),
        (
            "mandate-reject-negative-max-actions",
            "max_actions must not be negative",
            base_text.replace('"max_actions":12', '"max_actions":-1'),
        ),
        (
            "mandate-reject-extra-field",
            "an undefined field is refused",
            base_text[:-1] + ',"note":"x"}',
        ),
        (
            "mandate-reject-spend-without-currency",
            "the spend bound and its currency go together",
            base_text.replace(',"currency":"INR"', ""),
        ),
    ]
    for case_id, desc, text in raw:
        cases.append(
            {
                "id": case_id,
                "desc": desc,
                "input": {"mandate_text": text, "key_id": issuer},
                "expect": {"result": "REJECT", "reason": "VALIDATION_FAILED"},
            }
        )

    # Host matching (PROTOCOL.md 5.7: exact host or *.suffix).
    hosts = ["vendor.example", "*.bank.example"]
    for case_id, host, allowed in [
        ("mandate-host-exact", "vendor.example", True),
        ("mandate-host-case-insensitive", "VENDOR.Example", True),
        ("mandate-host-suffix-subdomain", "pay.bank.example", True),
        ("mandate-host-suffix-deep-subdomain", "a.b.bank.example", True),
        ("mandate-host-suffix-bare", "bank.example", True),
        ("mandate-host-lookalike-prefix", "evil-bank.example", False),
        ("mandate-host-suffix-trick", "vendor.example.evil.test", False),
        ("mandate-host-unlisted", "other.example", False),
        ("mandate-host-empty", "", False),
    ]:
        cases.append(
            {
                "id": case_id,
                "desc": f"is {host!r} inside allowed_hosts {hosts}",
                "input": {"allowed_hosts": hosts, "host": host},
                "expect": {"result": "ALLOWED" if allowed else "DENIED"},
            }
        )
    return cases


def commitment(salt_hex: str, value: Any) -> str:
    data = bytes.fromhex(salt_hex) + jcs_ref.canonical_bytes(value)
    return sha_hex(b"ABB1-FIELD\x00" + data)


def commitment_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    salt_a = "000102030405060708090a0b0c0d0e0f"
    salt_b = "ffeeddccbbaa99887766554433221100"
    values: list[tuple[str, str, Any, str]] = [
        ("string", "a card number", "4111111111111111", salt_a),
        (
            "same-value-other-salt",
            "the same value under a different salt must differ",
            "4111111111111111",
            salt_b,
        ),
        ("integer", "an integer value", 1234, salt_a),
        (
            "object-key-order",
            "object keys are sorted by JCS before committing",
            {"b": 2, "a": 1},
            salt_a,
        ),
        ("unicode", "non-ASCII text is committed as UTF-8 canonical JSON", "naïve café", salt_a),
        ("array", "arrays keep their order", ["x", "y"], salt_a),
        ("boolean", "a boolean value", True, salt_a),
        ("empty-string", "an empty string is still a value", "", salt_b),
    ]
    for name, desc, value, salt in values:
        cases.append(
            {
                "id": f"commitment-{name}",
                "desc": desc,
                "input": {"salt_hex": salt, "value_json": json.dumps(value, ensure_ascii=False)},
                "expect": {"result": "ACCEPT", "commitment": commitment(salt, value)},
            }
        )
    # A commitment is not the plain digest of the value.
    plain = sha_hex(jcs_ref.canonical_bytes("hunter2"))
    assert commitment(salt_a, "hunter2") != plain
    cases.append(
        {
            "id": "commitment-not-the-plain-digest",
            "desc": "the commitment differs from SHA-256 of the canonical value alone",
            "input": {"salt_hex": salt_a, "value_json": '"hunter2"'},
            "expect": {
                "result": "ACCEPT",
                "commitment": commitment(salt_a, "hunter2"),
                "differs_from_plain_digest": plain,
            },
        }
    )
    for name, desc, salt in [
        ("salt-too-short", "15 bytes is not a valid salt", "000102030405060708090a0b0c0d0e"),
        ("salt-too-long", "17 bytes is not a valid salt", "000102030405060708090a0b0c0d0e0f10"),
        ("salt-empty", "an empty salt is not a valid salt", ""),
    ]:
        cases.append(
            {
                "id": f"commitment-reject-{name}",
                "desc": desc,
                "input": {"salt_hex": salt, "value_json": '"x"'},
                "expect": {"result": "REJECT", "reason": "BAD_SALT"},
            }
        )
    return cases


def main() -> None:
    write(
        "jcs/canonical.json",
        "RFC 8785 canonical output",
        "Each case gives the exact canonical text and its SHA-256. Key order is "
        "UTF-16 code-unit order (PROTOCOL.md 3.1).",
        jcs_canonical_cases(),
    )
    write(
        "jcs/invalid.json",
        "inputs a conforming parser must reject",
        "PROTOCOL.md 3.2 and 3.3. `reason` is the stable rejection code.",
        jcs_invalid_cases(),
    )
    write(
        "hashing/domain_tags.json",
        "domain-separated digests",
        "PROTOCOL.md section 4. Every tag hashes the same input, so any two tags "
        "sharing a digest would be a domain-separation bug. The artifact digest is "
        "untagged by D-03.",
        hashing_tag_cases(),
    )
    write(
        "hashing/tree_hashes.json",
        "leaf and node hashing",
        "PROTOCOL.md section 8: leaf prefix 0x00, node prefix 0x01, empty tree is "
        "SHA-256 of zero bytes.",
        hashing_tree_cases(),
    )
    write(
        "merkle/roots.json",
        "tree hash for the required sizes",
        "Leaf i is the ASCII bytes `abb1-test-leaf-<i>`, so any implementation can "
        "rebuild the tree without this file.",
        merkle_root_cases(),
    )
    write(
        "merkle/inclusion.json",
        "inclusion proofs",
        "RFC 6962 section 2.1.1 audit paths for the first, middle and last leaf of "
        "every required size.",
        merkle_inclusion_cases(),
    )
    write(
        "merkle/consistency.json",
        "consistency proofs",
        "RFC 6962 section 2.1.2. A verifier prepends the first root itself when "
        "first_size is an exact power of two.",
        merkle_consistency_cases(),
    )
    write(
        "merkle/malformed.json",
        "proofs that must be rejected",
        "PROTOCOL.md section 8: wrong index, wrong path length, non-hex, bad sizes, empty proof.",
        merkle_malformed_cases(),
    )

    keys_path = VECTORS / "keys" / "test_keys.json"
    keys_path.parent.mkdir(parents=True, exist_ok=True)
    keys_path.write_text(
        json.dumps(key_cases(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print("keys/test_keys.json: 4 keys")

    write(
        "checkpoint/checkpoints.json",
        "checkpoint signing and chain rules",
        "PROTOCOL.md section 10. Roots are the trees of merkle/roots.json, so a "
        "checkpoint cannot claim a tree it does not describe.",
        checkpoint_cases(),
    )
    write(
        "global/global_log.json",
        "global log of run roots (D-10)",
        "PROTOCOL.md 8.5. Includes the deleted-run and altered-root cases that "
        "`abb verify-global` must catch (TS-11, TS-12).",
        global_cases(),
    )
    write(
        "approval/approvals.json",
        "signed human approvals (D-16)",
        "PROTOCOL.md 5.6. Signing bytes are `ABB1-APPROVAL || 0x00 || JCS(statement)`. "
        "Tampered cases keep the original signature and change one field.",
        approval_cases(),
    )
    write(
        "mandate/mandates.json",
        "signed mandate and host matching (D-16)",
        "PROTOCOL.md 5.7. `mandate_digest` is SHA-256 of the signing bytes "
        "`ABB1-MANDATE || 0x00 || JCS(mandate)`.",
        mandate_cases(),
    )
    write(
        "commitment/commitments.json",
        "salted field commitments (D-11)",
        "PROTOCOL.md 5.5. commitment = SHA-256(`ABB1-FIELD` || 0x00 || salt || JCS(value)); "
        "the salt is exactly 16 bytes.",
        commitment_cases(),
    )


if __name__ == "__main__":
    main()
