"""RFC 6962 Merkle tree hash and proofs — test-vector use only.

Written as the recursive definitions in RFC 6962 sections 2.1, 2.1.1 and 2.1.2,
on purpose: the self-check tests verify the output with the iterative frontier
and the audit-path verification algorithms instead, so a mistake here cannot
agree with a mistake there.

Same scope note as `jcs_ref`: vectors only, never imported by a service.
"""

from __future__ import annotations

import hashlib

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """LH(d) = SHA-256(0x00 || d)."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """NH(l, r) = SHA-256(0x01 || l || r)."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def largest_power_of_two_below(n: int) -> int:
    """The k of RFC 6962: largest power of two strictly less than n (n > 1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash over leaf *data* (not leaf hashes)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = largest_power_of_two_below(n)
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def inclusion_path(index: int, leaves: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]) from RFC 6962 section 2.1.1."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("leaf_index out of range")
    if n == 1:
        return []
    k = largest_power_of_two_below(n)
    if index < k:
        return [*inclusion_path(index, leaves[:k]), mth(leaves[k:])]
    return [*inclusion_path(index - k, leaves[k:]), mth(leaves[:k])]


def consistency_path(first_size: int, leaves: list[bytes]) -> list[bytes]:
    """PROOF(m, D[n]) from RFC 6962 section 2.1.2."""
    if first_size == 0 or first_size > len(leaves):
        raise ValueError("bad first_size")
    return _subproof(first_size, leaves, True)


def _subproof(m: int, leaves: list[bytes], is_whole: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        # The verifier already knows this hash when it is the whole first tree.
        return [] if is_whole else [mth(leaves)]
    k = largest_power_of_two_below(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], is_whole), mth(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), mth(leaves[:k])]


def synthetic_leaves(count: int) -> list[bytes]:
    """Fixed, documented leaf data so every implementation can rebuild the tree."""
    return [b"abb1-test-leaf-%d" % i for i in range(count)]
