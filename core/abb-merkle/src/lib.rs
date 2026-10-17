//! RFC 6962 Merkle tree hash, audit paths and consistency proofs (D-01).
//!
//! The leaf *data* is defined by `PROTOCOL.md` section 5 (a domain-tagged
//! event), not by Certificate Transparency, so this is "the RFC 6962 tree hash
//! over protocol-defined leaves" and not a claim of CT compliance.
//!
//! Three things live here and are deliberately separate:
//!
//! * [`mth`] — the recursive definition, used when a whole tree is available;
//! * [`Frontier`] — the incremental O(log n) state the signer keeps, so it can
//!   extend a tree without re-reading every event (`PROTOCOL.md` 11.1);
//! * the proof builders and the proof *verifiers*, which never call each other.
//!
//! No verifier in this crate panics on malformed input: every rejection is a
//! [`ProofError`].

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 digest.
pub type Hash = [u8; 32];

/// Leaf prefix from RFC 6962 section 2.1.
pub const LEAF_PREFIX: u8 = 0x00;
/// Interior node prefix from RFC 6962 section 2.1.
pub const NODE_PREFIX: u8 = 0x01;

/// Why a proof was rejected. The codes match `vectors/merkle/malformed.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// `leaf_index >= tree_size`.
    LeafIndexOutOfRange,
    /// The audit path has fewer elements than the tree size needs.
    PathTooShort,
    /// The audit path has more elements than the tree size needs.
    PathTooLong,
    /// A path element was not 32 lowercase hex bytes.
    NotHex,
    /// `first_size` was 0 in a consistency proof.
    FirstSizeZero,
    /// `first_size > second_size`.
    SizeRegression,
    /// A consistency proof between different sizes was empty.
    EmptyProof,
    /// The proof did not reproduce the first root it claims to cover.
    FirstRootMismatch,
}

impl ProofError {
    /// The wire form of the code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeafIndexOutOfRange => "LEAF_INDEX_OUT_OF_RANGE",
            Self::PathTooShort => "PATH_TOO_SHORT",
            Self::PathTooLong => "PATH_TOO_LONG",
            Self::NotHex => "NOT_HEX",
            Self::FirstSizeZero => "FIRST_SIZE_ZERO",
            Self::SizeRegression => "SIZE_REGRESSION",
            Self::EmptyProof => "EMPTY_PROOF",
            Self::FirstRootMismatch => "FIRST_ROOT_MISMATCH",
        }
    }
}

impl std::fmt::Display for ProofError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for ProofError {}

/// `LH(d) = SHA-256(0x00 || d)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(data);
    h.finalize().into()
}

/// `NH(l, r) = SHA-256(0x01 || l || r)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The root of the empty tree: `SHA-256("")`.
#[must_use]
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The `k` of RFC 6962: the largest power of two strictly below `n` (`n > 1`).
#[must_use]
pub fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash over leaf data, by the recursive RFC 6962 definition.
#[must_use]
pub fn mth(leaves: &[Vec<u8>]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaf_hash(leaves.first().map_or(&[][..], |l| l.as_slice())),
        n => {
            let k = largest_power_of_two_below(n);
            let (left, right) = leaves.split_at(k);
            node_hash(&mth(left), &mth(right))
        }
    }
}

/// Incremental tree state: the O(log n) hashes needed to extend a tree.
///
/// `levels[i]`, when present, is a complete subtree of exactly `2^i` leaves.
/// This is the "Merkle frontier" the signer stores per stream so that it can
/// recompute the root itself from new events (D-12) without the whole history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frontier {
    levels: Vec<Option<Hash>>,
    size: u64,
}

impl Frontier {
    /// An empty frontier.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of leaves folded in so far, which is the tree size.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Append one leaf's *data*.
    pub fn push_leaf_data(&mut self, data: &[u8]) {
        self.push_leaf_hash(leaf_hash(data));
    }

    /// Append one already-hashed leaf.
    pub fn push_leaf_hash(&mut self, hash: Hash) {
        let mut carry = hash;
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                self.levels.push(Some(carry));
                break;
            }
            match self.levels.get_mut(level) {
                Some(slot @ Some(_)) => {
                    // Combine with the held subtree, which is the left sibling.
                    let held = slot.take().unwrap_or(carry);
                    carry = node_hash(&held, &carry);
                    level += 1;
                }
                Some(slot) => {
                    *slot = Some(carry);
                    break;
                }
                None => break,
            }
        }
        self.size += 1;
    }

    /// The current root. Folds the held subtrees right to left.
    #[must_use]
    pub fn root(&self) -> Hash {
        let mut acc: Option<Hash> = None;
        for held in self.levels.iter().flatten() {
            acc = Some(match acc {
                None => *held,
                Some(right) => node_hash(held, &right),
            });
        }
        acc.unwrap_or_else(empty_root)
    }

    /// The held subtrees, smallest level first. `levels()[i]`, when present,
    /// covers exactly `2^i` leaves.
    ///
    /// Exposed so the signer can persist its frontier and reload it after a
    /// restart (`PROTOCOL.md` 11.1, 11.3) without replaying every event.
    #[must_use]
    pub fn levels(&self) -> &[Option<Hash>] {
        &self.levels
    }

    /// Rebuild a frontier from a persisted size and level list.
    ///
    /// Returns `None` when the two disagree: the number of leaves implied by
    /// the set levels must equal `size`, or the state is not a tree this code
    /// could have produced.
    #[must_use]
    pub fn from_parts(size: u64, levels: Vec<Option<Hash>>) -> Option<Self> {
        let implied: u64 = levels
            .iter()
            .enumerate()
            .filter_map(|(i, held)| held.map(|_| 1u64 << i))
            .sum();
        if implied != size {
            return None;
        }
        Some(Self { levels, size })
    }

    /// Build a frontier by folding every leaf in order.
    #[must_use]
    pub fn from_leaf_data(leaves: &[Vec<u8>]) -> Self {
        let mut f = Self::new();
        for leaf in leaves {
            f.push_leaf_data(leaf);
        }
        f
    }
}

// --------------------------------------------------------------------------- //
// building proofs
// --------------------------------------------------------------------------- //

/// `PATH(m, D[n])` from RFC 6962 section 2.1.1.
pub fn inclusion_path(index: usize, leaves: &[Vec<u8>]) -> Result<Vec<Hash>, ProofError> {
    let n = leaves.len();
    if index >= n {
        return Err(ProofError::LeafIndexOutOfRange);
    }
    if n == 1 {
        return Ok(Vec::new());
    }
    let k = largest_power_of_two_below(n);
    let (left, right) = leaves.split_at(k);
    if index < k {
        let mut path = inclusion_path(index, left)?;
        path.push(mth(right));
        Ok(path)
    } else {
        let mut path = inclusion_path(index - k, right)?;
        path.push(mth(left));
        Ok(path)
    }
}

/// `PROOF(m, D[n])` from RFC 6962 section 2.1.2.
pub fn consistency_path(first_size: usize, leaves: &[Vec<u8>]) -> Result<Vec<Hash>, ProofError> {
    if first_size == 0 {
        return Err(ProofError::FirstSizeZero);
    }
    if first_size > leaves.len() {
        return Err(ProofError::SizeRegression);
    }
    Ok(subproof(first_size, leaves, true))
}

fn subproof(m: usize, leaves: &[Vec<u8>], is_whole: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        // When the first tree is the whole subtree the verifier already holds
        // its root, so it is omitted.
        return if is_whole {
            Vec::new()
        } else {
            vec![mth(leaves)]
        };
    }
    let k = largest_power_of_two_below(n);
    let (left, right) = leaves.split_at(k);
    if m <= k {
        let mut path = subproof(m, left, is_whole);
        path.push(mth(right));
        path
    } else {
        let mut path = subproof(m - k, right, false);
        path.push(mth(left));
        path
    }
}

// --------------------------------------------------------------------------- //
// verifying proofs
// --------------------------------------------------------------------------- //

/// Verify an audit path and return the root it derives.
///
/// RFC 9162 section 2.1.3.2. Independent of [`inclusion_path`]: it walks the
/// path upwards and never builds one.
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    tree_size: u64,
    path: &[Hash],
) -> Result<Hash, ProofError> {
    if tree_size == 0 || index >= tree_size {
        return Err(ProofError::LeafIndexOutOfRange);
    }
    let mut node = *leaf;
    let mut fin = index;
    let mut sin = tree_size - 1;
    for sibling in path {
        if sin == 0 {
            return Err(ProofError::PathTooLong);
        }
        if fin % 2 == 1 || fin == sin {
            node = node_hash(sibling, &node);
            while fin.is_multiple_of(2) && fin != 0 {
                fin /= 2;
                sin /= 2;
            }
        } else {
            node = node_hash(&node, sibling);
        }
        fin /= 2;
        sin /= 2;
    }
    if sin != 0 {
        return Err(ProofError::PathTooShort);
    }
    Ok(node)
}

/// Verify a consistency proof and return the second root it derives.
///
/// RFC 9162 section 2.1.4.2. Also checks that the proof reproduces
/// `first_root`, so a proof cannot silently cover a different first tree.
pub fn verify_consistency(
    first_size: u64,
    second_size: u64,
    first_root: &Hash,
    path: &[Hash],
) -> Result<Hash, ProofError> {
    if first_size == 0 {
        return Err(ProofError::FirstSizeZero);
    }
    if first_size > second_size {
        return Err(ProofError::SizeRegression);
    }
    if first_size == second_size {
        return if path.is_empty() {
            Ok(*first_root)
        } else {
            Err(ProofError::PathTooLong)
        };
    }
    if path.is_empty() {
        return Err(ProofError::EmptyProof);
    }

    // A first_size that is an exact power of two means the omitted leading
    // node is the first root itself.
    let mut nodes: Vec<Hash> = Vec::with_capacity(path.len() + 1);
    if first_size & (first_size - 1) == 0 {
        nodes.push(*first_root);
    }
    nodes.extend_from_slice(path);

    let mut fin = first_size - 1;
    let mut sin = second_size - 1;
    while fin % 2 == 1 {
        fin /= 2;
        sin /= 2;
    }

    let mut iter = nodes.iter();
    let start = iter.next().ok_or(ProofError::EmptyProof)?;
    let mut first_derived = *start;
    let mut second_derived = *start;
    for sibling in iter {
        if sin == 0 {
            return Err(ProofError::PathTooLong);
        }
        if fin % 2 == 1 || fin == sin {
            first_derived = node_hash(sibling, &first_derived);
            second_derived = node_hash(sibling, &second_derived);
            while fin.is_multiple_of(2) && fin != 0 {
                fin /= 2;
                sin /= 2;
            }
        } else {
            second_derived = node_hash(&second_derived, sibling);
        }
        fin /= 2;
        sin /= 2;
    }
    if sin != 0 {
        return Err(ProofError::PathTooShort);
    }
    if first_derived != *first_root {
        return Err(ProofError::FirstRootMismatch);
    }
    Ok(second_derived)
}

/// The leaf data the conformance vectors use: `abb1-test-leaf-<i>`.
#[must_use]
pub fn synthetic_leaves(count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| format!("abb1-test-leaf-{i}").into_bytes())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_is_the_digest_of_zero_bytes() {
        assert_eq!(mth(&[]), empty_root());
        assert_eq!(Frontier::new().root(), empty_root());
    }

    #[test]
    fn single_leaf_tree_is_the_leaf_hash() {
        let leaves = synthetic_leaves(1);
        assert_eq!(mth(&leaves), leaf_hash(b"abb1-test-leaf-0"));
    }

    #[test]
    fn frontier_agrees_with_the_recursive_definition() {
        for n in 0..=64 {
            let leaves = synthetic_leaves(n);
            assert_eq!(
                Frontier::from_leaf_data(&leaves).root(),
                mth(&leaves),
                "size {n}"
            );
        }
    }

    #[test]
    fn a_frontier_round_trips_through_its_parts() {
        for n in 0..=40u64 {
            let leaves = synthetic_leaves(n as usize);
            let original = Frontier::from_leaf_data(&leaves);
            let restored = Frontier::from_parts(original.size(), original.levels().to_vec())
                .expect("parts agree");
            assert_eq!(restored, original, "size {n}");
            assert_eq!(restored.root(), mth(&leaves));
        }
    }

    #[test]
    fn a_frontier_whose_parts_disagree_is_refused() {
        let leaves = synthetic_leaves(5);
        let frontier = Frontier::from_leaf_data(&leaves);
        assert!(Frontier::from_parts(4, frontier.levels().to_vec()).is_none());
        assert!(Frontier::from_parts(5, vec![None, None, None]).is_none());
    }

    #[test]
    fn frontier_tracks_its_size() {
        let mut f = Frontier::new();
        for (n, leaf) in synthetic_leaves(10).iter().enumerate() {
            assert_eq!(f.size(), n as u64);
            f.push_leaf_data(leaf);
        }
        assert_eq!(f.size(), 10);
    }

    #[test]
    fn node_hash_is_order_sensitive() {
        let a = leaf_hash(b"a");
        let b = leaf_hash(b"b");
        assert_ne!(node_hash(&a, &b), node_hash(&b, &a));
    }

    #[test]
    fn leaf_and_node_prefixes_prevent_second_preimage() {
        // A two-leaf root must not equal a leaf whose data is the concatenation.
        let leaves = synthetic_leaves(2);
        let root = mth(&leaves);
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&leaf_hash(&leaves[0]));
        concatenated.extend_from_slice(&leaf_hash(&leaves[1]));
        assert_ne!(root, leaf_hash(&concatenated));
    }

    #[test]
    fn inclusion_proofs_verify_for_every_leaf_of_every_size() {
        for n in 1..=33_usize {
            let leaves = synthetic_leaves(n);
            let root = mth(&leaves);
            for index in 0..n {
                let path = inclusion_path(index, &leaves).unwrap();
                let derived =
                    verify_inclusion(&leaf_hash(&leaves[index]), index as u64, n as u64, &path)
                        .unwrap_or_else(|e| panic!("size {n} index {index}: {e}"));
                assert_eq!(derived, root, "size {n} index {index}");
            }
        }
    }

    #[test]
    fn consistency_proofs_verify_for_every_size_pair() {
        for second in 1..=33_usize {
            let leaves = synthetic_leaves(second);
            let second_root = mth(&leaves);
            for first in 1..=second {
                let first_root = mth(&synthetic_leaves(first));
                let path = consistency_path(first, &leaves).unwrap();
                let derived = verify_consistency(first as u64, second as u64, &first_root, &path)
                    .unwrap_or_else(|e| panic!("{first} -> {second}: {e}"));
                assert_eq!(derived, second_root, "{first} -> {second}");
            }
        }
    }

    #[test]
    fn a_tampered_leaf_breaks_its_inclusion_proof() {
        let leaves = synthetic_leaves(9);
        let root = mth(&leaves);
        let path = inclusion_path(4, &leaves).unwrap();
        let wrong = leaf_hash(b"abb1-test-leaf-4-edited");
        let derived = verify_inclusion(&wrong, 4, 9, &path).unwrap();
        assert_ne!(derived, root);
    }

    #[test]
    fn malformed_inclusion_proofs_are_rejected_with_the_right_code() {
        let leaves = synthetic_leaves(7);
        let good = inclusion_path(3, &leaves).unwrap();
        let leaf = leaf_hash(&leaves[3]);
        assert_eq!(
            verify_inclusion(&leaf, 7, 7, &good).unwrap_err(),
            ProofError::LeafIndexOutOfRange
        );
        assert_eq!(
            verify_inclusion(&leaf, 3, 7, &good[..good.len() - 1]).unwrap_err(),
            ProofError::PathTooShort
        );
        let mut too_long = good.clone();
        too_long.push([0u8; 32]);
        assert_eq!(
            verify_inclusion(&leaf, 3, 7, &too_long).unwrap_err(),
            ProofError::PathTooLong
        );
        assert_eq!(
            verify_inclusion(&leaf, 0, 0, &[]).unwrap_err(),
            ProofError::LeafIndexOutOfRange
        );
    }

    #[test]
    fn malformed_consistency_proofs_are_rejected_with_the_right_code() {
        let leaves = synthetic_leaves(7);
        let first_root = mth(&synthetic_leaves(4));
        let good = consistency_path(4, &leaves).unwrap();
        assert_eq!(
            verify_consistency(0, 7, &first_root, &good).unwrap_err(),
            ProofError::FirstSizeZero
        );
        assert_eq!(
            verify_consistency(9, 7, &first_root, &good).unwrap_err(),
            ProofError::SizeRegression
        );
        assert_eq!(
            verify_consistency(4, 7, &first_root, &[]).unwrap_err(),
            ProofError::EmptyProof
        );
        // Right shape, wrong first tree, when the proof does rebuild the first
        // root (first_size is not a power of two).
        let path3 = consistency_path(3, &leaves).unwrap();
        let wrong_first = mth(&synthetic_leaves(2));
        assert_eq!(
            verify_consistency(3, 7, &wrong_first, &path3).unwrap_err(),
            ProofError::FirstRootMismatch
        );
    }

    #[test]
    fn a_power_of_two_first_size_cannot_self_check_its_first_root() {
        // RFC 6962 omits the first root from the proof when the first tree is a
        // whole subtree, so the verifier is handed it instead of deriving it.
        // A caller that supplies a wrong first root therefore gets a wrong
        // second root, not FirstRootMismatch: the checkpoint chain is what
        // catches it, by comparing the second root with a signed one.
        let leaves = synthetic_leaves(7);
        let path = consistency_path(4, &leaves).unwrap();
        let wrong_first = mth(&synthetic_leaves(3));
        let derived = verify_consistency(4, 7, &wrong_first, &path).unwrap();
        assert_ne!(
            derived,
            mth(&leaves),
            "a wrong first root must not derive the real second root"
        );
    }

    #[test]
    fn equal_sizes_need_an_empty_proof() {
        let root = mth(&synthetic_leaves(5));
        assert_eq!(verify_consistency(5, 5, &root, &[]).unwrap(), root);
        assert_eq!(
            verify_consistency(5, 5, &root, &[[0u8; 32]]).unwrap_err(),
            ProofError::PathTooLong
        );
    }

    #[test]
    fn builders_reject_bad_arguments_instead_of_panicking() {
        assert_eq!(
            inclusion_path(0, &[]).unwrap_err(),
            ProofError::LeafIndexOutOfRange
        );
        assert_eq!(
            inclusion_path(5, &synthetic_leaves(5)).unwrap_err(),
            ProofError::LeafIndexOutOfRange
        );
        assert_eq!(
            consistency_path(0, &synthetic_leaves(5)).unwrap_err(),
            ProofError::FirstSizeZero
        );
        assert_eq!(
            consistency_path(6, &synthetic_leaves(5)).unwrap_err(),
            ProofError::SizeRegression
        );
    }
}
