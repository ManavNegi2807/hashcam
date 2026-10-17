//! Property tests: the tree rules must hold for any size and index, not only
//! for the sizes the vectors happen to list (TESTING.md section 2, R-TST-01).

use abb_merkle::{
    consistency_path, inclusion_path, leaf_hash, mth, synthetic_leaves, verify_consistency,
    verify_inclusion, Frontier,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn frontier_matches_the_recursive_tree_hash(n in 0usize..200) {
        let leaves = synthetic_leaves(n);
        prop_assert_eq!(Frontier::from_leaf_data(&leaves).root(), mth(&leaves));
    }

    #[test]
    fn every_inclusion_proof_verifies(n in 1usize..200, raw_index in 0usize..200) {
        let index = raw_index % n;
        let leaves = synthetic_leaves(n);
        let path = inclusion_path(index, &leaves).unwrap();
        let derived = verify_inclusion(
            &leaf_hash(&leaves[index]), index as u64, n as u64, &path,
        ).unwrap();
        prop_assert_eq!(derived, mth(&leaves));
    }

    #[test]
    fn audit_path_length_is_ceil_log2(n in 1usize..200, raw_index in 0usize..200) {
        let index = raw_index % n;
        let leaves = synthetic_leaves(n);
        let path = inclusion_path(index, &leaves).unwrap();
        let expected = (usize::BITS - (n - 1).leading_zeros()) as usize;
        prop_assert!(path.len() <= expected, "path {} > ceil(log2({}))={}", path.len(), n, expected);
    }

    #[test]
    fn every_consistency_proof_verifies(second in 1usize..120, raw_first in 1usize..120) {
        let first = (raw_first % second) + 1;
        let leaves = synthetic_leaves(second);
        let first_root = mth(&synthetic_leaves(first));
        let path = consistency_path(first, &leaves).unwrap();
        let derived = verify_consistency(
            first as u64, second as u64, &first_root, &path,
        ).unwrap();
        prop_assert_eq!(derived, mth(&leaves));
    }

    #[test]
    fn a_changed_leaf_changes_the_root(n in 1usize..100, raw_index in 0usize..100) {
        let index = raw_index % n;
        let mut leaves = synthetic_leaves(n);
        let before = mth(&leaves);
        leaves[index].push(b'!');
        prop_assert_ne!(mth(&leaves), before);
    }

    #[test]
    fn reordering_two_leaves_changes_the_root(n in 2usize..100) {
        let mut leaves = synthetic_leaves(n);
        let before = mth(&leaves);
        leaves.swap(0, n - 1);
        prop_assert_ne!(mth(&leaves), before);
    }

    #[test]
    fn verifiers_never_panic_on_arbitrary_paths(
        n in 1usize..64, raw_index in 0usize..64, path in prop::collection::vec(any::<[u8; 32]>(), 0..12),
    ) {
        let index = raw_index % n;
        let leaves = synthetic_leaves(n);
        // Any result is fine; the point is that it returns rather than panics.
        let _ = verify_inclusion(&leaf_hash(&leaves[index]), index as u64, n as u64, &path);
        let _ = verify_consistency(index as u64 + 1, n as u64, &mth(&leaves), &path);
    }
}
