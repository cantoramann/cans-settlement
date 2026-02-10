//! Greedy leaf selection algorithm.
//!
//! Selects the smallest set of leaves whose total value meets or exceeds
//! the target amount. Leaves are sorted descending by value, and the
//! algorithm picks greedily.

use super::store::TreeNode;

/// Select leaves to cover `target_sats` using a greedy algorithm.
///
/// Sorts available leaves descending by value and accumulates until the
/// target is met. Returns the selected leaves and the total value.
///
/// Returns `None` if the available leaves cannot cover the target.
pub fn select_leaves_greedy(
    available: &[TreeNode],
    target_sats: u64,
) -> Option<(Vec<&TreeNode>, u64)> {
    if target_sats == 0 {
        return Some((Vec::new(), 0));
    }

    // Sort indices by value descending.
    let mut indices: Vec<usize> = (0..available.len()).collect();
    indices.sort_unstable_by(|&a, &b| available[b].value.cmp(&available[a].value));

    let mut selected = Vec::new();
    let mut total = 0u64;

    for &idx in &indices {
        selected.push(&available[idx]);
        total += available[idx].value;
        if total >= target_sats {
            return Some((selected, total));
        }
    }

    // Not enough balance.
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::store::SigningKeyshare;

    fn leaf(id: &str, value: u64) -> TreeNode {
        TreeNode {
            id: id.to_owned(),
            tree_id: "t".to_owned(),
            value,
            node_tx: vec![],
            refund_tx: None,
            verifying_public_key: [0x02; 33],
            owner_identity_public_key: [0x03; 33],
            signing_keyshare: SigningKeyshare {
                operator_public_key: [0x04; 33],
                owner_public_key: [0x05; 33],
            },
            vout: 0,
        }
    }

    #[test]
    fn select_zero_returns_empty() {
        let leaves = vec![leaf("a", 100)];
        let (selected, total) = select_leaves_greedy(&leaves, 0).unwrap();
        assert!(selected.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn select_exact_match() {
        let leaves = vec![leaf("a", 100), leaf("b", 200)];
        let (selected, total) = select_leaves_greedy(&leaves, 200).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 200);
    }

    #[test]
    fn select_multiple_leaves() {
        let leaves = vec![leaf("a", 50), leaf("b", 60), leaf("c", 40)];
        let (selected, total) = select_leaves_greedy(&leaves, 100).unwrap();
        assert!(total >= 100);
        assert!(selected.len() <= 3);
    }

    #[test]
    fn select_insufficient_returns_none() {
        let leaves = vec![leaf("a", 50)];
        assert!(select_leaves_greedy(&leaves, 100).is_none());
    }

    #[test]
    fn select_empty_returns_none() {
        let leaves: Vec<TreeNode> = vec![];
        assert!(select_leaves_greedy(&leaves, 1).is_none());
    }

    #[test]
    fn select_prefers_largest_first() {
        let leaves = vec![leaf("a", 10), leaf("b", 100), leaf("c", 50)];
        let (selected, total) = select_leaves_greedy(&leaves, 100).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 100);
        assert_eq!(selected[0].id, "b");
    }
}
