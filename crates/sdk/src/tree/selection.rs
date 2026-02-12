//! Leaf selection strategies.
//!
//! [`LeafSelector`] is the trait that all selection algorithms implement.
//! The SDK stores the active strategy as `Arc<dyn LeafSelector>` and
//! delegates all leaf picking to it. Strategies can be swapped at runtime
//! via [`crate::Sdk::set_leaf_selector`].
//!
//! # Built-in strategies
//!
//! - [`GreedySelector`]: Largest-first greedy pick (default).

use super::store::TreeNode;

// ---------------------------------------------------------------------------
// LeafSelector trait
// ---------------------------------------------------------------------------

/// Strategy for selecting leaves to cover a target amount.
///
/// Implementations receive the full set of available (non-reserved) leaves
/// and the target satoshi amount. They return the selected subset and the
/// total value, or `None` if the target cannot be met.
///
/// Stateful strategies (e.g., FIFO with retry tracking) can use interior
/// mutability (`RwLock`, `AtomicU64`, etc.) since the method takes `&self`.
pub trait LeafSelector: Send + Sync {
    /// Select leaves whose total value meets or exceeds `target_sats`.
    ///
    /// Returns `None` if the available leaves cannot cover the target.
    fn select<'a>(
        &self,
        available: &'a [TreeNode],
        target_sats: u64,
    ) -> Option<(Vec<&'a TreeNode>, u64)>;
}

// ---------------------------------------------------------------------------
// GreedySelector
// ---------------------------------------------------------------------------

/// Largest-first greedy selection. Stateless, zero-sized.
///
/// Sorts leaves descending by value and accumulates until the target is
/// met. Minimizes the number of leaves used but may overshoot the target.
pub struct GreedySelector;

impl LeafSelector for GreedySelector {
    fn select<'a>(
        &self,
        available: &'a [TreeNode],
        target_sats: u64,
    ) -> Option<(Vec<&'a TreeNode>, u64)> {
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
            direct_tx: None,
            direct_refund_tx: None,
            direct_from_cpfp_refund_tx: None,
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
        let selector = GreedySelector;
        let leaves = vec![leaf("a", 100)];
        let (selected, total) = selector.select(&leaves, 0).unwrap();
        assert!(selected.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn select_exact_match() {
        let selector = GreedySelector;
        let leaves = vec![leaf("a", 100), leaf("b", 200)];
        let (selected, total) = selector.select(&leaves, 200).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 200);
    }

    #[test]
    fn select_multiple_leaves() {
        let selector = GreedySelector;
        let leaves = vec![leaf("a", 50), leaf("b", 60), leaf("c", 40)];
        let (selected, total) = selector.select(&leaves, 100).unwrap();
        assert!(total >= 100);
        assert!(selected.len() <= 3);
    }

    #[test]
    fn select_insufficient_returns_none() {
        let selector = GreedySelector;
        let leaves = vec![leaf("a", 50)];
        assert!(selector.select(&leaves, 100).is_none());
    }

    #[test]
    fn select_empty_returns_none() {
        let selector = GreedySelector;
        let leaves: Vec<TreeNode> = vec![];
        assert!(selector.select(&leaves, 1).is_none());
    }

    #[test]
    fn select_prefers_largest_first() {
        let selector = GreedySelector;
        let leaves = vec![leaf("a", 10), leaf("b", 100), leaf("c", 50)];
        let (selected, total) = selector.select(&leaves, 100).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(total, 100);
        assert_eq!(selected[0].id, "b");
    }
}
