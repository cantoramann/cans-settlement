//! Token output selection strategies.

use super::store::TokenOutput;

/// Strategy for selecting token outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionStrategy {
    /// Pick smallest outputs first (consolidates dust).
    SmallFirst,
    /// Pick largest outputs first (minimizes input count).
    LargeFirst,
}

/// Select token outputs to cover `target_amount` using the given strategy.
///
/// Returns the selected outputs and total amount, or `None` if insufficient.
///
/// Max 500 outputs per selection (matching JS SDK limit).
pub fn select_token_outputs(
    available: &[TokenOutput],
    target_amount: u128,
    strategy: SelectionStrategy,
) -> Option<(Vec<&TokenOutput>, u128)> {
    if target_amount == 0 {
        return Some((Vec::new(), 0));
    }

    let mut indices: Vec<usize> = (0..available.len()).collect();
    match strategy {
        SelectionStrategy::SmallFirst => {
            indices.sort_unstable_by(|&a, &b| available[a].amount.cmp(&available[b].amount));
        }
        SelectionStrategy::LargeFirst => {
            indices.sort_unstable_by(|&a, &b| available[b].amount.cmp(&available[a].amount));
        }
    }

    let mut selected = Vec::new();
    let mut total = 0u128;

    for &idx in &indices {
        if selected.len() >= 500 {
            break;
        }
        selected.push(&available[idx]);
        total += available[idx].amount;
        if total >= target_amount {
            return Some((selected, total));
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn output(id: &str, amount: u128) -> TokenOutput {
        TokenOutput {
            id: id.to_owned(),
            owner_public_key: [0x02; 33],
            token_id: [0xAA; 32],
            amount,
            previous_transaction_hash: [0; 32],
            previous_transaction_vout: 0,
            withdraw_bond_sats: 1000,
            withdraw_relative_block_locktime: 144,
        }
    }

    #[test]
    fn zero_target_returns_empty() {
        let outputs = vec![output("a", 100)];
        let (sel, total) =
            select_token_outputs(&outputs, 0, SelectionStrategy::SmallFirst).unwrap();
        assert!(sel.is_empty());
        assert_eq!(total, 0);
    }

    #[test]
    fn small_first_picks_smallest() {
        let outputs = vec![output("a", 10), output("b", 5), output("c", 20)];
        let (sel, total) =
            select_token_outputs(&outputs, 15, SelectionStrategy::SmallFirst).unwrap();
        // 5 + 10 = 15
        assert_eq!(total, 15);
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].id, "b"); // smallest first
    }

    #[test]
    fn large_first_picks_largest() {
        let outputs = vec![output("a", 10), output("b", 5), output("c", 20)];
        let (sel, total) =
            select_token_outputs(&outputs, 15, SelectionStrategy::LargeFirst).unwrap();
        assert_eq!(total, 20);
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].id, "c");
    }

    #[test]
    fn insufficient_returns_none() {
        let outputs = vec![output("a", 10)];
        assert!(select_token_outputs(&outputs, 100, SelectionStrategy::SmallFirst).is_none());
    }
}
