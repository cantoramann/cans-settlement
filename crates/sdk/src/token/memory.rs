//! In-memory token store backed by `RwLock<HashMap>`.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::SdkError;

use super::selection::{SelectionStrategy, select_token_outputs};
use super::store::{AcquiredOutputs, LockId, TokenOutput, TokenStore};

/// Lock expiry duration (matching JS SDK's 30-second default).
const LOCK_EXPIRY: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Lock state
// ---------------------------------------------------------------------------

struct OutputLock {
    output_ids: Vec<String>,
    created_at: Instant,
}

// ---------------------------------------------------------------------------
// InMemoryTokenStore
// ---------------------------------------------------------------------------

/// In-memory token store with local output locking.
///
/// Outputs are keyed by their string ID. Locks expire after 30 seconds
/// to prevent deadlocks from abandoned operations.
pub struct InMemoryTokenStore {
    /// All outputs keyed by output ID.
    outputs: RwLock<HashMap<String, TokenOutput>>,
    /// Active locks: lock ID -> locked output IDs.
    locks: RwLock<HashMap<LockId, OutputLock>>,
    /// Reverse map: output ID -> lock ID (for quick exclusion).
    locked_ids: RwLock<HashSet<String>>,
    /// Auto-incrementing lock counter.
    next_lock: AtomicU64,
}

impl InMemoryTokenStore {
    /// Creates an empty in-memory token store.
    pub fn new() -> Self {
        Self {
            outputs: RwLock::new(HashMap::new()),
            locks: RwLock::new(HashMap::new()),
            locked_ids: RwLock::new(HashSet::new()),
            next_lock: AtomicU64::new(1),
        }
    }

    /// Clean up expired locks.
    fn cleanup_expired(&self) {
        let now = Instant::now();
        let mut locks = self.locks.write().unwrap();
        let mut locked_ids = self.locked_ids.write().unwrap();

        locks.retain(|_, lock| {
            if now.duration_since(lock.created_at) > LOCK_EXPIRY {
                for id in &lock.output_ids {
                    locked_ids.remove(id);
                }
                false
            } else {
                true
            }
        });
    }
}

impl Default for InMemoryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore for InMemoryTokenStore {
    fn set_outputs(&self, outputs: &[TokenOutput]) -> Result<(), SdkError> {
        let mut map = self.outputs.write().unwrap();

        // Collect token IDs being updated.
        let updated_tokens: HashSet<[u8; 32]> = outputs.iter().map(|o| o.token_id).collect();

        // Remove old outputs for the updated token IDs.
        map.retain(|_, o| !updated_tokens.contains(&o.token_id));

        // Insert new outputs.
        for output in outputs {
            map.insert(output.id.clone(), output.clone());
        }

        Ok(())
    }

    fn acquire_outputs(
        &self,
        token_id: &[u8; 32],
        amount: u128,
    ) -> Result<AcquiredOutputs, SdkError> {
        self.cleanup_expired();

        let outputs_map = self.outputs.read().unwrap();
        let locked = self.locked_ids.read().unwrap();

        // Filter to available outputs for this token.
        let available: Vec<TokenOutput> = outputs_map
            .values()
            .filter(|o| o.token_id == *token_id && !locked.contains(&o.id))
            .cloned()
            .collect();

        let (selected, total) =
            select_token_outputs(&available, amount, SelectionStrategy::SmallFirst)
                .ok_or(SdkError::InsufficientTokenBalance)?;

        // Lock the selected outputs.
        let selected_outputs: Vec<TokenOutput> = selected.into_iter().cloned().collect();
        let output_ids: Vec<String> = selected_outputs.iter().map(|o| o.id.clone()).collect();

        drop(locked);
        drop(outputs_map);

        let mut locked = self.locked_ids.write().unwrap();
        let mut locks = self.locks.write().unwrap();

        let lid = LockId(self.next_lock.fetch_add(1, Ordering::Relaxed));
        for id in &output_ids {
            locked.insert(id.clone());
        }
        locks.insert(
            lid,
            OutputLock {
                output_ids,
                created_at: Instant::now(),
            },
        );

        Ok(AcquiredOutputs {
            lock_id: lid,
            outputs: selected_outputs,
            total_amount: total,
        })
    }

    fn release_outputs(&self, lock_id: LockId) -> Result<(), SdkError> {
        let mut locks = self.locks.write().unwrap();
        let mut locked_ids = self.locked_ids.write().unwrap();

        let lock = locks.remove(&lock_id).ok_or(SdkError::LockNotFound)?;
        for id in &lock.output_ids {
            locked_ids.remove(id);
        }

        Ok(())
    }

    fn get_balance(&self, token_id: &[u8; 32]) -> Result<u128, SdkError> {
        self.cleanup_expired();

        let outputs = self.outputs.read().unwrap();
        let locked = self.locked_ids.read().unwrap();

        let total = outputs
            .values()
            .filter(|o| o.token_id == *token_id && !locked.contains(&o.id))
            .map(|o| o.amount)
            .sum();

        Ok(total)
    }

    fn list_token_ids(&self) -> Result<Vec<[u8; 32]>, SdkError> {
        let outputs = self.outputs.read().unwrap();
        let mut ids: HashSet<[u8; 32]> = HashSet::new();
        for o in outputs.values() {
            ids.insert(o.token_id);
        }
        Ok(ids.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN_A: [u8; 32] = [0xAA; 32];
    const TOKEN_B: [u8; 32] = [0xBB; 32];

    fn output(id: &str, token_id: [u8; 32], amount: u128) -> TokenOutput {
        TokenOutput {
            id: id.to_owned(),
            owner_public_key: [0x02; 33],
            token_id,
            amount,
            previous_transaction_hash: [0; 32],
            previous_transaction_vout: 0,
            withdraw_bond_sats: 1000,
            withdraw_relative_block_locktime: 144,
        }
    }

    #[test]
    fn set_and_get_balance() {
        let store = InMemoryTokenStore::new();
        store
            .set_outputs(&[
                output("1", TOKEN_A, 100),
                output("2", TOKEN_A, 200),
                output("3", TOKEN_B, 50),
            ])
            .unwrap();

        assert_eq!(store.get_balance(&TOKEN_A).unwrap(), 300);
        assert_eq!(store.get_balance(&TOKEN_B).unwrap(), 50);
    }

    #[test]
    fn acquire_locks_outputs() {
        let store = InMemoryTokenStore::new();
        store
            .set_outputs(&[output("1", TOKEN_A, 100), output("2", TOKEN_A, 200)])
            .unwrap();

        let acquired = store.acquire_outputs(&TOKEN_A, 100).unwrap();
        assert!(acquired.total_amount >= 100);

        // Balance should decrease.
        let remaining = store.get_balance(&TOKEN_A).unwrap();
        assert!(remaining < 300);
    }

    #[test]
    fn release_restores_balance() {
        let store = InMemoryTokenStore::new();
        store.set_outputs(&[output("1", TOKEN_A, 100)]).unwrap();

        let acquired = store.acquire_outputs(&TOKEN_A, 100).unwrap();
        assert_eq!(store.get_balance(&TOKEN_A).unwrap(), 0);

        store.release_outputs(acquired.lock_id).unwrap();
        assert_eq!(store.get_balance(&TOKEN_A).unwrap(), 100);
    }

    #[test]
    fn insufficient_balance_rejected() {
        let store = InMemoryTokenStore::new();
        store.set_outputs(&[output("1", TOKEN_A, 50)]).unwrap();

        match store.acquire_outputs(&TOKEN_A, 100) {
            Err(SdkError::InsufficientTokenBalance) => {}
            Err(e) => panic!("expected InsufficientTokenBalance, got {e:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn list_token_ids_works() {
        let store = InMemoryTokenStore::new();
        store
            .set_outputs(&[output("1", TOKEN_A, 100), output("2", TOKEN_B, 50)])
            .unwrap();

        let ids = store.list_token_ids().unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&TOKEN_A));
        assert!(ids.contains(&TOKEN_B));
    }

    #[test]
    fn set_outputs_replaces_for_token() {
        let store = InMemoryTokenStore::new();
        store.set_outputs(&[output("1", TOKEN_A, 100)]).unwrap();
        store.set_outputs(&[output("2", TOKEN_A, 200)]).unwrap();

        assert_eq!(store.get_balance(&TOKEN_A).unwrap(), 200);
    }

    #[test]
    fn release_unknown_lock_fails() {
        let store = InMemoryTokenStore::new();
        assert_eq!(
            store.release_outputs(LockId(999)),
            Err(SdkError::LockNotFound)
        );
    }
}
