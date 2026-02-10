//! In-memory tree store backed by `RwLock<HashMap>`.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::SdkError;

use super::store::{LeafReservation, ReservationId, TreeNode, TreeStore};

// ---------------------------------------------------------------------------
// InMemoryTreeStore
// ---------------------------------------------------------------------------

/// In-memory tree store for development and testing.
///
/// Uses `RwLock` for concurrent access. Reservations are tracked by
/// an auto-incrementing counter.
pub struct InMemoryTreeStore {
    /// Available + reserved leaves keyed by node ID.
    leaves: RwLock<HashMap<String, TreeNode>>,
    /// Active reservations: reservation ID -> set of leaf IDs.
    reservations: RwLock<HashMap<ReservationId, Vec<String>>>,
    /// Reserved leaf IDs (quick lookup to exclude from available set).
    reserved_ids: RwLock<HashMap<String, ReservationId>>,
    /// Auto-incrementing reservation counter.
    next_reservation: AtomicU64,
}

impl InMemoryTreeStore {
    /// Creates an empty in-memory tree store.
    pub fn new() -> Self {
        Self {
            leaves: RwLock::new(HashMap::new()),
            reservations: RwLock::new(HashMap::new()),
            reserved_ids: RwLock::new(HashMap::new()),
            next_reservation: AtomicU64::new(1),
        }
    }
}

impl Default for InMemoryTreeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TreeStore for InMemoryTreeStore {
    fn insert_leaves(&self, leaves: &[TreeNode]) -> Result<(), SdkError> {
        let mut map = self.leaves.write().unwrap();
        for leaf in leaves {
            map.insert(leaf.id.clone(), leaf.clone());
        }
        Ok(())
    }

    fn remove_leaves(&self, leaf_ids: &[&str]) -> Result<(), SdkError> {
        let mut map = self.leaves.write().unwrap();
        for id in leaf_ids {
            map.remove(*id);
        }
        Ok(())
    }

    fn get_available_leaves(&self) -> Result<Vec<TreeNode>, SdkError> {
        let leaves = self.leaves.read().unwrap();
        let reserved = self.reserved_ids.read().unwrap();
        Ok(leaves
            .values()
            .filter(|l| !reserved.contains_key(&l.id))
            .cloned()
            .collect())
    }

    fn reserve_leaves(&self, leaf_ids: &[&str]) -> Result<LeafReservation, SdkError> {
        let leaves_map = self.leaves.read().unwrap();
        let mut reserved = self.reserved_ids.write().unwrap();
        let mut reservations = self.reservations.write().unwrap();

        // Verify all leaves exist and are not already reserved.
        let mut nodes = Vec::with_capacity(leaf_ids.len());
        for id in leaf_ids {
            let leaf = leaves_map.get(*id).ok_or(SdkError::InsufficientBalance)?;
            if reserved.contains_key(*id) {
                return Err(SdkError::InsufficientBalance);
            }
            nodes.push(leaf.clone());
        }

        let rid = ReservationId(self.next_reservation.fetch_add(1, Ordering::Relaxed));
        let ids: Vec<String> = leaf_ids.iter().map(|s| (*s).to_owned()).collect();

        for id in &ids {
            reserved.insert(id.clone(), rid);
        }
        reservations.insert(rid, ids);

        Ok(LeafReservation {
            id: rid,
            leaves: nodes,
        })
    }

    fn finalize_reservation(
        &self,
        id: ReservationId,
        new_leaves: Option<&[TreeNode]>,
    ) -> Result<(), SdkError> {
        let mut reservations = self.reservations.write().unwrap();
        let mut reserved = self.reserved_ids.write().unwrap();
        let mut leaves = self.leaves.write().unwrap();

        let leaf_ids = reservations
            .remove(&id)
            .ok_or(SdkError::ReservationNotFound)?;

        // Remove reserved leaves from both maps.
        for lid in &leaf_ids {
            reserved.remove(lid);
            leaves.remove(lid);
        }

        // Insert replacement leaves if provided.
        if let Some(new) = new_leaves {
            for leaf in new {
                leaves.insert(leaf.id.clone(), leaf.clone());
            }
        }

        Ok(())
    }

    fn cancel_reservation(&self, id: ReservationId) -> Result<(), SdkError> {
        let mut reservations = self.reservations.write().unwrap();
        let mut reserved = self.reserved_ids.write().unwrap();

        let leaf_ids = reservations
            .remove(&id)
            .ok_or(SdkError::ReservationNotFound)?;
        for lid in &leaf_ids {
            reserved.remove(lid);
        }

        Ok(())
    }

    fn available_balance(&self) -> Result<u64, SdkError> {
        let leaves = self.leaves.read().unwrap();
        let reserved = self.reserved_ids.read().unwrap();
        let total = leaves
            .values()
            .filter(|l| !reserved.contains_key(&l.id))
            .map(|l| l.value)
            .sum();
        Ok(total)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::store::SigningKeyshare;

    fn make_leaf(id: &str, value: u64) -> TreeNode {
        TreeNode {
            id: id.to_owned(),
            tree_id: "tree-1".to_owned(),
            value,
            node_tx: vec![0x01],
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
    fn insert_and_get_available() {
        let store = InMemoryTreeStore::new();
        store
            .insert_leaves(&[make_leaf("a", 100), make_leaf("b", 200)])
            .unwrap();

        let leaves = store.get_available_leaves().unwrap();
        assert_eq!(leaves.len(), 2);
        assert_eq!(store.available_balance().unwrap(), 300);
    }

    #[test]
    fn reserve_excludes_from_available() {
        let store = InMemoryTreeStore::new();
        store
            .insert_leaves(&[make_leaf("a", 100), make_leaf("b", 200)])
            .unwrap();

        let reservation = store.reserve_leaves(&["a"]).unwrap();
        assert_eq!(reservation.leaves.len(), 1);
        assert_eq!(reservation.leaves[0].value, 100);

        let available = store.get_available_leaves().unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].id, "b");
        assert_eq!(store.available_balance().unwrap(), 200);
    }

    #[test]
    fn finalize_removes_reserved_leaves() {
        let store = InMemoryTreeStore::new();
        store
            .insert_leaves(&[make_leaf("a", 100), make_leaf("b", 200)])
            .unwrap();

        let reservation = store.reserve_leaves(&["a"]).unwrap();
        store.finalize_reservation(reservation.id, None).unwrap();

        let available = store.get_available_leaves().unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].id, "b");
    }

    #[test]
    fn finalize_with_replacement_leaves() {
        let store = InMemoryTreeStore::new();
        store.insert_leaves(&[make_leaf("a", 100)]).unwrap();

        let reservation = store.reserve_leaves(&["a"]).unwrap();
        store
            .finalize_reservation(reservation.id, Some(&[make_leaf("c", 50)]))
            .unwrap();

        let available = store.get_available_leaves().unwrap();
        assert_eq!(available.len(), 1);
        assert_eq!(available[0].id, "c");
        assert_eq!(available[0].value, 50);
    }

    #[test]
    fn cancel_returns_leaves_to_available() {
        let store = InMemoryTreeStore::new();
        store.insert_leaves(&[make_leaf("a", 100)]).unwrap();

        let reservation = store.reserve_leaves(&["a"]).unwrap();
        assert_eq!(store.available_balance().unwrap(), 0);

        store.cancel_reservation(reservation.id).unwrap();
        assert_eq!(store.available_balance().unwrap(), 100);
    }

    #[test]
    fn double_reserve_fails() {
        let store = InMemoryTreeStore::new();
        store.insert_leaves(&[make_leaf("a", 100)]).unwrap();

        let _r = store.reserve_leaves(&["a"]).unwrap();
        assert!(store.reserve_leaves(&["a"]).is_err());
    }

    #[test]
    fn finalize_unknown_reservation_fails() {
        let store = InMemoryTreeStore::new();
        assert!(
            store
                .finalize_reservation(ReservationId(999), None)
                .is_err()
        );
    }

    #[test]
    fn remove_leaves_works() {
        let store = InMemoryTreeStore::new();
        store
            .insert_leaves(&[make_leaf("a", 100), make_leaf("b", 200)])
            .unwrap();
        store.remove_leaves(&["a"]).unwrap();
        assert_eq!(store.available_balance().unwrap(), 200);
    }
}
