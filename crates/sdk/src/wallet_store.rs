//! Wallet key storage: resolves compressed public keys to wallet entries.
//!
//! The SDK uses [`WalletStore`] to look up wallet credentials (secret keys)
//! from a compressed 33-byte identity public key provided in each request.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::SdkError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Compressed secp256k1 identity public key (33 bytes).
pub type IdentityPubKey = [u8; 33];

/// Wallet credentials resolved from a public key.
///
/// Contains the raw key material needed for signing operations.
/// The `WalletSigner` is constructed from these fields on each operation.
#[derive(Clone)]
pub struct WalletEntry {
    /// The wallet's BIP32 seed (typically 64 bytes from BIP39 mnemonic).
    pub seed: Vec<u8>,

    /// BIP32 account index (hardened).
    pub account: u32,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Resolves identity public keys to wallet credentials.
///
/// Implementations must be `Send + Sync` for concurrent SDK operations.
pub trait WalletStore: Send + Sync {
    /// Look up the wallet entry for the given identity public key.
    ///
    /// Returns `None` if the key is not registered.
    fn resolve(&self, pubkey: &IdentityPubKey) -> Option<WalletEntry>;

    /// Register a wallet entry for the given identity public key.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::DuplicateEntry`] if the key is already registered.
    fn insert(&self, pubkey: IdentityPubKey, entry: WalletEntry) -> Result<(), SdkError>;

    /// Remove a wallet entry. Returns `true` if removed, `false` if not found.
    fn remove(&self, pubkey: &IdentityPubKey) -> bool;
}

// ---------------------------------------------------------------------------
// InMemoryWalletStore
// ---------------------------------------------------------------------------

/// In-memory wallet store backed by `RwLock<HashMap>`.
///
/// Suitable for development and testing. For production, implement
/// [`WalletStore`] with a persistent backend (e.g. encrypted database).
pub struct InMemoryWalletStore {
    entries: RwLock<HashMap<IdentityPubKey, WalletEntry>>,
}

impl InMemoryWalletStore {
    /// Creates an empty in-memory wallet store.
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryWalletStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletStore for InMemoryWalletStore {
    fn resolve(&self, pubkey: &IdentityPubKey) -> Option<WalletEntry> {
        self.entries.read().unwrap().get(pubkey).cloned()
    }

    fn insert(&self, pubkey: IdentityPubKey, entry: WalletEntry) -> Result<(), SdkError> {
        let mut map = self.entries.write().unwrap();
        if map.contains_key(&pubkey) {
            return Err(SdkError::DuplicateEntry);
        }
        map.insert(pubkey, entry);
        Ok(())
    }

    fn remove(&self, pubkey: &IdentityPubKey) -> bool {
        self.entries.write().unwrap().remove(pubkey).is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(byte: u8) -> IdentityPubKey {
        let mut key = [0u8; 33];
        key[0] = 0x02;
        key[32] = byte;
        key
    }

    fn test_entry(account: u32) -> WalletEntry {
        WalletEntry {
            seed: vec![0xAA; 64],
            account,
        }
    }

    #[test]
    fn resolve_returns_none_for_unknown_key() {
        let store = InMemoryWalletStore::new();
        assert!(store.resolve(&test_key(1)).is_none());
    }

    #[test]
    fn insert_and_resolve() {
        let store = InMemoryWalletStore::new();
        let key = test_key(1);
        store.insert(key, test_entry(0)).unwrap();

        let entry = store.resolve(&key).unwrap();
        assert_eq!(entry.account, 0);
    }

    #[test]
    fn insert_duplicate_rejected() {
        let store = InMemoryWalletStore::new();
        let key = test_key(1);
        store.insert(key, test_entry(0)).unwrap();
        assert_eq!(
            store.insert(key, test_entry(1)),
            Err(SdkError::DuplicateEntry)
        );
    }

    #[test]
    fn remove_returns_true_when_present() {
        let store = InMemoryWalletStore::new();
        let key = test_key(1);
        store.insert(key, test_entry(0)).unwrap();
        assert!(store.remove(&key));
        assert!(store.resolve(&key).is_none());
    }

    #[test]
    fn remove_returns_false_when_absent() {
        let store = InMemoryWalletStore::new();
        assert!(!store.remove(&test_key(99)));
    }

    #[test]
    fn multiple_wallets_independent() {
        let store = InMemoryWalletStore::new();
        let k1 = test_key(1);
        let k2 = test_key(2);
        store.insert(k1, test_entry(0)).unwrap();
        store.insert(k2, test_entry(1)).unwrap();

        assert_eq!(store.resolve(&k1).unwrap().account, 0);
        assert_eq!(store.resolve(&k2).unwrap().account, 1);

        store.remove(&k1);
        assert!(store.resolve(&k1).is_none());
        assert!(store.resolve(&k2).is_some());
    }
}
