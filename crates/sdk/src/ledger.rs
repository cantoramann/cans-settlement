//! Hash-chained balance ledger.
//!
//! The ledger records per-pubkey state transitions as an append-only,
//! tamper-evident chain. Each entry includes the SHA-256 hash of the
//! previous entry's serialized bytes.
//!
//! Storage is decoupled via the [`LedgerStore`] trait -- the SDK defines
//! the chain logic and types; consumers provide the persistence backend
//! (LMDB, Postgres, in-memory, etc.).
//!
//! # Schema
//!
//! ```text
//! Key:   [pubkey: 33 bytes][seq: 8 bytes big-endian]
//! Value: LedgerEntry (serialization format is backend-defined)
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use bitcoin::hashes::{Hash, sha256};

use crate::SdkError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 33-byte compressed public key.
pub type PubKey = [u8; 33];

/// A ledger event describing what happened.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum LedgerEvent {
    /// Wallet initialized / genesis entry.
    Genesis,

    // -- BTC --
    /// Claim operation started (funds in transit toward us).
    ClaimStarted {
        operation_id: u64,
        expected_sats: u64,
    },
    /// Claim operation completed (funds now available).
    ClaimCompleted {
        operation_id: u64,
        claimed_sats: u64,
        leaves_claimed: usize,
    },
    /// Claim operation failed.
    ClaimFailed { operation_id: u64, reason: String },

    /// Transfer send started (funds in transit away from us).
    TransferStarted { operation_id: u64, amount_sats: u64 },
    /// Transfer completed (funds left our balance, change returned).
    TransferCompleted {
        operation_id: u64,
        sent_sats: u64,
        /// Sats temporarily held during SSP swap that have been returned.
        change_sats: u64,
    },
    /// Transfer failed (reserved funds released back).
    TransferFailed { operation_id: u64, reason: String },

    // -- Token --
    /// Token created by this wallet.
    TokenCreated { operation_id: u64, token_id: String },
    /// Tokens minted to self.
    TokenMinted {
        operation_id: u64,
        token_id: String,
        amount: u128,
    },
    /// Token send started.
    TokenSendStarted {
        operation_id: u64,
        token_id: String,
        amount: u128,
    },
    /// Token send completed.
    TokenSendCompleted {
        operation_id: u64,
        token_id: String,
        sent_amount: u128,
    },
    /// Token send failed.
    TokenSendFailed {
        operation_id: u64,
        token_id: String,
        reason: String,
    },

    /// Wallet sync completed (initial state loaded).
    SyncCompleted {
        balance_sats: u64,
        leaf_count: usize,
    },
}

/// A single entry in the hash-chained ledger.
#[derive(Debug, Clone)]
pub struct LedgerEntry {
    /// Entry format version (for forward-compatible deserialization).
    pub version: u8,
    /// Sequence number within this pubkey's chain (0-indexed).
    pub seq: u64,
    /// The event that caused this state transition.
    pub event: LedgerEvent,
    /// BTC balance available for spending after this event.
    pub btc_balance_sats: u64,
    /// BTC currently in transit (positive = incoming).
    pub btc_in_transit_sats: u64,
    /// BTC reserved for outbound operations (will be deducted on completion).
    pub btc_reserved_sats: u64,
    /// Per-token balances: `{ token_id_hex -> available_amount }`.
    pub token_balances: HashMap<String, u128>,
    /// Per-token in-transit amounts.
    pub token_in_transit: HashMap<String, u128>,
    /// SHA-256 hash of the previous entry's serialized bytes.
    /// All zeros for the genesis entry.
    pub prev_hash: [u8; 32],
}

/// An immutable snapshot of a pubkey's balance state.
#[derive(Debug, Clone, Default)]
pub struct BalanceState {
    /// BTC available for spending.
    pub btc_balance_sats: u64,
    /// BTC currently in transit (incoming).
    pub btc_in_transit_sats: u64,
    /// BTC reserved for outbound operations.
    pub btc_reserved_sats: u64,
    /// Per-token available balances.
    pub token_balances: HashMap<String, u128>,
    /// Per-token in-transit amounts.
    pub token_in_transit: HashMap<String, u128>,
    /// Next sequence number for this pubkey.
    pub next_seq: u64,
    /// SHA-256 hash of the most recent entry.
    pub prev_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

/// Persistence backend for the hash-chained ledger.
///
/// Implementations are responsible for serialization format and storage
/// engine. The `Ledger` struct handles chain logic, hashing, and caching.
///
/// Keys are 41 bytes: `[pubkey: 33][seq: 8 big-endian]`.
pub trait LedgerStore: Send + Sync {
    /// Retrieve a single entry by its exact key.
    fn get(&self, key: &[u8]) -> Result<Option<LedgerEntry>, SdkError>;

    /// Persist an entry at the given key along with its serialized bytes.
    ///
    /// The `bytes` are the canonical serialized form whose SHA-256 hash
    /// becomes the next entry's `prev_hash`. Implementations must store
    /// these bytes verbatim so that [`get`] and [`list_entries`] can
    /// reconstruct entries deterministically.
    fn put(&self, key: &[u8], entry: &LedgerEntry, bytes: &[u8]) -> Result<(), SdkError>;

    /// List all entries for a pubkey, ordered by sequence number.
    ///
    /// Returns `(serialized_bytes, entry)` pairs so the caller can
    /// verify hashes without re-serializing.
    fn list_entries(&self, pubkey: &PubKey) -> Result<Vec<(Vec<u8>, LedgerEntry)>, SdkError>;

    /// Serialize a [`LedgerEntry`] to bytes.
    ///
    /// This must be deterministic: the same entry must always produce
    /// the same bytes, because those bytes are hashed into the chain.
    fn serialize(&self, entry: &LedgerEntry) -> Result<Vec<u8>, SdkError>;
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

/// Hash-chained balance ledger.
///
/// Thread-safe: uses a `Mutex` around the in-memory state cache.
/// The backing [`LedgerStore`] is called under the lock so that
/// append operations are serialized per pubkey.
pub struct Ledger<S: LedgerStore> {
    store: S,
    /// Per-pubkey in-memory state cache.
    state: Mutex<HashMap<PubKey, BalanceState>>,
}

impl<S: LedgerStore> Ledger<S> {
    /// Create a new ledger backed by the given store.
    pub fn new(store: S) -> Self {
        Self {
            store,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Initialize a pubkey with a genesis entry if it doesn't exist yet.
    ///
    /// If entries already exist for this pubkey (e.g. after a restart),
    /// the in-memory state is rebuilt by replaying the chain from disk.
    pub fn init_pubkey(&self, pubkey: &PubKey) -> Result<(), SdkError> {
        let mut state = self.state.lock().unwrap();
        if state.contains_key(pubkey) {
            return Ok(());
        }

        // Check if there are existing entries.
        let genesis_key = entry_key(pubkey, 0);
        if self.store.get(&genesis_key)?.is_some() {
            let rebuilt = self.rebuild_state(pubkey)?;
            state.insert(*pubkey, rebuilt);
            return Ok(());
        }

        // Write genesis entry.
        let genesis = LedgerEntry {
            version: 1,
            seq: 0,
            event: LedgerEvent::Genesis,
            btc_balance_sats: 0,
            btc_in_transit_sats: 0,
            btc_reserved_sats: 0,
            token_balances: HashMap::new(),
            token_in_transit: HashMap::new(),
            prev_hash: [0u8; 32],
        };

        let bytes = self.store.serialize(&genesis)?;
        let key = entry_key(pubkey, 0);
        self.store.put(&key, &genesis, &bytes)?;

        let hash = hash256(&bytes);
        state.insert(
            *pubkey,
            BalanceState {
                next_seq: 1,
                prev_hash: hash,
                ..Default::default()
            },
        );

        Ok(())
    }

    /// Append an event to the ledger and update the balance state.
    ///
    /// The `patch` closure receives the current balance state and must
    /// return the new state. The event and new state are written
    /// atomically to the store.
    pub fn append(
        &self,
        pubkey: &PubKey,
        event: LedgerEvent,
        patch: impl FnOnce(&BalanceState) -> BalanceState,
    ) -> Result<LedgerEntry, SdkError> {
        let mut states = self.state.lock().unwrap();
        let current = states.get(pubkey).ok_or(SdkError::LedgerNotInitialized)?;

        let new_state = patch(current);

        let entry = LedgerEntry {
            version: 1,
            seq: current.next_seq,
            event,
            btc_balance_sats: new_state.btc_balance_sats,
            btc_in_transit_sats: new_state.btc_in_transit_sats,
            btc_reserved_sats: new_state.btc_reserved_sats,
            token_balances: new_state.token_balances.clone(),
            token_in_transit: new_state.token_in_transit.clone(),
            prev_hash: current.prev_hash,
        };

        let bytes = self.store.serialize(&entry)?;
        let key = entry_key(pubkey, entry.seq);
        self.store.put(&key, &entry, &bytes)?;

        let hash = hash256(&bytes);
        let mut updated = new_state;
        updated.next_seq = entry.seq + 1;
        updated.prev_hash = hash;
        states.insert(*pubkey, updated);

        Ok(entry)
    }

    /// Get the current balance state for a pubkey (from cache).
    pub fn balance(&self, pubkey: &PubKey) -> Option<BalanceState> {
        self.state.lock().unwrap().get(pubkey).cloned()
    }

    /// Read all entries for a pubkey from the store.
    pub fn read_all(&self, pubkey: &PubKey) -> Result<Vec<LedgerEntry>, SdkError> {
        Ok(self
            .store
            .list_entries(pubkey)?
            .into_iter()
            .map(|(_bytes, entry)| entry)
            .collect())
    }

    /// Verify the hash chain for a pubkey.
    ///
    /// Returns the number of entries verified, or an error at the first
    /// broken link.
    pub fn verify_chain(&self, pubkey: &PubKey) -> Result<usize, SdkError> {
        let pairs = self.store.list_entries(pubkey)?;
        if pairs.is_empty() {
            return Ok(0);
        }

        // Genesis must have all-zero prev_hash.
        let (ref genesis_bytes, ref genesis) = pairs[0];
        if genesis.prev_hash != [0u8; 32] {
            return Err(SdkError::LedgerChainBroken {
                seq: 0,
                reason: "genesis entry has non-zero prev_hash".into(),
            });
        }

        let mut prev_hash = hash256(genesis_bytes);

        for (bytes, entry) in &pairs[1..] {
            if entry.prev_hash != prev_hash {
                return Err(SdkError::LedgerChainBroken {
                    seq: entry.seq,
                    reason: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        hex_short(&prev_hash),
                        hex_short(&entry.prev_hash)
                    ),
                });
            }
            prev_hash = hash256(bytes);
        }

        Ok(pairs.len())
    }

    /// Access the underlying store (e.g. for dump operations).
    pub fn store(&self) -> &S {
        &self.store
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn rebuild_state(&self, pubkey: &PubKey) -> Result<BalanceState, SdkError> {
        let pairs = self.store.list_entries(pubkey)?;

        let mut last_entry: Option<&LedgerEntry> = None;
        let mut last_hash = [0u8; 32];

        for (bytes, entry) in &pairs {
            last_hash = hash256(bytes);
            last_entry = Some(entry);
        }

        match last_entry {
            Some(entry) => Ok(BalanceState {
                btc_balance_sats: entry.btc_balance_sats,
                btc_in_transit_sats: entry.btc_in_transit_sats,
                btc_reserved_sats: entry.btc_reserved_sats,
                token_balances: entry.token_balances.clone(),
                token_in_transit: entry.token_in_transit.clone(),
                next_seq: entry.seq + 1,
                prev_hash: last_hash,
            }),
            None => Ok(BalanceState::default()),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a 41-byte key: `[pubkey: 33][seq: 8 big-endian]`.
pub fn entry_key(pubkey: &PubKey, seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(41);
    key.extend_from_slice(pubkey);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn hash256(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn hex_short(bytes: &[u8; 32]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
        + "..."
}
