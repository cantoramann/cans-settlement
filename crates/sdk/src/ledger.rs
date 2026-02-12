//! Hash-chained balance ledger backed by heed (LMDB).
//!
//! Each entry records a state transition and includes the SHA-256 hash of
//! the previous entry, forming a tamper-evident chain. Entries are keyed by
//! `[pubkey (33 bytes)][sequence (u64 big-endian)]` for natural per-pubkey
//! ordering via the B+ tree.
//!
//! # Schema
//!
//! ```text
//! Table "entries"
//! Key:   [pubkey: 33 bytes][seq: 8 bytes big-endian]
//! Value: LedgerEntry (JSON-serialized, version-prefixed)
//! ```
//!
//! The ledger is designed to be extended: new event variants and balance
//! fields can be added without breaking existing entries (the `version`
//! field in each entry handles backward compatibility).
//!
//! # Feature Gate
//!
//! This module is only available when the `ledger` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! sdk = { path = "...", features = ["ledger"] }
//! ```

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bitcoin::hashes::{Hash, sha256};
use heed::types::Bytes as HeedBytes;
use heed::{Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// 33-byte compressed public key.
pub type PubKey = [u8; 33];

/// A ledger event describing what happened.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
// Ledger
// ---------------------------------------------------------------------------

/// Hash-chained balance ledger backed by LMDB (via heed).
///
/// Thread-safe: uses a `Mutex` around the in-memory state cache and
/// heed's native transaction isolation for disk access. Multiple
/// readers can proceed concurrently; writes are serialized.
pub struct Ledger {
    env: Env,
    db: Database<HeedBytes, HeedBytes>,
    /// Per-pubkey in-memory state cache.
    state: Mutex<HashMap<PubKey, BalanceState>>,
}

impl Ledger {
    /// Open or create a ledger at the given directory path.
    ///
    /// Creates the directory if it doesn't exist. The LMDB environment
    /// is configured with a 256 MB map size (grows lazily on disk).
    pub fn open(path: &Path) -> Result<Arc<Self>, LedgerError> {
        fs::create_dir_all(path).map_err(|e| LedgerError::Io(e.to_string()))?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(256 * 1024 * 1024) // 256 MB
                .max_dbs(1)
                .open(path)
                .map_err(|e| LedgerError::Db(e.to_string()))?
        };

        let mut wtxn = env
            .write_txn()
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        let db: Database<HeedBytes, HeedBytes> = env
            .create_database(&mut wtxn, Some("entries"))
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        wtxn.commit().map_err(|e| LedgerError::Db(e.to_string()))?;

        let ledger = Arc::new(Self {
            env,
            db,
            state: Mutex::new(HashMap::new()),
        });

        Ok(ledger)
    }

    /// Initialize a pubkey with a genesis entry if it doesn't exist yet.
    ///
    /// If entries already exist for this pubkey (e.g. after a restart),
    /// the in-memory state is rebuilt by replaying the chain from disk.
    pub fn init_pubkey(&self, pubkey: &PubKey) -> Result<(), LedgerError> {
        let mut state = self.state.lock().unwrap();
        if state.contains_key(pubkey) {
            return Ok(());
        }

        // Check if there are existing entries in the DB for this pubkey.
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        let prefix = entry_key(pubkey, 0);
        let existing = self
            .db
            .get(&rtxn, &prefix)
            .map_err(|e| LedgerError::Db(e.to_string()))?;

        if existing.is_some() {
            // Rebuild state from existing entries.
            let rebuilt = self.rebuild_state(&rtxn, pubkey)?;
            state.insert(*pubkey, rebuilt);
            return Ok(());
        }
        drop(rtxn);

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

        let bytes =
            serde_json::to_vec(&genesis).map_err(|e| LedgerError::Serialize(e.to_string()))?;
        let key = entry_key(pubkey, 0);

        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        self.db
            .put(&mut wtxn, &key, &bytes)
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        wtxn.commit().map_err(|e| LedgerError::Db(e.to_string()))?;

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
    /// atomically to LMDB in a single transaction.
    pub fn append(
        &self,
        pubkey: &PubKey,
        event: LedgerEvent,
        patch: impl FnOnce(&BalanceState) -> BalanceState,
    ) -> Result<LedgerEntry, LedgerError> {
        let mut states = self.state.lock().unwrap();
        let current = states
            .get(pubkey)
            .ok_or(LedgerError::PubKeyNotInitialized)?;

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

        let bytes =
            serde_json::to_vec(&entry).map_err(|e| LedgerError::Serialize(e.to_string()))?;
        let key = entry_key(pubkey, entry.seq);

        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        self.db
            .put(&mut wtxn, &key, &bytes)
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        wtxn.commit().map_err(|e| LedgerError::Db(e.to_string()))?;

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

    /// Read all entries for a pubkey from the database.
    pub fn read_all(&self, pubkey: &PubKey) -> Result<Vec<LedgerEntry>, LedgerError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| LedgerError::Db(e.to_string()))?;
        let prefix = pubkey.as_slice();

        let mut entries = Vec::new();
        let iter = self
            .db
            .prefix_iter(&rtxn, prefix)
            .map_err(|e| LedgerError::Db(e.to_string()))?;

        for result in iter {
            let (_key, value) = result.map_err(|e| LedgerError::Db(e.to_string()))?;
            let entry: LedgerEntry =
                serde_json::from_slice(value).map_err(|e| LedgerError::Serialize(e.to_string()))?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Verify the hash chain for a pubkey.
    ///
    /// Returns the number of entries verified, or an error at the first
    /// broken link.
    pub fn verify_chain(&self, pubkey: &PubKey) -> Result<usize, LedgerError> {
        let entries = self.read_all(pubkey)?;
        if entries.is_empty() {
            return Ok(0);
        }

        // Genesis must have all-zero prev_hash.
        if entries[0].prev_hash != [0u8; 32] {
            return Err(LedgerError::ChainBroken {
                seq: 0,
                reason: "genesis entry has non-zero prev_hash".into(),
            });
        }

        let genesis_bytes =
            serde_json::to_vec(&entries[0]).map_err(|e| LedgerError::Serialize(e.to_string()))?;
        let mut prev_hash = hash256(&genesis_bytes);

        for entry in &entries[1..] {
            if entry.prev_hash != prev_hash {
                return Err(LedgerError::ChainBroken {
                    seq: entry.seq,
                    reason: format!(
                        "prev_hash mismatch: expected {}, got {}",
                        hex_short(&prev_hash),
                        hex_short(&entry.prev_hash)
                    ),
                });
            }
            let bytes =
                serde_json::to_vec(entry).map_err(|e| LedgerError::Serialize(e.to_string()))?;
            prev_hash = hash256(&bytes);
        }

        Ok(entries.len())
    }

    /// Dump all entries for a pubkey to a JSON file.
    pub fn dump_to_file(&self, pubkey: &PubKey, path: &Path) -> Result<usize, LedgerError> {
        let entries = self.read_all(pubkey)?;
        let count = entries.len();
        let json = serde_json::to_string_pretty(&entries)
            .map_err(|e| LedgerError::Serialize(e.to_string()))?;
        fs::write(path, json).map_err(|e| LedgerError::Io(e.to_string()))?;
        Ok(count)
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn rebuild_state(
        &self,
        rtxn: &heed::RoTxn<'_>,
        pubkey: &PubKey,
    ) -> Result<BalanceState, LedgerError> {
        let prefix = pubkey.as_slice();

        let mut last_entry: Option<LedgerEntry> = None;
        let mut last_hash = [0u8; 32];

        let iter = self
            .db
            .prefix_iter(rtxn, prefix)
            .map_err(|e| LedgerError::Db(e.to_string()))?;

        for result in iter {
            let (_key, value) = result.map_err(|e| LedgerError::Db(e.to_string()))?;
            last_hash = hash256(value);
            let entry: LedgerEntry =
                serde_json::from_slice(value).map_err(|e| LedgerError::Serialize(e.to_string()))?;
            last_entry = Some(entry);
        }

        match last_entry {
            Some(entry) => Ok(BalanceState {
                btc_balance_sats: entry.btc_balance_sats,
                btc_in_transit_sats: entry.btc_in_transit_sats,
                btc_reserved_sats: entry.btc_reserved_sats,
                token_balances: entry.token_balances,
                token_in_transit: entry.token_in_transit,
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
fn entry_key(pubkey: &PubKey, seq: u64) -> Vec<u8> {
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

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from the hash-chained ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// LMDB / heed database error.
    Db(String),
    /// Filesystem I/O error.
    Io(String),
    /// JSON serialization/deserialization error.
    Serialize(String),
    /// The pubkey was not initialized via [`Ledger::init_pubkey`].
    PubKeyNotInitialized,
    /// The hash chain is broken at the given sequence number.
    ChainBroken {
        /// Sequence number where the break was detected.
        seq: u64,
        /// Human-readable description of the mismatch.
        reason: String,
    },
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "ledger db error: {e}"),
            Self::Io(e) => write!(f, "ledger io error: {e}"),
            Self::Serialize(e) => write!(f, "ledger serialization error: {e}"),
            Self::PubKeyNotInitialized => write!(f, "pubkey not initialized in ledger"),
            Self::ChainBroken { seq, reason } => {
                write!(f, "hash chain broken at seq {seq}: {reason}")
            }
        }
    }
}

impl std::error::Error for LedgerError {}
