//! LMDB-backed [`LedgerStore`] implementation using heed.
//!
//! Keys: `[pubkey: 33 bytes][seq: 8 bytes big-endian]`
//! Values: JSON-serialized [`LedgerEntry`]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use heed::types::Bytes as HeedBytes;
use heed::{Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};

use sdk::SdkError;
use sdk::ledger::{LedgerEntry, LedgerEvent, LedgerStore, PubKey};

// ---------------------------------------------------------------------------
// Serde mirror types
//
// LedgerEntry/LedgerEvent in the SDK are intentionally serde-free.
// We define local serde wrappers here so the serialization format is
// fully owned by this backend.
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct EntryDto {
    version: u8,
    seq: u64,
    event: EventDto,
    btc_balance_sats: u64,
    btc_in_transit_sats: u64,
    btc_reserved_sats: u64,
    token_balances: HashMap<String, u128>,
    token_in_transit: HashMap<String, u128>,
    prev_hash: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum EventDto {
    Genesis,
    ClaimStarted {
        operation_id: u64,
        expected_sats: u64,
    },
    ClaimCompleted {
        operation_id: u64,
        claimed_sats: u64,
        leaves_claimed: usize,
    },
    ClaimFailed {
        operation_id: u64,
        reason: String,
    },
    TransferStarted {
        operation_id: u64,
        amount_sats: u64,
    },
    TransferCompleted {
        operation_id: u64,
        sent_sats: u64,
        change_sats: u64,
    },
    TransferFailed {
        operation_id: u64,
        reason: String,
    },
    TokenCreated {
        operation_id: u64,
        token_id: String,
    },
    TokenMinted {
        operation_id: u64,
        token_id: String,
        amount: u128,
    },
    TokenSendStarted {
        operation_id: u64,
        token_id: String,
        amount: u128,
    },
    TokenSendCompleted {
        operation_id: u64,
        token_id: String,
        sent_amount: u128,
    },
    TokenSendFailed {
        operation_id: u64,
        token_id: String,
        reason: String,
    },
    SyncCompleted {
        balance_sats: u64,
        leaf_count: usize,
    },
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

fn entry_to_dto(e: &LedgerEntry) -> EntryDto {
    EntryDto {
        version: e.version,
        seq: e.seq,
        event: event_to_dto(&e.event),
        btc_balance_sats: e.btc_balance_sats,
        btc_in_transit_sats: e.btc_in_transit_sats,
        btc_reserved_sats: e.btc_reserved_sats,
        token_balances: e.token_balances.clone(),
        token_in_transit: e.token_in_transit.clone(),
        prev_hash: e.prev_hash,
    }
}

fn dto_to_entry(d: EntryDto) -> LedgerEntry {
    LedgerEntry {
        version: d.version,
        seq: d.seq,
        event: dto_to_event(d.event),
        btc_balance_sats: d.btc_balance_sats,
        btc_in_transit_sats: d.btc_in_transit_sats,
        btc_reserved_sats: d.btc_reserved_sats,
        token_balances: d.token_balances,
        token_in_transit: d.token_in_transit,
        prev_hash: d.prev_hash,
    }
}

fn event_to_dto(e: &LedgerEvent) -> EventDto {
    match e {
        LedgerEvent::Genesis => EventDto::Genesis,
        LedgerEvent::ClaimStarted {
            operation_id,
            expected_sats,
        } => EventDto::ClaimStarted {
            operation_id: *operation_id,
            expected_sats: *expected_sats,
        },
        LedgerEvent::ClaimCompleted {
            operation_id,
            claimed_sats,
            leaves_claimed,
        } => EventDto::ClaimCompleted {
            operation_id: *operation_id,
            claimed_sats: *claimed_sats,
            leaves_claimed: *leaves_claimed,
        },
        LedgerEvent::ClaimFailed {
            operation_id,
            reason,
        } => EventDto::ClaimFailed {
            operation_id: *operation_id,
            reason: reason.clone(),
        },
        LedgerEvent::TransferStarted {
            operation_id,
            amount_sats,
        } => EventDto::TransferStarted {
            operation_id: *operation_id,
            amount_sats: *amount_sats,
        },
        LedgerEvent::TransferCompleted {
            operation_id,
            sent_sats,
            change_sats,
        } => EventDto::TransferCompleted {
            operation_id: *operation_id,
            sent_sats: *sent_sats,
            change_sats: *change_sats,
        },
        LedgerEvent::TransferFailed {
            operation_id,
            reason,
        } => EventDto::TransferFailed {
            operation_id: *operation_id,
            reason: reason.clone(),
        },
        LedgerEvent::TokenCreated {
            operation_id,
            token_id,
        } => EventDto::TokenCreated {
            operation_id: *operation_id,
            token_id: token_id.clone(),
        },
        LedgerEvent::TokenMinted {
            operation_id,
            token_id,
            amount,
        } => EventDto::TokenMinted {
            operation_id: *operation_id,
            token_id: token_id.clone(),
            amount: *amount,
        },
        LedgerEvent::TokenSendStarted {
            operation_id,
            token_id,
            amount,
        } => EventDto::TokenSendStarted {
            operation_id: *operation_id,
            token_id: token_id.clone(),
            amount: *amount,
        },
        LedgerEvent::TokenSendCompleted {
            operation_id,
            token_id,
            sent_amount,
        } => EventDto::TokenSendCompleted {
            operation_id: *operation_id,
            token_id: token_id.clone(),
            sent_amount: *sent_amount,
        },
        LedgerEvent::TokenSendFailed {
            operation_id,
            token_id,
            reason,
        } => EventDto::TokenSendFailed {
            operation_id: *operation_id,
            token_id: token_id.clone(),
            reason: reason.clone(),
        },
        LedgerEvent::SyncCompleted {
            balance_sats,
            leaf_count,
        } => EventDto::SyncCompleted {
            balance_sats: *balance_sats,
            leaf_count: *leaf_count,
        },
        _ => EventDto::Genesis, // forward-compat: unknown variants stored as genesis
    }
}

fn dto_to_event(d: EventDto) -> LedgerEvent {
    match d {
        EventDto::Genesis => LedgerEvent::Genesis,
        EventDto::ClaimStarted {
            operation_id,
            expected_sats,
        } => LedgerEvent::ClaimStarted {
            operation_id,
            expected_sats,
        },
        EventDto::ClaimCompleted {
            operation_id,
            claimed_sats,
            leaves_claimed,
        } => LedgerEvent::ClaimCompleted {
            operation_id,
            claimed_sats,
            leaves_claimed,
        },
        EventDto::ClaimFailed {
            operation_id,
            reason,
        } => LedgerEvent::ClaimFailed {
            operation_id,
            reason,
        },
        EventDto::TransferStarted {
            operation_id,
            amount_sats,
        } => LedgerEvent::TransferStarted {
            operation_id,
            amount_sats,
        },
        EventDto::TransferCompleted {
            operation_id,
            sent_sats,
            change_sats,
        } => LedgerEvent::TransferCompleted {
            operation_id,
            sent_sats,
            change_sats,
        },
        EventDto::TransferFailed {
            operation_id,
            reason,
        } => LedgerEvent::TransferFailed {
            operation_id,
            reason,
        },
        EventDto::TokenCreated {
            operation_id,
            token_id,
        } => LedgerEvent::TokenCreated {
            operation_id,
            token_id,
        },
        EventDto::TokenMinted {
            operation_id,
            token_id,
            amount,
        } => LedgerEvent::TokenMinted {
            operation_id,
            token_id,
            amount,
        },
        EventDto::TokenSendStarted {
            operation_id,
            token_id,
            amount,
        } => LedgerEvent::TokenSendStarted {
            operation_id,
            token_id,
            amount,
        },
        EventDto::TokenSendCompleted {
            operation_id,
            token_id,
            sent_amount,
        } => LedgerEvent::TokenSendCompleted {
            operation_id,
            token_id,
            sent_amount,
        },
        EventDto::TokenSendFailed {
            operation_id,
            token_id,
            reason,
        } => LedgerEvent::TokenSendFailed {
            operation_id,
            token_id,
            reason,
        },
        EventDto::SyncCompleted {
            balance_sats,
            leaf_count,
        } => LedgerEvent::SyncCompleted {
            balance_sats,
            leaf_count,
        },
    }
}

// ---------------------------------------------------------------------------
// HeedLedgerStore
// ---------------------------------------------------------------------------

/// LMDB-backed ledger store using heed.
pub struct HeedLedgerStore {
    env: Env,
    db: Database<HeedBytes, HeedBytes>,
}

impl HeedLedgerStore {
    /// Open or create the LMDB environment at the given directory.
    pub fn open(path: &Path) -> Result<Self, SdkError> {
        fs::create_dir_all(path).map_err(|_| SdkError::LedgerStoreFailed)?;

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(256 * 1024 * 1024)
                .max_dbs(1)
                .open(path)
                .map_err(|_| SdkError::LedgerStoreFailed)?
        };

        let mut wtxn = env.write_txn().map_err(|_| SdkError::LedgerStoreFailed)?;
        let db: Database<HeedBytes, HeedBytes> = env
            .create_database(&mut wtxn, Some("entries"))
            .map_err(|_| SdkError::LedgerStoreFailed)?;
        wtxn.commit().map_err(|_| SdkError::LedgerStoreFailed)?;

        Ok(Self { env, db })
    }

    /// Dump all entries for a pubkey to a JSON file.
    pub fn dump_to_file(&self, pubkey: &PubKey, path: &Path) -> Result<usize, SdkError> {
        let pairs = self.list_entries(pubkey)?;
        let dtos: Vec<EntryDto> = pairs.iter().map(|(_, e)| entry_to_dto(e)).collect();
        let json = serde_json::to_string_pretty(&dtos).map_err(|_| SdkError::LedgerStoreFailed)?;
        fs::write(path, json).map_err(|_| SdkError::LedgerStoreFailed)?;
        Ok(dtos.len())
    }
}

impl LedgerStore for HeedLedgerStore {
    fn get(&self, key: &[u8]) -> Result<Option<LedgerEntry>, SdkError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|_| SdkError::LedgerStoreFailed)?;
        let Some(bytes) = self
            .db
            .get(&rtxn, key)
            .map_err(|_| SdkError::LedgerStoreFailed)?
        else {
            return Ok(None);
        };
        let dto: EntryDto =
            serde_json::from_slice(bytes).map_err(|_| SdkError::LedgerStoreFailed)?;
        Ok(Some(dto_to_entry(dto)))
    }

    fn put(&self, key: &[u8], _entry: &LedgerEntry, bytes: &[u8]) -> Result<(), SdkError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|_| SdkError::LedgerStoreFailed)?;
        self.db
            .put(&mut wtxn, key, bytes)
            .map_err(|_| SdkError::LedgerStoreFailed)?;
        wtxn.commit().map_err(|_| SdkError::LedgerStoreFailed)?;
        Ok(())
    }

    fn list_entries(&self, pubkey: &PubKey) -> Result<Vec<(Vec<u8>, LedgerEntry)>, SdkError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|_| SdkError::LedgerStoreFailed)?;
        let prefix = pubkey.as_slice();

        let mut entries = Vec::new();
        let iter = self
            .db
            .prefix_iter(&rtxn, prefix)
            .map_err(|_| SdkError::LedgerStoreFailed)?;

        for result in iter {
            let (_key, value) = result.map_err(|_| SdkError::LedgerStoreFailed)?;
            let dto: EntryDto =
                serde_json::from_slice(value).map_err(|_| SdkError::LedgerStoreFailed)?;
            entries.push((value.to_vec(), dto_to_entry(dto)));
        }

        Ok(entries)
    }

    fn serialize(&self, entry: &LedgerEntry) -> Result<Vec<u8>, SdkError> {
        let dto = entry_to_dto(entry);
        serde_json::to_vec(&dto).map_err(|_| SdkError::LedgerStoreFailed)
    }
}
