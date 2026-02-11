//! SDK operations: transfers, tokens, Lightning, deposits, exits, and sync.
//!
//! Each submodule implements one family of Spark protocol operations.
//! All operations follow the pattern:
//!
//! 1. Check cancellation token
//! 2. Resolve wallet from public key via `WalletStore`
//! 3. Authenticate with operators via `Sdk::authenticate`
//! 4. Execute the protocol flow (signing, RPC calls, state updates)

pub mod balance;
pub mod claim;
pub mod convert;
pub mod deposit;
pub mod events;
pub mod exit;
pub mod lightning;
pub mod swap;
pub mod sync;
pub mod sync_tokens;
pub mod token;
pub mod transfer;
pub(crate) mod transfer_core;
