//! BTC leaf operations: transfers, claims, swaps, deposits, exits, and sync.
//!
//! These operations use FROST threshold signatures and the Spark leaf tree.
//! Each module implements one family of operations following the standard
//! pattern: check cancellation, resolve wallet, authenticate, execute.

pub mod balance;
pub mod claim;
pub mod deposit;
pub mod events;
pub mod exit;
pub mod lightning;
pub mod swap;
pub mod sync;
pub mod transfer;
pub(crate) mod transfer_core;

// Re-export public types for consumer convenience.
pub use balance::WalletBalance;
pub use claim::ClaimTransferResult;
pub use deposit::DepositAddress;
pub use events::SparkEvent;
pub use exit::CooperativeExitResult;
pub use lightning::{CreateInvoiceResult, GeneratePreimageResult, PayInvoiceResult};
pub use sync::SyncResult;
pub use transfer::SendTransferResult;
