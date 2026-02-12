//! SDK operations: BTC leaf transfers, token operations, and shared helpers.
//!
//! Operations are split into two families:
//!
//! - **`btc`**: BTC leaf operations using FROST threshold signatures
//!   (transfer, claim, swap, deposit, exit, sync, events, balance, lightning)
//! - **`token`**: Token operations using ECDSA identity key signatures
//!   (send, create, mint, freeze, query, sync)
//!
//! Shared proto-to-SDK conversions live in [`convert`].

pub mod btc;
pub mod convert;
pub mod token;
pub mod tracking;
