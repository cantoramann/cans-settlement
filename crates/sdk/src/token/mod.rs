//! Token output management.
//!
//! Manages the set of token outputs (TTXOs) representing token balances.
//! Token operations use ECDSA identity key signatures (not FROST).

mod memory;
mod selection;
mod store;

pub use memory::InMemoryTokenStore;
pub use selection::SelectionStrategy;
pub use store::{AcquiredOutputs, LockId, TokenOutput, TokenStore};
