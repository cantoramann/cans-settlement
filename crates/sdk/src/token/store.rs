//! Token store trait and domain types.

use crate::SdkError;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Unique identifier for a token output lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LockId(pub u64);

/// A token output (TTXO) in the Spark token ledger.
#[derive(Debug, Clone)]
pub struct TokenOutput {
    /// Server-assigned output ID.
    pub id: String,

    /// Owner's identity public key (33 bytes, compressed).
    pub owner_public_key: [u8; 33],

    /// Token identifier (32 bytes).
    pub token_id: [u8; 32],

    /// Token amount (uint128, big-endian encoded in proto).
    pub amount: u128,

    /// Hash of the transaction that created this output.
    pub previous_transaction_hash: [u8; 32],

    /// Output index in the creating transaction.
    pub previous_transaction_vout: u32,

    /// Withdraw bond in satoshis (for L1 withdrawal security).
    pub withdraw_bond_sats: u64,

    /// Relative block locktime for withdrawal.
    pub withdraw_relative_block_locktime: u64,
}

/// A set of acquired (locked) token outputs.
pub struct AcquiredOutputs {
    /// Lock identifier (used to release).
    pub lock_id: LockId,

    /// The locked outputs.
    pub outputs: Vec<TokenOutput>,

    /// Total amount of the locked outputs.
    pub total_amount: u128,
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Storage for token outputs (TTXOs).
///
/// Implementations manage output lifecycle: setting outputs from server
/// state, acquiring (locking) for transfers, and releasing after completion.
pub trait TokenStore: Send + Sync {
    /// Set (sync) outputs from server state.
    ///
    /// Replaces all outputs for the token IDs present in the input.
    fn set_outputs(&self, outputs: &[TokenOutput]) -> Result<(), SdkError>;

    /// Acquire outputs for a transfer: selects and locks outputs for
    /// the given token ID and minimum amount.
    ///
    /// Returns [`SdkError::InsufficientTokenBalance`] if the available
    /// outputs cannot cover the requested amount.
    fn acquire_outputs(
        &self,
        token_id: &[u8; 32],
        amount: u128,
    ) -> Result<AcquiredOutputs, SdkError>;

    /// Release a previously acquired lock, returning outputs to available.
    fn release_outputs(&self, lock_id: LockId) -> Result<(), SdkError>;

    /// Get the available (unlocked) balance for a token.
    fn get_balance(&self, token_id: &[u8; 32]) -> Result<u128, SdkError>;

    /// List all known token identifiers.
    fn list_token_ids(&self) -> Result<Vec<[u8; 32]>, SdkError>;
}
