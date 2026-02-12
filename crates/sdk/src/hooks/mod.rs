//! Runtime hook system for SDK operation interception.
//!
//! Hooks are named, ordered callbacks attached to specific operation points.
//! They can be added and removed at runtime without recompilation.
//!
//! # Hook Points
//!
//! Each [`HookPoint`] identifies a place in an operation's lifecycle where
//! hooks run. Currently supported:
//!
//! - [`HookPoint::PreClaim`]: Runs before each transfer is claimed.
//!   Hooks implement [`PreClaimHook`] and receive a [`PreClaimContext`]
//!   with transfer metadata. Any hook returning `Err` short-circuits
//!   the chain and rejects the claim.
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use sdk::hooks::{Hook, HookPoint};
//!
//! // Register a pre-claim validator at runtime.
//! sdk.add_hook(HookPoint::PreClaim, "sparkscan", Hook::PreClaim(Arc::new(validator)));
//!
//! // Remove it later without rebuilding.
//! sdk.remove_hook(HookPoint::PreClaim, "sparkscan");
//! ```

#[cfg(feature = "sparkscan-validation")]
pub mod sparkscan;

use std::sync::Arc;

use tokio::sync::RwLock;
use transport::spark;

use crate::SdkError;

// ---------------------------------------------------------------------------
// HookPoint
// ---------------------------------------------------------------------------

/// Identifies an operation lifecycle point where hooks can be attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HookPoint {
    /// Before claiming each pending transfer.
    PreClaim,
}

// ---------------------------------------------------------------------------
// PreClaimHook
// ---------------------------------------------------------------------------

/// Context passed to pre-claim hooks.
///
/// Contains the raw transfer metadata from the coordinator, before any
/// verification or decryption has occurred.
pub struct PreClaimContext<'a> {
    /// Transfer identifier.
    pub transfer_id: &'a str,
    /// Sender's identity public key (compressed, 33 bytes).
    pub sender_identity_public_key: &'a [u8],
    /// Receiver's identity public key (compressed, 33 bytes).
    pub receiver_identity_public_key: &'a [u8],
    /// Total transfer value in satoshis.
    pub total_value: u64,
    /// Transfer leaves with metadata.
    pub leaves: &'a [spark::TransferLeaf],
}

impl<'a> PreClaimContext<'a> {
    /// Build a context from a raw `Transfer` proto.
    pub(crate) fn from_transfer(transfer: &'a spark::Transfer) -> Self {
        Self {
            transfer_id: &transfer.id,
            sender_identity_public_key: &transfer.sender_identity_public_key,
            receiver_identity_public_key: &transfer.receiver_identity_public_key,
            total_value: transfer.total_value,
            leaves: &transfer.leaves,
        }
    }
}

/// Trait for hooks that run before a transfer is claimed.
///
/// Implementations validate the transfer and return `Ok(())` to proceed
/// or `Err(SdkError::HookRejected)` to reject it.
///
/// # Implementors
///
/// - Feature `sparkscan-validation`: [`sparkscan::SparkscanValidator`]
pub trait PreClaimHook: Send + Sync {
    /// Validate a transfer before claiming.
    ///
    /// This is called synchronously in the hook chain. Use
    /// [`Box::pin`] for async implementations.
    fn check(
        &self,
        ctx: &PreClaimContext<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), SdkError>> + Send + '_>>;
}

// ---------------------------------------------------------------------------
// Hook enum
// ---------------------------------------------------------------------------

/// A type-safe hook instance, discriminated by hook point.
///
/// Used with [`crate::Sdk::add_hook`] to register hooks at runtime.
#[non_exhaustive]
pub enum Hook {
    /// A pre-claim validation hook.
    PreClaim(Arc<dyn PreClaimHook>),
}

// ---------------------------------------------------------------------------
// Hooks registry
// ---------------------------------------------------------------------------

/// Internal registry of all hook chains.
///
/// Each hook point has its own `RwLock`-protected ordered list.
/// Read-locks are taken when running hooks; write-locks only during
/// add/remove.
pub(crate) struct Hooks {
    pre_claim: RwLock<Vec<(&'static str, Arc<dyn PreClaimHook>)>>,
}

impl Hooks {
    /// Create an empty hook registry.
    pub(crate) fn new() -> Self {
        Self {
            pre_claim: RwLock::new(Vec::new()),
        }
    }

    /// Add a named hook to the pre-claim chain.
    ///
    /// If a hook with the same name already exists, it is replaced
    /// in-place (preserving order). Otherwise appended to the end.
    pub(crate) async fn add_pre_claim(&self, name: &'static str, hook: Arc<dyn PreClaimHook>) {
        let mut chain = self.pre_claim.write().await;
        if let Some(entry) = chain.iter_mut().find(|(n, _)| *n == name) {
            entry.1 = hook;
        } else {
            chain.push((name, hook));
        }
    }

    /// Remove a named hook from the pre-claim chain. Returns `true` if found.
    pub(crate) async fn remove_pre_claim(&self, name: &'static str) -> bool {
        let mut chain = self.pre_claim.write().await;
        let len_before = chain.len();
        chain.retain(|(n, _)| *n != name);
        chain.len() < len_before
    }

    /// Run the pre-claim hook chain. Short-circuits on the first error.
    ///
    /// Acquires a read lock for the duration of the chain. If no hooks
    /// are registered, this is a near-zero-cost no-op.
    pub(crate) async fn run_pre_claim(&self, transfer: &spark::Transfer) -> Result<(), SdkError> {
        let chain = self.pre_claim.read().await;
        if chain.is_empty() {
            return Ok(());
        }

        let ctx = PreClaimContext::from_transfer(transfer);
        for (_, hook) in chain.iter() {
            hook.check(&ctx).await?;
        }
        Ok(())
    }

    /// Returns `true` if there are no pre-claim hooks registered.
    pub(crate) fn pre_claim_is_empty(&self) -> bool {
        self.pre_claim
            .try_read()
            .map(|chain| chain.is_empty())
            .unwrap_or(true)
    }
}
