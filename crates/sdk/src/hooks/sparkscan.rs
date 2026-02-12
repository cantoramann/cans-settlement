//! Sparkscan pre-claim validation hook.
//!
//! When registered, this hook fetches transfer data from the Sparkscan
//! block explorer and validates it against what the coordinator reported
//! before the claim proceeds.
//!
//! # Feature Gate
//!
//! Only compiled when `sparkscan-validation` is enabled:
//!
//! ```toml
//! [dependencies]
//! sdk = { path = "...", features = ["sparkscan-validation"] }
//! ```

use std::pin::Pin;

use sparkscan_client::SparkscanClient;
use tracing::{debug, warn};

use super::{PreClaimContext, PreClaimHook};
use crate::SdkError;

// ---------------------------------------------------------------------------
// SparkscanValidator
// ---------------------------------------------------------------------------

/// Pre-claim hook that validates transfers against the Sparkscan API.
///
/// Compares the transfer ID and total value reported by the coordinator
/// with what Sparkscan has indexed. Rejects the claim if:
///
/// - The transfer cannot be found on Sparkscan.
/// - The satoshi amounts do not match.
pub struct SparkscanValidator {
    client: SparkscanClient,
}

impl SparkscanValidator {
    /// Create a new validator from an existing [`SparkscanClient`].
    pub fn new(client: SparkscanClient) -> Self {
        Self { client }
    }
}

impl PreClaimHook for SparkscanValidator {
    fn check(
        &self,
        ctx: &PreClaimContext<'_>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), SdkError>> + Send + '_>> {
        let transfer_id = ctx.transfer_id.to_owned();
        let total_value = ctx.total_value;

        Box::pin(async move {
            let transfer = self
                .client
                .fetch_transfer(&transfer_id)
                .await
                .map_err(|e| {
                    warn!(%e, %transfer_id, "sparkscan validation failed: fetch error");
                    SdkError::HookRejected
                })?;

            // Validate the total value matches.
            if let Some(amount_sats) = transfer.amount_sats {
                if amount_sats != u128::from(total_value) {
                    warn!(
                        %transfer_id,
                        coordinator_value = total_value,
                        sparkscan_value = %amount_sats,
                        "sparkscan validation failed: value mismatch"
                    );
                    return Err(SdkError::HookRejected);
                }
            }

            debug!(%transfer_id, "sparkscan pre-claim validation passed");
            Ok(())
        })
    }
}
