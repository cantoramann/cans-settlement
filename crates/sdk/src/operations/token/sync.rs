//! Token output synchronization: populate `TokenStore` from operator state.
//!
//! Queries the coordinator's `SparkTokenService` for token outputs owned
//! by the wallet's identity public key and inserts them into the local
//! `TokenStore`.

use bytes::Bytes;
use signer::WalletSigner;
use tracing::error;
use transport::spark_token;

use crate::network::spark_network_proto;
use crate::operations::convert::proto_to_token_output;
use crate::token::TokenStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Result of a token synchronization.
pub struct SyncTokensResult {
    /// Number of token outputs inserted.
    pub output_count: usize,
    /// Number of distinct token types found.
    pub token_types: usize,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: crate::tree::TreeStore,
    K: TokenStore,
    S: crate::ssp::SspClient,
{
    /// Synchronize token outputs from the coordinator.
    ///
    /// Queries `SparkTokenService::QueryTokenOutputs` for all token
    /// outputs owned by this wallet and populates the local `TokenStore`.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::AuthFailed`] on authentication errors,
    /// [`SdkError::TransportFailed`] on RPC errors.
    pub async fn sync_tokens(
        &self,
        pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<SyncTokensResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // Query all token outputs for this wallet.
        let resp = authed
            .query_token_outputs(spark_token::QueryTokenOutputsRequest {
                owner_public_keys: vec![Bytes::copy_from_slice(pubkey)],
                network: spark_network_proto(self.inner.config.network.network),
                ..Default::default()
            })
            .await
            .map_err(|e| {
                error!("query_token_outputs failed: {e}");
                SdkError::TransportFailed
            })?;

        // Convert proto outputs to SDK types.
        let mut outputs = Vec::with_capacity(resp.outputs_with_previous_transaction_data.len());
        for entry in &resp.outputs_with_previous_transaction_data {
            if let Some(ref output) = entry.output {
                if let Some(sdk_output) = proto_to_token_output(output, entry) {
                    outputs.push(sdk_output);
                }
            }
        }

        // Count distinct token types.
        let mut seen_tokens = std::collections::HashSet::new();
        for o in &outputs {
            seen_tokens.insert(o.token_id);
        }
        let token_types = seen_tokens.len();
        let output_count = outputs.len();

        // Insert into store (set_outputs replaces all for each token present).
        if !outputs.is_empty() {
            self.inner.token_store.set_outputs(&outputs)?;
        }

        Ok(SyncTokensResult {
            output_count,
            token_types,
        })
    }
}
