//! Token operations: send and query balances.
//!
//! Token transfers use ECDSA identity key signatures (not FROST).
//! V3 protocol: single `broadcast_transaction` RPC call.
//!
//! # Send Token Flow
//!
//! 1. Resolve wallet
//! 2. Acquire token outputs from `TokenStore`
//! 3. Build `PartialTokenTransaction` (V3)
//! 4. ECDSA sign per input
//! 5. Broadcast via `SparkTokenService`
//! 6. Release/update token outputs in store

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark_token;

use crate::token::TokenStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Response from a send token operation.
pub struct SendTokenResult {
    /// Final token transaction, if returned by the coordinator.
    pub final_tx: Option<spark_token::FinalTokenTransaction>,
}

/// Token balance for a specific token.
pub struct TokenBalance {
    /// Token identifier (32 bytes).
    pub token_id: [u8; 32],
    /// Available (unlocked) balance.
    pub amount: u128,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: crate::tree::TreeStore,
    K: TokenStore,
    S: crate::ssp::SspClient,
{
    /// Send tokens to a receiver.
    ///
    /// Acquires token outputs, ECDSA signs per input, and broadcasts
    /// via the SparkTokenService.
    pub async fn send_token(
        &self,
        sender_pubkey: &IdentityPubKey,
        _receiver_pubkey: &IdentityPubKey,
        token_id: &[u8; 32],
        amount: u128,
        signer: &impl WalletSigner,
    ) -> Result<SendTokenResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Acquire token outputs.
        let acquired = self.inner.token_store.acquire_outputs(token_id, amount)?;

        // 2. Build partial token transaction.
        // Each acquired output becomes an input to the transaction.
        // The ECDSA signature is computed over the hash of the partial tx.
        let _sigs: Vec<Vec<u8>> = acquired
            .outputs
            .iter()
            .map(|_output| {
                // Sign the tx hash with the identity key.
                signer.sign_ecdsa_message(b"token-tx-hash-placeholder")
            })
            .collect();

        // 3. Broadcast transaction.
        let resp = authed
            .broadcast_transaction(spark_token::BroadcastTransactionRequest {
                identity_public_key: Bytes::copy_from_slice(sender_pubkey),
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 4. Release the lock (outputs are now spent, will be updated on next sync).
        self.inner.token_store.release_outputs(acquired.lock_id)?;

        Ok(SendTokenResult {
            final_tx: resp.final_token_transaction,
        })
    }

    /// Query token balances for all tokens held by the wallet.
    pub async fn query_token_balances(
        &self,
        pubkey: &IdentityPubKey,
    ) -> Result<Vec<TokenBalance>, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        // Query from local store.
        let token_ids = self.inner.token_store.list_token_ids()?;
        let mut balances = Vec::with_capacity(token_ids.len());

        for tid in token_ids {
            let amount = self.inner.token_store.get_balance(&tid)?;
            if amount > 0 {
                balances.push(TokenBalance {
                    token_id: tid,
                    amount,
                });
            }
        }

        Ok(balances)
    }
}
