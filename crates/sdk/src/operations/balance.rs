//! Balance and node queries.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::token::TokenStore;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Combined wallet balance.
pub struct WalletBalance {
    /// Available BTC balance in satoshis (from tree store).
    pub btc_available_sats: u64,
    /// Token balances (token_id -> amount).
    pub token_balances: Vec<([u8; 32], u128)>,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: TokenStore,
    S: crate::ssp::SspClient,
{
    /// Query combined BTC and token balances for a wallet.
    ///
    /// Reads from local stores only -- no network calls. Call `sync_wallet`
    /// first to populate the stores from operator state.
    pub async fn query_balance(&self, pubkey: &IdentityPubKey) -> Result<WalletBalance, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let btc_available_sats = self.inner.tree_store.available_balance()?;

        let token_ids = self.inner.token_store.list_token_ids()?;
        let mut token_balances = Vec::with_capacity(token_ids.len());
        for tid in token_ids {
            let amount = self.inner.token_store.get_balance(&tid)?;
            if amount > 0 {
                token_balances.push((tid, amount));
            }
        }

        Ok(WalletBalance {
            btc_available_sats,
            token_balances,
        })
    }

    /// Query tree nodes from a specific operator (authenticated).
    pub async fn query_nodes(
        &self,
        pubkey: &IdentityPubKey,
        operator_id: &str,
        signer: &impl WalletSigner,
    ) -> Result<spark::QueryNodesResponse, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        authed
            .query_nodes(
                operator_id,
                spark::QueryNodesRequest {
                    source: Some(spark::query_nodes_request::Source::OwnerIdentityPubkey(
                        Bytes::copy_from_slice(pubkey),
                    )),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| SdkError::TransportFailed)
    }
}
