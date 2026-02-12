//! Wallet synchronization: populate local stores from operator state.
//!
//! # Sync Flow
//!
//! 1. Authenticate with the coordinator
//! 2. Query nodes owned by the wallet's identity public key
//! 3. Convert proto `TreeNode`s to SDK `TreeNode`s
//! 4. Insert into the `TreeStore` (dedup by ID)
//! 5. Return sync summary
//!
//! This is the first operation that should be called after constructing
//! the SDK with a new or existing wallet. Without sync, the local
//! `TreeStore` is empty and balance queries return zero.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::operations::convert::proto_to_tree_node;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Result of a wallet synchronization.
pub struct SyncResult {
    /// Number of leaves inserted into the tree store.
    pub leaf_count: usize,
    /// Total balance of synced leaves in satoshis.
    pub balance_sats: u64,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Synchronize local stores with operator state.
    ///
    /// Queries the coordinator for all tree nodes owned by this wallet
    /// and inserts them into the `TreeStore`. This must be called before
    /// any balance query or transfer to ensure the SDK knows about
    /// existing leaves.
    ///
    /// # Arguments
    ///
    /// * `pubkey` -- The wallet's compressed identity public key.
    /// * `signer` -- The wallet signer (used for authentication).
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::WalletNotFound`] if the pubkey is not in the
    /// wallet store, [`SdkError::AuthFailed`] on authentication errors,
    /// [`SdkError::TransportFailed`] on RPC errors.
    pub async fn sync_wallet(
        &self,
        pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<SyncResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        // 1. Authenticate and get an auth-injected transport.
        let authed = self.authenticate(signer).await?;

        // 2. Query nodes from the coordinator.
        let coordinator_id = authed.coordinator_id().to_owned();
        let resp = authed
            .query_nodes(
                &coordinator_id,
                spark::QueryNodesRequest {
                    source: Some(spark::query_nodes_request::Source::OwnerIdentityPubkey(
                        Bytes::copy_from_slice(pubkey),
                    )),
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 3. Convert proto nodes to SDK TreeNodes.
        let mut leaves = Vec::with_capacity(resp.nodes.len());
        for proto_node in resp.nodes.values() {
            if let Some(tree_node) = proto_to_tree_node(proto_node) {
                leaves.push(tree_node);
            }
        }

        // 4. Compute summary before inserting.
        let leaf_count = leaves.len();
        let balance_sats: u64 = leaves.iter().map(|l| l.value).sum();

        // 5. Insert into the tree store.
        if !leaves.is_empty() {
            self.inner.tree_store.insert_leaves(&leaves)?;
        }

        Ok(SyncResult {
            leaf_count,
            balance_sats,
        })
    }
}
