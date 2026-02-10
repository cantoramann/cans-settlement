//! Event subscription: background stream from the coordinator.
//!
//! Subscribes to the coordinator's server-streaming RPC and dispatches
//! incoming events:
//!
//! - **TransferEvent**: A new BTC transfer is pending. Auto-claims if
//!   the receiver wallet is known in the `WalletStore`.
//! - **DepositEvent**: An on-chain deposit has been confirmed and a
//!   Spark tree created. The leaf is inserted into the `TreeStore`.
//! - **ConnectedEvent**: Heartbeat confirming the stream is alive.
//!
//! The subscription task runs until the cancellation token fires or the
//! stream terminates. Reconnection is not built-in at this layer;
//! callers should re-invoke on stream closure.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use super::convert::proto_to_tree_node;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Event received from the coordinator event stream.
pub enum SparkEvent {
    /// A new BTC transfer is pending for the wallet.
    Transfer(Box<spark::Transfer>),
    /// An on-chain deposit has been confirmed.
    Deposit(Box<spark::TreeNode>),
    /// Heartbeat / stream connected.
    Connected,
}

impl<W, T, K> Sdk<W, T, K>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
{
    /// Subscribe to events and automatically handle them.
    ///
    /// Opens a server-streaming gRPC connection and processes events:
    /// 1. On `TransferEvent`: auto-claims via `claim_transfer`
    /// 2. On `DepositEvent`: inserts the leaf into the `TreeStore`
    /// 3. On `ConnectedEvent`: no-op (heartbeat)
    ///
    /// The loop exits when the cancellation token fires or the stream ends.
    /// Returns the number of events processed before exit.
    pub async fn subscribe_and_handle_events(
        &self,
        pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<usize, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        let mut stream = authed
            .subscribe_to_events(spark::SubscribeToEventsRequest {
                identity_public_key: Bytes::copy_from_slice(pubkey),
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        let mut events_processed = 0usize;

        loop {
            if self.is_cancelled() {
                break;
            }

            let msg = tokio::select! {
                _ = self.inner.cancel.cancelled() => break,
                msg = stream_next(&mut stream) => msg,
            };

            let resp = match msg {
                Some(Ok(resp)) => resp,
                Some(Err(_)) => break,
                None => break, // Stream ended.
            };

            match resp.event {
                Some(spark::subscribe_to_events_response::Event::Transfer(transfer_event)) => {
                    if let Some(ref transfer) = transfer_event.transfer {
                        let receiver_pk = &transfer.receiver_identity_public_key;
                        if receiver_pk.len() == 33 {
                            let mut pk = [0u8; 33];
                            pk.copy_from_slice(receiver_pk);
                            if self.inner.wallet_store.resolve(&pk).is_some() {
                                let _ = self.claim_transfer(&pk, signer).await;
                            }
                        }
                    }
                }
                Some(spark::subscribe_to_events_response::Event::Deposit(deposit_event)) => {
                    if let Some(ref node) = deposit_event.deposit {
                        if let Some(tree_node) = proto_to_tree_node(node) {
                            let _ = self.inner.tree_store.insert_leaves(&[tree_node]);
                        }
                    }
                }
                Some(spark::subscribe_to_events_response::Event::Connected(_)) => {
                    // Heartbeat, no action needed.
                }
                None => {}
            }

            events_processed += 1;
        }

        Ok(events_processed)
    }
}

/// Pull the next message from a tonic streaming response.
async fn stream_next(
    stream: &mut tonic::Streaming<spark::SubscribeToEventsResponse>,
) -> Option<Result<spark::SubscribeToEventsResponse, tonic::Status>> {
    stream.message().await.transpose()
}
