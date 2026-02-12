//! BTC leaf transfers: send.
//!
//! # Send Transfer Flow
//!
//! A Spark transfer is a **two-phase key rotation** through an ephemeral
//! intermediate key:
//!
//! 1. **Select and reserve** leaves covering the amount.
//! 2. **Ephemeral key generation**: Per leaf, generate a random ephemeral
//!    keypair. The ephemeral key bridges sender → receiver.
//! 3. **Key tweak**: `tweak = current_key - ephemeral_key`. VSS-split the
//!    tweak and build `SendLeafKeyTweak` per operator.
//! 4. **`secret_cipher`**: ECIES-encrypt the ephemeral private key to the
//!    receiver's identity public key.
//! 5. **Refund transactions**: Build CPFP, direct-from-CPFP, and direct
//!    refund txs paying to the **ephemeral** public key.
//! 6. **FROST signing**: Get operator signing commitments, then FROST-sign
//!    each refund tx with the sender's **current** key.
//! 7. **`TransferPackage`**: Assemble `UserSignedTxSigningJob`s, encrypted
//!    `key_tweak_package`, and package-level user signature.
//! 8. **Submit**: Call `start_transfer_v2` with the `TransferPackage`.
//! 9. **Finalize**: Mark reserved leaves as spent.
//!
//! The receiver later claims the transfer (Phase 2) by decrypting the
//! ephemeral key and rotating from ephemeral → receiver-derived key.
//!
//! See [`crate::operations::btc::claim`] for the claim (receive) flow.
//!
//! # Module Structure
//!
//! - [`signing`]: Leaf context construction, FROST signing loop, job
//!   assembly, and coordinator submission.

mod signing;

use std::time::Instant;

use signer::WalletSigner;
use tracing::info;

use crate::network::bitcoin_network;
use crate::operations::tracking::{OperationError, OperationKind, OperationStep};
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Response from a send transfer operation.
pub struct SendTransferResult {
    /// The transfer proto returned by the coordinator.
    pub transfer: Option<transport::spark::Transfer>,
}

// ---------------------------------------------------------------------------
// Sdk::send_transfer
// ---------------------------------------------------------------------------

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Send BTC to a receiver via a Spark transfer.
    ///
    /// Implements the full Phase 1 of the two-phase transfer protocol:
    /// key rotation from sender's current key to a randomly generated
    /// ephemeral key, with the ephemeral private key ECIES-encrypted
    /// for the receiver.
    ///
    /// If the selected leaves exceed the requested amount, an SSP swap
    /// is performed first to produce exact-denomination leaves.  The
    /// swap returns change to the sender's wallet as an inbound transfer
    /// that must be claimed separately.
    pub async fn send_transfer(
        &self,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        amount_sats: u64,
        signer: &impl WalletSigner,
    ) -> Result<SendTransferResult, OperationError> {
        let mut tracker = self.tracker(OperationKind::Transfer);
        let op_id = tracker.id();

        if let Err(e) = self.check_cancelled() {
            return Err(tracker.fail(OperationStep::Auth, e));
        }

        if self.inner.wallet_store.resolve(sender_pubkey).is_none() {
            return Err(tracker.fail(OperationStep::Auth, SdkError::WalletNotFound));
        }

        // Auth.
        let t = Instant::now();
        let authed = match self.authenticate(signer).await {
            Ok(a) => a,
            Err(e) => return Err(tracker.fail(OperationStep::Auth, e)),
        };
        tracker.step_ok(OperationStep::Auth, t.elapsed());

        let network = bitcoin_network(self.inner.config.network.network);

        // Leaf selection.
        let t = Instant::now();
        let selector = self.leaf_selector();
        let available = match self.inner.tree_store.get_available_leaves() {
            Ok(a) => a,
            Err(_) => return Err(tracker.fail(OperationStep::LeafSelection, SdkError::StoreFailed)),
        };
        let (selected, total) = match selector.select(&available, amount_sats) {
            Some(s) => s,
            None => {
                return Err(tracker.fail(OperationStep::LeafSelection, SdkError::InsufficientBalance))
            }
        };
        tracker.step_ok(OperationStep::LeafSelection, t.elapsed());

        let change = total - amount_sats;

        // SSP swap if change needed.
        if change > 0 {
            let t = Instant::now();
            let fee = crate::ssp::SSP_SWAP_FEE_SATS;
            let target_amounts = vec![amount_sats, change.saturating_sub(fee)];

            if let Err(e) = self
                .ssp_swap(sender_pubkey, &selected, &target_amounts, signer)
                .await
            {
                return Err(tracker.fail(OperationStep::SspSwap, e));
            }

            let spent_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
            if let Err(_) = self.inner.tree_store.remove_leaves(&spent_ids) {
                return Err(tracker.fail(OperationStep::SspSwap, SdkError::StoreFailed));
            }
            tracker.step_ok(OperationStep::SspSwap, t.elapsed());

            // Re-authenticate after swap.
            let t = Instant::now();
            let authed = match self.authenticate(signer).await {
                Ok(a) => a,
                Err(e) => return Err(tracker.fail(OperationStep::Auth, e)),
            };
            tracker.step_ok(OperationStep::Auth, t.elapsed());

            // Re-select.
            let refreshed = match self.inner.tree_store.get_available_leaves() {
                Ok(r) => r,
                Err(_) => {
                    return Err(tracker.fail(OperationStep::LeafSelection, SdkError::StoreFailed))
                }
            };
            let (re_selected, _) = match selector.select(&refreshed, amount_sats) {
                Some(s) => s,
                None => {
                    return Err(tracker.fail(
                        OperationStep::LeafSelection,
                        SdkError::InsufficientBalance,
                    ))
                }
            };

            let leaf_ids: Vec<&str> = re_selected.iter().map(|l| l.id.as_str()).collect();
            let reservation = match self.inner.tree_store.reserve_leaves(&leaf_ids) {
                Ok(r) => r,
                Err(_) => {
                    return Err(tracker.fail(OperationStep::Reservation, SdkError::StoreFailed))
                }
            };

            let t = Instant::now();
            let result = signing::send_transfer_inner(
                self,
                &authed,
                &reservation,
                sender_pubkey,
                receiver_pubkey,
                signer,
                network,
            )
            .await;

            return match result {
                Ok(resp) => {
                    tracker.step_ok(OperationStep::TransferSubmit, t.elapsed());
                    if let Err(_) = self
                        .inner
                        .tree_store
                        .finalize_reservation(reservation.id, None)
                    {
                        return Err(
                            tracker.fail(OperationStep::Finalization, SdkError::StoreFailed)
                        );
                    }
                    tracker.step_ok(OperationStep::Finalization, t.elapsed());
                    info!(op_id = %op_id, amount_sats, "transfer sent");
                    tracker.succeed();
                    Ok(resp)
                }
                Err(e) => {
                    let _ = self.inner.tree_store.cancel_reservation(reservation.id);
                    Err(tracker.fail(OperationStep::TransferSubmit, e))
                }
            };
        }

        // No change -- direct transfer.
        let t_res = Instant::now();
        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = match self.inner.tree_store.reserve_leaves(&leaf_ids) {
            Ok(r) => r,
            Err(_) => {
                return Err(tracker.fail(OperationStep::Reservation, SdkError::StoreFailed))
            }
        };
        tracker.step_ok(OperationStep::Reservation, t_res.elapsed());

        let t = Instant::now();
        let result = signing::send_transfer_inner(
            self,
            &authed,
            &reservation,
            sender_pubkey,
            receiver_pubkey,
            signer,
            network,
        )
        .await;

        match result {
            Ok(resp) => {
                tracker.step_ok(OperationStep::TransferSubmit, t.elapsed());
                if let Err(_) = self
                    .inner
                    .tree_store
                    .finalize_reservation(reservation.id, None)
                {
                    return Err(tracker.fail(OperationStep::Finalization, SdkError::StoreFailed));
                }
                info!(op_id = %op_id, amount_sats, "transfer sent");
                tracker.succeed();
                Ok(resp)
            }
            Err(e) => {
                let _ = self.inner.tree_store.cancel_reservation(reservation.id);
                Err(tracker.fail(OperationStep::TransferSubmit, e))
            }
        }
    }
}
