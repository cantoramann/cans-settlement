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

use signer::WalletSigner;

use crate::network::bitcoin_network;
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
    ) -> Result<SendTransferResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;
        let network = bitcoin_network(self.inner.config.network.network);

        // 1. Select and reserve leaves.
        let selector = self.leaf_selector();
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, total) =
            selector.select(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let change = total - amount_sats;

        // 2. If there's change, SSP swap first.
        //    `ssp_swap` sends the oversized leaves to the SSP, claims the
        //    inbound transfer, and inserts the exact-denomination leaves
        //    into the tree store. We then re-select and proceed.
        if change > 0 {
            let fee = crate::ssp::SSP_SWAP_FEE_SATS;
            let target_amounts = vec![amount_sats, change.saturating_sub(fee)];

            self.ssp_swap(sender_pubkey, &selected, &target_amounts, signer)
                .await?;

            // Remove the leaves we sent to the SSP -- they're no longer ours.
            let spent_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
            self.inner.tree_store.remove_leaves(&spent_ids)?;

            // Re-authenticate: the swap's internal claim may have cycled
            // the session token with the coordinator.
            let authed = self.authenticate(signer).await?;

            // Re-select from the freshly claimed leaves.
            let refreshed = self.inner.tree_store.get_available_leaves()?;
            let (re_selected, _re_total) = selector
                .select(&refreshed, amount_sats)
                .ok_or(SdkError::InsufficientBalance)?;

            let leaf_ids: Vec<&str> = re_selected.iter().map(|l| l.id.as_str()).collect();
            let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

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
                    self.inner
                        .tree_store
                        .finalize_reservation(reservation.id, None)?;
                    Ok(resp)
                }
                Err(e) => {
                    let _ = self.inner.tree_store.cancel_reservation(reservation.id);
                    Err(e)
                }
            };
        }

        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        // From here, any error should cancel the reservation.
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
                // Finalize: remove spent leaves.
                self.inner
                    .tree_store
                    .finalize_reservation(reservation.id, None)?;
                Ok(resp)
            }
            Err(e) => {
                // Cancel reservation on failure.
                let _ = self.inner.tree_store.cancel_reservation(reservation.id);
                Err(e)
            }
        }
    }
}
