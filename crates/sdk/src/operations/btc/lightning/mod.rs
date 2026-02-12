//! Lightning operations: pay invoice and create invoice.
//!
//! # Pay Invoice (Send)
//!
//! 1. Resolve wallet + select leaves covering the payment amount
//! 2. If there's change, SSP-swap to get exact-denomination leaves
//! 3. Build per-leaf FROST signing contexts (ephemeral key, key tweak,
//!    CPFP/direct/direct-from-CPFP refund txs)
//! 4. Get signing commitments from the coordinator (6 per leaf: 3 plain
//!    P2TR for field 4 + 3 HTLC for field 7)
//! 5. FROST-sign all refund types with the sender's current key
//! 6. Assemble `TransferPackage` with signed jobs + key tweaks
//! 7. Wrap in `InitiatePreimageSwapRequest` with payment_hash and
//!    invoice amount, submit via `initiate_preimage_swap_v3`
//! 8. If the coordinator returns a preimage, the payment is settled
//!
//! # Create Invoice (Receive)
//!
//! 1. Generate random 32-byte preimage
//! 2. Compute `payment_hash = SHA256(preimage)`
//! 3. VSS-split preimage into shares
//! 4. Store shares on ALL operators via `store_preimage_share`
//! 5. Return payment_hash (BOLT11 encoding delegated to the LN gateway)
//!
//! # Module Structure
//!
//! - [`htlc`]: Inner pay logic (HTLC + plain refund construction, dual
//!   signing loop, coordinator submission)
//! - [`preimage`]: Create invoice via VSS-split preimage distribution

mod htlc;
mod preimage;

use signer::WalletSigner;
use transport::spark;

use crate::network::bitcoin_network;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/// Response from a pay invoice operation.
pub struct PayInvoiceResult {
    /// The preimage revealed by the swap, if the payment settled.
    pub preimage: Option<[u8; 32]>,
    /// The transfer proto, if returned by the coordinator.
    pub transfer: Option<spark::Transfer>,
}

/// Response from generating a payment preimage.
pub struct GeneratePreimageResult {
    /// The random preimage (32 bytes).
    pub preimage: [u8; 32],
    /// The payment hash (`SHA256(preimage)`).
    pub payment_hash: [u8; 32],
}

/// Response from a create invoice operation.
pub struct CreateInvoiceResult {
    /// The payment hash (`SHA256(preimage)`).
    pub payment_hash: [u8; 32],
}

// ---------------------------------------------------------------------------
// Sdk impl -- Lightning operations
// ---------------------------------------------------------------------------

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Pay a Lightning invoice by initiating a preimage swap.
    ///
    /// The payment is a Spark transfer wrapped in a preimage-swap
    /// request: the coordinator atomically reveals the preimage only
    /// when the transfer succeeds.
    ///
    /// # Arguments
    ///
    /// * `sender_pubkey` -- the sender wallet's identity public key
    /// * `payment_hash` -- 32-byte SHA256 hash from the invoice
    /// * `amount_sats` -- payment amount in satoshis
    /// * `receiver_identity_pubkey` -- the LN gateway operator's identity
    ///   public key (receiver of the Spark transfer)
    /// * `bolt11` -- the encoded BOLT11 invoice string (used as
    ///   `InvoiceAmountProof`)
    /// * `signer` -- wallet signer for FROST and ECDSA operations
    pub async fn pay_invoice(
        &self,
        sender_pubkey: &IdentityPubKey,
        payment_hash: &[u8; 32],
        amount_sats: u64,
        receiver_identity_pubkey: &IdentityPubKey,
        bolt11: &str,
        signer: &impl WalletSigner,
    ) -> Result<PayInvoiceResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;
        let network = bitcoin_network(self.inner.config.network.network);

        // 1. Select leaves covering the payment amount.
        let selector = self.leaf_selector();
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, total) =
            selector.select(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let change = total - amount_sats;

        // 2. If there's change, SSP-swap first to get exact-denomination leaves.
        if change > 0 {
            let fee = crate::ssp::SSP_SWAP_FEE_SATS;
            let target_amounts = vec![amount_sats, change.saturating_sub(fee)];

            self.ssp_swap(sender_pubkey, &selected, &target_amounts, signer)
                .await?;

            let spent_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
            self.inner.tree_store.remove_leaves(&spent_ids)?;

            let authed = self.authenticate(signer).await?;

            let refreshed = self.inner.tree_store.get_available_leaves()?;
            let (re_selected, _) = selector
                .select(&refreshed, amount_sats)
                .ok_or(SdkError::InsufficientBalance)?;

            let leaf_ids: Vec<&str> = re_selected.iter().map(|l| l.id.as_str()).collect();
            let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

            let result = htlc::pay_invoice_inner(
                self,
                &authed,
                &reservation,
                sender_pubkey,
                receiver_identity_pubkey,
                payment_hash,
                amount_sats,
                bolt11,
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

        // No change -- proceed directly.
        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        let result = htlc::pay_invoice_inner(
            self,
            &authed,
            &reservation,
            sender_pubkey,
            receiver_identity_pubkey,
            payment_hash,
            amount_sats,
            bolt11,
            signer,
            network,
        )
        .await;

        match result {
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
        }
    }

    /// Generate a random preimage and its payment hash.
    ///
    /// This is the first step of the receive flow: generate the preimage
    /// locally, then use the `payment_hash` to build a BOLT11 invoice
    /// (externally), and finally call [`Self::create_invoice`] with the
    /// invoice string to distribute preimage shares to operators.
    pub fn generate_payment_preimage(&self) -> GeneratePreimageResult {
        use bitcoin::hashes::{Hash, sha256};

        let mut preimage = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut preimage);
        let payment_hash: [u8; 32] = *sha256::Hash::hash(&preimage).as_byte_array();

        GeneratePreimageResult {
            preimage,
            payment_hash,
        }
    }

    /// Create a Lightning invoice by storing a preimage across operators.
    ///
    /// VSS-splits the preimage into shares and distributes them to all
    /// operators via `store_preimage_share`. The `invoice_string` is a
    /// BOLT11 invoice encoding the same `payment_hash = SHA256(preimage)`.
    ///
    /// # Typical flow
    ///
    /// ```ignore
    /// let gen = sdk.generate_payment_preimage();
    /// let bolt11 = build_bolt11_invoice(&gen.payment_hash, amount);
    /// let result = sdk.create_invoice(pubkey, &gen.preimage, &bolt11, signer).await?;
    /// ```
    pub async fn create_invoice(
        &self,
        receiver_pubkey: &IdentityPubKey,
        preimage: &[u8; 32],
        invoice_string: &str,
        signer: &impl WalletSigner,
    ) -> Result<CreateInvoiceResult, SdkError> {
        preimage::create_invoice_inner(self, receiver_pubkey, preimage, invoice_string, signer)
            .await
    }
}
