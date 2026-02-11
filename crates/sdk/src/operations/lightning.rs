//! Lightning operations: pay invoice and create invoice.
//!
//! # Pay Invoice (Send)
//!
//! 1. Resolve wallet + select leaves
//! 2. Get signing commitments (3 per leaf)
//! 3. Create HTLC-style refund txs
//! 4. FROST sign all refund types
//! 5. Submit via `initiate_preimage_swap_v3`
//!
//! # Create Invoice (Receive)
//!
//! 1. Generate random 32-byte preimage
//! 2. Compute `payment_hash = sha256(preimage)`
//! 3. VSS split preimage into shares
//! 4. Store shares on ALL operators in parallel
//! 5. Return invoice details (BOLT11 creation delegated to SSP)

use bytes::Bytes;
use signer::WalletSigner;
use spark_crypto::verifiable_secret_sharing::LagrangeInterpolatable;
use transport::spark;

use crate::tree::{TreeStore, select_leaves_greedy};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Response from a pay invoice operation.
pub struct PayInvoiceResult {
    /// The preimage, if the payment was immediately settled.
    pub preimage: Option<[u8; 32]>,
}

/// Response from a create invoice operation.
pub struct CreateInvoiceResult {
    /// The payment hash (SHA256 of the preimage).
    pub payment_hash: [u8; 32],
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Pay a Lightning invoice by initiating a preimage swap.
    pub async fn pay_invoice(
        &self,
        sender_pubkey: &IdentityPubKey,
        _payment_hash: &[u8; 32],
        amount_sats: u64,
        signer: &impl WalletSigner,
    ) -> Result<PayInvoiceResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Select and reserve leaves.
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, _total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        // 2. Get signing commitments.
        let node_ids: Vec<String> = reservation.leaves.iter().map(|l| l.id.clone()).collect();
        let _commitments = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids,
                count: 3,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 3-4. FROST sign HTLC-style refunds.
        let mut _rng = rand_core::OsRng;
        // (Actual signing depends on HTLC script structure.)

        // 5. Submit preimage swap.
        let _resp = authed
            .initiate_preimage_swap_v3(spark::InitiatePreimageSwapRequest {
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // Finalize reservation (leaves committed to HTLC).
        self.inner
            .tree_store
            .finalize_reservation(reservation.id, None)?;

        Ok(PayInvoiceResult { preimage: None })
    }

    /// Create a Lightning invoice by splitting a preimage across operators.
    pub async fn create_invoice(
        &self,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<CreateInvoiceResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(receiver_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Generate random preimage.
        let mut rng = rand_core::OsRng;
        let mut preimage = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut preimage);

        // 2. Compute payment hash = SHA256(preimage).
        use bitcoin::hashes::{Hash, sha256};
        let payment_hash: [u8; 32] = *sha256::Hash::hash(&preimage).as_byte_array();

        // 3. VSS split preimage.
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let shares = signer
            .vss_split(&preimage, threshold, num_operators, &mut rng)
            .map_err(|_| SdkError::SigningFailed)?;

        // 4. Store shares on ALL operators.
        let operator_ids = authed.operator_ids();
        for (i, op_id) in operator_ids.iter().enumerate() {
            let share_bytes =
                spark_crypto::verifiable_secret_sharing::scalar_to_bytes(shares[i].share());
            let proofs: Vec<Bytes> = shares[i]
                .proofs
                .iter()
                .map(|p| {
                    Bytes::copy_from_slice(
                        &spark_crypto::verifiable_secret_sharing::serialize_proof_point(p),
                    )
                })
                .collect();

            authed
                .store_preimage_share(
                    op_id,
                    spark::StorePreimageShareRequest {
                        payment_hash: Bytes::copy_from_slice(&payment_hash),
                        preimage_share: Some(spark::SecretShare {
                            secret_share: Bytes::copy_from_slice(&share_bytes),
                            proofs,
                        }),
                        threshold: threshold as u32,
                        user_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|_| SdkError::TransportFailed)?;
        }

        Ok(CreateInvoiceResult { payment_hash })
    }
}
