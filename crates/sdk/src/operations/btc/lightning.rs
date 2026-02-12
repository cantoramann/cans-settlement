//! Lightning operations: pay invoice and create invoice.
//!
//! # Pay Invoice (Send)
//!
//! 1. Resolve wallet + select leaves covering the payment amount
//! 2. If there's change, SSP-swap to get exact-denomination leaves
//! 3. Build per-leaf FROST signing contexts (ephemeral key, key tweak,
//!    CPFP/direct/direct-from-CPFP refund txs)
//! 4. Get signing commitments from the coordinator (3 per leaf)
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

use bytes::Bytes;
use signer::WalletSigner;
use spark_crypto::verifiable_secret_sharing::LagrangeInterpolatable;
use tracing::error;
use transport::spark;

use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_htlc_refund_tx, create_direct_htlc_refund_tx,
    create_direct_refund_tx, parse_tx, serialize_tx,
};
use crate::frost_bridge::commitment_to_proto;
use crate::network::bitcoin_network;
use crate::operations::btc::transfer_core::{
    self, BuildLeafParams, LeafTransferContext, build_cpfp_signing_job, build_key_tweak_package,
    frost_sign_user_share, generate_uuid_v4, next_htlc_sequence, next_send_sequence,
    one_hour_expiry, sign_transfer_package,
};
use crate::tree::{TreeStore, select_leaves_greedy};
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
// Direct refund data (same as transfer.rs -- layered on LeafTransferContext)
// ---------------------------------------------------------------------------

/// Additional per-leaf data for direct refund paths.
struct DirectRefundData {
    direct_from_cpfp_refund_tx: bitcoin::Transaction,
    direct_refund_tx: Option<bitcoin::Transaction>,
    direct_prev_out: Option<bitcoin::TxOut>,
    direct_from_cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    direct_nonce_pair: Option<spark_crypto::frost::FrostNoncePair>,
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
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

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
            let (re_selected, _) = select_leaves_greedy(&refreshed, amount_sats)
                .ok_or(SdkError::InsufficientBalance)?;

            let leaf_ids: Vec<&str> = re_selected.iter().map(|l| l.id.as_str()).collect();
            let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

            let result = self
                .pay_invoice_inner(
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

        let result = self
            .pay_invoice_inner(
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

    /// Inner pay logic: build both `StartUserSignedTransferRequest`
    /// (field 4) and `StartTransferRequest` (field 7, with `TransferPackage`
    /// containing key tweaks), then submit the preimage swap.
    #[allow(clippy::too_many_arguments)]
    async fn pay_invoice_inner(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        reservation: &crate::tree::LeafReservation,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        payment_hash: &[u8; 32],
        amount_sats: u64,
        bolt11: &str,
        signer: &impl WalletSigner,
        network: bitcoin::Network,
    ) -> Result<PayInvoiceResult, SdkError> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let operator_ids: Vec<String> = operators.iter().map(|o| o.id.to_string()).collect();
        let mut rng = rand_core::OsRng;

        let receiver_xonly = compressed_to_xonly(receiver_pubkey).ok_or(SdkError::SigningFailed)?;
        let sender_xonly = compressed_to_xonly(sender_pubkey).ok_or(SdkError::SigningFailed)?;

        // -----------------------------------------------------------------
        // Build per-leaf contexts (plain P2TR for field 4) + HTLC data (for field 7)
        // -----------------------------------------------------------------
        let mut leaf_contexts: Vec<LeafTransferContext> =
            Vec::with_capacity(reservation.leaves.len());
        let mut direct_data: Vec<DirectRefundData> = Vec::with_capacity(reservation.leaves.len());

        // HTLC refund txs (for TransferPackage in field 7).
        let mut htlc_cpfp_txs: Vec<bitcoin::Transaction> =
            Vec::with_capacity(reservation.leaves.len());
        let mut htlc_direct_from_cpfp_txs: Vec<bitcoin::Transaction> =
            Vec::with_capacity(reservation.leaves.len());
        let mut htlc_direct_txs: Vec<Option<bitcoin::Transaction>> =
            Vec::with_capacity(reservation.leaves.len());

        for leaf in &reservation.leaves {
            // build_leaf_context produces plain P2TR CPFP refund tx (for field 4).
            let ctx = transfer_core::build_leaf_context(
                &BuildLeafParams {
                    leaf_id: &leaf.id,
                    node_tx: &leaf.node_tx,
                    refund_tx: leaf.refund_tx.as_deref(),
                    vout: leaf.vout,
                    verifying_public_key: leaf.verifying_public_key,
                    receiver_pk: receiver_pubkey,
                    network,
                    num_operators,
                    threshold,
                    operator_ids: &operator_ids,
                },
                signer,
                &mut rng,
                &secp,
            )?;

            let node_tx = parse_tx(&leaf.node_tx).map_err(|_| SdkError::InvalidRequest)?;
            let node_txid = node_tx.compute_txid();

            // Plain P2TR direct refunds (for field 4).
            let old_cpfp_seq = transfer_core::extract_sequence(leaf.refund_tx.as_deref());
            let (_next_cpfp_seq, next_direct_seq) =
                next_send_sequence(old_cpfp_seq).ok_or(SdkError::InvalidRequest)?;

            let direct_from_cpfp_refund_tx = create_direct_refund_tx(
                node_txid,
                leaf.vout,
                ctx.prev_out.value,
                next_direct_seq,
                &receiver_xonly,
                network,
            );

            let (direct_refund_tx, direct_prev_out) = if let Some(ref direct_tx_raw) =
                leaf.direct_tx
            {
                let direct_tx = parse_tx(direct_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
                let dpo = direct_tx
                    .output
                    .first()
                    .ok_or(SdkError::InvalidRequest)?
                    .clone();
                let dtx = create_direct_refund_tx(
                    direct_tx.compute_txid(),
                    0,
                    dpo.value,
                    next_direct_seq,
                    &receiver_xonly,
                    network,
                );
                (Some(dtx), Some(dpo))
            } else {
                (None, None)
            };

            // HTLC refund txs (for TransferPackage in field 7).
            let (htlc_cpfp_seq, htlc_direct_seq) =
                next_htlc_sequence(old_cpfp_seq).ok_or(SdkError::InvalidRequest)?;

            htlc_cpfp_txs.push(create_cpfp_htlc_refund_tx(
                node_txid,
                leaf.vout,
                ctx.prev_out.value,
                htlc_cpfp_seq,
                payment_hash,
                &receiver_xonly,
                &sender_xonly,
                network,
            ));
            htlc_direct_from_cpfp_txs.push(create_direct_htlc_refund_tx(
                node_txid,
                leaf.vout,
                ctx.prev_out.value,
                htlc_direct_seq,
                payment_hash,
                &receiver_xonly,
                &sender_xonly,
                network,
            ));
            if let Some(ref direct_tx_raw) = leaf.direct_tx {
                let direct_tx = parse_tx(direct_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
                let dpo = direct_tx.output.first().ok_or(SdkError::InvalidRequest)?;
                htlc_direct_txs.push(Some(create_direct_htlc_refund_tx(
                    direct_tx.compute_txid(),
                    0,
                    dpo.value,
                    htlc_direct_seq,
                    payment_hash,
                    &receiver_xonly,
                    &sender_xonly,
                    network,
                )));
            } else {
                htlc_direct_txs.push(None);
            }

            let signing_share =
                spark_crypto::frost::deserialize_signing_share(&ctx.current_sk.secret_bytes())
                    .map_err(|_| SdkError::SigningFailed)?;

            let direct_from_cpfp_nonce_pair =
                spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
            let direct_nonce_pair = if direct_refund_tx.is_some() {
                Some(spark_crypto::frost::generate_nonces(
                    &signing_share,
                    &mut rng,
                ))
            } else {
                None
            };

            direct_data.push(DirectRefundData {
                direct_from_cpfp_refund_tx,
                direct_refund_tx,
                direct_prev_out,
                direct_from_cpfp_nonce_pair,
                direct_nonce_pair,
            });

            leaf_contexts.push(ctx);
        }

        // -----------------------------------------------------------------
        // Get signing commitments (6 per leaf: 3 plain + 3 HTLC)
        // -----------------------------------------------------------------
        let node_ids: Vec<String> = leaf_contexts.iter().map(|c| c.leaf_id.clone()).collect();
        let commitments_resp = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids,
                count: 6,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        let n_leaves = leaf_contexts.len();
        let commitments = &commitments_resp.signing_commitments;

        // -----------------------------------------------------------------
        // FROST-sign plain refunds (field 4) + HTLC refunds (field 7)
        //
        // Commitment layout (6 per leaf):
        //   [0..n)    plain CPFP      [n..2n)   plain direct
        //   [2n..3n)  plain dfcpfp    [3n..4n)  HTLC CPFP
        //   [4n..5n)  HTLC direct     [5n..6n)  HTLC dfcpfp
        // -----------------------------------------------------------------
        // -- Plain jobs (field 4) --
        let mut plain_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut plain_direct_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(n_leaves);
        let mut plain_dfcpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(n_leaves);
        // -- HTLC jobs (field 7 TransferPackage) --
        let mut htlc_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut htlc_direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut htlc_dfcpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);

        let signing_share_fn = |ctx: &LeafTransferContext| {
            spark_crypto::frost::deserialize_signing_share(&ctx.current_sk.secret_bytes())
                .map_err(|_| SdkError::SigningFailed)
        };

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let dd = &direct_data[leaf_idx];
            let pk_bytes_fn = || Bytes::copy_from_slice(&ctx.current_pk.serialize());

            // ---- Plain CPFP (index: leaf_idx) ----
            let cpfp_op = commitments
                .get(leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let cpfp_sig = frost_sign_user_share(
                ctx,
                &ctx.cpfp_refund_tx,
                &ctx.cpfp_nonce_pair,
                cpfp_op,
                &ctx.prev_out,
            )?;
            plain_cpfp_jobs.push(build_cpfp_signing_job(ctx, &cpfp_sig, cpfp_op));

            // ---- Plain direct (index: n + leaf_idx) ----
            if let (Some(dtx), Some(dnp), Some(dpo)) = (
                &dd.direct_refund_tx,
                &dd.direct_nonce_pair,
                &dd.direct_prev_out,
            ) {
                let direct_op = commitments
                    .get(n_leaves + leaf_idx)
                    .ok_or(SdkError::InvalidOperatorResponse)?;
                let direct_sig = frost_sign_user_share(ctx, dtx, dnp, direct_op, dpo)?;
                let dc =
                    commitment_to_proto(&dnp.commitment).map_err(|_| SdkError::SigningFailed)?;
                plain_direct_jobs.push(spark::UserSignedTxSigningJob {
                    leaf_id: ctx.leaf_id.clone(),
                    signing_public_key: pk_bytes_fn(),
                    raw_tx: Bytes::from(serialize_tx(dtx)),
                    signing_nonce_commitment: Some(dc),
                    user_signature: Bytes::from(direct_sig),
                    signing_commitments: Some(spark::SigningCommitments {
                        signing_commitments: direct_op.signing_nonce_commitments.clone(),
                    }),
                });
            }

            // ---- Plain direct-from-CPFP (index: 2n + leaf_idx) ----
            let dfcpfp_op = commitments
                .get(2 * n_leaves + leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let dfcpfp_sig = frost_sign_user_share(
                ctx,
                &dd.direct_from_cpfp_refund_tx,
                &dd.direct_from_cpfp_nonce_pair,
                dfcpfp_op,
                &ctx.prev_out,
            )?;
            let dfcpfp_c = commitment_to_proto(&dd.direct_from_cpfp_nonce_pair.commitment)
                .map_err(|_| SdkError::SigningFailed)?;
            plain_dfcpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes_fn(),
                raw_tx: Bytes::from(serialize_tx(&dd.direct_from_cpfp_refund_tx)),
                signing_nonce_commitment: Some(dfcpfp_c),
                user_signature: Bytes::from(dfcpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: dfcpfp_op.signing_nonce_commitments.clone(),
                }),
            });

            // ---- HTLC CPFP (index: 3n + leaf_idx) ----
            let htlc_cpfp_op = commitments
                .get(3 * n_leaves + leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let ss = signing_share_fn(ctx)?;
            let htlc_cpfp_np = spark_crypto::frost::generate_nonces(&ss, &mut rng);
            let htlc_cpfp_sig = frost_sign_user_share(
                ctx,
                &htlc_cpfp_txs[leaf_idx],
                &htlc_cpfp_np,
                htlc_cpfp_op,
                &ctx.prev_out,
            )?;
            let htlc_cpfp_c = commitment_to_proto(&htlc_cpfp_np.commitment)
                .map_err(|_| SdkError::SigningFailed)?;
            htlc_cpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes_fn(),
                raw_tx: Bytes::from(serialize_tx(&htlc_cpfp_txs[leaf_idx])),
                signing_nonce_commitment: Some(htlc_cpfp_c),
                user_signature: Bytes::from(htlc_cpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: htlc_cpfp_op.signing_nonce_commitments.clone(),
                }),
            });

            // ---- HTLC direct (index: 4n + leaf_idx) ----
            if let Some(htlc_dtx) = &htlc_direct_txs[leaf_idx] {
                let htlc_d_op = commitments
                    .get(4 * n_leaves + leaf_idx)
                    .ok_or(SdkError::InvalidOperatorResponse)?;
                let htlc_d_np = spark_crypto::frost::generate_nonces(&ss, &mut rng);
                let dpo = dd
                    .direct_prev_out
                    .as_ref()
                    .ok_or(SdkError::InvalidRequest)?;
                let htlc_d_sig = frost_sign_user_share(ctx, htlc_dtx, &htlc_d_np, htlc_d_op, dpo)?;
                let htlc_d_c = commitment_to_proto(&htlc_d_np.commitment)
                    .map_err(|_| SdkError::SigningFailed)?;
                htlc_direct_jobs.push(spark::UserSignedTxSigningJob {
                    leaf_id: ctx.leaf_id.clone(),
                    signing_public_key: pk_bytes_fn(),
                    raw_tx: Bytes::from(serialize_tx(htlc_dtx)),
                    signing_nonce_commitment: Some(htlc_d_c),
                    user_signature: Bytes::from(htlc_d_sig),
                    signing_commitments: Some(spark::SigningCommitments {
                        signing_commitments: htlc_d_op.signing_nonce_commitments.clone(),
                    }),
                });
            }

            // ---- HTLC direct-from-CPFP (index: 5n + leaf_idx) ----
            let htlc_dfcpfp_op = commitments
                .get(5 * n_leaves + leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let htlc_dfcpfp_np = spark_crypto::frost::generate_nonces(&ss, &mut rng);
            let htlc_dfcpfp_sig = frost_sign_user_share(
                ctx,
                &htlc_direct_from_cpfp_txs[leaf_idx],
                &htlc_dfcpfp_np,
                htlc_dfcpfp_op,
                &ctx.prev_out,
            )?;
            let htlc_dfcpfp_c = commitment_to_proto(&htlc_dfcpfp_np.commitment)
                .map_err(|_| SdkError::SigningFailed)?;
            htlc_dfcpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes_fn(),
                raw_tx: Bytes::from(serialize_tx(&htlc_direct_from_cpfp_txs[leaf_idx])),
                signing_nonce_commitment: Some(htlc_dfcpfp_c),
                user_signature: Bytes::from(htlc_dfcpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: htlc_dfcpfp_op.signing_nonce_commitments.clone(),
                }),
            });
        }

        // -----------------------------------------------------------------
        // Build key tweak package + TransferPackage
        // -----------------------------------------------------------------
        let transfer_id = generate_uuid_v4(&mut rng);
        let key_tweak_package =
            build_key_tweak_package(&leaf_contexts, operators, signer, &transfer_id, &mut rng)?;
        let package_sig = sign_transfer_package(&transfer_id, &key_tweak_package, signer)?;

        // Field 7 TransferPackage: HTLC refund txs.
        let transfer_package = spark::TransferPackage {
            leaves_to_send: htlc_cpfp_jobs,
            direct_leaves_to_send: htlc_direct_jobs,
            direct_from_cpfp_leaves_to_send: htlc_dfcpfp_jobs,
            key_tweak_package,
            user_signature: Bytes::from(package_sig),
            hash_variant: spark::HashVariant::Unspecified as i32,
        };

        // Field 7: StartTransferRequest (carries the HTLC TransferPackage).
        let transfer_request = spark::StartTransferRequest {
            transfer_id: transfer_id.clone(),
            owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
            receiver_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
            transfer_package: Some(transfer_package),
            expiry_time: Some(one_hour_expiry()),
            leaves_to_send: Vec::new(),
            spark_invoice: String::new(),
        };

        // Field 4: StartUserSignedTransferRequest (plain P2TR refund txs).
        let user_signed_transfer = spark::StartUserSignedTransferRequest {
            transfer_id,
            owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
            leaves_to_send: plain_cpfp_jobs,
            receiver_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
            expiry_time: Some(one_hour_expiry()),
            direct_leaves_to_send: plain_direct_jobs,
            direct_from_cpfp_leaves_to_send: plain_dfcpfp_jobs,
        };

        // -----------------------------------------------------------------
        // Submit InitiatePreimageSwapRequest with both fields
        // -----------------------------------------------------------------
        let swap_resp = authed
            .initiate_preimage_swap_v3(spark::InitiatePreimageSwapRequest {
                payment_hash: Bytes::copy_from_slice(payment_hash),
                invoice_amount: Some(spark::InvoiceAmount {
                    value_sats: amount_sats,
                    invoice_amount_proof: Some(spark::InvoiceAmountProof {
                        bolt11_invoice: bolt11.to_owned(),
                    }),
                }),
                reason: spark::initiate_preimage_swap_request::Reason::Send as i32,
                transfer: Some(user_signed_transfer),
                receiver_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                fee_sats: 0,
                transfer_request: Some(transfer_request),
            })
            .await
            .map_err(|e| {
                error!("initiate_preimage_swap_v3 failed: {e}");
                SdkError::TransportFailed
            })?;

        // -----------------------------------------------------------------
        // Parse response
        // -----------------------------------------------------------------
        let preimage = if swap_resp.preimage.len() == 32 {
            let mut buf = [0u8; 32];
            buf.copy_from_slice(&swap_resp.preimage);
            Some(buf)
        } else {
            None
        };

        Ok(PayInvoiceResult {
            preimage,
            transfer: swap_resp.transfer,
        })
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
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(receiver_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        use bitcoin::hashes::{Hash, sha256};
        let payment_hash: [u8; 32] = *sha256::Hash::hash(preimage).as_byte_array();

        // VSS-split preimage.
        let mut rng = rand_core::OsRng;
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let shares = signer
            .vss_split(preimage, threshold, num_operators, &mut rng)
            .map_err(|_| SdkError::SigningFailed)?;

        // Store shares on ALL operators.
        let operator_ids: Vec<String> = self
            .inner
            .transport
            .operator_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();

        for (i, op_id) in operator_ids.iter().enumerate() {
            let op_token = self
                .inner
                .transport
                .session_token(op_id, signer)
                .await
                .map_err(|e| {
                    error!("session_token for operator {op_id} failed: {e}");
                    SdkError::AuthFailed
                })?;
            let op_authed = self.inner.transport.authenticated(&op_token).map_err(|e| {
                error!("authenticated for operator {op_id} failed: {e}");
                SdkError::AuthFailed
            })?;

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

            op_authed
                .store_preimage_share(
                    op_id,
                    spark::StorePreimageShareRequest {
                        payment_hash: Bytes::copy_from_slice(&payment_hash),
                        preimage_share: Some(spark::SecretShare {
                            secret_share: Bytes::copy_from_slice(&share_bytes),
                            proofs,
                        }),
                        threshold: threshold as u32,
                        invoice_string: invoice_string.to_owned(),
                        user_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                    },
                )
                .await
                .map_err(|e| {
                    error!("store_preimage_share for operator {op_id} failed: {e}");
                    SdkError::TransportFailed
                })?;
        }

        Ok(CreateInvoiceResult { payment_hash })
    }
}
