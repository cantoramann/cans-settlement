//! Inner pay-invoice logic: HTLC + plain refund construction, dual FROST
//! signing loop, and `initiate_preimage_swap_v3` submission.
//!
//! The coordinator validates two independent paths:
//! - **Field 4** (`StartUserSignedTransferRequest`): plain P2TR refund txs,
//!   validated by `ValidateGetPreimageRequest`.
//! - **Field 7** (`StartTransferRequest.transfer_package`): HTLC refund txs,
//!   validated by `buildHtlcRefundMaps`.
//!
//! This module builds both sets, signs them with FROST, and submits them.

use bytes::Bytes;
use signer::WalletSigner;
use tracing::error;
use transport::spark;

use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_htlc_refund_tx, create_direct_htlc_refund_tx, parse_tx,
    serialize_tx,
};
use crate::frost_bridge::commitment_to_proto;
use crate::operations::btc::transfer_core::{
    self, BuildDirectRefundParams, BuildLeafParams, LeafTransferContext, build_cpfp_signing_job,
    build_direct_signing_job, build_key_tweak_package, frost_sign_user_share, generate_uuid_v4,
    next_htlc_sequence, next_send_sequence, one_hour_expiry, sign_transfer_package,
};
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

use super::PayInvoiceResult;

/// Build both field-4 (plain P2TR) and field-7 (HTLC) refund transactions,
/// FROST-sign all variants, and submit the preimage swap.
#[allow(clippy::too_many_arguments)]
pub(super) async fn pay_invoice_inner<W, T, K, S>(
    sdk: &Sdk<W, T, K, S>,
    authed: &transport::grpc::AuthenticatedTransport<'_>,
    reservation: &crate::tree::LeafReservation,
    sender_pubkey: &IdentityPubKey,
    receiver_pubkey: &IdentityPubKey,
    payment_hash: &[u8; 32],
    amount_sats: u64,
    bolt11: &str,
    signer: &impl WalletSigner,
    network: bitcoin::Network,
) -> Result<PayInvoiceResult, SdkError>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let num_operators = sdk.inner.config.network.num_operators();
    let threshold = sdk.inner.config.network.threshold;
    let operators = sdk.inner.config.network.operators();
    let operator_ids: Vec<&'static str> = operators.iter().map(|o| o.id).collect();
    let mut rng = rand_core::OsRng;

    let receiver_xonly = compressed_to_xonly(receiver_pubkey).ok_or(SdkError::SigningFailed)?;
    let sender_xonly = compressed_to_xonly(sender_pubkey).ok_or(SdkError::SigningFailed)?;

    // -----------------------------------------------------------------
    // Build per-leaf contexts (plain P2TR for field 4) + HTLC data (for field 7)
    // -----------------------------------------------------------------
    let n_leaves = reservation.leaves.len();
    let mut leaf_contexts: Vec<LeafTransferContext> = Vec::with_capacity(n_leaves);
    let mut direct_data: Vec<transfer_core::DirectRefundData> = Vec::with_capacity(n_leaves);

    // HTLC refund txs (for TransferPackage in field 7).
    let mut htlc_cpfp_txs: Vec<bitcoin::Transaction> = Vec::with_capacity(n_leaves);
    let mut htlc_dfcpfp_txs: Vec<bitcoin::Transaction> = Vec::with_capacity(n_leaves);
    let mut htlc_direct_txs: Vec<Option<bitcoin::Transaction>> = Vec::with_capacity(n_leaves);

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

        let dd = transfer_core::build_direct_refund_data(
            &BuildDirectRefundParams {
                node_tx: &leaf.node_tx,
                vout: leaf.vout,
                prev_out_value: ctx.prev_out.value,
                direct_tx: leaf.direct_tx.as_deref(),
                next_direct_seq,
                receiver_xonly: &receiver_xonly,
                network,
            },
            &ctx.current_sk,
            &mut rng,
        )?;

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
        htlc_dfcpfp_txs.push(create_direct_htlc_refund_tx(
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

        leaf_contexts.push(ctx);
        direct_data.push(dd);
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
    let mut plain_direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    let mut plain_dfcpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    // -- HTLC jobs (field 7 TransferPackage) --
    let mut htlc_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    let mut htlc_direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    let mut htlc_dfcpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);

    for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
        let dd = &direct_data[leaf_idx];

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
            plain_direct_jobs.push(build_direct_signing_job(
                ctx,
                dtx,
                dnp,
                &direct_sig,
                direct_op,
            ));
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
        plain_dfcpfp_jobs.push(build_direct_signing_job(
            ctx,
            &dd.direct_from_cpfp_refund_tx,
            &dd.direct_from_cpfp_nonce_pair,
            &dfcpfp_sig,
            dfcpfp_op,
        ));

        // ---- HTLC CPFP (index: 3n + leaf_idx) ----
        let htlc_cpfp_op = commitments
            .get(3 * n_leaves + leaf_idx)
            .ok_or(SdkError::InvalidOperatorResponse)?;
        let signing_share =
            spark_crypto::frost::deserialize_signing_share(&ctx.current_sk.secret_bytes())
                .map_err(|_| SdkError::SigningFailed)?;
        let htlc_cpfp_np = spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
        let htlc_cpfp_sig = frost_sign_user_share(
            ctx,
            &htlc_cpfp_txs[leaf_idx],
            &htlc_cpfp_np,
            htlc_cpfp_op,
            &ctx.prev_out,
        )?;
        let htlc_cpfp_c =
            commitment_to_proto(&htlc_cpfp_np.commitment).map_err(|_| SdkError::SigningFailed)?;
        htlc_cpfp_jobs.push(spark::UserSignedTxSigningJob {
            leaf_id: ctx.leaf_id.clone(),
            signing_public_key: Bytes::copy_from_slice(&ctx.current_pk.serialize()),
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
            let htlc_d_np = spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
            let dpo = dd
                .direct_prev_out
                .as_ref()
                .ok_or(SdkError::InvalidRequest)?;
            let htlc_d_sig = frost_sign_user_share(ctx, htlc_dtx, &htlc_d_np, htlc_d_op, dpo)?;
            let htlc_d_c =
                commitment_to_proto(&htlc_d_np.commitment).map_err(|_| SdkError::SigningFailed)?;
            htlc_direct_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: Bytes::copy_from_slice(&ctx.current_pk.serialize()),
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
        let htlc_dfcpfp_np = spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
        let htlc_dfcpfp_sig = frost_sign_user_share(
            ctx,
            &htlc_dfcpfp_txs[leaf_idx],
            &htlc_dfcpfp_np,
            htlc_dfcpfp_op,
            &ctx.prev_out,
        )?;
        let htlc_dfcpfp_c =
            commitment_to_proto(&htlc_dfcpfp_np.commitment).map_err(|_| SdkError::SigningFailed)?;
        htlc_dfcpfp_jobs.push(spark::UserSignedTxSigningJob {
            leaf_id: ctx.leaf_id.clone(),
            signing_public_key: Bytes::copy_from_slice(&ctx.current_pk.serialize()),
            raw_tx: Bytes::from(serialize_tx(&htlc_dfcpfp_txs[leaf_idx])),
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
