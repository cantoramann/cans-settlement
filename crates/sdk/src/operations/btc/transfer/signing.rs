//! FROST signing loop, job assembly, and coordinator submission for
//! BTC send transfers.
//!
//! Builds per-leaf signing contexts (CPFP + direct + direct-from-CPFP),
//! gets operator commitments, FROST-signs all refund variants, assembles
//! the `TransferPackage`, and submits via `start_transfer_v2`.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::bitcoin_tx::compressed_to_xonly;
use crate::operations::btc::transfer_core::{
    self, BuildDirectRefundParams, BuildLeafParams, LeafTransferContext, build_cpfp_signing_job,
    build_direct_signing_job, build_key_tweak_package, frost_sign_user_share, generate_uuid_v4,
    next_send_sequence, one_hour_expiry, sign_transfer_package,
};
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

use super::SendTransferResult;

/// Inner send logic, separated for clean reservation error handling.
///
/// Builds leaf contexts, FROST-signs all refund variants, assembles the
/// `TransferPackage`, and submits to the coordinator.
pub(super) async fn send_transfer_inner<W, T, K, S>(
    sdk: &Sdk<W, T, K, S>,
    authed: &transport::grpc::AuthenticatedTransport<'_>,
    reservation: &crate::tree::LeafReservation,
    sender_pubkey: &IdentityPubKey,
    receiver_pubkey: &IdentityPubKey,
    signer: &impl WalletSigner,
    network: bitcoin::Network,
) -> Result<SendTransferResult, SdkError>
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

    // Receiver xonly for direct refunds.
    let receiver_xonly = compressed_to_xonly(receiver_pubkey).ok_or(SdkError::SigningFailed)?;

    // 2. Build per-leaf contexts (shared) + direct refund data.
    let n_leaves = reservation.leaves.len();
    let mut leaf_contexts: Vec<LeafTransferContext> = Vec::with_capacity(n_leaves);
    let mut direct_data: Vec<transfer_core::DirectRefundData> = Vec::with_capacity(n_leaves);

    for leaf in &reservation.leaves {
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

        leaf_contexts.push(ctx);
        direct_data.push(dd);
    }

    // 3. Get signing commitments from coordinator.
    //    count = 3: one for CPFP, one for direct, one for direct-from-CPFP.
    let node_ids: Vec<String> = leaf_contexts.iter().map(|c| c.leaf_id.clone()).collect();
    let commitments_resp = authed
        .get_signing_commitments(spark::GetSigningCommitmentsRequest {
            node_ids,
            count: 3,
            ..Default::default()
        })
        .await
        .map_err(|_| SdkError::TransportFailed)?;

    let commitments = &commitments_resp.signing_commitments;

    // 4. Build UserSignedTxSigningJobs with FROST signatures.
    let mut cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    let mut direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
    let mut direct_from_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
        Vec::with_capacity(n_leaves);

    for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
        let dd = &direct_data[leaf_idx];

        // CPFP refund: commitment at index (0 * n_leaves + leaf_idx).
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

        cpfp_jobs.push(build_cpfp_signing_job(ctx, &cpfp_sig, cpfp_op));

        // Direct refund: commitment at index (1 * n_leaves + leaf_idx).
        if let (Some(dtx), Some(dnp), Some(dpo)) = (
            &dd.direct_refund_tx,
            &dd.direct_nonce_pair,
            &dd.direct_prev_out,
        ) {
            let direct_op = commitments
                .get(n_leaves + leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let direct_sig = frost_sign_user_share(ctx, dtx, dnp, direct_op, dpo)?;
            direct_jobs.push(build_direct_signing_job(
                ctx,
                dtx,
                dnp,
                &direct_sig,
                direct_op,
            ));
        }

        // Direct-from-CPFP refund: commitment at index (2 * n_leaves + leaf_idx).
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

        direct_from_cpfp_jobs.push(build_direct_signing_job(
            ctx,
            &dd.direct_from_cpfp_refund_tx,
            &dd.direct_from_cpfp_nonce_pair,
            &dfcpfp_sig,
            dfcpfp_op,
        ));
    }

    // 5. Build key_tweak_package.
    let transfer_id = generate_uuid_v4(&mut rng);
    let key_tweak_package =
        build_key_tweak_package(&leaf_contexts, operators, signer, &transfer_id, &mut rng)?;

    // 6. Sign the transfer package.
    let package_sig = sign_transfer_package(&transfer_id, &key_tweak_package, signer)?;

    // 7. Assemble TransferPackage.
    let transfer_package = spark::TransferPackage {
        leaves_to_send: cpfp_jobs,
        direct_leaves_to_send: direct_jobs,
        direct_from_cpfp_leaves_to_send: direct_from_cpfp_jobs,
        key_tweak_package,
        user_signature: Bytes::from(package_sig),
        hash_variant: spark::HashVariant::Unspecified as i32,
    };

    // 8. Build and submit StartTransferRequest.
    let transfer_resp = authed
        .start_transfer_v2(spark::StartTransferRequest {
            transfer_id: transfer_id.clone(),
            owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
            receiver_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
            transfer_package: Some(transfer_package),
            expiry_time: Some(one_hour_expiry()),
            leaves_to_send: Vec::new(),
            spark_invoice: String::new(),
        })
        .await
        .map_err(|_| SdkError::TransportFailed)?;

    Ok(SendTransferResult {
        transfer: transfer_resp.transfer,
    })
}
