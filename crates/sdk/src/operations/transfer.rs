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
//! See [`crate::operations::claim`] for the claim (receive) flow.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::bitcoin_tx::{compressed_to_xonly, create_direct_refund_tx, parse_tx, serialize_tx};
use crate::frost_bridge::commitment_to_proto;
use crate::network::bitcoin_network;
use crate::operations::transfer_core::{
    self, BuildLeafParams, LeafTransferContext, build_cpfp_signing_job, build_key_tweak_package,
    frost_sign_user_share, generate_uuid_v4, next_send_sequence, one_hour_expiry,
    sign_transfer_package,
};
use crate::tree::{TreeStore, select_leaves_greedy};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Response from a send transfer operation.
pub struct SendTransferResult {
    /// The transfer proto returned by the coordinator.
    pub transfer: Option<spark::Transfer>,
}

// ---------------------------------------------------------------------------
// Transfer-specific: direct refund data layered on top of LeafTransferContext
// ---------------------------------------------------------------------------

/// Additional per-leaf data for direct refund paths (not used by SSP swaps).
struct DirectRefundData {
    /// Direct-from-CPFP refund transaction.
    direct_from_cpfp_refund_tx: bitcoin::Transaction,
    /// Direct refund transaction (if direct_tx exists on the leaf).
    direct_refund_tx: Option<bitcoin::Transaction>,
    /// Prev out from direct_tx (for direct sighash), if present.
    direct_prev_out: Option<bitcoin::TxOut>,
    /// FROST nonces for direct-from-CPFP refund.
    direct_from_cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    /// FROST nonces for direct refund (if applicable).
    direct_nonce_pair: Option<spark_crypto::frost::FrostNoncePair>,
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
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

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
            let (re_selected, _re_total) = select_leaves_greedy(&refreshed, amount_sats)
                .ok_or(SdkError::InsufficientBalance)?;

            let leaf_ids: Vec<&str> = re_selected.iter().map(|l| l.id.as_str()).collect();
            let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

            let result = self
                .send_transfer_inner(
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
        let result = self
            .send_transfer_inner(
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

    /// Inner send logic, separated for clean reservation error handling.
    async fn send_transfer_inner(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        reservation: &crate::tree::LeafReservation,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
        network: bitcoin::Network,
    ) -> Result<SendTransferResult, SdkError> {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let operator_ids: Vec<String> = operators.iter().map(|o| o.id.to_string()).collect();
        let mut rng = rand_core::OsRng;

        // Receiver xonly for direct refunds.
        let receiver_xonly = compressed_to_xonly(receiver_pubkey).ok_or(SdkError::SigningFailed)?;

        // 2. Build per-leaf contexts (shared) + direct refund data (transfer-specific).
        let mut leaf_contexts: Vec<LeafTransferContext> =
            Vec::with_capacity(reservation.leaves.len());
        let mut direct_data: Vec<DirectRefundData> = Vec::with_capacity(reservation.leaves.len());

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

            // Build direct refund txs (transfer-specific, not needed for swaps).
            let node_tx = parse_tx(&leaf.node_tx).map_err(|_| SdkError::InvalidRequest)?;
            let node_txid = node_tx.compute_txid();

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

            // Generate additional FROST nonces for direct refund paths.
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

        let n_leaves = leaf_contexts.len();
        let commitments = &commitments_resp.signing_commitments;

        // 4. Build UserSignedTxSigningJobs with FROST signatures.
        let mut cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut direct_from_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(n_leaves);

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let dd = &direct_data[leaf_idx];

            // CPFP refund: commitment at index (0 * n_leaves + leaf_idx).
            let cpfp_op_commitments = commitments
                .get(leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let cpfp_sig = frost_sign_user_share(
                ctx,
                &ctx.cpfp_refund_tx,
                &ctx.cpfp_nonce_pair,
                cpfp_op_commitments,
                &ctx.prev_out,
            )?;

            cpfp_jobs.push(build_cpfp_signing_job(ctx, &cpfp_sig, cpfp_op_commitments));

            // Direct refund: commitment at index (1 * n_leaves + leaf_idx).
            let direct_commitment_idx = n_leaves + leaf_idx;
            if let (Some(dtx), Some(dnp), Some(dpo)) = (
                &dd.direct_refund_tx,
                &dd.direct_nonce_pair,
                &dd.direct_prev_out,
            ) {
                let direct_op_commitments = commitments
                    .get(direct_commitment_idx)
                    .ok_or(SdkError::InvalidOperatorResponse)?;

                let direct_sig = frost_sign_user_share(ctx, dtx, dnp, direct_op_commitments, dpo)?;

                let pk_bytes = Bytes::copy_from_slice(&ctx.current_pk.serialize());
                let direct_user_commitment =
                    commitment_to_proto(&dnp.commitment).map_err(|_| SdkError::SigningFailed)?;

                direct_jobs.push(spark::UserSignedTxSigningJob {
                    leaf_id: ctx.leaf_id.clone(),
                    signing_public_key: pk_bytes,
                    raw_tx: Bytes::from(serialize_tx(dtx)),
                    signing_nonce_commitment: Some(direct_user_commitment),
                    user_signature: Bytes::from(direct_sig),
                    signing_commitments: Some(spark::SigningCommitments {
                        signing_commitments: direct_op_commitments
                            .signing_nonce_commitments
                            .clone(),
                    }),
                });
            }

            // Direct-from-CPFP refund: commitment at index (2 * n_leaves + leaf_idx).
            let dfcpfp_commitment_idx = 2 * n_leaves + leaf_idx;
            let dfcpfp_op_commitments = commitments
                .get(dfcpfp_commitment_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let dfcpfp_sig = frost_sign_user_share(
                ctx,
                &dd.direct_from_cpfp_refund_tx,
                &dd.direct_from_cpfp_nonce_pair,
                dfcpfp_op_commitments,
                &ctx.prev_out,
            )?;

            let pk_bytes = Bytes::copy_from_slice(&ctx.current_pk.serialize());
            let dfcpfp_user_commitment =
                commitment_to_proto(&dd.direct_from_cpfp_nonce_pair.commitment)
                    .map_err(|_| SdkError::SigningFailed)?;

            direct_from_cpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes,
                raw_tx: Bytes::from(serialize_tx(&dd.direct_from_cpfp_refund_tx)),
                signing_nonce_commitment: Some(dfcpfp_user_commitment),
                user_signature: Bytes::from(dfcpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: dfcpfp_op_commitments.signing_nonce_commitments.clone(),
                }),
            });
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
}
