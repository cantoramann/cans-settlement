//! Claim pending BTC transfers.
//!
//! # Claim Flow
//!
//! 1. Query pending transfers from the coordinator
//! 2. For each transfer:
//!    a. Verify sender's ECDSA signature on each leaf
//!    b. ECIES-decrypt `secret_cipher` to recover leaf signing key
//!    c. Compute key tweak (old - new), VSS-split into shares
//!    d. Send shares to ALL operators via `ClaimTransferTweakKeys`
//!    e. Construct new refund transactions, generate FROST nonce commitments
//!    f. Send signing jobs to coordinator via `ClaimTransferSignRefunds`
//!    g. FROST-sign and aggregate refund signatures
//!    h. Finalize with coordinator via `FinalizeNodeSignatures`
//!    i. Insert claimed leaves into tree store
//!
//! # Module Structure
//!
//! - [`verify_decrypt`]: Verify sender signatures, ECIES-decrypt leaf keys
//! - [`key_tweaks`]: Compute key tweaks and distribute VSS shares to operators
//! - [`signing`]: Build refund transactions, FROST sign, and aggregate

mod key_tweaks;
mod signing;
mod verify_decrypt;

use bytes::Bytes;
use signer::WalletSigner;
use transport::{common, spark};

use crate::operations::convert::proto_to_tree_node;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

use signing::{build_signing_data, frost_sign_and_aggregate};
use verify_decrypt::verify_and_decrypt_transfer;

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Response from a claim transfer operation.
pub struct ClaimTransferResult {
    /// Number of leaves claimed across all transfers.
    pub leaves_claimed: usize,
}

// ---------------------------------------------------------------------------
// Sdk::claim_transfer
// ---------------------------------------------------------------------------

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Claim pending BTC transfers addressed to this wallet.
    ///
    /// Queries the coordinator for **all** pending transfers for this
    /// receiver and claims them. Use [`Self::claim_by_transfer_id`] to
    /// claim a specific transfer (e.g. an SSP swap inbound).
    pub async fn claim_transfer(
        &self,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<ClaimTransferResult, SdkError> {
        self.claim_inner(receiver_pubkey, signer, None).await
    }

    /// Claim a specific pending transfer by its transfer ID.
    ///
    /// This is used by the SSP swap flow to claim only the inbound
    /// transfer from the SSP, without affecting other pending transfers.
    pub async fn claim_by_transfer_id(
        &self,
        receiver_pubkey: &IdentityPubKey,
        transfer_id: &str,
        signer: &impl WalletSigner,
    ) -> Result<ClaimTransferResult, SdkError> {
        self.claim_inner(receiver_pubkey, signer, Some(transfer_id))
            .await
    }

    /// Shared claim logic with optional transfer ID filter.
    async fn claim_inner(
        &self,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
        transfer_id: Option<&str>,
    ) -> Result<ClaimTransferResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(receiver_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Query pending transfers.
        let network = crate::network::spark_network_proto(self.inner.config.network.network);
        let transfer_ids = transfer_id
            .map(|id| vec![id.to_owned()])
            .unwrap_or_default();

        let pending = authed
            .query_pending_transfers(spark::TransferFilter {
                participant: Some(
                    spark::transfer_filter::Participant::ReceiverIdentityPublicKey(
                        Bytes::copy_from_slice(receiver_pubkey),
                    ),
                ),
                transfer_ids,
                network,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        if pending.transfers.is_empty() {
            return Ok(ClaimTransferResult { leaves_claimed: 0 });
        }

        let mut total_claimed = 0usize;

        for transfer in &pending.transfers {
            self.check_cancelled()?;

            // Run pre-claim hook chain (no-op when empty).
            self.inner.hooks.run_pre_claim(transfer).await?;

            let claimed = self
                .claim_single_transfer(&authed, transfer, receiver_pubkey, signer)
                .await?;
            total_claimed += claimed;
        }

        Ok(ClaimTransferResult {
            leaves_claimed: total_claimed,
        })
    }

    /// Claim a single pending transfer.
    async fn claim_single_transfer(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        transfer: &spark::Transfer,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<usize, SdkError> {
        let status = transfer.status;

        // 2. Verify and decrypt.
        let claimable = verify_and_decrypt_transfer(transfer, signer)?;
        if claimable.is_empty() {
            return Ok(0);
        }

        // 3. Prepare and apply key tweaks -- only needed when the transfer
        //    is still waiting for the receiver to apply tweaks.
        //    Statuses that indicate tweaks are done:
        //      3 = ReceiverKeyTweaked
        //     10 = ReceiverKeyTweakApplied
        //    Statuses that need tweaks:
        //      2 = SenderKeyTweaked
        let needs_tweak = status == spark::TransferStatus::SenderKeyTweaked as i32;
        if needs_tweak {
            self.prepare_and_apply_key_tweaks(
                authed,
                transfer,
                &claimable,
                receiver_pubkey,
                signer,
            )
            .await?;
        }

        // 4. Sign refunds and finalize.
        self.sign_and_finalize_refunds(authed, transfer, &claimable, receiver_pubkey, signer)
            .await
    }

    /// Step 4: Build signing data, send to coordinator, FROST sign, aggregate, finalize.
    async fn sign_and_finalize_refunds(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        transfer: &spark::Transfer,
        claimable: &[verify_decrypt::ClaimableLeaf],
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<usize, SdkError> {
        let network = crate::network::bitcoin_network(self.inner.config.network.network);

        // Build refund transactions and FROST nonce commitments.
        let (signing_jobs, leaf_signing_data) = build_signing_data(claimable, signer, network)?;

        // Send signing jobs to coordinator.
        let sign_resp = authed
            .claim_transfer_sign_refunds(spark::ClaimTransferSignRefundsRequest {
                transfer_id: transfer.id.clone(),
                owner_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                signing_jobs,
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // FROST sign and aggregate for each leaf.
        let mut node_signatures = Vec::with_capacity(leaf_signing_data.len());
        for signing_result in &sign_resp.signing_results {
            let ctx = leaf_signing_data
                .iter()
                .find(|c| c.leaf_id == signing_result.leaf_id)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let cpfp_refund_sig = frost_sign_and_aggregate(
                ctx,
                &ctx.cpfp_refund_tx,
                &ctx.prev_out,
                &ctx.cpfp_nonce_pair,
                signing_result
                    .refund_tx_signing_result
                    .as_ref()
                    .ok_or(SdkError::InvalidOperatorResponse)?,
                &signing_result.verifying_key,
            )?;

            let direct_refund_sig = if let (Some(result), Some(dtx), Some(dnp), Some(dpo)) = (
                &signing_result.direct_refund_tx_signing_result,
                &ctx.direct_refund_tx,
                &ctx.direct_nonce_pair,
                &ctx.direct_prev_out,
            ) {
                Bytes::from(frost_sign_and_aggregate(
                    ctx,
                    dtx,
                    dpo,
                    dnp,
                    result,
                    &signing_result.verifying_key,
                )?)
            } else {
                Bytes::new()
            };

            let direct_from_cpfp_sig = if let Some(ref result) =
                signing_result.direct_from_cpfp_refund_tx_signing_result
            {
                Bytes::from(frost_sign_and_aggregate(
                    ctx,
                    &ctx.direct_from_cpfp_refund_tx,
                    &ctx.prev_out,
                    &ctx.direct_from_cpfp_nonce_pair,
                    result,
                    &signing_result.verifying_key,
                )?)
            } else {
                Bytes::new()
            };

            node_signatures.push(spark::NodeSignatures {
                node_id: ctx.leaf_id.clone(),
                node_tx_signature: Bytes::new(),
                refund_tx_signature: Bytes::from(cpfp_refund_sig),
                direct_node_tx_signature: Bytes::new(),
                direct_refund_tx_signature: direct_refund_sig,
                direct_from_cpfp_refund_tx_signature: direct_from_cpfp_sig,
            });
        }

        // Finalize with coordinator.
        let finalize_resp = authed
            .finalize_node_signatures(spark::FinalizeNodeSignaturesRequest {
                intent: common::SignatureIntent::Transfer as i32,
                node_signatures,
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // Insert claimed leaves into tree store.
        let mut claimed_nodes = Vec::with_capacity(finalize_resp.nodes.len());
        for proto_node in &finalize_resp.nodes {
            if let Some(node) = proto_to_tree_node(proto_node) {
                claimed_nodes.push(node);
            }
        }

        let claimed_count = claimed_nodes.len();
        if !claimed_nodes.is_empty() {
            self.inner
                .tree_store
                .insert_leaves(&claimed_nodes)
                .map_err(|_| SdkError::StoreFailed)?;
        }

        Ok(claimed_count)
    }
}
