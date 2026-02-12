//! SSP leaf swap: exchange oversized leaves for exact-denomination leaves.
//!
//! # SSP Swap Flow
//!
//! When `select_leaves_greedy` picks leaves whose total exceeds the
//! transfer amount, the excess must be returned as change.  Spark leaves
//! are indivisible, so we swap them through the SSP:
//!
//! 1. **Adaptor key**: Generate a random adaptor secret `t` and compute
//!    `T = t * G`.  This binds the swap atomically.
//! 2. **Transfer to SSP**: Build the same two-phase transfer as
//!    [`send_transfer`](super::transfer), but:
//!    - The receiver is the SSP's identity public key.
//!    - We call `initiate_swap_primary_transfer` (not `start_transfer_v2`),
//!      passing the adaptor public key package.
//! 3. **Request swap**: Call the SSP GraphQL API with the adaptor pubkey,
//!    leaf metadata, and desired output denominations.
//! 4. **Claim inbound**: Poll for the SSP's inbound transfer and claim it.
//!    Returns the newly claimed `TreeNode`s (already inserted into the tree
//!    store).
//!
//! The adaptor signature scheme ensures atomicity: the SSP can only
//! complete the outbound transfer by revealing the adaptor secret,
//! which the user can then use to claim the inbound transfer.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::bitcoin_tx::{compressed_to_xonly, serialize_tx, taproot_sighash};
use crate::operations::btc::transfer_core::{
    BuildLeafParams, build_cpfp_signing_job, build_key_tweak_package,
    frost_sign_user_share_with_adaptor, generate_uuid_v4, hex_encode, one_hour_expiry,
    sign_transfer_package,
};
use crate::ssp::{RequestSwapInput, SSP_SWAP_FEE_SATS, SspClient, UserLeafInput};
use crate::tree::{TreeNode, TreeStore};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Maximum number of claim attempts when waiting for the SSP's inbound transfer.
const SSP_CLAIM_MAX_ATTEMPTS: u32 = 10;

/// Initial delay between claim attempts (doubles on each retry).
const SSP_CLAIM_INITIAL_DELAY_MS: u64 = 500;

// ---------------------------------------------------------------------------
// Sdk::ssp_swap
// ---------------------------------------------------------------------------

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: SspClient,
{
    /// Swap leaves through the SSP to produce exact-denomination outputs.
    ///
    /// Sends the provided `leaves` to the SSP, requests new leaves matching
    /// `target_amounts`, then claims the SSP's inbound transfer. The claimed
    /// leaves are inserted into the tree store and returned.
    ///
    /// This is a self-contained operation: callers receive usable
    /// `TreeNode`s and do not need to call claim separately.
    pub async fn ssp_swap(
        &self,
        sender_pubkey: &IdentityPubKey,
        leaves: &[&TreeNode],
        target_amounts: &[u64],
        signer: &impl WalletSigner,
    ) -> Result<Vec<TreeNode>, SdkError> {
        self.check_cancelled()?;

        let authed = self.authenticate(signer).await?;
        let network = crate::network::bitcoin_network(self.inner.config.network.network);
        let secp = Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let ssp_pk = self.inner.ssp.identity_public_key();
        let operator_ids: Vec<&'static str> = operators.iter().map(|o| o.id).collect();
        let mut rng = rand_core::OsRng;

        // 1. Generate adaptor secret and public key.
        let mut adaptor_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut adaptor_bytes);
        let adaptor_sk =
            SecretKey::from_slice(&adaptor_bytes).expect("32 random bytes always valid");
        let adaptor_pk = PublicKey::from_secret_key(&secp, &adaptor_sk);
        let adaptor_pk_hex = hex_encode(&adaptor_pk.serialize());

        // SSP identity key as xonly for refund outputs.
        let ssp_pk_bytes = ssp_pk.serialize();
        compressed_to_xonly(&ssp_pk_bytes).ok_or(SdkError::SspSwapFailed)?;

        // 2. Build per-leaf transfer contexts using shared logic.
        let total_sats: u64 = leaves.iter().map(|l| l.value).sum();
        let mut leaf_contexts = Vec::with_capacity(leaves.len());

        for leaf in leaves {
            let ctx = crate::operations::btc::transfer_core::build_leaf_context(
                &BuildLeafParams {
                    leaf_id: &leaf.id,
                    node_tx: &leaf.node_tx,
                    refund_tx: leaf.refund_tx.as_deref(),
                    vout: leaf.vout,
                    verifying_public_key: leaf.verifying_public_key,
                    receiver_pk: &ssp_pk_bytes,
                    network,
                    num_operators,
                    threshold,
                    operator_ids: &operator_ids,
                },
                signer,
                &mut rng,
                &secp,
            )?;
            leaf_contexts.push(ctx);
        }

        // 3. Get signing commitments.
        //    Swap primary transfers only need CPFP refund signatures (count=1).
        let node_ids: Vec<String> = leaf_contexts.iter().map(|c| c.leaf_id.clone()).collect();
        let commitments_resp = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids,
                count: 1,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        let commitments = &commitments_resp.signing_commitments;

        // 4. Build CPFP-only signing jobs with adaptor signatures.
        //    Save each user's serialized signature share for reuse during
        //    aggregation (step 10). Nonces are one-time-use, so we cannot
        //    re-sign -- we must reuse the exact same share.
        let mut cpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(leaf_contexts.len());
        let mut user_share_bytes: Vec<Vec<u8>> = Vec::with_capacity(leaf_contexts.len());

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let cpfp_op_commitments = commitments
                .get(leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let sig_bytes = frost_sign_user_share_with_adaptor(
                ctx,
                &ctx.cpfp_refund_tx,
                &ctx.cpfp_nonce_pair,
                cpfp_op_commitments,
                &ctx.prev_out,
                &adaptor_pk,
            )?;

            user_share_bytes.push(sig_bytes.clone());
            cpfp_jobs.push(build_cpfp_signing_job(ctx, &sig_bytes, cpfp_op_commitments));
        }

        // 5. Build key_tweak_package.
        let transfer_id = generate_uuid_v4(&mut rng);
        let key_tweak_package =
            build_key_tweak_package(&leaf_contexts, operators, signer, &transfer_id, &mut rng)?;

        // 6. Package signature.
        let package_sig = sign_transfer_package(&transfer_id, &key_tweak_package, signer)?;

        // 7. Assemble TransferPackage.
        //    For swap primary transfers, the coordinator only accepts CPFP
        //    refund jobs. Direct and direct-from-CPFP must be empty.
        let transfer_package = spark::TransferPackage {
            leaves_to_send: cpfp_jobs,
            direct_leaves_to_send: Vec::new(),
            direct_from_cpfp_leaves_to_send: Vec::new(),
            key_tweak_package,
            user_signature: Bytes::from(package_sig),
            hash_variant: spark::HashVariant::Unspecified as i32,
        };

        let start_request = spark::StartTransferRequest {
            transfer_id: transfer_id.clone(),
            owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
            receiver_identity_public_key: Bytes::copy_from_slice(&ssp_pk_bytes),
            transfer_package: Some(transfer_package),
            expiry_time: Some(one_hour_expiry()),
            leaves_to_send: Vec::new(),
            spark_invoice: String::new(),
        };

        // 8. Adaptor public key package.
        let adaptor_pk_compressed = Bytes::copy_from_slice(&adaptor_pk.serialize());
        let adaptor_keys = spark::AdaptorPublicKeyPackage {
            adaptor_public_key: adaptor_pk_compressed.clone(),
            direct_adaptor_public_key: adaptor_pk_compressed.clone(),
            direct_from_cpfp_adaptor_public_key: adaptor_pk_compressed,
        };

        // 9. Submit via initiate_swap_primary_transfer.
        let swap_coordinator_resp = authed
            .initiate_swap_primary_transfer(spark::InitiateSwapPrimaryTransferRequest {
                transfer: Some(start_request),
                adaptor_public_keys: Some(adaptor_keys),
            })
            .await
            .map_err(|_| SdkError::SspSwapFailed)?;

        // 10. Aggregate FROST signatures: combine operator shares from the
        //     coordinator response with the user's shares (saved from step 4)
        //     to produce the final adaptor CPFP refund signatures per leaf.
        let mut user_leaves: Vec<UserLeafInput> = Vec::with_capacity(leaf_contexts.len());
        let user_id = spark_crypto::frost::user_identifier();

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let signing_result = swap_coordinator_resp
                .signing_results
                .iter()
                .find(|r| r.leaf_id == ctx.leaf_id)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let cpfp_signing = signing_result
                .refund_tx_signing_result
                .as_ref()
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let op_data = crate::frost_bridge::parse_signing_result(cpfp_signing)?;

            let mut all_commitments = op_data.commitments;
            all_commitments.insert(user_id, ctx.cpfp_nonce_pair.commitment);

            let user_share =
                spark_crypto::frost::deserialize_signature_share(&user_share_bytes[leaf_idx])
                    .map_err(|_| SdkError::SigningFailed)?;
            let mut all_shares = op_data.signature_shares;
            all_shares.insert(user_id, user_share);

            let verifying_key = PublicKey::from_slice(&ctx.verifying_public_key)
                .map_err(|_| SdkError::InvalidRequest)?;

            let cpfp_sighash =
                taproot_sighash(&ctx.cpfp_refund_tx, 0, std::slice::from_ref(&ctx.prev_out))
                    .map_err(|_| SdkError::SigningFailed)?;

            let frost_sig = spark_crypto::frost::aggregate_nested_with_adaptor(
                &cpfp_sighash,
                all_commitments,
                &all_shares,
                &op_data.verifying_shares,
                &verifying_key,
                &adaptor_pk,
            )
            .map_err(|_| SdkError::SigningFailed)?;

            let sig_bytes = crate::frost_bridge::serialize_frost_signature(&frost_sig)?;

            user_leaves.push(UserLeafInput {
                leaf_id: ctx.leaf_id.clone(),
                raw_unsigned_refund_transaction: hex_encode(&serialize_tx(&ctx.cpfp_refund_tx)),
                adaptor_added_signature: hex_encode(&sig_bytes),
            });
        }

        // 11. Authenticate with the SSP, then call the swap API.
        let identity_compressed = signer.identity_public_key_compressed();
        let identity_hex = hex_encode(&identity_compressed);

        let sign_fn = |bytes: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            signer.sign_challenge(bytes)
        };

        let auth_token = self.inner.ssp.authenticate(&identity_hex, &sign_fn).await?;

        let swap_resp = self
            .inner
            .ssp
            .request_swap(RequestSwapInput {
                adaptor_pubkey: adaptor_pk_hex,
                total_amount_sats: total_sats,
                target_amount_sats: target_amounts.to_vec(),
                fee_sats: SSP_SWAP_FEE_SATS,
                user_leaves,
                user_outbound_transfer_external_id: transfer_id,
                auth_token,
            })
            .await?;

        let inbound_id = &swap_resp.inbound_transfer_id;
        tracing::info!(transfer_id = %inbound_id, "SSP swap submitted, claiming inbound transfer");

        // 12. Poll for the SSP's inbound transfer and claim it.
        //     The SSP may need a moment to create the inbound transfer after
        //     `request_swap` returns, so we retry with exponential backoff.
        let mut delay_ms = SSP_CLAIM_INITIAL_DELAY_MS;

        for attempt in 1..=SSP_CLAIM_MAX_ATTEMPTS {
            self.check_cancelled()?;

            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;

            let claim_result = self
                .claim_by_transfer_id(sender_pubkey, inbound_id, signer)
                .await?;

            if claim_result.leaves_claimed > 0 {
                tracing::info!(
                    leaves = claim_result.leaves_claimed,
                    attempt,
                    "SSP swap inbound claimed"
                );

                // Return the freshly claimed leaves from the tree store.
                let all_leaves = self.inner.tree_store.get_available_leaves()?;
                return Ok(all_leaves);
            }

            tracing::debug!(attempt, delay_ms, "SSP inbound not ready, retrying");
            delay_ms = (delay_ms * 2).min(5_000);
        }

        tracing::error!(
            transfer_id = %inbound_id,
            "SSP inbound transfer not claimable after {} attempts",
            SSP_CLAIM_MAX_ATTEMPTS
        );
        Err(SdkError::SspSwapFailed)
    }
}
