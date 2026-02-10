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

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use signer::WalletSigner;
use transport::{common, spark};

use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_refund_tx, create_direct_refund_tx, parse_tx, serialize_tx,
    taproot_sighash,
};
use crate::frost_bridge::{commitment_to_proto, parse_signing_result, serialize_frost_signature};
use crate::operations::convert::proto_to_tree_node;
use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Response from a claim transfer operation.
pub struct ClaimTransferResult {
    /// Number of leaves claimed across all transfers.
    pub leaves_claimed: usize,
}

// ---------------------------------------------------------------------------
// Internal: claimable leaf data
// ---------------------------------------------------------------------------

/// Decrypted leaf data ready for claiming.
#[allow(dead_code)] // Fields reserved for direct/CPFP refund paths.
struct ClaimableLeaf {
    /// Leaf ID (UUID string).
    leaf_id: String,
    /// Value in satoshis.
    value: u64,
    /// Raw node transaction bytes (the tx being spent by the refund).
    node_tx_raw: Vec<u8>,
    /// Sequence from the CPFP refund tx (determines timelock).
    cpfp_refund_sequence: u32,
    /// Sequence from the direct-from-CPFP refund tx (may differ in encoding).
    direct_from_cpfp_refund_sequence: u32,
    /// Sequence from the direct refund tx.
    direct_refund_sequence: u32,
    /// Raw direct_tx bytes (separate tx for direct spend path).
    direct_tx_raw: Vec<u8>,
    /// The verifying (group aggregate) public key for FROST.
    verifying_public_key: [u8; 33],
    /// The signing secret key decrypted from ECIES (the sender's ephemeral key).
    decrypted_signing_key: SecretKey,
    /// Output index on the node tx.
    vout: u32,
    /// Whether intermediate direct refund tx exists.
    has_direct: bool,
    /// Whether intermediate direct-from-CPFP refund tx exists.
    has_direct_from_cpfp: bool,
}

// ---------------------------------------------------------------------------
// Sdk::claim_transfer
// ---------------------------------------------------------------------------

impl<W, T, K> Sdk<W, T, K>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
{
    /// Claim pending BTC transfers addressed to this wallet.
    ///
    /// Queries the coordinator for pending transfers, decrypts the leaf keys,
    /// rotates the FROST keyshares, signs new refund transactions, and
    /// finalizes the claim. Claimed leaves are inserted into the tree store.
    pub async fn claim_transfer(
        &self,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<ClaimTransferResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(receiver_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Query pending transfers.
        let network = spark_network_proto(self.inner.config.network.network);
        let pending = authed
            .query_pending_transfers(spark::TransferFilter {
                participant: Some(
                    spark::transfer_filter::Participant::ReceiverIdentityPublicKey(
                        Bytes::copy_from_slice(receiver_pubkey),
                    ),
                ),
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

    /// Step 3: Compute key tweaks, VSS-split, and send to all operators.
    async fn prepare_and_apply_key_tweaks(
        &self,
        _authed: &transport::grpc::AuthenticatedTransport<'_>,
        transfer: &spark::Transfer,
        claimable: &[ClaimableLeaf],
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<(), SdkError> {
        let secp = Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let mut rng = rand::thread_rng();

        // Build per-operator ClaimLeafKeyTweak lists.
        let mut per_operator_tweaks: Vec<Vec<spark::ClaimLeafKeyTweak>> =
            vec![Vec::new(); num_operators];

        for leaf in claimable {
            let (new_sk, _new_pk) = signer
                .derive_signing_keypair(&leaf.leaf_id)
                .map_err(|_| SdkError::SigningFailed)?;

            // key_tweak = decrypted_signing_key - new_signing_key
            let key_tweak = signer
                .subtract_secret_keys(&leaf.decrypted_signing_key, &new_sk)
                .map_err(|_| SdkError::SigningFailed)?;

            let shares = signer
                .vss_split(
                    &key_tweak.secret_bytes(),
                    threshold,
                    num_operators,
                    &mut rng,
                )
                .map_err(|_| SdkError::SigningFailed)?;

            // pubkey_shares_tweak: operator identifier -> compressed public key of share.
            let mut pubkey_shares_tweak = std::collections::HashMap::new();
            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let share_sk =
                    SecretKey::from_slice(&share_bytes).map_err(|_| SdkError::SigningFailed)?;
                let share_pk = PublicKey::from_secret_key(&secp, &share_sk);
                let op_identifier = operators[i].id.to_string();
                pubkey_shares_tweak
                    .insert(op_identifier, Bytes::copy_from_slice(&share_pk.serialize()));
            }

            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let proofs: Vec<Bytes> = share
                    .proofs
                    .iter()
                    .map(|p| {
                        let point = p.to_encoded_point(true);
                        Bytes::copy_from_slice(point.as_bytes())
                    })
                    .collect();

                per_operator_tweaks[i].push(spark::ClaimLeafKeyTweak {
                    leaf_id: leaf.leaf_id.clone(),
                    secret_share_tweak: Some(spark::SecretShare {
                        secret_share: Bytes::copy_from_slice(&share_bytes),
                        proofs,
                    }),
                    pubkey_shares_tweak: pubkey_shares_tweak.clone(),
                });
            }
        }

        // Send ClaimTransferTweakKeys to ALL operators in parallel.
        // Each operator requires its own auth token (tokens are per-operator).
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
                .map_err(|_| SdkError::AuthFailed)?;
            let op_authed = self
                .inner
                .transport
                .authenticated(&op_token)
                .map_err(|_| SdkError::AuthFailed)?;

            let tweaks = per_operator_tweaks[i].clone();
            let request = spark::ClaimTransferTweakKeysRequest {
                transfer_id: transfer.id.clone(),
                owner_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                leaves_to_receive: tweaks,
            };

            op_authed
                .claim_transfer_tweak_keys(op_id, request)
                .await
                .map_err(|_| SdkError::TransportFailed)?;
        }

        Ok(())
    }

    /// Step 4: Construct refund txs, FROST sign, aggregate, finalize.
    async fn sign_and_finalize_refunds(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        transfer: &spark::Transfer,
        claimable: &[ClaimableLeaf],
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<usize, SdkError> {
        let network = bitcoin_network(self.inner.config.network.network);
        let mut rng = rand::thread_rng();

        // For each leaf: derive new key, generate nonces, construct refund tx, build signing job.
        let mut signing_jobs = Vec::with_capacity(claimable.len());
        let mut leaf_signing_data: Vec<LeafSigningContext> = Vec::with_capacity(claimable.len());

        for leaf in claimable {
            let (new_sk, new_pk) = signer
                .derive_signing_keypair(&leaf.leaf_id)
                .map_err(|_| SdkError::SigningFailed)?;

            // The refund output pays to the new signing key (Taproot-tweaked).
            let new_xonly =
                compressed_to_xonly(&new_pk.serialize()).ok_or(SdkError::SigningFailed)?;

            // Parse the node tx to get its output for sighash computation.
            let node_tx = parse_tx(&leaf.node_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
            let prev_out = node_tx
                .output
                .first()
                .ok_or(SdkError::InvalidRequest)?
                .clone();

            // Timelocks: use the exact sequences from the existing refund txs.
            let cpfp_seq = bitcoin::Sequence::from_consensus(leaf.cpfp_refund_sequence);
            let direct_from_cpfp_seq =
                bitcoin::Sequence::from_consensus(leaf.direct_from_cpfp_refund_sequence);

            let node_txid = node_tx.compute_txid();

            // Construct CPFP refund tx (2 outputs: P2TR + P2A anchor).
            let cpfp_refund_tx = create_cpfp_refund_tx(
                node_txid,
                leaf.vout,
                prev_out.value,
                cpfp_seq,
                &new_xonly,
                network,
            );

            // Construct direct-from-CPFP refund tx (1 output: P2TR, fee deducted).
            let direct_from_cpfp_refund_tx = create_direct_refund_tx(
                node_txid,
                leaf.vout,
                prev_out.value,
                direct_from_cpfp_seq,
                &new_xonly,
                network,
            );

            // Construct direct refund tx (if direct_tx exists).
            let direct_seq = bitcoin::Sequence::from_consensus(leaf.direct_refund_sequence);
            let (direct_refund_tx, direct_prev_out) = if !leaf.direct_tx_raw.is_empty() {
                let direct_tx =
                    parse_tx(&leaf.direct_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
                let dpo = direct_tx
                    .output
                    .first()
                    .ok_or(SdkError::InvalidRequest)?
                    .clone();
                let dtx = create_direct_refund_tx(
                    direct_tx.compute_txid(),
                    0,
                    dpo.value,
                    direct_seq,
                    &new_xonly,
                    network,
                );
                (Some(dtx), Some(dpo))
            } else {
                (None, None)
            };

            // Generate FROST nonces using the **tweaked** signing share directly.
            // We bypass WalletSigner::frost_generate_nonces because it
            // re-derives the key from the node_id via BIP32, producing the
            // original key instead of the claim-tweaked one.
            let tweaked_share =
                spark_crypto::frost::deserialize_signing_share(&new_sk.secret_bytes())
                    .map_err(|_| SdkError::SigningFailed)?;
            let cpfp_nonce_pair = spark_crypto::frost::generate_nonces(&tweaked_share, &mut rng);
            let direct_nonce_pair = if direct_refund_tx.is_some() {
                Some(spark_crypto::frost::generate_nonces(
                    &tweaked_share,
                    &mut rng,
                ))
            } else {
                None
            };
            let direct_from_cpfp_nonce_pair =
                spark_crypto::frost::generate_nonces(&tweaked_share, &mut rng);

            let pk_bytes = Bytes::copy_from_slice(&new_pk.serialize());

            let cpfp_commitment = commitment_to_proto(&cpfp_nonce_pair.commitment)
                .map_err(|_| SdkError::SigningFailed)?;
            let cpfp_job = spark::SigningJob {
                signing_public_key: pk_bytes.clone(),
                raw_tx: Bytes::copy_from_slice(&serialize_tx(&cpfp_refund_tx)),
                signing_nonce_commitment: Some(cpfp_commitment),
            };

            let direct_job = if let (Some(dtx), Some(dnp)) = (&direct_refund_tx, &direct_nonce_pair)
            {
                let dc =
                    commitment_to_proto(&dnp.commitment).map_err(|_| SdkError::SigningFailed)?;
                Some(spark::SigningJob {
                    signing_public_key: pk_bytes.clone(),
                    raw_tx: Bytes::copy_from_slice(&serialize_tx(dtx)),
                    signing_nonce_commitment: Some(dc),
                })
            } else {
                None
            };

            let direct_from_cpfp_commitment =
                commitment_to_proto(&direct_from_cpfp_nonce_pair.commitment)
                    .map_err(|_| SdkError::SigningFailed)?;
            let direct_from_cpfp_job = spark::SigningJob {
                signing_public_key: pk_bytes,
                raw_tx: Bytes::copy_from_slice(&serialize_tx(&direct_from_cpfp_refund_tx)),
                signing_nonce_commitment: Some(direct_from_cpfp_commitment),
            };

            signing_jobs.push(spark::LeafRefundTxSigningJob {
                leaf_id: leaf.leaf_id.clone(),
                refund_tx_signing_job: Some(cpfp_job),
                direct_refund_tx_signing_job: direct_job,
                direct_from_cpfp_refund_tx_signing_job: Some(direct_from_cpfp_job),
            });

            leaf_signing_data.push(LeafSigningContext {
                leaf_id: leaf.leaf_id.clone(),
                new_sk,
                new_pk,
                verifying_public_key: leaf.verifying_public_key,
                cpfp_nonce_pair,
                direct_nonce_pair,
                direct_from_cpfp_nonce_pair,
                cpfp_refund_tx,
                direct_refund_tx,
                direct_from_cpfp_refund_tx,
                prev_out,
                direct_prev_out,
            });
        }

        // Send signing jobs to coordinator.
        let sign_resp = authed
            .claim_transfer_sign_refunds(spark::ClaimTransferSignRefundsRequest {
                transfer_id: transfer.id.clone(),
                owner_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                signing_jobs,
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // Aggregate signatures and build NodeSignatures.
        let mut node_signatures = Vec::with_capacity(leaf_signing_data.len());

        for signing_result in &sign_resp.signing_results {
            let ctx = leaf_signing_data
                .iter()
                .find(|c| c.leaf_id == signing_result.leaf_id)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            // CPFP refund signature.
            let cpfp_refund_sig = self
                .frost_sign_and_aggregate(
                    ctx,
                    &ctx.cpfp_refund_tx,
                    &ctx.cpfp_nonce_pair,
                    signing_result
                        .refund_tx_signing_result
                        .as_ref()
                        .ok_or(SdkError::InvalidOperatorResponse)?,
                    &signing_result.verifying_key,
                    signer,
                )
                .await?;

            // Direct refund signature (if present).
            let direct_refund_sig = if let (Some(result), Some(dtx), Some(dnp), Some(dpo)) = (
                &signing_result.direct_refund_tx_signing_result,
                &ctx.direct_refund_tx,
                &ctx.direct_nonce_pair,
                &ctx.direct_prev_out,
            ) {
                // For direct, the prev_out is from direct_tx, not node_tx.
                let direct_ctx_override = LeafSigningContext {
                    leaf_id: ctx.leaf_id.clone(),
                    new_sk: ctx.new_sk,
                    new_pk: ctx.new_pk,
                    verifying_public_key: ctx.verifying_public_key,
                    cpfp_nonce_pair: ctx.cpfp_nonce_pair.clone(),
                    direct_nonce_pair: ctx.direct_nonce_pair.clone(),
                    direct_from_cpfp_nonce_pair: ctx.direct_from_cpfp_nonce_pair.clone(),
                    cpfp_refund_tx: ctx.cpfp_refund_tx.clone(),
                    direct_refund_tx: ctx.direct_refund_tx.clone(),
                    direct_from_cpfp_refund_tx: ctx.direct_from_cpfp_refund_tx.clone(),
                    prev_out: dpo.clone(),
                    direct_prev_out: ctx.direct_prev_out.clone(),
                };
                let sig = self
                    .frost_sign_and_aggregate(
                        &direct_ctx_override,
                        dtx,
                        dnp,
                        result,
                        &signing_result.verifying_key,
                        signer,
                    )
                    .await?;
                Bytes::copy_from_slice(&sig)
            } else {
                Bytes::new()
            };

            // Direct-from-CPFP refund signature.
            let direct_from_cpfp_sig = if let Some(ref result) =
                signing_result.direct_from_cpfp_refund_tx_signing_result
            {
                let sig = self
                    .frost_sign_and_aggregate(
                        ctx,
                        &ctx.direct_from_cpfp_refund_tx,
                        &ctx.direct_from_cpfp_nonce_pair,
                        result,
                        &signing_result.verifying_key,
                        signer,
                    )
                    .await?;
                Bytes::copy_from_slice(&sig)
            } else {
                Bytes::new()
            };

            node_signatures.push(spark::NodeSignatures {
                node_id: ctx.leaf_id.clone(),
                node_tx_signature: Bytes::new(),
                refund_tx_signature: Bytes::copy_from_slice(&cpfp_refund_sig),
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

        // Insert finalized nodes into tree store.
        let mut claimed_nodes = Vec::new();
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

    /// FROST sign a refund tx and aggregate with operator shares.
    ///
    /// Uses `ctx.new_sk` / `ctx.new_pk` (the **tweaked** leaf key) directly
    /// rather than re-deriving via `WalletSigner::frost_sign`, which would
    /// produce the original BIP32-derived key instead of the claim-tweaked one.
    #[allow(clippy::too_many_arguments)]
    async fn frost_sign_and_aggregate(
        &self,
        ctx: &LeafSigningContext,
        refund_tx: &bitcoin::Transaction,
        nonce_pair: &spark_crypto::frost::FrostNoncePair,
        operator_result: &spark::SigningResult,
        verifying_key_bytes: &[u8],
        _signer: &impl WalletSigner,
    ) -> Result<Vec<u8>, SdkError> {
        let operator_data =
            parse_signing_result(operator_result).map_err(|_| SdkError::InvalidOperatorResponse)?;

        // Compute sighash for the refund tx.
        let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(&ctx.prev_out))
            .map_err(|_| SdkError::SigningFailed)?;

        // Use the fixed Spark user identifier (derived from "user" string),
        // matching the official SDK's FROST_USER_IDENTIFIER constant.
        let user_identifier = spark_crypto::frost::user_identifier();

        // Build the complete commitments map: operator commitments + our commitment.
        let mut all_commitments = operator_data.commitments;
        all_commitments.insert(user_identifier, nonce_pair.commitment);

        // Determine verifying key from the operator's result (or from the leaf).
        let verifying_key = if !verifying_key_bytes.is_empty() {
            PublicKey::from_slice(verifying_key_bytes)
                .map_err(|_| SdkError::InvalidOperatorResponse)?
        } else {
            PublicKey::from_slice(&ctx.verifying_public_key)
                .map_err(|_| SdkError::InvalidOperatorResponse)?
        };

        // FROST round 2: sign as the user (role 1) with nested signing groups.
        // Uses the claim-tweaked key directly (bypasses WalletSigner BIP32 re-derivation).
        // The user signs with even-Y adjusted key (no tweak scalar), matching the
        // official Spark SDK's role 1 behavior.
        let user_share = spark_crypto::frost::sign_as_user(
            &sighash,
            &ctx.new_sk,
            &ctx.new_pk,
            &verifying_key,
            &nonce_pair.nonces,
            all_commitments.clone(),
        )
        .map_err(|_| SdkError::SigningFailed)?;

        // Build complete signature shares map.
        let mut all_shares = operator_data.signature_shares;
        all_shares.insert(user_identifier, user_share);

        // Build complete verifying shares map (including ours).
        let mut all_verifying_shares = operator_data.verifying_shares;
        all_verifying_shares.insert(user_identifier, ctx.new_pk);

        // Aggregate using nested signing groups (operators + user).
        let aggregate_sig = spark_crypto::frost::aggregate_nested(
            &sighash,
            all_commitments,
            &all_shares,
            &all_verifying_shares,
            &verifying_key,
        )
        .map_err(|_| SdkError::SigningFailed)?;

        serialize_frost_signature(&aggregate_sig)
    }
}

// ---------------------------------------------------------------------------
// Leaf signing context (held during the sign+aggregate step)
// ---------------------------------------------------------------------------

#[allow(dead_code)] // new_sk reserved for adaptor signature paths.
struct LeafSigningContext {
    leaf_id: String,
    new_sk: SecretKey,
    new_pk: PublicKey,
    verifying_public_key: [u8; 33],
    cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    direct_nonce_pair: Option<spark_crypto::frost::FrostNoncePair>,
    direct_from_cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    cpfp_refund_tx: bitcoin::Transaction,
    direct_refund_tx: Option<bitcoin::Transaction>,
    direct_from_cpfp_refund_tx: bitcoin::Transaction,
    /// Prev out from node_tx (for CPFP and direct-from-CPFP sighash).
    prev_out: bitcoin::TxOut,
    /// Prev out from direct_tx (for direct sighash), if present.
    direct_prev_out: Option<bitcoin::TxOut>,
}

// ---------------------------------------------------------------------------
// Step 2: Verify and decrypt
// ---------------------------------------------------------------------------

/// Verify the sender's ECDSA signature and ECIES-decrypt each leaf's secret.
fn verify_and_decrypt_transfer(
    transfer: &spark::Transfer,
    signer: &impl WalletSigner,
) -> Result<Vec<ClaimableLeaf>, SdkError> {
    let secp = Secp256k1::verification_only();

    let sender_pk = PublicKey::from_slice(&transfer.sender_identity_public_key)
        .map_err(|_| SdkError::InvalidOperatorResponse)?;

    let mut claimable = Vec::with_capacity(transfer.leaves.len());

    for transfer_leaf in &transfer.leaves {
        let leaf = transfer_leaf
            .leaf
            .as_ref()
            .ok_or(SdkError::InvalidOperatorResponse)?;

        // Verify sender's signature: SHA256(leaf_id || transfer_id || secret_cipher).
        let mut payload = Vec::new();
        payload.extend_from_slice(leaf.id.as_bytes());
        payload.extend_from_slice(transfer.id.as_bytes());
        payload.extend_from_slice(&transfer_leaf.secret_cipher);

        let payload_hash = bitcoin::hashes::sha256::Hash::hash(&payload);

        if !transfer_leaf.signature.is_empty() {
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&transfer_leaf.signature)
                .map_err(|_| SdkError::InvalidOperatorResponse)?;

            let msg = bitcoin::secp256k1::Message::from_digest(payload_hash.to_byte_array());
            secp.verify_ecdsa(&msg, &sig, &sender_pk)
                .map_err(|_| SdkError::InvalidOperatorResponse)?;
        }

        // ECIES-decrypt the secret cipher to get the leaf signing key.
        if transfer_leaf.secret_cipher.is_empty() {
            continue;
        }

        let decrypted = signer
            .ecies_decrypt(&transfer_leaf.secret_cipher)
            .map_err(|_| SdkError::SigningFailed)?;

        let decrypted_signing_key =
            SecretKey::from_slice(&decrypted).map_err(|_| SdkError::SigningFailed)?;

        // Extract CPFP refund sequence.
        let cpfp_refund_sequence =
            extract_sequence_from_tx_bytes(&transfer_leaf.intermediate_refund_tx, &leaf.refund_tx);

        // Extract direct-from-CPFP refund sequence (different encoding from CPFP).
        let direct_from_cpfp_refund_sequence = extract_sequence_from_tx_bytes(
            &transfer_leaf.intermediate_direct_from_cpfp_refund_tx,
            &leaf.direct_from_cpfp_refund_tx,
        );

        // Extract direct refund sequence.
        let direct_refund_sequence = extract_sequence_from_tx_bytes(
            &transfer_leaf.intermediate_direct_refund_tx,
            &leaf.direct_refund_tx,
        );

        // Direct tx bytes (the separate transaction for the direct spend path).
        let direct_tx_raw = leaf.direct_tx.to_vec();

        let verifying_public_key: [u8; 33] = leaf
            .verifying_public_key
            .as_ref()
            .try_into()
            .map_err(|_| SdkError::InvalidOperatorResponse)?;

        claimable.push(ClaimableLeaf {
            leaf_id: leaf.id.clone(),
            value: leaf.value,
            node_tx_raw: leaf.node_tx.to_vec(),
            cpfp_refund_sequence,
            direct_from_cpfp_refund_sequence,
            direct_refund_sequence,
            direct_tx_raw,
            verifying_public_key,
            decrypted_signing_key,
            vout: leaf.vout,
            has_direct: !transfer_leaf.intermediate_direct_refund_tx.is_empty(),
            has_direct_from_cpfp: !transfer_leaf
                .intermediate_direct_from_cpfp_refund_tx
                .is_empty(),
        });
    }

    Ok(claimable)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the nSequence from a refund transaction, with a fallback source.
///
/// Tries `primary` first, then `fallback`. Returns 2000 if neither is available.
fn extract_sequence_from_tx_bytes(primary: &[u8], fallback: &[u8]) -> u32 {
    let source = if !primary.is_empty() {
        primary
    } else if !fallback.is_empty() {
        fallback
    } else {
        return 2000;
    };
    deserialize::<bitcoin::Transaction>(source)
        .ok()
        .and_then(|tx| tx.input.first().map(|i| i.sequence.to_consensus_u32()))
        .unwrap_or(2000)
}

/// Map `sdk_core::Network` to the proto `Network` enum value.
fn spark_network_proto(network: sdk_core::Network) -> i32 {
    match network {
        sdk_core::Network::Mainnet => 1,
        sdk_core::Network::Regtest => 2,
    }
}

/// Map `sdk_core::Network` to `bitcoin::Network`.
fn bitcoin_network(network: sdk_core::Network) -> bitcoin::Network {
    match network {
        sdk_core::Network::Mainnet => bitcoin::Network::Bitcoin,
        sdk_core::Network::Regtest => bitcoin::Network::Regtest,
    }
}
