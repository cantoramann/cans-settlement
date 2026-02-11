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
//! 4. **Claim inbound**: The SSP sends back new leaves via a regular
//!    transfer.  The caller claims them via `claim_transfer`.
//!
//! The adaptor signature scheme ensures atomicity: the SSP can only
//! complete the outbound transfer by revealing the adaptor secret,
//! which the user can then use to claim the inbound transfer.

use std::collections::HashMap;

use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use signer::WalletSigner;
use transport::spark;

use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_refund_tx, serialize_tx, taproot_sighash,
};
use crate::frost_bridge::commitment_to_proto;
use crate::network::bitcoin_network;
use crate::ssp::{RequestSwapInput, SSP_SWAP_FEE_SATS, SspClient, UserLeafInput};
use crate::tree::{TreeNode, TreeStore};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Result of an SSP swap operation.
pub struct SspSwapResult {
    /// Transfer ID of the inbound (SSP -> user) transfer to claim.
    pub inbound_transfer_id: String,
}

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
    /// `leaves` are the already-reserved leaves whose total value exceeds
    /// `target_amounts`.  `target_amounts` lists the desired output
    /// denominations the SSP should send back.
    ///
    /// Returns the inbound transfer ID to claim via `claim_transfer`.
    pub async fn ssp_swap(
        &self,
        sender_pubkey: &IdentityPubKey,
        leaves: &[&TreeNode],
        target_amounts: &[u64],
        signer: &impl WalletSigner,
    ) -> Result<SspSwapResult, SdkError> {
        self.check_cancelled()?;

        let authed = self.authenticate(signer).await?;
        let network = bitcoin_network(self.inner.config.network.network);
        let secp = Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let ssp_pk = self.inner.ssp.identity_public_key();
        let mut rng = rand_core::OsRng;

        // 1. Generate adaptor secret and public key.
        let mut adaptor_bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rng, &mut adaptor_bytes);
        let adaptor_sk =
            SecretKey::from_slice(&adaptor_bytes).expect("32 random bytes always valid");
        let adaptor_pk = PublicKey::from_secret_key(&secp, &adaptor_sk);
        let adaptor_pk_hex = hex_encode(&adaptor_pk.serialize());

        // SSP identity key as xonly for refund outputs.
        let ssp_xonly = compressed_to_xonly(&ssp_pk.serialize()).ok_or(SdkError::SspSwapFailed)?;

        // 2. Build per-leaf transfer contexts (same pattern as send_transfer).
        let total_sats: u64 = leaves.iter().map(|l| l.value).sum();
        let mut leaf_contexts: Vec<SwapLeafContext> = Vec::with_capacity(leaves.len());

        for leaf in leaves {
            let (current_sk, current_pk) = signer
                .derive_signing_keypair(&leaf.id)
                .map_err(|_| SdkError::SigningFailed)?;

            // Generate ephemeral keypair.
            let mut eph_bytes = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rng, &mut eph_bytes);
            let ephemeral_sk =
                SecretKey::from_slice(&eph_bytes).expect("32 random bytes always valid");
            let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);

            // Key tweak: current - ephemeral.
            let key_tweak = signer
                .subtract_secret_keys(&current_sk, &ephemeral_sk)
                .map_err(|_| SdkError::SigningFailed)?;

            // VSS-split the tweak.
            let shares = signer
                .vss_split(
                    &key_tweak.secret_bytes(),
                    threshold,
                    num_operators,
                    &mut rng,
                )
                .map_err(|_| SdkError::SigningFailed)?;

            // pubkey_shares_tweak per operator.
            let mut pubkey_shares_tweak: HashMap<String, Bytes> = HashMap::new();
            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let share_sk =
                    SecretKey::from_slice(&share_bytes).map_err(|_| SdkError::SigningFailed)?;
                let share_pk = PublicKey::from_secret_key(&secp, &share_sk);
                pubkey_shares_tweak.insert(
                    operators[i].id.to_string(),
                    Bytes::copy_from_slice(&share_pk.serialize()),
                );
            }

            // Per-operator tweak data.
            let mut per_operator_tweaks = Vec::with_capacity(num_operators);
            for share in &shares {
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
                per_operator_tweaks.push(PerOperatorTweak {
                    secret_share_tweak: spark::SecretShare {
                        secret_share: Bytes::copy_from_slice(&share_bytes),
                        proofs,
                    },
                    pubkey_shares_tweak: pubkey_shares_tweak.clone(),
                });
            }

            // ECIES-encrypt ephemeral key for SSP.
            let secret_cipher = signer
                .ecies_encrypt(&ssp_pk.serialize(), &ephemeral_sk.secret_bytes(), &mut rng)
                .map_err(|_| SdkError::SigningFailed)?;

            // Build refund transactions.
            let node_tx =
                crate::bitcoin_tx::parse_tx(&leaf.node_tx).map_err(|_| SdkError::InvalidRequest)?;
            let prev_out = node_tx
                .output
                .first()
                .ok_or(SdkError::InvalidRequest)?
                .clone();
            let node_txid = node_tx.compute_txid();

            let old_cpfp_seq = extract_sequence(leaf.refund_tx.as_deref());
            let (next_cpfp_seq, _next_direct_seq) =
                next_send_sequence(old_cpfp_seq).ok_or(SdkError::InvalidRequest)?;

            let cpfp_refund_tx = create_cpfp_refund_tx(
                node_txid,
                leaf.vout,
                prev_out.value,
                next_cpfp_seq,
                &ssp_xonly,
                network,
            );

            // FROST nonce for the CPFP refund (only one needed for swaps).
            let signing_share =
                spark_crypto::frost::deserialize_signing_share(&current_sk.secret_bytes())
                    .map_err(|_| SdkError::SigningFailed)?;
            let cpfp_nonce_pair = spark_crypto::frost::generate_nonces(&signing_share, &mut rng);

            leaf_contexts.push(SwapLeafContext {
                leaf_id: leaf.id.clone(),
                current_sk,
                current_pk,
                _ephemeral_sk: ephemeral_sk,
                _ephemeral_pk: ephemeral_pk,
                verifying_public_key: leaf.verifying_public_key,
                cpfp_refund_tx,
                prev_out,
                cpfp_nonce_pair,
                secret_cipher,
                per_operator_tweaks,
            });
        }

        // 3. Get signing commitments.
        //    Swap primary transfers only need CPFP refund signatures (count=1).
        let node_ids: Vec<String> = leaf_contexts.iter().map(|c| c.leaf_id.clone()).collect();
        let commitments_resp = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids: node_ids.clone(),
                count: 1,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        let commitments = &commitments_resp.signing_commitments;

        // 4. Build CPFP-only signing jobs (no direct/direct-from-CPFP for swaps).
        //    Save each user's serialized signature share for reuse during
        //    aggregation (step 10). Nonces are one-time-use, so we cannot
        //    re-sign -- we must reuse the exact same share.
        let mut cpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(leaf_contexts.len());
        let mut user_share_bytes: Vec<Vec<u8>> = Vec::with_capacity(leaf_contexts.len());

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let pk_bytes = Bytes::copy_from_slice(&ctx.current_pk.serialize());

            let cpfp_op_commitments = commitments
                .get(leaf_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let cpfp_user_commitment = commitment_to_proto(&ctx.cpfp_nonce_pair.commitment)
                .map_err(|_| SdkError::SigningFailed)?;

            let sig_bytes = self
                .frost_sign_swap(
                    ctx,
                    &ctx.cpfp_refund_tx,
                    &ctx.cpfp_nonce_pair,
                    cpfp_op_commitments,
                    &ctx.prev_out,
                    &adaptor_pk,
                )
                .await?;

            user_share_bytes.push(sig_bytes.clone());

            cpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes,
                raw_tx: Bytes::copy_from_slice(&serialize_tx(&ctx.cpfp_refund_tx)),
                signing_nonce_commitment: Some(cpfp_user_commitment),
                user_signature: Bytes::copy_from_slice(&sig_bytes),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: cpfp_op_commitments.signing_nonce_commitments.clone(),
                }),
            });
        }

        // 5. Build key_tweak_package (same structure as send_transfer).
        let transfer_id = generate_uuid_v4(&mut rng);
        let transfer_id_bytes = transfer_id.as_bytes();

        let mut key_tweak_package: HashMap<String, Bytes> = HashMap::new();
        let ssp_pk_bytes = ssp_pk.serialize();

        for (op_idx, op) in operators.iter().enumerate() {
            let mut tweak_list: Vec<spark::SendLeafKeyTweak> =
                Vec::with_capacity(leaf_contexts.len());

            for ctx in &leaf_contexts {
                let mut sig_payload = Vec::new();
                sig_payload.extend_from_slice(ctx.leaf_id.as_bytes());
                sig_payload.extend_from_slice(transfer_id_bytes);
                sig_payload.extend_from_slice(&ctx.secret_cipher);

                let payload_hash = bitcoin::hashes::sha256::Hash::hash(&sig_payload);
                let sig_compact = signer.sign_ecdsa_digest_compact(payload_hash.as_byte_array());

                let op_tweak = &ctx.per_operator_tweaks[op_idx];

                tweak_list.push(spark::SendLeafKeyTweak {
                    leaf_id: ctx.leaf_id.clone(),
                    secret_share_tweak: Some(op_tweak.secret_share_tweak.clone()),
                    pubkey_shares_tweak: op_tweak.pubkey_shares_tweak.clone(),
                    secret_cipher: Bytes::copy_from_slice(&ctx.secret_cipher),
                    signature: Bytes::copy_from_slice(&sig_compact),
                    refund_signature: Bytes::new(),
                    direct_refund_signature: Bytes::new(),
                    direct_from_cpfp_refund_signature: Bytes::new(),
                });
            }

            let tweaks_proto = spark::SendLeafKeyTweaks {
                leaves_to_send: tweak_list,
            };
            let tweaks_bytes = prost::Message::encode_to_vec(&tweaks_proto);

            let op_pubkey =
                hex_decode_pubkey(op.identity_public_key).ok_or(SdkError::InvalidRequest)?;
            let encrypted = signer
                .ecies_encrypt(&op_pubkey, &tweaks_bytes, &mut rng)
                .map_err(|_| SdkError::SigningFailed)?;

            key_tweak_package.insert(op.id.to_string(), Bytes::from(encrypted));
        }

        // 6. Package signature.
        let transfer_id_hex = transfer_id.replace('-', "");
        let transfer_id_raw = hex_decode_bytes(&transfer_id_hex).ok_or(SdkError::InvalidRequest)?;

        let mut pairs: Vec<(&String, &Bytes)> = key_tweak_package.iter().collect();
        pairs.sort_by_key(|(k, _)| (*k).clone());

        let mut package_payload = transfer_id_raw;
        for (key, value) in pairs {
            package_payload.extend_from_slice(key.as_bytes());
            package_payload.extend_from_slice(b":");
            package_payload.extend_from_slice(value);
            package_payload.extend_from_slice(b";");
        }
        let package_sig = signer.sign_ecdsa_message(&package_payload);

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

        let expiry_time = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let expiry = now + std::time::Duration::from_secs(3600);
            Some(prost_types::Timestamp {
                seconds: expiry.as_secs() as i64,
                nanos: 0,
            })
        };

        let start_request = spark::StartTransferRequest {
            transfer_id: transfer_id.clone(),
            owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
            receiver_identity_public_key: Bytes::copy_from_slice(&ssp_pk_bytes),
            transfer_package: Some(transfer_package),
            expiry_time,
            leaves_to_send: Vec::new(),
            spark_invoice: String::new(),
        };

        // 8. Adaptor public key package.
        //    For SSP swaps, we use the same adaptor key for all three refund types.
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
            .map_err(|e| {
                eprintln!("[ssp_swap] initiate_swap_primary_transfer failed: {e:?}");
                SdkError::SspSwapFailed
            })?;

        // 10. Aggregate FROST signatures: combine operator shares from the
        //     coordinator response with the user's shares (saved from step 4)
        //     to produce the final adaptor CPFP refund signatures per leaf.
        let mut user_leaves: Vec<UserLeafInput> = Vec::with_capacity(leaf_contexts.len());
        let user_id = spark_crypto::frost::user_identifier();

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            // Find the matching signing result from the coordinator.
            let signing_result = swap_coordinator_resp
                .signing_results
                .iter()
                .find(|r| r.leaf_id == ctx.leaf_id)
                .ok_or(SdkError::InvalidOperatorResponse)?;

            // Parse the CPFP refund signing result.
            let cpfp_signing = signing_result
                .refund_tx_signing_result
                .as_ref()
                .ok_or(SdkError::InvalidOperatorResponse)?;

            let op_data = crate::frost_bridge::parse_signing_result(cpfp_signing).map_err(|e| {
                eprintln!("[ssp_swap] parse_signing_result failed: {e:?}");
                e
            })?;

            // Build the complete commitments + shares maps (operators + user).
            let mut all_commitments = op_data.commitments;
            all_commitments.insert(user_id, ctx.cpfp_nonce_pair.commitment);

            // Reuse the user's signature share from step 4 (nonces are one-time-use).
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

            // Aggregate into an adaptor FROST signature.
            let frost_sig = spark_crypto::frost::aggregate_nested_with_adaptor(
                &cpfp_sighash,
                all_commitments,
                &all_shares,
                &op_data.verifying_shares,
                &verifying_key,
                &adaptor_pk,
            )
            .map_err(|e| {
                eprintln!("[ssp_swap] aggregate_nested_with_adaptor failed: {e:?}");
                SdkError::SigningFailed
            })?;

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
        eprintln!("[ssp_swap] authenticating with SSP as {identity_hex}");

        // Create a signing closure that delegates to the signer's sign_challenge.
        let sign_fn = |bytes: &[u8]| -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
            signer.sign_challenge(bytes)
        };

        let auth_token = self
            .inner
            .ssp
            .authenticate(&identity_hex, &sign_fn)
            .await
            .map_err(|e| {
                eprintln!("[ssp_swap] SSP authenticate failed: {e:?}");
                e
            })?;

        eprintln!(
            "[ssp_swap] calling SSP GraphQL: total={total_sats}, targets={target_amounts:?}, transfer_id={transfer_id}"
        );
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
            .await
            .map_err(|e| {
                eprintln!("[ssp_swap] SSP request_swap failed: {e:?}");
                e
            })?;

        Ok(SspSwapResult {
            inbound_transfer_id: swap_resp.inbound_transfer_id,
        })
    }

    /// FROST sign a refund tx for the swap (identical to send_transfer signing).
    /// FROST sign a refund tx for the swap with the adaptor public key.
    ///
    /// Returns the serialized user signature share bytes (used both for the
    /// proto `UserSignedTxSigningJob` and for later aggregation).
    async fn frost_sign_swap(
        &self,
        ctx: &SwapLeafContext,
        refund_tx: &bitcoin::Transaction,
        nonce_pair: &spark_crypto::frost::FrostNoncePair,
        operator_commitments: &spark::RequestedSigningCommitments,
        prev_out: &bitcoin::TxOut,
        adaptor_pk: &PublicKey,
    ) -> Result<Vec<u8>, SdkError> {
        let mut op_commitments = std::collections::BTreeMap::new();
        for (hex_id, proto_commitment) in &operator_commitments.signing_nonce_commitments {
            let id = crate::frost_bridge::identifier_from_hex(hex_id)?;
            let commitment = spark_crypto::frost::commitments_from_components(
                &proto_commitment.hiding,
                &proto_commitment.binding,
            )
            .map_err(|_| SdkError::InvalidOperatorResponse)?;
            op_commitments.insert(id, commitment);
        }

        let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(prev_out))
            .map_err(|_| SdkError::SigningFailed)?;

        let user_identifier = spark_crypto::frost::user_identifier();
        let mut all_commitments = op_commitments;
        all_commitments.insert(user_identifier, nonce_pair.commitment);

        let verifying_key = PublicKey::from_slice(&ctx.verifying_public_key)
            .map_err(|_| SdkError::InvalidRequest)?;

        let user_share = spark_crypto::frost::sign_as_user_with_adaptor(
            &sighash,
            &ctx.current_sk,
            &ctx.current_pk,
            &verifying_key,
            &nonce_pair.nonces,
            &all_commitments,
            adaptor_pk,
        )
        .map_err(|e| {
            eprintln!("[ssp_swap] frost sign_as_user_with_adaptor failed: {e:?}");
            SdkError::SigningFailed
        })?;

        let share_bytes = crate::frost_bridge::serialize_signature_share(&user_share);
        Ok(share_bytes)
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

/// Per-leaf prepared data for a swap transfer.
///
/// Only CPFP refund data is required for swap primary transfers.
/// Direct and direct-from-CPFP fields are omitted because the
/// coordinator does not accept them for swaps.
struct SwapLeafContext {
    leaf_id: String,
    current_sk: SecretKey,
    current_pk: PublicKey,
    _ephemeral_sk: SecretKey,
    _ephemeral_pk: PublicKey,
    verifying_public_key: [u8; 33],
    cpfp_refund_tx: bitcoin::Transaction,
    prev_out: bitcoin::TxOut,
    cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    secret_cipher: Vec<u8>,
    per_operator_tweaks: Vec<PerOperatorTweak>,
}

struct PerOperatorTweak {
    secret_share_tweak: spark::SecretShare,
    pubkey_shares_tweak: HashMap<String, Bytes>,
}

// ---------------------------------------------------------------------------
// Helpers (re-implemented here to avoid leaking private fns across modules)
// ---------------------------------------------------------------------------

fn extract_sequence(raw: Option<&[u8]>) -> bitcoin::Sequence {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return bitcoin::Sequence::from_consensus(2000),
    };
    bitcoin::consensus::deserialize::<bitcoin::Transaction>(bytes)
        .ok()
        .and_then(|tx| tx.input.first().map(|i| i.sequence))
        .unwrap_or(bitcoin::Sequence::from_consensus(2000))
}

const TIMELOCK_MASK: u32 = 0x0000_FFFF;
const TIME_LOCK_INTERVAL: u16 = 100;
const DIRECT_TIME_LOCK_OFFSET: u16 = 50;

fn next_send_sequence(
    current_cpfp_seq: bitcoin::Sequence,
) -> Option<(bitcoin::Sequence, bitcoin::Sequence)> {
    let raw = current_cpfp_seq.to_consensus_u32();
    let timelock = (raw & TIMELOCK_MASK) as u16;
    let next_timelock = timelock.checked_sub(TIME_LOCK_INTERVAL)?;
    let flags = raw & !TIMELOCK_MASK;
    let cpfp = bitcoin::Sequence::from_consensus(flags | u32::from(next_timelock));
    let direct = bitcoin::Sequence::from_consensus(
        flags | u32::from(next_timelock + DIRECT_TIME_LOCK_OFFSET),
    );
    Some((cpfp, direct))
}

fn hex_decode_pubkey(hex: &str) -> Option<[u8; 33]> {
    if hex.len() != 66 {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_decode_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.as_bytes().chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn generate_uuid_v4<R: rand_core::RngCore>(rng: &mut R) -> String {
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        u16::from_be_bytes([bytes[8], bytes[9]]),
        u64::from_be_bytes([
            0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ]),
    )
}

/// Encode bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0x0F) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
