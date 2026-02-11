//! Shared transfer-building logic used by both `send_transfer` and `ssp_swap`.
//!
//! This module extracts the common patterns:
//! - Ephemeral keypair generation and key tweak computation
//! - VSS splitting and per-operator tweak data assembly
//! - CPFP refund transaction construction and FROST nonce generation
//! - Key tweak package building (ECDSA signing + ECIES encryption)
//! - Transfer package signature
//! - Utility functions (hex encoding/decoding, UUID generation, sequence math)

use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use signer::WalletSigner;
use transport::spark;

use crate::SdkError;
use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_refund_tx, serialize_tx, taproot_sighash,
};
use crate::frost_bridge::commitment_to_proto;

// ---------------------------------------------------------------------------
// Per-operator tweak data
// ---------------------------------------------------------------------------

/// Per-operator VSS share and public key tweaks for a single leaf.
pub(crate) struct PerOperatorTweak {
    pub secret_share_tweak: spark::SecretShare,
    pub pubkey_shares_tweak: HashMap<String, Bytes>,
}

// ---------------------------------------------------------------------------
// Leaf context builder
// ---------------------------------------------------------------------------

/// Common per-leaf context used by both transfer and swap flows.
///
/// Contains the ephemeral key, tweaks, CPFP refund tx, nonce, and
/// ECIES-encrypted secret cipher. The direct refund fields are only
/// populated for regular transfers (not swap primary transfers).
#[allow(dead_code)]
pub(crate) struct LeafTransferContext {
    pub leaf_id: String,
    pub current_sk: SecretKey,
    pub current_pk: PublicKey,
    pub ephemeral_sk: SecretKey,
    pub ephemeral_pk: PublicKey,
    pub verifying_public_key: [u8; 33],
    /// CPFP refund transaction.
    pub cpfp_refund_tx: bitcoin::Transaction,
    /// Previous output from node_tx (for sighash).
    pub prev_out: bitcoin::TxOut,
    /// FROST nonce pair for the CPFP refund.
    pub cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    /// ECIES-encrypted ephemeral key for receiver.
    pub secret_cipher: Vec<u8>,
    /// Per-operator tweak data.
    pub per_operator_tweaks: Vec<PerOperatorTweak>,
}

/// Parameters for building a leaf context.
pub(crate) struct BuildLeafParams<'a> {
    /// Leaf ID.
    pub leaf_id: &'a str,
    /// Raw node_tx bytes.
    pub node_tx: &'a [u8],
    /// Raw refund_tx bytes (for extracting current sequence).
    pub refund_tx: Option<&'a [u8]>,
    /// Leaf output index on node_tx.
    pub vout: u32,
    /// Verifying (group aggregate) public key.
    pub verifying_public_key: [u8; 33],
    /// Receiver's compressed public key (33 bytes) for xonly output and ECIES.
    pub receiver_pk: &'a [u8; 33],
    /// Bitcoin network.
    pub network: bitcoin::Network,
    /// Number of operators.
    pub num_operators: usize,
    /// Signing threshold.
    pub threshold: usize,
    /// Operator identifiers (in order).
    pub operator_ids: &'a [String],
}

/// Build a [`LeafTransferContext`] for a single leaf.
///
/// Generates an ephemeral keypair, computes the key tweak, VSS-splits it,
/// builds per-operator tweak data, constructs the CPFP refund tx, and
/// generates a FROST nonce pair.
pub(crate) fn build_leaf_context(
    params: &BuildLeafParams<'_>,
    signer: &impl WalletSigner,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<LeafTransferContext, SdkError> {
    let secp = Secp256k1::new();

    let (current_sk, current_pk) = signer
        .derive_signing_keypair(params.leaf_id)
        .map_err(|_| SdkError::SigningFailed)?;

    // Generate random ephemeral keypair.
    let mut eph_bytes = [0u8; 32];
    rand_core::RngCore::fill_bytes(rng, &mut eph_bytes);
    let ephemeral_sk = SecretKey::from_slice(&eph_bytes).expect("32 random bytes always valid");
    let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);

    // Compute key tweak: current - ephemeral.
    let key_tweak = signer
        .subtract_secret_keys(&current_sk, &ephemeral_sk)
        .map_err(|_| SdkError::SigningFailed)?;

    // VSS-split the tweak.
    let shares = signer
        .vss_split(
            &key_tweak.secret_bytes(),
            params.threshold,
            params.num_operators,
            rng,
        )
        .map_err(|_| SdkError::SigningFailed)?;

    // Build pubkey_shares_tweak: operator ID -> compressed pubkey of their share.
    let mut pubkey_shares_tweak: HashMap<String, Bytes> = HashMap::new();
    for (i, share) in shares.iter().enumerate() {
        let share_bytes =
            spark_crypto::verifiable_secret_sharing::scalar_to_bytes(&share.secret_share.share);
        let share_sk = SecretKey::from_slice(&share_bytes).map_err(|_| SdkError::SigningFailed)?;
        let share_pk = PublicKey::from_secret_key(&secp, &share_sk);
        pubkey_shares_tweak.insert(
            params.operator_ids[i].clone(),
            Bytes::copy_from_slice(&share_pk.serialize()),
        );
    }

    // Build per-operator tweak data.
    let mut per_operator_tweaks = Vec::with_capacity(params.num_operators);
    for share in &shares {
        let share_bytes =
            spark_crypto::verifiable_secret_sharing::scalar_to_bytes(&share.secret_share.share);
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

    // ECIES-encrypt ephemeral key for receiver.
    let secret_cipher = signer
        .ecies_encrypt(params.receiver_pk, &ephemeral_sk.secret_bytes(), rng)
        .map_err(|_| SdkError::SigningFailed)?;

    // Build CPFP refund transaction.
    let receiver_xonly = compressed_to_xonly(params.receiver_pk).ok_or(SdkError::SigningFailed)?;

    let node_tx =
        crate::bitcoin_tx::parse_tx(params.node_tx).map_err(|_| SdkError::InvalidRequest)?;
    let prev_out = node_tx
        .output
        .first()
        .ok_or(SdkError::InvalidRequest)?
        .clone();
    let node_txid = node_tx.compute_txid();

    let old_cpfp_seq = extract_sequence(params.refund_tx);
    let (next_cpfp_seq, _next_direct_seq) =
        next_send_sequence(old_cpfp_seq).ok_or(SdkError::InvalidRequest)?;

    let cpfp_refund_tx = create_cpfp_refund_tx(
        node_txid,
        params.vout,
        prev_out.value,
        next_cpfp_seq,
        &receiver_xonly,
        params.network,
    );

    // Generate FROST nonce pair with the sender's current key.
    let signing_share = spark_crypto::frost::deserialize_signing_share(&current_sk.secret_bytes())
        .map_err(|_| SdkError::SigningFailed)?;
    let cpfp_nonce_pair = spark_crypto::frost::generate_nonces(&signing_share, rng);

    Ok(LeafTransferContext {
        leaf_id: params.leaf_id.to_owned(),
        current_sk,
        current_pk,
        ephemeral_sk,
        ephemeral_pk,
        verifying_public_key: params.verifying_public_key,
        cpfp_refund_tx,
        prev_out,
        cpfp_nonce_pair,
        secret_cipher,
        per_operator_tweaks,
    })
}

// ---------------------------------------------------------------------------
// FROST signing (user share only, for TransferPackage)
// ---------------------------------------------------------------------------

/// Parse operator signing commitments from proto into a BTreeMap.
fn parse_operator_commitments(
    operator_commitments: &spark::RequestedSigningCommitments,
) -> Result<std::collections::BTreeMap<signer::FrostIdentifier, signer::SigningCommitments>, SdkError>
{
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
    Ok(op_commitments)
}

/// FROST sign a refund tx on the send side and return the user's signature share.
///
/// The returned bytes are used in the `UserSignedTxSigningJob` proto. The
/// coordinator aggregates them with operator shares.
pub(crate) fn frost_sign_user_share(
    ctx: &LeafTransferContext,
    refund_tx: &bitcoin::Transaction,
    nonce_pair: &spark_crypto::frost::FrostNoncePair,
    operator_commitments: &spark::RequestedSigningCommitments,
    prev_out: &bitcoin::TxOut,
) -> Result<Vec<u8>, SdkError> {
    let op_commitments = parse_operator_commitments(operator_commitments)?;

    let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(prev_out))
        .map_err(|_| SdkError::SigningFailed)?;

    let user_identifier = spark_crypto::frost::user_identifier();

    let mut all_commitments = op_commitments;
    all_commitments.insert(user_identifier, nonce_pair.commitment);

    let verifying_key =
        PublicKey::from_slice(&ctx.verifying_public_key).map_err(|_| SdkError::InvalidRequest)?;

    let user_share = spark_crypto::frost::sign_as_user(
        &sighash,
        &ctx.current_sk,
        &ctx.current_pk,
        &verifying_key,
        &nonce_pair.nonces,
        &all_commitments,
    )
    .map_err(|_| SdkError::SigningFailed)?;

    let share_bytes = crate::frost_bridge::serialize_signature_share(&user_share);
    Ok(share_bytes)
}

/// FROST sign a refund tx with an adaptor public key (for SSP swaps).
///
/// Similar to [`frost_sign_user_share`] but incorporates the adaptor point
/// `T` into the signing so the resulting share carries the adaptor twist.
pub(crate) fn frost_sign_user_share_with_adaptor(
    ctx: &LeafTransferContext,
    refund_tx: &bitcoin::Transaction,
    nonce_pair: &spark_crypto::frost::FrostNoncePair,
    operator_commitments: &spark::RequestedSigningCommitments,
    prev_out: &bitcoin::TxOut,
    adaptor_pk: &PublicKey,
) -> Result<Vec<u8>, SdkError> {
    let op_commitments = parse_operator_commitments(operator_commitments)?;

    let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(prev_out))
        .map_err(|_| SdkError::SigningFailed)?;

    let user_identifier = spark_crypto::frost::user_identifier();

    let mut all_commitments = op_commitments;
    all_commitments.insert(user_identifier, nonce_pair.commitment);

    let verifying_key =
        PublicKey::from_slice(&ctx.verifying_public_key).map_err(|_| SdkError::InvalidRequest)?;

    let user_share = spark_crypto::frost::sign_as_user_with_adaptor(
        &sighash,
        &ctx.current_sk,
        &ctx.current_pk,
        &verifying_key,
        &nonce_pair.nonces,
        &all_commitments,
        adaptor_pk,
    )
    .map_err(|_| SdkError::SigningFailed)?;

    let share_bytes = crate::frost_bridge::serialize_signature_share(&user_share);
    Ok(share_bytes)
}

// ---------------------------------------------------------------------------
// Key tweak package builder
// ---------------------------------------------------------------------------

/// Build the key_tweak_package: a map from operator_id -> ECIES-encrypted
/// `SendLeafKeyTweaks` proto bytes.
///
/// Also generates a UUIDv4 transfer ID and returns it alongside the package.
pub(crate) fn build_key_tweak_package(
    leaf_contexts: &[LeafTransferContext],
    operators: &[config::OperatorInfo],
    signer: &impl WalletSigner,
    transfer_id: &str,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<HashMap<String, Bytes>, SdkError> {
    let transfer_id_bytes = transfer_id.as_bytes();
    let mut key_tweak_package: HashMap<String, Bytes> = HashMap::new();

    for (op_idx, op) in operators.iter().enumerate() {
        let mut tweak_list: Vec<spark::SendLeafKeyTweak> = Vec::with_capacity(leaf_contexts.len());

        for ctx in leaf_contexts {
            // ECDSA signature: SHA256(leaf_id || transfer_id || secret_cipher).
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
            .ecies_encrypt(&op_pubkey, &tweaks_bytes, rng)
            .map_err(|_| SdkError::SigningFailed)?;

        key_tweak_package.insert(op.id.to_string(), Bytes::from(encrypted));
    }

    Ok(key_tweak_package)
}

// ---------------------------------------------------------------------------
// Package signature
// ---------------------------------------------------------------------------

/// Sign the transfer package payload.
///
/// Payload = `hex_decode(transfer_id without dashes)` + for each (key, value)
/// in `key_tweak_package` sorted by key: `key_bytes + ":" + value_bytes + ";"`.
pub(crate) fn sign_transfer_package(
    transfer_id: &str,
    key_tweak_package: &HashMap<String, Bytes>,
    signer: &impl WalletSigner,
) -> Result<Vec<u8>, SdkError> {
    let transfer_id_hex = transfer_id.replace('-', "");
    let transfer_id_raw = hex_decode(&transfer_id_hex).ok_or(SdkError::InvalidRequest)?;

    let mut pairs: Vec<(&String, &Bytes)> = key_tweak_package.iter().collect();
    pairs.sort_by_key(|(k, _)| (*k).clone());

    let mut package_payload = transfer_id_raw;
    for (key, value) in pairs {
        package_payload.extend_from_slice(key.as_bytes());
        package_payload.extend_from_slice(b":");
        package_payload.extend_from_slice(value);
        package_payload.extend_from_slice(b";");
    }

    Ok(signer.sign_ecdsa_message(&package_payload))
}

// ---------------------------------------------------------------------------
// CPFP signing job builder
// ---------------------------------------------------------------------------

/// Build a `UserSignedTxSigningJob` for a CPFP refund tx.
pub(crate) fn build_cpfp_signing_job(
    ctx: &LeafTransferContext,
    user_sig_bytes: &[u8],
    operator_commitments: &spark::RequestedSigningCommitments,
) -> spark::UserSignedTxSigningJob {
    let pk_bytes = Bytes::copy_from_slice(&ctx.current_pk.serialize());
    let user_commitment = commitment_to_proto(&ctx.cpfp_nonce_pair.commitment)
        .expect("commitment serialization should not fail");

    spark::UserSignedTxSigningJob {
        leaf_id: ctx.leaf_id.clone(),
        signing_public_key: pk_bytes,
        raw_tx: Bytes::copy_from_slice(&serialize_tx(&ctx.cpfp_refund_tx)),
        signing_nonce_commitment: Some(user_commitment),
        user_signature: Bytes::copy_from_slice(user_sig_bytes),
        signing_commitments: Some(spark::SigningCommitments {
            signing_commitments: operator_commitments.signing_nonce_commitments.clone(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Expiry time builder
// ---------------------------------------------------------------------------

/// Build a 1-hour expiry timestamp from now.
pub(crate) fn one_hour_expiry() -> prost_types::Timestamp {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let expiry = now + std::time::Duration::from_secs(3600);
    prost_types::Timestamp {
        seconds: expiry.as_secs() as i64,
        nanos: 0,
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Extract nSequence from a raw refund transaction.
///
/// Returns default 2000 if the bytes are empty or unparseable.
pub(crate) fn extract_sequence(raw: Option<&[u8]>) -> bitcoin::Sequence {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return bitcoin::Sequence::from_consensus(2000),
    };
    deserialize::<bitcoin::Transaction>(bytes)
        .ok()
        .and_then(|tx| tx.input.first().map(|i| i.sequence))
        .unwrap_or(bitcoin::Sequence::from_consensus(2000))
}

// Spark timelock constants (matching Breez SDK / coordinator expectations).
pub(crate) const TIMELOCK_MASK: u32 = 0x0000_FFFF;
pub(crate) const TIME_LOCK_INTERVAL: u16 = 100;
pub(crate) const DIRECT_TIME_LOCK_OFFSET: u16 = 50;

/// Compute the next (decremented) sequences for a send transfer.
///
/// Returns `(cpfp_sequence, direct_sequence)`.
/// Returns `None` if the timelock is already too low to decrement.
pub(crate) fn next_send_sequence(
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

// Re-export utils used by `transfer.rs` and `swap.rs` so they can import
// from `transfer_core` without reaching into `crate::utils` directly.
pub(crate) use crate::utils::{generate_uuid_v4, hex_decode, hex_decode_pubkey, hex_encode};
