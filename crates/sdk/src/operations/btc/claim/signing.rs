//! FROST signing and aggregation for claim refund transactions.
//!
//! Given a `LeafSigningContext`, constructs signing jobs, performs the
//! user's FROST key share signing, and aggregates with operator shares
//! into a final Schnorr signature.

use bitcoin::secp256k1::{PublicKey, SecretKey};
use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::SdkError;
use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_refund_tx, create_direct_refund_tx, parse_tx, serialize_tx,
    taproot_sighash,
};
use crate::frost_bridge::{commitment_to_proto, parse_signing_result, serialize_frost_signature};

use super::verify_decrypt::ClaimableLeaf;

// ---------------------------------------------------------------------------
// Leaf signing context
// ---------------------------------------------------------------------------

/// Per-leaf state needed to sign refund transactions.
///
/// Built during [`build_signing_data`] and consumed during
/// FROST signing + aggregation.
pub(super) struct LeafSigningContext {
    pub leaf_id: String,
    pub new_sk: SecretKey,
    pub new_pk: PublicKey,
    pub verifying_public_key: [u8; 33],
    pub cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    pub direct_nonce_pair: Option<spark_crypto::frost::FrostNoncePair>,
    pub direct_from_cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    pub cpfp_refund_tx: bitcoin::Transaction,
    pub direct_refund_tx: Option<bitcoin::Transaction>,
    pub direct_from_cpfp_refund_tx: bitcoin::Transaction,
    pub prev_out: bitcoin::TxOut,
    pub direct_prev_out: Option<bitcoin::TxOut>,
}

// ---------------------------------------------------------------------------
// Build signing data for all claimable leaves
// ---------------------------------------------------------------------------

/// Build per-leaf signing context and coordinator signing jobs.
///
/// For each claimable leaf:
/// 1. Derive new keypair
/// 2. Construct CPFP, direct, and direct-from-CPFP refund transactions
/// 3. Generate FROST nonce pairs
/// 4. Build protobuf signing jobs for the coordinator
pub(super) fn build_signing_data(
    claimable: &[ClaimableLeaf],
    signer: &impl WalletSigner,
    network: bitcoin::Network,
) -> Result<(Vec<spark::LeafRefundTxSigningJob>, Vec<LeafSigningContext>), SdkError> {
    let mut signing_jobs = Vec::with_capacity(claimable.len());
    let mut leaf_signing_data = Vec::with_capacity(claimable.len());
    let mut rng = rand_core::OsRng;

    for leaf in claimable {
        let (new_sk, new_pk) = signer
            .derive_signing_keypair(&leaf.leaf_id)
            .map_err(|_| SdkError::SigningFailed)?;

        let new_xonly = compressed_to_xonly(&new_pk.serialize()).ok_or(SdkError::SigningFailed)?;

        let node_tx = parse_tx(&leaf.node_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
        let prev_out = node_tx
            .output
            .first()
            .ok_or(SdkError::InvalidRequest)?
            .clone();

        let cpfp_seq = bitcoin::Sequence::from_consensus(leaf.cpfp_refund_sequence);
        let direct_from_cpfp_seq =
            bitcoin::Sequence::from_consensus(leaf.direct_from_cpfp_refund_sequence);

        let node_txid = node_tx.compute_txid();

        let cpfp_refund_tx = create_cpfp_refund_tx(
            node_txid,
            leaf.vout,
            prev_out.value,
            cpfp_seq,
            &new_xonly,
            network,
        );

        let direct_from_cpfp_refund_tx = create_direct_refund_tx(
            node_txid,
            leaf.vout,
            prev_out.value,
            direct_from_cpfp_seq,
            &new_xonly,
            network,
        );

        let direct_seq = bitcoin::Sequence::from_consensus(leaf.direct_refund_sequence);
        let (direct_refund_tx, direct_prev_out) = if !leaf.direct_tx_raw.is_empty() {
            let direct_tx = parse_tx(&leaf.direct_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
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

        let tweaked_share = spark_crypto::frost::deserialize_signing_share(&new_sk.secret_bytes())
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
            raw_tx: Bytes::from(serialize_tx(&cpfp_refund_tx)),
            signing_nonce_commitment: Some(cpfp_commitment),
        };

        let direct_job = if let (Some(dtx), Some(dnp)) = (&direct_refund_tx, &direct_nonce_pair) {
            let dc = commitment_to_proto(&dnp.commitment).map_err(|_| SdkError::SigningFailed)?;
            Some(spark::SigningJob {
                signing_public_key: pk_bytes.clone(),
                raw_tx: Bytes::from(serialize_tx(dtx)),
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
            raw_tx: Bytes::from(serialize_tx(&direct_from_cpfp_refund_tx)),
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

    Ok((signing_jobs, leaf_signing_data))
}

// ---------------------------------------------------------------------------
// FROST sign and aggregate a single refund tx
// ---------------------------------------------------------------------------

/// Perform FROST signing and aggregation for a single refund transaction.
///
/// 1. Parse operator signing result (commitments + shares + verifying shares)
/// 2. Compute taproot sighash
/// 3. Sign as user share
/// 4. Aggregate all shares into final Schnorr signature
pub(super) fn frost_sign_and_aggregate(
    ctx: &LeafSigningContext,
    refund_tx: &bitcoin::Transaction,
    prev_out: &bitcoin::TxOut,
    nonce_pair: &spark_crypto::frost::FrostNoncePair,
    operator_result: &spark::SigningResult,
    verifying_key_bytes: &[u8],
) -> Result<Vec<u8>, SdkError> {
    let operator_data =
        parse_signing_result(operator_result).map_err(|_| SdkError::InvalidOperatorResponse)?;

    let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(prev_out))
        .map_err(|_| SdkError::SigningFailed)?;

    let user_identifier = spark_crypto::frost::user_identifier();

    let mut all_commitments = operator_data.commitments;
    all_commitments.insert(user_identifier, nonce_pair.commitment);

    let verifying_key = if !verifying_key_bytes.is_empty() {
        PublicKey::from_slice(verifying_key_bytes).map_err(|_| SdkError::InvalidOperatorResponse)?
    } else {
        PublicKey::from_slice(&ctx.verifying_public_key)
            .map_err(|_| SdkError::InvalidOperatorResponse)?
    };

    let user_share = spark_crypto::frost::sign_as_user(
        &sighash,
        &ctx.new_sk,
        &ctx.new_pk,
        &verifying_key,
        &nonce_pair.nonces,
        &all_commitments,
    )
    .map_err(|_| SdkError::SigningFailed)?;

    let mut all_shares = operator_data.signature_shares;
    all_shares.insert(user_identifier, user_share);

    let mut all_verifying_shares = operator_data.verifying_shares;
    all_verifying_shares.insert(user_identifier, ctx.new_pk);

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
