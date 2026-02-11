//! Verify sender signatures and ECIES-decrypt leaf secrets.
//!
//! Produces `ClaimableLeaf` list used by key tweaks and sign/finalize steps.

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use signer::WalletSigner;
use transport::spark;

use crate::SdkError;

// ---------------------------------------------------------------------------
// Claimable leaf
// ---------------------------------------------------------------------------

/// Decrypted leaf data ready for claiming.
#[allow(dead_code)] // Fields reserved for direct/CPFP refund paths.
pub(crate) struct ClaimableLeaf {
    /// Leaf ID (UUID string).
    pub leaf_id: String,
    /// Value in satoshis.
    pub value: u64,
    /// Raw node transaction bytes (the tx being spent by the refund).
    pub node_tx_raw: Vec<u8>,
    /// Sequence from the CPFP refund tx (determines timelock).
    pub cpfp_refund_sequence: u32,
    /// Sequence from the direct-from-CPFP refund tx (may differ in encoding).
    pub direct_from_cpfp_refund_sequence: u32,
    /// Sequence from the direct refund tx.
    pub direct_refund_sequence: u32,
    /// Raw direct_tx bytes (separate tx for direct spend path).
    pub direct_tx_raw: Vec<u8>,
    /// The verifying (group aggregate) public key for FROST.
    pub verifying_public_key: [u8; 33],
    /// The signing secret key decrypted from ECIES (the sender's ephemeral key).
    pub decrypted_signing_key: SecretKey,
    /// Output index on the node tx.
    pub vout: u32,
    /// Whether intermediate direct refund tx exists.
    pub has_direct: bool,
    /// Whether intermediate direct-from-CPFP refund tx exists.
    pub has_direct_from_cpfp: bool,
}

// ---------------------------------------------------------------------------
// Verify and decrypt
// ---------------------------------------------------------------------------

/// Verify the sender's ECDSA signature and ECIES-decrypt each leaf's secret.
pub(crate) fn verify_and_decrypt_transfer(
    transfer: &spark::Transfer,
    signer: &impl WalletSigner,
) -> Result<Vec<ClaimableLeaf>, SdkError> {
    let secp = Secp256k1::verification_only();

    let sender_pk = PublicKey::from_slice(&transfer.sender_identity_public_key)
        .map_err(|_| SdkError::InvalidOperatorResponse)?;

    let mut claimable = Vec::with_capacity(transfer.leaves.len());
    let mut payload = Vec::with_capacity(512);

    for transfer_leaf in &transfer.leaves {
        let leaf = transfer_leaf
            .leaf
            .as_ref()
            .ok_or(SdkError::InvalidOperatorResponse)?;

        // Verify sender's signature: SHA256(leaf_id || transfer_id || secret_cipher).
        payload.clear();
        payload.extend_from_slice(leaf.id.as_bytes());
        payload.extend_from_slice(transfer.id.as_bytes());
        payload.extend_from_slice(&transfer_leaf.secret_cipher);

        let payload_hash = bitcoin::hashes::sha256::Hash::hash(&payload);

        if !transfer_leaf.signature.is_empty() {
            // Signatures may arrive as compact (64 bytes, r||s) or DER (~70-72
            // bytes).  The SSP sends DER; user-to-user transfers send compact.
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&transfer_leaf.signature)
                .or_else(|_| {
                    bitcoin::secp256k1::ecdsa::Signature::from_der(&transfer_leaf.signature)
                })
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

        let cpfp_refund_sequence =
            extract_sequence_from_tx_bytes(&transfer_leaf.intermediate_refund_tx, &leaf.refund_tx);

        let direct_from_cpfp_refund_sequence = extract_sequence_from_tx_bytes(
            &transfer_leaf.intermediate_direct_from_cpfp_refund_tx,
            &leaf.direct_from_cpfp_refund_tx,
        );

        let direct_refund_sequence = extract_sequence_from_tx_bytes(
            &transfer_leaf.intermediate_direct_refund_tx,
            &leaf.direct_refund_tx,
        );

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
pub(crate) fn extract_sequence_from_tx_bytes(primary: &[u8], fallback: &[u8]) -> u32 {
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
