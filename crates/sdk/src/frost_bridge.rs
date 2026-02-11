//! FROST protocol bridge: proto <-> `frost-secp256k1-tr` type conversions.
//!
//! Converts between the transport layer's protobuf types (`SigningResult`,
//! `SigningCommitment`) and the FROST library's native types used by the
//! crypto crate.

use std::collections::BTreeMap;

use bitcoin::secp256k1::PublicKey;
use signer::{FrostIdentifier as Identifier, SignatureShare, SigningCommitments};

use crate::SdkError;

// ---------------------------------------------------------------------------
// Identifier parsing
// ---------------------------------------------------------------------------

/// Parse a FROST identifier from a hex-encoded string.
///
/// Spark operators use hex-encoded identifiers like `"0000...0001"` as
/// map keys in proto `SigningResult` messages.
///
/// # Errors
///
/// Returns [`SdkError::InvalidOperatorResponse`] if the hex is invalid.
pub fn identifier_from_hex(hex_str: &str) -> Result<Identifier, SdkError> {
    let bytes = crate::utils::hex_decode(hex_str).ok_or(SdkError::InvalidOperatorResponse)?;
    Identifier::deserialize(&bytes).map_err(|_| SdkError::InvalidOperatorResponse)
}

// ---------------------------------------------------------------------------
// Proto -> FROST conversions
// ---------------------------------------------------------------------------

/// Parsed operator signing result from a coordinator response.
pub struct OperatorSigningData {
    /// Operator FROST nonce commitments keyed by identifier.
    pub commitments: BTreeMap<Identifier, SigningCommitments>,
    /// Operator signature shares keyed by identifier.
    pub signature_shares: BTreeMap<Identifier, SignatureShare>,
    /// Operator verifying (public key) shares keyed by identifier.
    pub verifying_shares: BTreeMap<Identifier, PublicKey>,
}

/// Parse a proto `SigningResult` into FROST types.
///
/// The `SigningResult` contains maps keyed by hex-encoded FROST identifiers:
/// - `public_keys`: identifier -> 33-byte compressed public key
/// - `signing_nonce_commitments`: identifier -> `SigningCommitment` (hiding + binding)
/// - `signature_shares`: identifier -> serialized signature share
///
/// # Errors
///
/// Returns [`SdkError::InvalidOperatorResponse`] if any field is malformed.
pub fn parse_signing_result(
    result: &transport::spark::SigningResult,
) -> Result<OperatorSigningData, SdkError> {
    let mut commitments = BTreeMap::new();
    let mut signature_shares = BTreeMap::new();
    let mut verifying_shares = BTreeMap::new();

    // Parse nonce commitments.
    for (hex_id, proto_commitment) in &result.signing_nonce_commitments {
        let id = identifier_from_hex(hex_id)?;

        // Convert proto hiding/binding bytes → FROST SigningCommitments.
        // The proto carries each nonce commitment component separately,
        // so we reconstruct via `commitments_from_components`.
        let commitment = spark_crypto::frost::commitments_from_components(
            &proto_commitment.hiding,
            &proto_commitment.binding,
        )
        .map_err(|_| SdkError::InvalidOperatorResponse)?;
        commitments.insert(id, commitment);
    }

    // Parse signature shares.
    for (hex_id, share_bytes) in &result.signature_shares {
        let id = identifier_from_hex(hex_id)?;
        let share = spark_crypto::frost::deserialize_signature_share(share_bytes)
            .map_err(|_| SdkError::InvalidOperatorResponse)?;
        signature_shares.insert(id, share);
    }

    // Parse verifying (public key) shares.
    for (hex_id, pk_bytes) in &result.public_keys {
        let id = identifier_from_hex(hex_id)?;
        let pk = PublicKey::from_slice(pk_bytes).map_err(|_| SdkError::InvalidOperatorResponse)?;
        verifying_shares.insert(id, pk);
    }

    Ok(OperatorSigningData {
        commitments,
        signature_shares,
        verifying_shares,
    })
}

// ---------------------------------------------------------------------------
// FROST -> Proto conversions
// ---------------------------------------------------------------------------

/// Serialize a FROST `SigningCommitments` into the proto `SigningCommitment`.
///
/// Splits the serialized commitment into its hiding and binding components.
///
/// # Errors
///
/// Returns [`SdkError::SigningFailed`] if serialization fails.
pub fn commitment_to_proto(
    commitment: &SigningCommitments,
) -> Result<transport::common::SigningCommitment, SdkError> {
    // Extract hiding and binding directly rather than slicing the full
    // serialization (which includes an identifier prefix).
    let hiding_bytes = commitment
        .hiding()
        .serialize()
        .map_err(|_| SdkError::SigningFailed)?;
    let binding_bytes = commitment
        .binding()
        .serialize()
        .map_err(|_| SdkError::SigningFailed)?;

    Ok(transport::common::SigningCommitment {
        hiding: bytes::Bytes::copy_from_slice(&hiding_bytes),
        binding: bytes::Bytes::copy_from_slice(&binding_bytes),
    })
}

/// Serialize a FROST `SignatureShare` to bytes.
pub fn serialize_signature_share(share: &SignatureShare) -> Vec<u8> {
    share.serialize()
}

/// Serialize a FROST `Signature` to bytes (64 bytes).
///
/// # Errors
///
/// Returns [`SdkError::SigningFailed`] if serialization fails.
pub fn serialize_frost_signature(sig: &signer::FrostSignature) -> Result<Vec<u8>, SdkError> {
    sig.serialize().map_err(|_| SdkError::SigningFailed)
}
