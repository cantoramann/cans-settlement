//! FROST (Flexible Round-Optimized Schnorr Threshold) signature operations.
//!
//! FROST is a threshold signature scheme that allows a group of participants
//! to collectively sign messages without any single party having access to
//! the full signing key.
//!
//! This module provides:
//! - Nonce generation for signing commitments
//! - Signature share creation (round 2 of the FROST protocol)
//! - Signature aggregation to produce the final Schnorr signature
//! - Identifier derivation and serialization helpers

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use frost_secp256k1_tr::{
    Identifier, SigningPackage, VerifyingKey,
    keys::{EvenY, KeyPackage, PublicKeyPackage, SigningShare, Tweak, VerifyingShare},
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};
use rand_core::{CryptoRng, RngCore};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by FROST operations.
#[derive(Debug)]
pub enum FrostError {
    /// Signing round 2 failed (invalid key, nonce, or commitment).
    SigningFailed,

    /// Signature aggregation failed (invalid shares or commitment mismatch).
    AggregationFailed,

    /// An identifier could not be derived or converted.
    InvalidIdentifier,

    /// A signing commitment is invalid or could not be deserialized.
    InvalidCommitment,

    /// A signature share is invalid or could not be deserialized.
    InvalidSignatureShare,
}

impl fmt::Display for FrostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigningFailed => write!(f, "FROST signing failed"),
            Self::AggregationFailed => write!(f, "FROST signature aggregation failed"),
            Self::InvalidIdentifier => write!(f, "invalid FROST identifier"),
            Self::InvalidCommitment => write!(f, "invalid signing commitment"),
            Self::InvalidSignatureShare => write!(f, "invalid signature share"),
        }
    }
}

impl std::error::Error for FrostError {}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A nonce pair for FROST signing, including the commitment.
///
/// Generated during round 1 and used in round 2 for signing.
#[derive(Debug, Clone)]
pub struct FrostNoncePair {
    /// The signing nonces (kept secret, used for signing).
    pub nonces: SigningNonces,
    /// The public commitments (shared with other signers).
    pub commitment: SigningCommitments,
}

// ---------------------------------------------------------------------------
// Round 1 -- Nonce generation
// ---------------------------------------------------------------------------

/// Generate a random nonce pair for FROST signing.
///
/// This should be called once per signing operation and the nonces
/// should be kept secret until the signature share is created.
///
/// The caller provides the RNG, keeping this crate free of runtime
/// `rand` dependencies.
///
/// # Arguments
///
/// * `signing_share` -- The signer's secret share
/// * `rng` -- A cryptographically secure random number generator
pub fn generate_nonces(
    signing_share: &SigningShare,
    rng: &mut (impl RngCore + CryptoRng),
) -> FrostNoncePair {
    let (nonces, commitment) = frost_secp256k1_tr::round1::commit(signing_share, rng);
    FrostNoncePair { nonces, commitment }
}

// ---------------------------------------------------------------------------
// Round 2 -- Signing
// ---------------------------------------------------------------------------

/// Create a FROST signature share.
///
/// This is round 2 of the FROST protocol. Each signer creates their
/// signature share using their secret key, nonces, and the commitments
/// from all participants.
///
/// # Arguments
///
/// * `message` -- The message being signed (typically a 32-byte sighash)
/// * `signing_key` -- The signer's secret key share
/// * `public_key` -- The signer's public key (corresponding to `signing_key`)
/// * `verifying_key` -- The group's aggregate public key
/// * `nonces` -- The nonces generated in round 1
/// * `all_commitments` -- All participants' commitments (including self), consumed
/// * `participant_id` -- This signer's identifier
///
/// # Errors
///
/// Returns [`FrostError::SigningFailed`] if key conversion or signing fails.
pub fn sign(
    message: &[u8],
    signing_key: &SecretKey,
    public_key: &PublicKey,
    verifying_key: &PublicKey,
    nonces: &SigningNonces,
    all_commitments: BTreeMap<Identifier, SigningCommitments>,
    participant_id: Identifier,
) -> Result<SignatureShare, FrostError> {
    let signing_package = SigningPackage::new(all_commitments, message);

    let signing_share = SigningShare::deserialize(&signing_key.secret_bytes())
        .map_err(|_| FrostError::SigningFailed)?;

    let verifying_share = VerifyingShare::deserialize(&public_key.serialize())
        .map_err(|_| FrostError::SigningFailed)?;

    let group_verifying_key = VerifyingKey::deserialize(&verifying_key.serialize())
        .map_err(|_| FrostError::SigningFailed)?;

    let key_package = KeyPackage::new(
        participant_id,
        signing_share,
        verifying_share,
        group_verifying_key,
        1, // min_signers from this participant's perspective
    );

    // Taproot: use `sign_with_tweak` which internally applies even-Y
    // adjustment and Taproot tweak in the correct order, consistent
    // with `aggregate_with_tweak`.
    frost_secp256k1_tr::round2::sign_with_tweak(&signing_package, nonces, &key_package, Some(b""))
        .map_err(|_| FrostError::SigningFailed)
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/// Aggregate FROST signature shares into a complete Schnorr signature.
///
/// Combines signature shares from all participants to produce a final
/// Schnorr signature verifiable with the group's aggregate public key.
///
/// # Arguments
///
/// * `message` -- The message that was signed
/// * `all_commitments` -- All participants' commitments, consumed
/// * `signature_shares` -- All participants' signature shares
/// * `verifying_shares` -- All participants' public keys
/// * `verifying_key` -- The group's aggregate public key
///
/// # Errors
///
/// Returns [`FrostError::AggregationFailed`] if key conversion or aggregation fails.
pub fn aggregate(
    message: &[u8],
    all_commitments: BTreeMap<Identifier, SigningCommitments>,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    verifying_shares: &BTreeMap<Identifier, PublicKey>,
    verifying_key: &PublicKey,
) -> Result<frost_secp256k1_tr::Signature, FrostError> {
    let signing_package = SigningPackage::new(all_commitments, message);

    let mut frost_verifying_shares = BTreeMap::new();
    for (id, pk) in verifying_shares {
        let vs = VerifyingShare::deserialize(&pk.serialize())
            .map_err(|_| FrostError::AggregationFailed)?;
        frost_verifying_shares.insert(*id, vs);
    }

    let group_verifying_key = VerifyingKey::deserialize(&verifying_key.serialize())
        .map_err(|_| FrostError::AggregationFailed)?;

    let public_key_package = PublicKeyPackage::new(frost_verifying_shares, group_verifying_key);

    frost_secp256k1_tr::aggregate_with_tweak(
        &signing_package,
        signature_shares,
        &public_key_package,
        Some(b""),
    )
    .map_err(|_| FrostError::AggregationFailed)
}

// ---------------------------------------------------------------------------
// Spark-specific: nested signing (user + operators)
// ---------------------------------------------------------------------------

/// The fixed FROST user identifier used by the Spark protocol.
///
/// The Spark protocol derives the user's FROST identifier from the fixed
/// string `"user"`, not from a public key. This matches the official Spark SDK
/// constant `FROST_USER_IDENTIFIER`.
pub fn user_identifier() -> Identifier {
    Identifier::derive(b"user").expect("FROST user identifier derivation must not fail")
}

/// Create a FROST signature share as the **user** (Spark role 1).
///
/// The user's signing differs from an operator (role 0) in two ways:
///
/// 1. The key package is adjusted for even-Y without adding the Taproot tweak
///    scalar to the signing share. Only the group verifying key receives the
///    tweak. This is critical because `aggregate_with_tweak` adds the tweak
///    to the operator verifying shares, and the math works out only when the
///    user's signing share does NOT include the tweak.
///
/// 2. The signing package uses **nested signing groups**: operators form one
///    group, the user forms a separate group. This changes how Lagrange
///    coefficients are computed, which is essential for correct threshold
///    reconstruction in Spark's additive key structure.
///
/// # Arguments
///
/// * `message` -- The message being signed (typically a 32-byte sighash)
/// * `signing_key` -- The user's secret key share (the claim-tweaked key)
/// * `public_key` -- The user's public key (corresponding to `signing_key`)
/// * `verifying_key` -- The group's aggregate public key
/// * `nonces` -- The nonces generated in round 1
/// * `all_commitments` -- All participants' commitments (including self)
///
/// # Errors
///
/// Returns [`FrostError::SigningFailed`] if key conversion or signing fails.
pub fn sign_as_user(
    message: &[u8],
    signing_key: &SecretKey,
    public_key: &PublicKey,
    verifying_key: &PublicKey,
    nonces: &SigningNonces,
    all_commitments: &BTreeMap<Identifier, SigningCommitments>,
) -> Result<SignatureShare, FrostError> {
    let user_id = user_identifier();

    // Build nested signing groups: [operators], [user].
    let operator_group: BTreeSet<Identifier> = all_commitments
        .keys()
        .filter(|id| **id != user_id)
        .cloned()
        .collect();
    let user_group = BTreeSet::from([user_id]);
    let groups = vec![operator_group, user_group];

    // SigningPackage requires ownership; clone once here.
    let signing_package = SigningPackage::new_with_participants_groups(
        all_commitments.clone(),
        Some(groups),
        message,
    );

    // Deserialize raw key material.
    let signing_share = SigningShare::deserialize(&signing_key.secret_bytes())
        .map_err(|_| FrostError::SigningFailed)?;
    let verifying_share = VerifyingShare::deserialize(&public_key.serialize())
        .map_err(|_| FrostError::SigningFailed)?;
    let group_verifying_key = VerifyingKey::deserialize(&verifying_key.serialize())
        .map_err(|_| FrostError::SigningFailed)?;

    // Build the untweaked key package with the user identifier.
    let raw_kp = KeyPackage::new(
        user_id,
        signing_share,
        verifying_share,
        group_verifying_key,
        1, // min_signers (user perspective)
    );

    // Role 1 manual tweak (matches official Spark SDK `frost_key_package_from_proto`):
    //   - signing_share + verifying_share: even-Y adjusted only (NO tweak scalar)
    //   - verifying_key: fully tweaked (even-Y + Taproot tweak)
    let tweaked = raw_kp.clone().tweak(Some(&[] as &[u8]));
    let even_y = raw_kp.into_even_y(Some(group_verifying_key.has_even_y()));

    let final_kp = KeyPackage::new(
        *even_y.identifier(),
        *even_y.signing_share(),
        *even_y.verifying_share(),
        *tweaked.verifying_key(),
        *tweaked.min_signers(),
    );

    // Sign with plain round2::sign (NOT sign_with_tweak -- that is for operators).
    frost_secp256k1_tr::round2::sign(&signing_package, nonces, &final_kp)
        .map_err(|_| FrostError::SigningFailed)
}

/// Aggregate FROST signature shares using nested signing groups.
///
/// Uses the same nested-group structure as [`sign_as_user`]: operators in one
/// group, user in another. This is required for correct Lagrange coefficient
/// computation under Spark's additive key model.
///
/// # Arguments
///
/// * `message` -- The message that was signed
/// * `all_commitments` -- All participants' commitments
/// * `signature_shares` -- All participants' signature shares
/// * `verifying_shares` -- All participants' public keys
/// * `verifying_key` -- The group's aggregate public key
///
/// # Errors
///
/// Returns [`FrostError::AggregationFailed`] if key conversion or aggregation fails.
pub fn aggregate_nested(
    message: &[u8],
    all_commitments: BTreeMap<Identifier, SigningCommitments>,
    signature_shares: &BTreeMap<Identifier, SignatureShare>,
    verifying_shares: &BTreeMap<Identifier, PublicKey>,
    verifying_key: &PublicKey,
) -> Result<frost_secp256k1_tr::Signature, FrostError> {
    let user_id = user_identifier();

    // Build nested signing groups: [operators], [user].
    let operator_group: BTreeSet<Identifier> = all_commitments
        .keys()
        .filter(|id| **id != user_id)
        .cloned()
        .collect();
    let user_group = BTreeSet::from([user_id]);
    let groups = vec![operator_group, user_group];

    let signing_package =
        SigningPackage::new_with_participants_groups(all_commitments, Some(groups), message);

    let mut frost_verifying_shares = BTreeMap::new();
    for (id, pk) in verifying_shares {
        let vs = VerifyingShare::deserialize(&pk.serialize())
            .map_err(|_| FrostError::AggregationFailed)?;
        frost_verifying_shares.insert(*id, vs);
    }

    let group_verifying_key = VerifyingKey::deserialize(&verifying_key.serialize())
        .map_err(|_| FrostError::AggregationFailed)?;

    let public_key_package = PublicKeyPackage::new(frost_verifying_shares, group_verifying_key);

    frost_secp256k1_tr::aggregate_with_tweak(
        &signing_package,
        signature_shares,
        &public_key_package,
        Some(b""),
    )
    .map_err(|_| FrostError::AggregationFailed)
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

/// Derive an identifier from a byte string.
///
/// Creates a deterministic identifier for a participant.
///
/// # Errors
///
/// Returns [`FrostError::InvalidIdentifier`] if derivation fails.
pub fn derive_identifier(name: &[u8]) -> Result<Identifier, FrostError> {
    Identifier::derive(name).map_err(|_| FrostError::InvalidIdentifier)
}

/// Create an identifier from a u16 index.
///
/// # Errors
///
/// Returns [`FrostError::InvalidIdentifier`] if the index is invalid (e.g., zero).
pub fn identifier_from_u16(index: u16) -> Result<Identifier, FrostError> {
    Identifier::try_from(index).map_err(|_| FrostError::InvalidIdentifier)
}

// ---------------------------------------------------------------------------
// Serialization helpers
// ---------------------------------------------------------------------------

/// Serialize a signing commitment to bytes.
///
/// # Errors
///
/// Returns [`FrostError::InvalidCommitment`] if serialization fails.
pub fn serialize_commitment(commitment: &SigningCommitments) -> Result<Vec<u8>, FrostError> {
    commitment
        .serialize()
        .map_err(|_| FrostError::InvalidCommitment)
}

/// Deserialize a signing commitment from bytes.
///
/// # Errors
///
/// Returns [`FrostError::InvalidCommitment`] if the bytes are invalid.
pub fn deserialize_commitment(bytes: &[u8]) -> Result<SigningCommitments, FrostError> {
    SigningCommitments::deserialize(bytes).map_err(|_| FrostError::InvalidCommitment)
}

/// Construct [`SigningCommitments`] from separate hiding and binding byte
/// slices (each 33-byte compressed SEC1 point).
///
/// This is the inverse of extracting `commitment.hiding().serialize()` /
/// `commitment.binding().serialize()` and is needed when proto messages
/// carry the two components separately.
///
/// # Errors
///
/// Returns [`FrostError::InvalidCommitment`] if either component is invalid.
pub fn commitments_from_components(
    hiding: &[u8],
    binding: &[u8],
) -> Result<SigningCommitments, FrostError> {
    use frost_secp256k1_tr::round1::NonceCommitment;

    let hiding_nc =
        NonceCommitment::deserialize(hiding).map_err(|_| FrostError::InvalidCommitment)?;
    let binding_nc =
        NonceCommitment::deserialize(binding).map_err(|_| FrostError::InvalidCommitment)?;
    Ok(SigningCommitments::new(hiding_nc, binding_nc))
}

/// Deserialize a signature share from bytes.
///
/// # Errors
///
/// Returns [`FrostError::InvalidSignatureShare`] if the bytes are invalid.
pub fn deserialize_signature_share(bytes: &[u8]) -> Result<SignatureShare, FrostError> {
    SignatureShare::deserialize(bytes).map_err(|_| FrostError::InvalidSignatureShare)
}

/// Deserialize a signing share (secret key share) from bytes.
///
/// # Errors
///
/// Returns [`FrostError::InvalidSignatureShare`] if the bytes are invalid.
pub fn deserialize_signing_share(bytes: &[u8]) -> Result<SigningShare, FrostError> {
    SigningShare::deserialize(bytes).map_err(|_| FrostError::InvalidSignatureShare)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_identifier_deterministic() {
        let id1 = derive_identifier(b"user").unwrap();
        let id2 = derive_identifier(b"user").unwrap();
        let id3 = derive_identifier(b"operator").unwrap();

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn identifier_from_u16_distinct() {
        let id1 = identifier_from_u16(1).unwrap();
        let id2 = identifier_from_u16(2).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn identifier_from_u16_zero_fails() {
        assert!(identifier_from_u16(0).is_err());
    }

    #[test]
    fn commitment_roundtrip() {
        let signing_share =
            SigningShare::deserialize(&[1u8; 32]).expect("valid signing share for test");

        let pair = generate_nonces(&signing_share, &mut rand_core::OsRng);
        let bytes = serialize_commitment(&pair.commitment).unwrap();
        let recovered = deserialize_commitment(&bytes).unwrap();

        // Re-serialize to verify roundtrip.
        let bytes2 = serialize_commitment(&recovered).unwrap();
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn error_display() {
        assert_eq!(
            FrostError::SigningFailed.to_string(),
            "FROST signing failed"
        );
        assert_eq!(
            FrostError::AggregationFailed.to_string(),
            "FROST signature aggregation failed"
        );
        assert_eq!(
            FrostError::InvalidIdentifier.to_string(),
            "invalid FROST identifier"
        );
    }
}
