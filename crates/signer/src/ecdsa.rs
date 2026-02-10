//! ECDSA signing and verification over secp256k1.
//!
//! Provides thin, zero-allocation wrappers around `bitcoin::secp256k1::ecdsa`
//! with SHA256 hashing convenience and a unified error type.
//!
//! # Operations
//!
//! | Function | Description |
//! |----------|-------------|
//! | [`sign_digest`] | ECDSA-sign a 32-byte digest |
//! | [`verify_digest`] | Verify signature against a 32-byte digest |
//! | [`sign_message`] | SHA256-hash a message, then ECDSA-sign the digest |
//! | [`verify_message`] | SHA256-hash a message, then verify the signature |
//!
//! All functions accept a `Secp256k1` context as parameter so callers can
//! share a single context across operations (avoids re-initializing the
//! precomputed tables).

use std::fmt;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signing, Verification};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by ECDSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaError {
    /// The signature does not verify against the given public key and digest.
    VerificationFailed,
    /// The provided bytes are not a valid DER-encoded ECDSA signature.
    InvalidDer,
    /// The provided bytes are not a valid compact (64-byte) ECDSA signature.
    InvalidCompact,
}

impl fmt::Display for EcdsaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerificationFailed => write!(f, "ECDSA signature verification failed"),
            Self::InvalidDer => write!(f, "invalid DER-encoded ECDSA signature"),
            Self::InvalidCompact => write!(f, "invalid compact ECDSA signature"),
        }
    }
}

impl std::error::Error for EcdsaError {}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// ECDSA-sign a 32-byte digest.
///
/// The caller is responsible for hashing the message before calling this.
/// For convenience with SHA256 hashing, use [`sign_message`].
///
/// Zero heap allocations.
pub fn sign_digest(
    secp: &Secp256k1<impl Signing>,
    secret_key: &SecretKey,
    digest: &[u8; 32],
) -> Signature {
    let msg = Message::from_digest(*digest);
    secp.sign_ecdsa(&msg, secret_key)
}

/// SHA256-hash a message and ECDSA-sign the resulting digest.
///
/// Equivalent to `sign_digest(secp, sk, &sha256(message))`.
///
/// Zero heap allocations.
pub fn sign_message(
    secp: &Secp256k1<impl Signing>,
    secret_key: &SecretKey,
    message: &[u8],
) -> Signature {
    let hash = sha256::Hash::hash(message);
    sign_digest(secp, secret_key, hash.as_byte_array())
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an ECDSA signature against a 32-byte digest.
///
/// # Errors
///
/// Returns [`EcdsaError::VerificationFailed`] if the signature is invalid.
pub fn verify_digest(
    secp: &Secp256k1<impl Verification>,
    public_key: &PublicKey,
    digest: &[u8; 32],
    signature: &Signature,
) -> Result<(), EcdsaError> {
    let msg = Message::from_digest(*digest);
    secp.verify_ecdsa(&msg, signature, public_key)
        .map_err(|_| EcdsaError::VerificationFailed)
}

/// SHA256-hash a message and verify the ECDSA signature against the digest.
///
/// # Errors
///
/// Returns [`EcdsaError::VerificationFailed`] if the signature is invalid.
pub fn verify_message(
    secp: &Secp256k1<impl Verification>,
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), EcdsaError> {
    let hash = sha256::Hash::hash(message);
    verify_digest(secp, public_key, hash.as_byte_array(), signature)
}

// ---------------------------------------------------------------------------
// Deserialization helpers
// ---------------------------------------------------------------------------

/// Decode a DER-encoded ECDSA signature.
///
/// # Errors
///
/// Returns [`EcdsaError::InvalidDer`] if the bytes are not valid DER.
pub fn signature_from_der(bytes: &[u8]) -> Result<Signature, EcdsaError> {
    Signature::from_der(bytes).map_err(|_| EcdsaError::InvalidDer)
}

/// Decode a compact (64-byte) ECDSA signature.
///
/// # Errors
///
/// Returns [`EcdsaError::InvalidCompact`] if the bytes are not valid.
pub fn signature_from_compact(bytes: &[u8]) -> Result<Signature, EcdsaError> {
    Signature::from_compact(bytes).map_err(|_| EcdsaError::InvalidCompact)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_keypair() -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).expect("valid secret key");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    #[test]
    fn sign_and_verify_digest() {
        let secp = Secp256k1::new();
        let (sk, pk) = test_keypair();
        let digest = [0xab; 32];

        let sig = sign_digest(&secp, &sk, &digest);
        verify_digest(&secp, &pk, &digest, &sig).expect("should verify");
    }

    #[test]
    fn sign_and_verify_message() {
        let secp = Secp256k1::new();
        let (sk, pk) = test_keypair();

        let sig = sign_message(&secp, &sk, b"hello spark");
        verify_message(&secp, &pk, b"hello spark", &sig).expect("should verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let secp = Secp256k1::new();
        let (sk, pk) = test_keypair();

        let sig = sign_message(&secp, &sk, b"correct message");
        let result = verify_message(&secp, &pk, b"wrong message", &sig);

        assert_eq!(result, Err(EcdsaError::VerificationFailed));
    }

    #[test]
    fn wrong_key_fails_verification() {
        let secp = Secp256k1::new();
        let (sk, _pk) = test_keypair();
        let other_sk = SecretKey::from_slice(&[0xef; 32]).expect("valid");
        let other_pk = PublicKey::from_secret_key(&secp, &other_sk);

        let sig = sign_message(&secp, &sk, b"test");
        let result = verify_message(&secp, &other_pk, b"test", &sig);

        assert_eq!(result, Err(EcdsaError::VerificationFailed));
    }

    #[test]
    fn der_roundtrip() {
        let secp = Secp256k1::new();
        let (sk, pk) = test_keypair();

        let sig = sign_message(&secp, &sk, b"roundtrip test");
        let der = sig.serialize_der();
        let recovered = signature_from_der(&der).expect("valid DER");

        verify_message(&secp, &pk, b"roundtrip test", &recovered).expect("should verify");
    }

    #[test]
    fn compact_roundtrip() {
        let secp = Secp256k1::new();
        let (sk, pk) = test_keypair();

        let sig = sign_message(&secp, &sk, b"compact test");
        let compact = sig.serialize_compact();
        let recovered = signature_from_compact(&compact).expect("valid compact");

        verify_message(&secp, &pk, b"compact test", &recovered).expect("should verify");
    }

    #[test]
    fn invalid_der_rejected() {
        assert_eq!(signature_from_der(b"garbage"), Err(EcdsaError::InvalidDer));
    }

    #[test]
    fn invalid_compact_rejected() {
        assert_eq!(
            signature_from_compact(b"not 64 bytes"),
            Err(EcdsaError::InvalidCompact)
        );
    }

    #[test]
    fn sign_digest_matches_sign_message() {
        let secp = Secp256k1::new();
        let (sk, _pk) = test_keypair();
        let message = b"equivalence test";

        let hash = sha256::Hash::hash(message);
        let sig_digest = sign_digest(&secp, &sk, hash.as_byte_array());
        let sig_message = sign_message(&secp, &sk, message);

        assert_eq!(sig_digest, sig_message);
    }

    #[test]
    fn error_display() {
        assert_eq!(
            EcdsaError::VerificationFailed.to_string(),
            "ECDSA signature verification failed"
        );
    }
}
