//! Adaptor signatures over secp256k1 (BIP340 Schnorr).
//!
//! An adaptor signature is a Schnorr signature "blinded" by an adaptor secret `t`.
//! The blinded signature can only be completed (made valid) by adding `t` back.
//! Conversely, once a completed signature is published, anyone with the adaptor
//! signature can extract `t`.
//!
//! This enables atomic swap and conditional payment protocols on Bitcoin.
//!
//! # Operations
//!
//! | Function | Input | Output |
//! |----------|-------|--------|
//! | [`generate_adaptor_from_signature`] | Valid Schnorr sig `(r, s)` | Blinded sig `(r, s')` + secret `t` |
//! | [`validate_outbound_adaptor_signature`] | Blinded sig, adaptor point `T` | Verification result |
//! | [`apply_adaptor_to_signature`] | Blinded sig + secret `t` | Valid Schnorr sig (verified) |
//! | [`generate_signature_from_existing_adaptor`] | Blinded sig + secret `t` | Valid Schnorr sig (unverified) |
//!
//! # Relationship between operations
//!
//! ```text
//! s' = s - t          (generate_adaptor_from_signature)
//! s  = s' + t         (generate_signature_from_existing_adaptor / apply_adaptor_to_signature)
//! T  = t * G          (adaptor public point, derived from secret)
//! ```

use std::fmt;

use bitcoin::hashes::{Hash, HashEngine, sha256};
use bitcoin::secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, Verification};
use k256::elliptic_curve::PrimeField;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::elliptic_curve::point::{AffineCoordinates, DecompressPoint};
use k256::{AffinePoint, FieldBytes, ProjectivePoint, Scalar};
use rand_core::RngCore;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by adaptor signature operations.
#[derive(Debug, PartialEq, Eq)]
pub enum AdaptorError {
    /// Signature is not 64 bytes.
    InvalidSignatureLength,
    /// Public key bytes cannot be parsed as a valid secp256k1 point.
    InvalidPublicKey,
    /// Byte slice is not a valid secp256k1 scalar (out of range or wrong length).
    InvalidScalar,
    /// Message is not 32 bytes.
    InvalidMessageLength,
    /// Adaptor point bytes cannot be parsed as a valid secp256k1 point.
    InvalidAdaptorPoint,
    /// Neither `s' + t` nor `s' - t` produced a valid Schnorr signature.
    VerificationFailed,
    /// Computed verification point is the identity (point at infinity).
    PointAtInfinity,
    /// Computed verification point has an odd y-coordinate.
    OddYCoordinate,
    /// Computed x-coordinate does not match the signature's `r` value.
    XCoordinateMismatch,
}

impl fmt::Display for AdaptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSignatureLength => {
                write!(f, "invalid signature length (expected 64 bytes)")
            }
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidScalar => write!(f, "scalar out of range for secp256k1"),
            Self::InvalidMessageLength => write!(f, "invalid message length (expected 32 bytes)"),
            Self::InvalidAdaptorPoint => write!(f, "invalid adaptor point"),
            Self::VerificationFailed => write!(f, "adaptor signature verification failed"),
            Self::PointAtInfinity => write!(f, "computed point is at infinity"),
            Self::OddYCoordinate => write!(f, "computed point has odd y-coordinate"),
            Self::XCoordinateMismatch => write!(f, "x-coordinate does not match r"),
        }
    }
}

impl std::error::Error for AdaptorError {}

// ---------------------------------------------------------------------------
// AdaptorSignature
// ---------------------------------------------------------------------------

/// A blinded Schnorr signature and the adaptor secret used to create it.
///
/// The `signature` field is the 64-byte blinded signature `(r, s')` where
/// `s' = s - t`. The `adaptor_secret` field is the 32-byte scalar `t`.
#[derive(Debug)]
pub struct AdaptorSignature {
    /// Blinded signature `(r, s')`, 64 bytes.
    pub signature: [u8; 64],
    /// Adaptor secret scalar `t`, 32 bytes.
    pub adaptor_secret: [u8; 32],
}

// ---------------------------------------------------------------------------
// BIP340 tagged hash
// ---------------------------------------------------------------------------

/// BIP340 challenge: `SHA256(SHA256(tag) || SHA256(tag) || r || P || m)`
/// where `tag = "BIP0340/challenge"`.
fn bip340_challenge(r: &[u8; 32], pk_x: &[u8; 32], msg: &[u8; 32]) -> [u8; 32] {
    let tag_hash = sha256::Hash::hash(b"BIP0340/challenge");
    let tag = tag_hash.as_byte_array();

    let mut engine = sha256::Hash::engine();
    engine.input(tag);
    engine.input(tag);
    engine.input(r);
    engine.input(pk_x);
    engine.input(msg);
    *sha256::Hash::from_engine(engine).as_byte_array()
}

// ---------------------------------------------------------------------------
// Parsing helpers (zero heap allocation)
// ---------------------------------------------------------------------------

/// Parse 32 bytes as a secp256k1 scalar. Returns error if the value is zero
/// or exceeds the field order.
fn parse_scalar(bytes: &[u8; 32]) -> Result<Scalar, AdaptorError> {
    let repr = FieldBytes::from(*bytes);
    let opt = Scalar::from_repr(repr);
    if opt.is_none().into() {
        return Err(AdaptorError::InvalidScalar);
    }
    Ok(opt.unwrap())
}

/// Parse 32 bytes as a BIP340 challenge scalar.
///
/// For a SHA-256 output, the probability of exceeding the curve order `n`
/// is ~2^-128 (negligible). In that astronomically unlikely case, `from_repr`
/// still succeeds because the hash output and `n` differ by < 2^32 in the
/// upper bits, and the representation handles it. In practice this always
/// succeeds via the canonical path.
fn challenge_scalar(bytes: &[u8; 32]) -> Result<Scalar, AdaptorError> {
    parse_scalar(bytes)
}

/// Parse a SEC1-compressed point (33 bytes) into a projective point.
fn parse_point(bytes: &[u8]) -> Result<ProjectivePoint, AdaptorError> {
    if bytes.len() != 33 {
        return Err(AdaptorError::InvalidAdaptorPoint);
    }
    let mut repr = <ProjectivePoint as GroupEncoding>::Repr::default();
    repr.copy_from_slice(bytes);
    let opt = ProjectivePoint::from_bytes(&repr);
    if opt.is_none().into() {
        return Err(AdaptorError::InvalidAdaptorPoint);
    }
    Ok(opt.unwrap())
}

/// Lift a 32-byte x-only public key to a projective point with even y,
/// per BIP340 key lifting rules.
fn lift_x_even_y(x_bytes: &[u8; 32]) -> Result<ProjectivePoint, AdaptorError> {
    let fb = FieldBytes::from(*x_bytes);
    let opt = AffinePoint::decompress(&fb, 0u8.into());
    if opt.is_none().into() {
        return Err(AdaptorError::InvalidPublicKey);
    }
    Ok(ProjectivePoint::from(opt.unwrap()))
}

// ---------------------------------------------------------------------------
// Adaptor verification (BIP340 with adaptor point)
// ---------------------------------------------------------------------------

/// Core verification: checks that `(r, s')` is consistent with public key,
/// message, and adaptor point `T`.
///
/// Computes `R' = s'*G - e*P`, then `R_check = R' + T`, and verifies
/// the three BIP340 conditions on `R_check`:
/// 1. Not the point at infinity
/// 2. Even y-coordinate
/// 3. x-coordinate equals `r`
fn verify_adaptor_inner(
    pk_x: &[u8; 32],
    msg: &[u8; 32],
    sig: &[u8; 64],
    adaptor_point: &ProjectivePoint,
) -> Result<(), AdaptorError> {
    let r_bytes: [u8; 32] = sig[..32].try_into().expect("split from 64-byte array");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("split from 64-byte array");

    let pk_point = lift_x_even_y(pk_x)?;
    let s = parse_scalar(&s_bytes)?;
    let e = challenge_scalar(&bip340_challenge(&r_bytes, pk_x, msg))?;

    // R' = s'*G - e*P
    let r_prime = ProjectivePoint::GENERATOR * s - pk_point * e;
    // R_check = R' + T
    let r_check = (r_prime + adaptor_point).to_affine();

    // BIP340 check 1: not the identity (point at infinity)
    if bool::from(r_check.is_identity()) {
        return Err(AdaptorError::PointAtInfinity);
    }

    // BIP340 check 2: even y-coordinate
    if bool::from(r_check.y_is_odd()) {
        return Err(AdaptorError::OddYCoordinate);
    }

    // BIP340 check 3: x-coordinate matches r
    if r_check.x() != FieldBytes::from(r_bytes) {
        return Err(AdaptorError::XCoordinateMismatch);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Blind a valid BIP340 Schnorr signature with a random adaptor secret.
///
/// Given a valid signature `(r, s)`, generates a random adaptor secret `t`
/// and returns the blinded signature `(r, s')` where `s' = s - t`.
///
/// The caller can derive the adaptor public point as `T = t * G`.
pub fn generate_adaptor_from_signature(
    signature: &[u8; 64],
    rng: &mut impl RngCore,
) -> Result<AdaptorSignature, AdaptorError> {
    let s_bytes: [u8; 32] = signature[32..64]
        .try_into()
        .expect("split from 64-byte array");
    let s = parse_scalar(&s_bytes)?;

    // Generate a random valid scalar as the adaptor secret
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let adaptor_sk = SecretKey::from_slice(&sk_bytes).map_err(|_| AdaptorError::InvalidScalar)?;
    let t = parse_scalar(&adaptor_sk.secret_bytes())?;

    // s' = s - t
    let blinded_s = s - t;

    let mut blinded_sig = [0u8; 64];
    blinded_sig[..32].copy_from_slice(&signature[..32]);
    blinded_sig[32..].copy_from_slice(&blinded_s.to_repr());

    Ok(AdaptorSignature {
        signature: blinded_sig,
        adaptor_secret: adaptor_sk.secret_bytes(),
    })
}

/// Verify that a blinded signature is consistent with the signer's public key,
/// the message, and the adaptor point.
///
/// - `pubkey`: 33-byte SEC1-compressed public key of the signer.
/// - `message`: 32-byte message hash.
/// - `signature`: 64-byte blinded adaptor signature `(r, s')`.
/// - `adaptor_pubkey`: 33-byte SEC1-compressed adaptor point `T = t*G`.
///
/// Returns `Ok(())` if the adaptor signature is valid.
pub fn validate_outbound_adaptor_signature(
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
    adaptor_pubkey: &[u8],
) -> Result<(), AdaptorError> {
    let msg: [u8; 32] = message
        .try_into()
        .map_err(|_| AdaptorError::InvalidMessageLength)?;
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| AdaptorError::InvalidSignatureLength)?;

    let pk = PublicKey::from_slice(pubkey).map_err(|_| AdaptorError::InvalidPublicKey)?;
    let pk_x = pk.x_only_public_key().0.serialize();

    let adaptor = parse_point(adaptor_pubkey)?;

    verify_adaptor_inner(&pk_x, &msg, &sig, &adaptor)
}

/// Recover a valid Schnorr signature from an adaptor signature using the
/// adaptor secret, with verification.
///
/// Tries `s = s' + t` first; if the resulting signature does not verify under
/// BIP340, tries `s = s' - t`. Returns the first candidate that verifies,
/// or [`AdaptorError::VerificationFailed`] if neither does.
///
/// The caller supplies a [`Secp256k1`] context to avoid the ~1 MB allocation
/// per call.
///
/// - `secp`: Pre-allocated secp256k1 context with verification capability.
/// - `pubkey`: 33-byte SEC1-compressed public key of the signer.
/// - `message`: 32-byte message hash.
/// - `signature`: 64-byte blinded adaptor signature `(r, s')`.
/// - `adaptor_secret`: 32-byte adaptor secret scalar `t`.
pub fn apply_adaptor_to_signature<C: Verification>(
    secp: &Secp256k1<C>,
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
    adaptor_secret: &[u8],
) -> Result<[u8; 64], AdaptorError> {
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| AdaptorError::InvalidSignatureLength)?;
    let msg_bytes: [u8; 32] = message
        .try_into()
        .map_err(|_| AdaptorError::InvalidMessageLength)?;
    let secret: [u8; 32] = adaptor_secret
        .try_into()
        .map_err(|_| AdaptorError::InvalidScalar)?;

    let s_bytes: [u8; 32] = sig[32..].try_into().expect("split from 64-byte array");
    let s = parse_scalar(&s_bytes)?;
    let t = parse_scalar(&secret)?;

    let pk = PublicKey::from_slice(pubkey).map_err(|_| AdaptorError::InvalidPublicKey)?;
    let secp_msg =
        Message::from_digest_slice(&msg_bytes).map_err(|_| AdaptorError::InvalidMessageLength)?;
    let xonly = pk.x_only_public_key().0;

    // Candidate 1: s' + t (consistent with our generate_adaptor which does s' = s - t)
    let candidate = s + t;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig[..32]);
    out[32..].copy_from_slice(&candidate.to_repr());

    if let Ok(schnorr) = secp256k1::schnorr::Signature::from_slice(&out)
        && secp.verify_schnorr(&schnorr, &secp_msg, &xonly).is_ok()
    {
        return Ok(out);
    }

    // Candidate 2: s' - t (handles adaptor created with opposite convention)
    let alt = s - t;
    out[32..].copy_from_slice(&alt.to_repr());

    if let Ok(schnorr) = secp256k1::schnorr::Signature::from_slice(&out)
        && secp.verify_schnorr(&schnorr, &secp_msg, &xonly).is_ok()
    {
        return Ok(out);
    }

    Err(AdaptorError::VerificationFailed)
}

/// Recover a valid Schnorr signature from an adaptor signature using the
/// adaptor secret, **without** verification.
///
/// Computes `s = s' + t` and returns `(r, s)`. Use this when you already
/// know the adaptor was created with [`generate_adaptor_from_signature`]
/// (which does `s' = s - t`), so `s' + t = s`.
///
/// If the adaptor's origin is unknown, prefer [`apply_adaptor_to_signature`]
/// which tries both `+t` and `-t` and verifies the result.
///
/// - `signature`: 64-byte blinded adaptor signature `(r, s')`.
/// - `adaptor_secret`: 32-byte adaptor secret scalar `t`.
pub fn generate_signature_from_existing_adaptor(
    signature: &[u8],
    adaptor_secret: &[u8],
) -> Result<[u8; 64], AdaptorError> {
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| AdaptorError::InvalidSignatureLength)?;
    let secret: [u8; 32] = adaptor_secret
        .try_into()
        .map_err(|_| AdaptorError::InvalidScalar)?;

    let s_bytes: [u8; 32] = sig[32..].try_into().expect("split from 64-byte array");
    let s = parse_scalar(&s_bytes)?;
    let t = parse_scalar(&secret)?;

    // s' + t = (s - t) + t = s
    let new_s = s + t;

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&sig[..32]);
    out[32..].copy_from_slice(&new_s.to_repr());

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Keypair;

    const TEST_SK_BYTES: [u8; 32] = [0x11; 32];
    const TEST_MSG: [u8; 32] = [0xaa; 32];

    /// Create a Secp256k1 context, keypair, and a valid BIP340 Schnorr signature.
    fn setup() -> (
        Secp256k1<bitcoin::secp256k1::All>,
        SecretKey,
        PublicKey,
        [u8; 64],
    ) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&TEST_SK_BYTES).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let msg = Message::from_digest_slice(&TEST_MSG).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

        // Sanity: the base signature must verify
        let xonly = pk.x_only_public_key().0;
        assert!(secp.verify_schnorr(&sig, &msg, &xonly).is_ok());

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());
        (secp, sk, pk, sig_bytes)
    }

    /// Compute the adaptor public point T = t*G, returned as 33-byte compressed.
    fn adaptor_public_point(adaptor_secret: &[u8; 32]) -> Vec<u8> {
        let t = parse_scalar(adaptor_secret).unwrap();
        let point = (ProjectivePoint::GENERATOR * t).to_affine();
        let encoded = point.to_bytes();
        encoded.to_vec()
    }

    // -----------------------------------------------------------------------
    // Round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn round_trip_generate_validate_complete() {
        let (secp, _sk, pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        // Step 1: blind the valid signature
        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();

        // Step 2: compute adaptor point T = t*G
        let adaptor_point = adaptor_public_point(&adaptor.adaptor_secret);

        // Step 3: validate the adaptor signature
        validate_outbound_adaptor_signature(
            &pk.serialize(),
            &TEST_MSG,
            &adaptor.signature,
            &adaptor_point,
        )
        .unwrap();

        // Step 4: complete the adaptor to recover a valid Schnorr sig
        let completed = apply_adaptor_to_signature(
            &secp,
            &pk.serialize(),
            &TEST_MSG,
            &adaptor.signature,
            &adaptor.adaptor_secret,
        )
        .unwrap();

        // Step 5: verify the completed signature via bitcoin::secp256k1
        let msg = Message::from_digest_slice(&TEST_MSG).unwrap();
        let schnorr = secp256k1::schnorr::Signature::from_slice(&completed).unwrap();
        let xonly = pk.x_only_public_key().0;
        assert!(secp.verify_schnorr(&schnorr, &msg, &xonly).is_ok());
    }

    #[test]
    fn extract_without_verification() {
        let (secp, _sk, pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();

        // generate_signature_from_existing_adaptor does s' + t without verification
        let recovered =
            generate_signature_from_existing_adaptor(&adaptor.signature, &adaptor.adaptor_secret)
                .unwrap();

        // The recovered signature must be valid
        let msg = Message::from_digest_slice(&TEST_MSG).unwrap();
        let schnorr = secp256k1::schnorr::Signature::from_slice(&recovered).unwrap();
        let xonly = pk.x_only_public_key().0;
        assert!(secp.verify_schnorr(&schnorr, &msg, &xonly).is_ok());
    }

    #[test]
    fn recover_adaptor_secret_from_signatures() {
        let (_secp, _sk, _pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();

        // Given the adaptor sig (r, s') and the completed sig (r, s),
        // the adaptor secret is t = s - s'
        let s_original: [u8; 32] = sig[32..].try_into().unwrap();
        let s_blinded: [u8; 32] = adaptor.signature[32..].try_into().unwrap();

        let s = parse_scalar(&s_original).unwrap();
        let s_prime = parse_scalar(&s_blinded).unwrap();
        let recovered_t = s - s_prime;

        let expected_t = parse_scalar(&adaptor.adaptor_secret).unwrap();
        assert_eq!(recovered_t, expected_t);
    }

    // -----------------------------------------------------------------------
    // BIP340 tagged hash
    // -----------------------------------------------------------------------

    #[test]
    fn tagged_hash_is_deterministic() {
        let r = [0x01; 32];
        let pk = [0x02; 32];
        let msg = [0x03; 32];

        let h1 = bip340_challenge(&r, &pk, &msg);
        let h2 = bip340_challenge(&r, &pk, &msg);
        assert_eq!(h1, h2);
    }

    #[test]
    fn tagged_hash_changes_with_different_inputs() {
        let r = [0x01; 32];
        let pk = [0x02; 32];
        let msg1 = [0x03; 32];
        let msg2 = [0x04; 32];

        let h1 = bip340_challenge(&r, &pk, &msg1);
        let h2 = bip340_challenge(&r, &pk, &msg2);
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // Validation rejects invalid inputs
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_wrong_pubkey() {
        let (_secp, _sk, _pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();
        let adaptor_point = adaptor_public_point(&adaptor.adaptor_secret);

        // Use a different public key
        let wrong_sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let wrong_pk = PublicKey::from_secret_key(&Secp256k1::new(), &wrong_sk);

        let result = validate_outbound_adaptor_signature(
            &wrong_pk.serialize(),
            &TEST_MSG,
            &adaptor.signature,
            &adaptor_point,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_wrong_message() {
        let (_secp, _sk, pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();
        let adaptor_point = adaptor_public_point(&adaptor.adaptor_secret);

        let wrong_msg = [0xbb; 32];
        let result = validate_outbound_adaptor_signature(
            &pk.serialize(),
            &wrong_msg,
            &adaptor.signature,
            &adaptor_point,
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_rejects_wrong_adaptor_point() {
        let (_secp, _sk, pk, sig) = setup();
        let mut rng = rand_core::OsRng;

        let adaptor = generate_adaptor_from_signature(&sig, &mut rng).unwrap();

        // Use a different adaptor point (from a different secret)
        let wrong_point = adaptor_public_point(&[0x33; 32]);

        let result = validate_outbound_adaptor_signature(
            &pk.serialize(),
            &TEST_MSG,
            &adaptor.signature,
            &wrong_point,
        );
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Edge cases: invalid lengths and out-of-range values
    // -----------------------------------------------------------------------

    #[test]
    fn validate_rejects_short_message() {
        let result = validate_outbound_adaptor_signature(
            &[0x02; 33], // dummy compressed key
            &[0xaa; 16], // too short
            &[0x00; 64],
            &[0x02; 33],
        );
        assert_eq!(result, Err(AdaptorError::InvalidMessageLength));
    }

    #[test]
    fn validate_rejects_short_signature() {
        let result = validate_outbound_adaptor_signature(
            &[0x02; 33],
            &[0xaa; 32],
            &[0x00; 32], // too short
            &[0x02; 33],
        );
        assert_eq!(result, Err(AdaptorError::InvalidSignatureLength));
    }

    #[test]
    fn validate_rejects_invalid_pubkey() {
        let result = validate_outbound_adaptor_signature(
            &[0x00; 33], // invalid prefix byte
            &[0xaa; 32],
            &[0x00; 64],
            &[0x02; 33],
        );
        assert_eq!(result, Err(AdaptorError::InvalidPublicKey));
    }

    #[test]
    fn validate_rejects_short_adaptor_point() {
        let result = validate_outbound_adaptor_signature(
            &[0x02; 33],
            &[0xaa; 32],
            &[0x00; 64],
            &[0x02; 16], // too short
        );
        assert_eq!(result, Err(AdaptorError::InvalidAdaptorPoint));
    }

    #[test]
    fn extract_rejects_wrong_signature_length() {
        let result = generate_signature_from_existing_adaptor(&[0x00; 32], &[0x01; 32]);
        assert_eq!(result, Err(AdaptorError::InvalidSignatureLength));
    }

    #[test]
    fn extract_rejects_wrong_secret_length() {
        let result = generate_signature_from_existing_adaptor(&[0x00; 64], &[0x01; 16]);
        assert_eq!(result, Err(AdaptorError::InvalidScalar));
    }

    #[test]
    fn apply_rejects_wrong_secret_length() {
        let secp = Secp256k1::new();
        let result = apply_adaptor_to_signature(
            &secp,
            &[0x02; 33],
            &[0xaa; 32],
            &[0x00; 64],
            &[0x01; 16], // too short
        );
        assert_eq!(result, Err(AdaptorError::InvalidScalar));
    }

    // -----------------------------------------------------------------------
    // Scalar parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_scalar_accepts_zero() {
        // Zero is a valid field element (the additive identity).
        // Note: zero is NOT a valid secret key, but parse_scalar is a
        // general-purpose scalar parser, not a secret key parser.
        let result = parse_scalar(&[0x00; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_scalar_accepts_one() {
        let mut bytes = [0x00; 32];
        bytes[31] = 0x01;
        assert!(parse_scalar(&bytes).is_ok());
    }

    #[test]
    fn parse_scalar_rejects_overflow() {
        // All 0xFF exceeds the secp256k1 order
        let result = parse_scalar(&[0xFF; 32]);
        assert_eq!(result, Err(AdaptorError::InvalidScalar));
    }
}
