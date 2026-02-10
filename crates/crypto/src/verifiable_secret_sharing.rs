//! Verifiable Secret Sharing (VSS) over secp256k1.
//!
//! Implements Shamir's Secret Sharing with verifiable shares using the secp256k1 curve.
//! Secrets are split into `n` shares where any `k` (threshold) shares can reconstruct
//! the original secret. Each share includes cryptographic proofs for authenticity
//! verification without revealing the secret.
//!
//! # Example
//!
//! ```
//! use bitcoin::secp256k1::rand::RngCore;
//! use k256::{Scalar, elliptic_curve::PrimeField};
//! use spark_crypto::verifiable_secret_sharing::*;
//!
//! let secret = scalar_from_bytes(&[0x42; 32]).unwrap();
//! let mut rng = bitcoin::secp256k1::rand::thread_rng();
//! let shares = split_secret_with_proofs(&secret, 3, 5, &mut rng).unwrap();
//!
//! for share in &shares {
//!     validate_share(share).unwrap();
//! }
//!
//! let recovered = recover_secret(&shares[0..3]).unwrap();
//! assert_eq!(secret, recovered);
//! ```

use std::collections::HashSet;
use std::fmt;

use bitcoin::secp256k1::rand::RngCore;
use k256::{
    AffinePoint, FieldBytes, ProjectivePoint, PublicKey, Scalar, elliptic_curve::PrimeField,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by VSS operations.
#[derive(Debug)]
pub enum VssError {
    /// Threshold is zero or exceeds the number of shares.
    InvalidThreshold,
    /// Byte slice is not 32 bytes.
    InvalidByteLength { expected: usize, got: usize },
    /// Byte value exceeds the secp256k1 scalar field order.
    ScalarOutOfRange,
    /// Attempted division by zero in field arithmetic.
    DivisionByZero,
    /// Scalar has no multiplicative inverse (should only occur for zero).
    NotInvertible,
    /// Fewer shares provided than the threshold requires.
    InsufficientShares { required: usize, provided: usize },
    /// Two or more shares have the same index.
    DuplicateShareIndices,
    /// Proof vector length does not match the threshold.
    InvalidProofLength { expected: usize, got: usize },
    /// Proof-based verification of a share failed.
    ShareValidationFailed,
}

impl fmt::Display for VssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold => write!(f, "invalid threshold"),
            Self::InvalidByteLength { expected, got } => {
                write!(f, "invalid byte length: expected {expected}, got {got}")
            }
            Self::ScalarOutOfRange => write!(f, "scalar out of range"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::NotInvertible => write!(f, "element not invertible"),
            Self::InsufficientShares { required, provided } => {
                write!(f, "insufficient shares: need {required}, got {provided}")
            }
            Self::DuplicateShareIndices => write!(f, "duplicate share indices"),
            Self::InvalidProofLength { expected, got } => {
                write!(
                    f,
                    "invalid VSS proof length: expected {expected}, got {got}"
                )
            }
            Self::ShareValidationFailed => write!(f, "share validation failed"),
        }
    }
}

impl std::error::Error for VssError {}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Trait for types that can participate in Lagrange interpolation.
pub trait LagrangeInterpolatable {
    /// The share index (x-coordinate on the polynomial).
    fn index(&self) -> &Scalar;
    /// The share value (y-coordinate on the polynomial).
    fn share(&self) -> &Scalar;
    /// The threshold required to reconstruct the secret.
    fn threshold(&self) -> usize;
}

/// A single share produced by Shamir's Secret Sharing.
#[derive(Debug, Clone)]
pub struct SecretShare {
    /// Minimum number of shares needed for reconstruction.
    pub threshold: usize,
    /// Index (x-coordinate) of this share.
    pub index: Scalar,
    /// Value (y-coordinate) of this share.
    pub share: Scalar,
}

impl LagrangeInterpolatable for SecretShare {
    fn index(&self) -> &Scalar {
        &self.index
    }
    fn share(&self) -> &Scalar {
        &self.share
    }
    fn threshold(&self) -> usize {
        self.threshold
    }
}

/// A verifiable secret share with cryptographic proofs.
#[derive(Debug, Clone)]
pub struct VerifiableSecretShare {
    /// The underlying secret share.
    pub secret_share: SecretShare,
    /// One proof (public key) per polynomial coefficient.
    pub proofs: Vec<PublicKey>,
}

impl LagrangeInterpolatable for VerifiableSecretShare {
    fn index(&self) -> &Scalar {
        &self.secret_share.index
    }
    fn share(&self) -> &Scalar {
        &self.secret_share.share
    }
    fn threshold(&self) -> usize {
        self.secret_share.threshold
    }
}

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

/// Converts a 32-byte big-endian slice to a secp256k1 scalar.
///
/// # Errors
///
/// Returns [`VssError::InvalidByteLength`] if `bytes.len() != 32`, or
/// [`VssError::ScalarOutOfRange`] if the value exceeds the curve order.
pub fn scalar_from_bytes(bytes: &[u8]) -> Result<Scalar, VssError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| VssError::InvalidByteLength {
        expected: 32,
        got: bytes.len(),
    })?;
    Scalar::from_repr_vartime(FieldBytes::from(arr)).ok_or(VssError::ScalarOutOfRange)
}

/// Serializes a scalar to a 32-byte big-endian array.
pub fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}

/// Derives the public key (point on the curve) for a given scalar.
fn scalar_to_pubkey(secret: &Scalar) -> PublicKey {
    let point = ProjectivePoint::GENERATOR * *secret;
    PublicKey::from_affine(AffinePoint::from(point)).expect("non-zero scalar yields valid point")
}

/// Computes `base ^ exp` in the scalar field via square-and-multiply.
fn scalar_modpow(base: &Scalar, exp: usize) -> Scalar {
    if exp == 0 {
        return Scalar::ONE;
    }
    let mut result = Scalar::ONE;
    let mut b = *base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        b *= b;
        e >>= 1;
    }
    result
}

/// Divides `numerator` by `denominator` in the scalar field.
fn field_div(numerator: &Scalar, denominator: &Scalar) -> Result<Scalar, VssError> {
    if bool::from(denominator.is_zero()) {
        return Err(VssError::DivisionByZero);
    }
    let inverse = denominator
        .invert()
        .into_option()
        .ok_or(VssError::NotInvertible)?;
    Ok(*numerator * inverse)
}

// ---------------------------------------------------------------------------
// Polynomial (internal)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Polynomial {
    coefficients: Vec<Scalar>,
    proofs: Vec<PublicKey>,
}

impl Polynomial {
    /// Evaluates the polynomial at `x`.
    fn evaluate(&self, x: &Scalar) -> Scalar {
        let mut result = Scalar::ZERO;
        let mut x_power = Scalar::ONE;
        for coeff in &self.coefficients {
            result += *coeff * x_power;
            x_power *= x;
        }
        result
    }
}

/// Generates a random polynomial with the given secret as the constant term.
fn generate_polynomial(
    secret: &Scalar,
    threshold: usize,
    rng: &mut impl RngCore,
) -> Result<Polynomial, VssError> {
    let degree = threshold - 1;
    let mut coefficients = Vec::with_capacity(threshold);
    let mut proofs = Vec::with_capacity(threshold);

    coefficients.push(*secret);
    proofs.push(scalar_to_pubkey(secret));

    for _ in 0..degree {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let coeff = scalar_from_bytes(&buf)?;
        proofs.push(scalar_to_pubkey(&coeff));
        coefficients.push(coeff);
    }

    Ok(Polynomial {
        coefficients,
        proofs,
    })
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Computes the Lagrange basis coefficient for `index` evaluated at zero.
///
/// Given a set of `points`, returns L_j(0) where j is identified by `index`.
pub fn compute_lagrange_coefficients<T: LagrangeInterpolatable>(
    index: &Scalar,
    points: &[T],
) -> Result<Scalar, VssError> {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;

    for point in points {
        if point.index() == index {
            continue;
        }
        // L_j(0) = product_{i != j} (-x_i) / (x_j - x_i)
        numerator *= -(*point.index());
        denominator *= *index - *point.index();
    }

    field_div(&numerator, &denominator)
}

/// Splits a secret into `number_of_shares` verifiable shares.
///
/// Any `threshold` shares are sufficient to recover the original secret.
/// Each share includes cryptographic proofs that allow verification without
/// revealing the secret.
///
/// # Errors
///
/// Returns [`VssError::InvalidThreshold`] if `threshold` is 0 or exceeds
/// `number_of_shares`.
pub fn split_secret_with_proofs(
    secret_scalar: &Scalar,
    threshold: usize,
    number_of_shares: usize,
    rng: &mut impl RngCore,
) -> Result<Vec<VerifiableSecretShare>, VssError> {
    if threshold == 0 || threshold > number_of_shares {
        return Err(VssError::InvalidThreshold);
    }

    let polynomial = generate_polynomial(secret_scalar, threshold, rng)?;

    let shares = (1..=number_of_shares)
        .map(|i| {
            let index = Scalar::from(i as u64);
            let share = polynomial.evaluate(&index);
            VerifiableSecretShare {
                secret_share: SecretShare {
                    threshold,
                    index,
                    share,
                },
                proofs: polynomial.proofs.clone(),
            }
        })
        .collect();

    Ok(shares)
}

/// Recovers the secret from a set of shares via Lagrange interpolation.
///
/// # Errors
///
/// Returns [`VssError::InsufficientShares`] if fewer shares than the threshold
/// are provided, or [`VssError::DuplicateShareIndices`] if any two shares
/// have the same index.
pub fn recover_secret<T: LagrangeInterpolatable>(shares: &[T]) -> Result<Scalar, VssError> {
    let required = shares[0].threshold();
    if shares.len() < required {
        return Err(VssError::InsufficientShares {
            required,
            provided: shares.len(),
        });
    }

    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(shares.len());
    for s in shares {
        let idx_bytes: [u8; 32] = s.index().to_bytes().into();
        if !seen.insert(idx_bytes) {
            return Err(VssError::DuplicateShareIndices);
        }
    }

    let mut result = Scalar::ZERO;
    for s in shares {
        let coeff = compute_lagrange_coefficients(s.index(), shares)?;
        result += s.share() * &coeff;
    }
    Ok(result)
}

/// Validates a verifiable share against its cryptographic proofs.
///
/// Checks that `share * G == sum_k(proof_k * index^k)` which confirms the
/// share is consistent with the polynomial committed to by the proofs.
///
/// # Errors
///
/// Returns [`VssError::InvalidProofLength`] if the proof count does not match
/// the threshold, or [`VssError::ShareValidationFailed`] if the check fails.
pub fn validate_share(share: &VerifiableSecretShare) -> Result<(), VssError> {
    let expected = share.secret_share.threshold;
    if share.proofs.len() != expected {
        return Err(VssError::InvalidProofLength {
            expected,
            got: share.proofs.len(),
        });
    }

    let target = scalar_to_pubkey(&share.secret_share.share);
    let mut accumulated = ProjectivePoint::IDENTITY;

    for (i, proof) in share.proofs.iter().enumerate() {
        let point = ProjectivePoint::from(proof.as_affine());
        let exp = scalar_modpow(&share.secret_share.index, i);
        accumulated += point * exp;
    }

    if AffinePoint::from(accumulated) == *target.as_affine() {
        Ok(())
    } else {
        Err(VssError::ShareValidationFailed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    fn test_rng() -> rand::rngs::ThreadRng {
        rand::thread_rng()
    }

    // -- scalar_from_bytes / scalar_to_bytes --

    #[test]
    fn scalar_roundtrip() {
        let bytes = [0x42; 32];
        let scalar = scalar_from_bytes(&bytes).unwrap();
        let out = scalar_to_bytes(&scalar);
        assert_eq!(bytes, out);
    }

    #[test]
    fn scalar_from_bytes_wrong_length() {
        let short = [0u8; 31];
        let long = [0u8; 33];
        assert!(matches!(
            scalar_from_bytes(&short),
            Err(VssError::InvalidByteLength {
                expected: 32,
                got: 31
            })
        ));
        assert!(matches!(
            scalar_from_bytes(&long),
            Err(VssError::InvalidByteLength {
                expected: 32,
                got: 33
            })
        ));
    }

    #[test]
    fn scalar_from_bytes_out_of_range() {
        // All 0xFF exceeds the secp256k1 curve order
        assert!(matches!(
            scalar_from_bytes(&[0xFF; 32]),
            Err(VssError::ScalarOutOfRange)
        ));
    }

    // -- scalar_modpow --

    #[test]
    fn modpow_zero_exponent() {
        let base = scalar_from_bytes(&[0x07; 32]).unwrap();
        assert_eq!(scalar_modpow(&base, 0), Scalar::ONE);
    }

    #[test]
    fn modpow_one_exponent() {
        let base = scalar_from_bytes(&[0x07; 32]).unwrap();
        assert_eq!(scalar_modpow(&base, 1), base);
    }

    #[test]
    fn modpow_small_values() {
        let x = Scalar::from(3u64);
        // 3^4 = 81
        assert_eq!(scalar_modpow(&x, 4), Scalar::from(81u64));
    }

    // -- Lagrange coefficients --

    #[test]
    fn lagrange_coefficients_sum_to_one() {
        // For any set of distinct points, the Lagrange basis polynomials
        // evaluated at 0 should satisfy: sum L_j(0) = 1
        let shares: Vec<SecretShare> = (1..=3u64)
            .map(|i| SecretShare {
                threshold: 3,
                index: Scalar::from(i),
                share: Scalar::ONE, // value doesn't affect coefficient computation
            })
            .collect();

        let mut sum = Scalar::ZERO;
        for s in &shares {
            sum += compute_lagrange_coefficients(s.index(), &shares).unwrap();
        }
        assert_eq!(sum, Scalar::ONE);
    }

    // -- threshold validation --

    #[test]
    fn split_rejects_zero_threshold() {
        let secret = scalar_from_bytes(&[0x11; 32]).unwrap();
        let result = split_secret_with_proofs(&secret, 0, 5, &mut test_rng());
        assert!(matches!(result, Err(VssError::InvalidThreshold)));
    }

    #[test]
    fn split_rejects_threshold_exceeding_shares() {
        let secret = scalar_from_bytes(&[0x11; 32]).unwrap();
        let result = split_secret_with_proofs(&secret, 6, 5, &mut test_rng());
        assert!(matches!(result, Err(VssError::InvalidThreshold)));
    }

    // -- recovery error paths --

    #[test]
    fn recover_rejects_insufficient_shares() {
        let secret = scalar_from_bytes(&[0x11; 32]).unwrap();
        let shares = split_secret_with_proofs(&secret, 3, 5, &mut test_rng()).unwrap();
        let result = recover_secret(&shares[0..2]);
        assert!(matches!(
            result,
            Err(VssError::InsufficientShares {
                required: 3,
                provided: 2
            })
        ));
    }

    #[test]
    fn recover_rejects_duplicate_indices() {
        let secret = scalar_from_bytes(&[0x11; 32]).unwrap();
        let shares = split_secret_with_proofs(&secret, 2, 3, &mut test_rng()).unwrap();
        // Duplicate the first share
        let duped = vec![shares[0].clone(), shares[0].clone()];
        let result = recover_secret(&duped);
        assert!(matches!(result, Err(VssError::DuplicateShareIndices)));
    }

    // -- full VSS round-trip --

    #[test]
    fn vss_roundtrip_deterministic() {
        let mut secret_bytes = [0u8; 32];
        secret_bytes[..5].copy_from_slice(&[1, 2, 3, 4, 5]);
        let secret = scalar_from_bytes(&secret_bytes).unwrap();

        let shares = split_secret_with_proofs(&secret, 3, 5, &mut test_rng()).unwrap();

        for share in &shares {
            validate_share(share).unwrap();
        }

        let recovered = recover_secret(&shares[0..3]).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn vss_roundtrip_random() {
        let mut rng = test_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = scalar_from_bytes(&secret_bytes).unwrap();

        let shares = split_secret_with_proofs(&secret, 3, 5, &mut rng).unwrap();

        for share in &shares {
            validate_share(share).unwrap();
        }

        let recovered = recover_secret(&shares[0..3]).unwrap();
        assert_eq!(secret, recovered);
    }

    #[test]
    fn share_bytes_compatibility() {
        let secret = scalar_from_bytes(&[0x11; 32]).unwrap();
        let shares = split_secret_with_proofs(&secret, 3, 5, &mut test_rng()).unwrap();

        let original_bytes: Vec<[u8; 32]> = shares
            .iter()
            .map(|s| scalar_to_bytes(&s.secret_share.share))
            .collect();

        // Reconstruct shares from serialized bytes
        let reconstructed: Vec<VerifiableSecretShare> = shares
            .iter()
            .enumerate()
            .map(|(i, orig)| {
                let share_scalar = scalar_from_bytes(&original_bytes[i]).unwrap();
                VerifiableSecretShare {
                    secret_share: SecretShare {
                        threshold: orig.secret_share.threshold,
                        index: Scalar::from((i + 1) as u64),
                        share: share_scalar,
                    },
                    proofs: orig.proofs.clone(),
                }
            })
            .collect();

        for share in &reconstructed {
            validate_share(share).unwrap();
        }

        let recovered_orig = recover_secret(&shares[0..3]).unwrap();
        let recovered_new = recover_secret(&reconstructed[0..3]).unwrap();
        assert_eq!(recovered_orig, recovered_new);
    }

    // -- validation error paths --

    #[test]
    fn catch_bad_proof_encoding() {
        let mut rng = test_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = scalar_from_bytes(&secret_bytes).unwrap();

        let mut shares = split_secret_with_proofs(&secret, 3, 5, &mut rng).unwrap();

        // Corrupt the first proof's first byte
        let mut proof_bytes = shares[0].proofs[0]
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        proof_bytes[0] ^= 0xFF;

        match PublicKey::from_sec1_bytes(&proof_bytes) {
            Ok(corrupted) => {
                shares[0].proofs[0] = corrupted;
                assert!(validate_share(&shares[0]).is_err());
            }
            Err(_) => {
                // Corrupted bytes rejected at parse time -- also correct behavior
            }
        }
    }

    #[test]
    fn catch_wrong_proof() {
        let mut rng = test_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = scalar_from_bytes(&secret_bytes).unwrap();

        let mut shares = split_secret_with_proofs(&secret, 3, 5, &mut rng).unwrap();

        // Swap share value so it no longer matches proofs
        shares[2].secret_share.share = shares[3].secret_share.share;
        assert!(validate_share(&shares[2]).is_err());
    }

    #[test]
    fn catch_invalid_proof_length() {
        let mut rng = test_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let secret = scalar_from_bytes(&secret_bytes).unwrap();

        let mut shares = split_secret_with_proofs(&secret, 3, 5, &mut rng).unwrap();

        let extra = shares[0].proofs[0].clone();
        shares[0].proofs.push(extra);

        assert!(matches!(
            validate_share(&shares[0]),
            Err(VssError::InvalidProofLength {
                expected: 3,
                got: 4
            })
        ));
    }
}
