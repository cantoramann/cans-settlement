//! Full wallet signing trait for Spark protocol operations.
//!
//! [`WalletSigner`] extends the base [`Signer`](crate::Signer) trait with
//! cryptographic capabilities required by the SDK: FROST threshold signing,
//! ECIES encryption, verifiable secret sharing, and HD key derivation.

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use frost_secp256k1_tr::Identifier;
use rand_core::{CryptoRng, RngCore};
use spark_crypto::frost::FrostNoncePair;
use spark_crypto::verifiable_secret_sharing::VerifiableSecretShare;

use crate::Signer;

// Re-export frost types the SDK needs through this module.
pub use frost_secp256k1_tr::{
    Signature as FrostSignature,
    round1::{SigningCommitments, SigningNonces},
    round2::SignatureShare,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from wallet signing operations.
///
/// No string payloads -- every variant is a zero-size discriminant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalletSignerError {
    // -- FROST --
    /// FROST round 2 signing failed (invalid key, nonce, or commitment).
    FrostSigningFailed,
    /// FROST signature aggregation failed.
    FrostAggregationFailed,
    /// A FROST participant identifier could not be derived.
    FrostInvalidIdentifier,

    // -- ECIES --
    /// ECIES encryption failed.
    EciesEncryptionFailed,
    /// ECIES decryption failed (wrong key or tampered ciphertext).
    EciesDecryptionFailed,
    /// The provided public or secret key is invalid.
    EciesInvalidKey,

    // -- VSS --
    /// VSS threshold is zero or exceeds the share count.
    VssInvalidThreshold,
    /// VSS secret bytes are not a valid secp256k1 scalar.
    VssScalarOutOfRange,
    /// VSS split operation failed.
    VssSplitFailed,

    // -- Key arithmetic --
    /// Secret key subtraction failed (result is zero or invalid).
    KeySubtractionFailed,

    // -- Key derivation --
    /// BIP32 key derivation failed (invalid seed, path, or index).
    KeyDerivationFailed,
}

impl fmt::Display for WalletSignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FrostSigningFailed => write!(f, "FROST signing failed"),
            Self::FrostAggregationFailed => write!(f, "FROST aggregation failed"),
            Self::FrostInvalidIdentifier => write!(f, "invalid FROST identifier"),
            Self::EciesEncryptionFailed => write!(f, "ECIES encryption failed"),
            Self::EciesDecryptionFailed => write!(f, "ECIES decryption failed"),
            Self::EciesInvalidKey => write!(f, "invalid ECIES key"),
            Self::VssInvalidThreshold => write!(f, "invalid VSS threshold"),
            Self::VssScalarOutOfRange => write!(f, "VSS scalar out of range"),
            Self::VssSplitFailed => write!(f, "VSS split failed"),
            Self::KeySubtractionFailed => write!(f, "secret key subtraction failed"),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for WalletSignerError {}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Full wallet signing capability for Spark SDK operations.
///
/// Extends [`Signer`] (authentication-only) with the cryptographic operations
/// required by the SDK: threshold signing, encryption, secret sharing, and
/// per-leaf key derivation.
///
/// Implementations must be `Send + Sync` to allow concurrent SDK operations.
///
/// # Design
///
/// Methods accept generic RNG parameters (`impl CryptoRng + RngCore`) so the
/// caller controls the entropy source. This keeps the trait testable with
/// deterministic RNGs while enforcing cryptographic randomness at the type level.
pub trait WalletSigner: Signer {
    /// Returns the compressed identity public key (33 bytes).
    fn identity_public_key_compressed(&self) -> [u8; 33];

    /// ECDSA-sign a message with the identity key.
    ///
    /// SHA256-hashes `message`, then ECDSA-signs the 32-byte digest.
    /// Returns the DER-encoded signature bytes.
    fn sign_ecdsa_message(&self, message: &[u8]) -> Vec<u8>;

    // -- Key arithmetic ---------------------------------------------------

    /// Subtract secret key `b` from secret key `a` (a - b).
    ///
    /// Used during claim to compute the key tweak: `old_signing_key - new_signing_key`.
    fn subtract_secret_keys(
        &self,
        a: &SecretKey,
        b: &SecretKey,
    ) -> Result<SecretKey, WalletSignerError>;

    // -- Key derivation ---------------------------------------------------

    /// Derive the leaf signing keypair for a given node ID.
    ///
    /// Uses the signing master key at `m/8797555'/account'/1'` and derives
    /// a hardened child via `SHA256(node_id) mod 2^31`.
    fn derive_signing_keypair(
        &self,
        node_id: &str,
    ) -> Result<(SecretKey, PublicKey), WalletSignerError>;

    // -- FROST threshold signing ------------------------------------------

    /// Generate a FROST nonce pair for the given node's signing share.
    ///
    /// Returns both the secret nonces (for signing) and public commitment
    /// (to share with operators).
    fn frost_generate_nonces(
        &self,
        node_id: &str,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<FrostNoncePair, WalletSignerError>;

    /// FROST round 2: produce a signature share.
    ///
    /// Signs `message` (typically a Bitcoin sighash) using the leaf key
    /// derived from `node_id`. The `verifying_key` is the group's aggregate
    /// public key for this leaf.
    fn frost_sign(
        &self,
        message: &[u8],
        node_id: &str,
        verifying_key: &PublicKey,
        nonces: &SigningNonces,
        all_commitments: BTreeMap<Identifier, SigningCommitments>,
        participant_id: Identifier,
    ) -> Result<SignatureShare, WalletSignerError>;

    /// Aggregate FROST signature shares into a final Schnorr signature.
    fn frost_aggregate(
        &self,
        message: &[u8],
        all_commitments: BTreeMap<Identifier, SigningCommitments>,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
        verifying_shares: &BTreeMap<Identifier, PublicKey>,
        verifying_key: &PublicKey,
    ) -> Result<FrostSignature, WalletSignerError>;

    // -- ECIES encryption -------------------------------------------------

    /// ECIES-encrypt `plaintext` for a receiver identified by `receiver_pub`.
    ///
    /// Output: `ephemeral_pk || nonce || tag || ciphertext`.
    fn ecies_encrypt(
        &self,
        receiver_pub: &[u8],
        plaintext: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<u8>, WalletSignerError>;

    /// ECIES-decrypt `ciphertext` using the identity secret key.
    fn ecies_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WalletSignerError>;

    // -- Verifiable Secret Sharing ----------------------------------------

    /// Split a 32-byte secret into verifiable Shamir shares.
    ///
    /// Any `threshold` shares can reconstruct the secret. Each share
    /// includes cryptographic proofs for verification.
    fn vss_split(
        &self,
        secret_bytes: &[u8; 32],
        threshold: usize,
        num_shares: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<VerifiableSecretShare>, WalletSignerError>;
}
