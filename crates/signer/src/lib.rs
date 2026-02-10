//! Signing abstractions and utilities for the Spark protocol.
//!
//! This crate provides:
//!
//! - [`Signer`] trait -- minimal auth signing (zero dependencies)
//! - [`WalletSigner`] trait -- full wallet crypto (FROST, ECIES, VSS, HD derivation)
//! - [`ecdsa`] module -- ECDSA sign/verify primitives over secp256k1
//! - [`SparkSigner`] -- simple ECDSA-only auth signer
//! - [`SparkWalletSigner`] -- full wallet signer backed by BIP32 seed
//!
//! # Feature flags
//!
//! - **`spark`** (default): Enables all concrete implementations and pulls in
//!   `bitcoin`, `spark-crypto`, and `frost-secp256k1-tr`.
//!
//! # Design
//!
//! The base [`Signer`] trait has **zero dependencies**. Crates that only need
//! authentication signing (e.g. `transport`) depend on this crate with
//! `default-features = false`.
//!
//! The [`WalletSigner`] supertrait adds FROST threshold signing, ECIES
//! encryption, verifiable secret sharing, and HD key derivation. The SDK
//! uses this trait to access all cryptographic operations without depending
//! on `spark-crypto` or `frost-secp256k1-tr` directly.

#[cfg(feature = "spark")]
pub mod ecdsa;

#[cfg(feature = "spark")]
mod spark;

#[cfg(feature = "spark")]
pub mod wallet_signer;

#[cfg(feature = "spark")]
pub mod wallet;

// -- Re-exports (auth signer) --

#[cfg(feature = "spark")]
pub use spark::SparkSigner;

// -- Re-exports (wallet signer) --

#[cfg(feature = "spark")]
pub use wallet::SparkWalletSigner;

#[cfg(feature = "spark")]
pub use wallet_signer::{WalletSigner, WalletSignerError};

// -- Re-exports (FROST types for SDK consumers) --

#[cfg(feature = "spark")]
pub use wallet_signer::{FrostSignature, SignatureShare, SigningCommitments, SigningNonces};

#[cfg(feature = "spark")]
pub use frost_secp256k1_tr::Identifier as FrostIdentifier;

#[cfg(feature = "spark")]
pub use spark_crypto::frost::FrostNoncePair;

#[cfg(feature = "spark")]
pub use spark_crypto::verifiable_secret_sharing::VerifiableSecretShare;

// ---------------------------------------------------------------------------
// Base types (zero dependencies)
// ---------------------------------------------------------------------------

/// Uncompressed secp256k1 public key (65 bytes, `0x04` prefix).
pub type PubKey = [u8; 65];

/// Signing capability for Spark authentication and protocol operations.
///
/// Implementations handle the cryptographic details (hashing, signing) so
/// that consumers like `GrpcTransport` remain agnostic to the key backend.
pub trait Signer: Send + Sync {
    /// Returns the uncompressed secp256k1 public key.
    fn public_key(&self) -> PubKey;

    /// Sign protobuf-encoded challenge bytes for Spark authentication.
    ///
    /// The implementation should:
    /// 1. SHA256-hash `challenge_bytes`
    /// 2. ECDSA-sign the 32-byte digest
    /// 3. Return the DER-encoded signature
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails (e.g. HSM timeout, invalid state).
    fn sign_challenge(
        &self,
        challenge_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>>;
}
