//! Core types and utilities for the Spark SDK.
//!
//! This crate provides foundational types used across the Spark wallet:
//!
//! - [`Network`] -- Spark network identifier (Mainnet, Regtest)
//! - [`SparkAddress`] -- Bech32m-encoded identity public key address

pub mod spark_address;

pub use spark_address::{
    SparkAddress, SparkAddressError, decode_spark_address, encode_spark_address,
};

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

/// Spark network identifier.
///
/// Determines the human-readable prefix (HRP) used in Spark addresses
/// and which set of operators the wallet communicates with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Spark mainnet.
    Mainnet,

    /// Spark regtest.
    Regtest,
}
