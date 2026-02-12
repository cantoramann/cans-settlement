//! Shared helpers for token operations.
//!
//! These functions are used by both token ops and potentially by
//! future token-related modules. They handle operator key sorting,
//! metadata construction, signing, and amount encoding.

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark_token::TokenTransactionMetadata;

use crate::SdkError;
use crate::network::spark_network_proto;

/// Token transaction version (V3 protocol).
pub(crate) const TOKEN_TX_VERSION: u32 = 3;

/// Decode operator identity public keys from the network config.
///
/// Returns the keys as `Bytes` sorted in strictly ascending bytewise
/// order, as required by the coordinator.
pub(crate) fn operator_identity_keys(config: &config::NetworkConfig) -> Vec<Bytes> {
    let mut keys: Vec<Vec<u8>> = config
        .operators()
        .iter()
        .filter_map(|op| crate::utils::hex_decode(op.identity_public_key))
        .collect();
    keys.sort();
    keys.into_iter().map(Bytes::from).collect()
}

/// Create a `TokenTransactionMetadata` for the current network.
pub(crate) fn build_metadata(config: &config::NetworkConfig) -> TokenTransactionMetadata {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    TokenTransactionMetadata {
        spark_operator_identity_public_keys: operator_identity_keys(config),
        network: spark_network_proto(config.network),
        client_created_timestamp: Some(prost_types::Timestamp {
            seconds: now.as_secs() as i64,
            nanos: now.subsec_nanos() as i32,
        }),
        validity_duration_seconds: config::constants::DEFAULT_TOKEN_VALIDITY_DURATION_SECS,
        invoice_attachments: vec![],
    }
}

/// ECDSA-sign a 32-byte digest and return the DER-encoded signature.
///
/// Uses the compact signature from `WalletSigner::sign_ecdsa_digest_compact`
/// and re-encodes it as DER.
pub(crate) fn sign_digest_der(
    signer: &impl WalletSigner,
    digest: &[u8; 32],
) -> Result<Vec<u8>, SdkError> {
    let compact = signer.sign_ecdsa_digest_compact(digest);
    let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&compact)
        .map_err(|_| SdkError::SigningFailed)?;
    Ok(sig.serialize_der().to_vec())
}

/// Encode a u128 as a 16-byte big-endian `Bytes` value.
pub(crate) fn u128_to_bytes(v: u128) -> Bytes {
    Bytes::copy_from_slice(&v.to_be_bytes())
}
