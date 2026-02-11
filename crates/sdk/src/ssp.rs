//! SSP client trait, types, and bridge to the `graphql` transport crate.
//!
//! The SDK defines the [`SspClient`] trait for SSP communication. The
//! concrete GraphQL implementation lives in `crates/graphql` to keep
//! transport concerns out of the SDK. This module provides:
//!
//! - [`SspClient`] trait
//! - Request/response types
//! - [`NoSspClient`] (no-op stub)
//! - [`SspClient`] implementation for [`graphql::GraphqlSspClient`]

use bitcoin::secp256k1::PublicKey;

use crate::SdkError;

// ---------------------------------------------------------------------------
// Fee constants
// ---------------------------------------------------------------------------

/// SSP swap fee in satoshis.
///
// TODO: Request fee estimate from SSP dynamically instead of hardcoding.
pub const SSP_SWAP_FEE_SATS: u64 = 0;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Input for an SSP swap request.
pub struct RequestSwapInput {
    /// Hex-encoded adaptor public key.
    pub adaptor_pubkey: String,
    /// Total satoshi value of the leaves being sent to the SSP.
    pub total_amount_sats: u64,
    /// Desired output denominations (sum must equal `total_amount_sats - fee_sats`).
    pub target_amount_sats: Vec<u64>,
    /// Fee paid to the SSP for the swap.
    pub fee_sats: u64,
    /// Per-leaf adaptor signature data.
    pub user_leaves: Vec<UserLeafInput>,
    /// Transfer ID of the outbound (user -> SSP) transfer.
    pub user_outbound_transfer_external_id: String,
    /// Bearer token from a prior `authenticate` call.
    pub auth_token: String,
}

/// Per-leaf data included in the swap request.
pub struct UserLeafInput {
    /// Leaf identifier.
    pub leaf_id: String,
    /// Hex-encoded raw unsigned CPFP refund transaction.
    pub raw_unsigned_refund_transaction: String,
    /// Hex-encoded adaptor-added FROST signature for the CPFP refund.
    pub adaptor_added_signature: String,
}

/// Response from an SSP swap request.
pub struct RequestSwapResponse {
    /// Spark transfer ID of the inbound (SSP -> user) transfer to claim.
    pub inbound_transfer_id: String,
}

/// Callback used by [`SspClient::authenticate`] to sign the challenge.
///
/// The implementation must:
/// 1. SHA256-hash the provided bytes
/// 2. ECDSA-sign the 32-byte digest
/// 3. Return the DER-encoded signature
pub type SignChallengeFn<'a> =
    &'a (dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> + Send + Sync);

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Trait for SSP communication.
///
/// Implementors handle authentication and swap requests. The SDK
/// orchestrates the transfer/claim protocol on top of this.
pub trait SspClient: Send + Sync {
    /// Returns the SSP's identity public key.
    fn identity_public_key(&self) -> PublicKey;

    /// Authenticates with the SSP and returns a session token.
    fn authenticate(
        &self,
        identity_pubkey_hex: &str,
        sign_fn: SignChallengeFn<'_>,
    ) -> impl std::future::Future<Output = Result<String, SdkError>> + Send;

    /// Requests a leaf swap from the SSP.
    fn request_swap(
        &self,
        input: RequestSwapInput,
    ) -> impl std::future::Future<Output = Result<RequestSwapResponse, SdkError>> + Send;
}

// ---------------------------------------------------------------------------
// No-op implementation
// ---------------------------------------------------------------------------

/// A no-op SSP client that always returns an error.
///
/// Use this when constructing an [`Sdk`](crate::Sdk) instance that will
/// never perform SSP swaps (e.g. claim-only wallets).
pub struct NoSspClient;

impl SspClient for NoSspClient {
    fn identity_public_key(&self) -> PublicKey {
        // Dummy key -- never used because request_swap always errors.
        PublicKey::from_slice(&[
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ])
        .expect("valid compressed pubkey")
    }

    async fn authenticate(
        &self,
        _identity_pubkey_hex: &str,
        _sign_fn: SignChallengeFn<'_>,
    ) -> Result<String, SdkError> {
        Err(SdkError::SspSwapFailed)
    }

    async fn request_swap(
        &self,
        _input: RequestSwapInput,
    ) -> Result<RequestSwapResponse, SdkError> {
        Err(SdkError::SspSwapFailed)
    }
}

// ---------------------------------------------------------------------------
// Bridge: graphql::GraphqlSspClient -> SspClient
// ---------------------------------------------------------------------------

impl SspClient for graphql::GraphqlSspClient {
    fn identity_public_key(&self) -> PublicKey {
        self.identity_public_key()
    }

    async fn authenticate(
        &self,
        identity_pubkey_hex: &str,
        sign_fn: SignChallengeFn<'_>,
    ) -> Result<String, SdkError> {
        self.authenticate(identity_pubkey_hex, sign_fn)
            .await
            .map_err(SdkError::from)
    }

    async fn request_swap(&self, input: RequestSwapInput) -> Result<RequestSwapResponse, SdkError> {
        let graphql_input = graphql::SwapRequest {
            adaptor_pubkey: input.adaptor_pubkey,
            total_amount_sats: input.total_amount_sats,
            target_amount_sats: input.target_amount_sats,
            fee_sats: input.fee_sats,
            user_leaves: input
                .user_leaves
                .into_iter()
                .map(|l| graphql::SwapLeaf {
                    leaf_id: l.leaf_id,
                    raw_unsigned_refund_transaction: l.raw_unsigned_refund_transaction,
                    adaptor_added_signature: l.adaptor_added_signature,
                })
                .collect(),
            user_outbound_transfer_external_id: input.user_outbound_transfer_external_id,
            auth_token: input.auth_token,
        };

        let resp = self
            .request_swap(graphql_input)
            .await
            .map_err(SdkError::from)?;

        Ok(RequestSwapResponse {
            inbound_transfer_id: resp.inbound_transfer_id,
        })
    }
}
