//! SSP GraphQL client: HTTPS transport and authentication.
//!
//! This crate provides [`GraphqlSspClient`], a standalone HTTPS client for
//! communicating with the Spark Service Provider (SSP) via its GraphQL API.
//!
//! # Architecture
//!
//! This crate is **transport only** -- it knows how to speak HTTP/GraphQL
//! to the SSP but has no knowledge of the SDK's trait system. The SDK
//! bridges the gap by implementing its `SspClient` trait on top of this.
//!
//! The separation mirrors how `crates/transport` provides gRPC communication
//! with the coordinator, while the SDK orchestrates the protocol logic.

mod base64;
mod error;
mod json;

pub use error::SspError;

use bitcoin::secp256k1::PublicKey;

// ---------------------------------------------------------------------------
// Request / response types (transport-level)
// ---------------------------------------------------------------------------

/// Input for an SSP swap request.
pub struct SwapRequest {
    /// Hex-encoded adaptor public key.
    pub adaptor_pubkey: String,
    /// Total satoshi value of the leaves being sent to the SSP.
    pub total_amount_sats: u64,
    /// Desired output denominations.
    pub target_amount_sats: Vec<u64>,
    /// Fee paid to the SSP for the swap.
    pub fee_sats: u64,
    /// Per-leaf adaptor signature data.
    pub user_leaves: Vec<SwapLeaf>,
    /// Transfer ID of the outbound (user -> SSP) transfer.
    pub user_outbound_transfer_external_id: String,
    /// Bearer token from a prior `authenticate` call.
    pub auth_token: String,
}

/// Per-leaf data included in the swap request.
pub struct SwapLeaf {
    /// Leaf identifier.
    pub leaf_id: String,
    /// Hex-encoded raw unsigned CPFP refund transaction.
    pub raw_unsigned_refund_transaction: String,
    /// Hex-encoded adaptor-added FROST signature for the CPFP refund.
    pub adaptor_added_signature: String,
}

/// Response from an SSP swap request.
pub struct SwapResponse {
    /// Spark transfer ID of the inbound (SSP -> user) transfer to claim.
    pub inbound_transfer_id: String,
}

/// Callback used by [`GraphqlSspClient::authenticate`] to sign the challenge.
///
/// The implementation must:
/// 1. SHA256-hash the provided bytes
/// 2. ECDSA-sign the 32-byte digest
/// 3. Return the DER-encoded signature
pub type SignChallengeFn<'a> =
    &'a (dyn Fn(&[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> + Send + Sync);

// ---------------------------------------------------------------------------
// GraphQL SSP client
// ---------------------------------------------------------------------------

/// SSP client backed by the SSP GraphQL API.
///
/// Uses hyper + rustls for HTTPS. Configuration comes from
/// [`config::SspConfig`].
pub struct GraphqlSspClient {
    /// Full URL for GraphQL requests.
    url: String,
    /// SSP identity public key.
    identity_pk: PublicKey,
}

impl GraphqlSspClient {
    /// Creates a new client from an [`SspConfig`](config::SspConfig).
    pub fn from_config(ssp: &config::SspConfig) -> Result<Self, SspError> {
        let url = format!("{}/{}", ssp.base_url, ssp.schema_endpoint);

        let pk_bytes = hex_decode_pubkey(ssp.identity_public_key)
            .ok_or(SspError::InvalidConfig("bad identity_public_key hex"))?;
        let identity_pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|_| SspError::InvalidConfig("invalid identity public key"))?;

        Ok(Self { url, identity_pk })
    }

    /// Returns the SSP's identity public key.
    pub fn identity_public_key(&self) -> PublicKey {
        self.identity_pk
    }

    /// Authenticates with the SSP and returns a session token.
    ///
    /// The flow is challenge-response:
    /// 1. `get_challenge(public_key)` -> `protected_challenge`
    /// 2. Decode challenge, sign with `sign_fn`
    /// 3. `verify_challenge(protected_challenge, signature, public_key)` -> `session_token`
    pub async fn authenticate(
        &self,
        identity_pubkey_hex: &str,
        sign_fn: SignChallengeFn<'_>,
    ) -> Result<String, SspError> {
        let client = self.make_https_client()?;

        // Step 1: get_challenge
        let get_challenge_body = format!(
            r#"{{"query":"mutation GetChallenge($input: GetChallengeInput!) {{ get_challenge(input: $input) {{ protected_challenge }} }}","variables":{{"input":{{"public_key":"{identity_pubkey_hex}"}}}}}}"#,
        );
        tracing::debug!(identity_pubkey_hex, "SSP get_challenge");

        let resp_str = self.graphql_post(&client, get_challenge_body, None).await?;

        // Extract protected_challenge from JSON response.
        let protected_challenge = json::extract_string_field(&resp_str, "protected_challenge")
            .ok_or_else(|| {
                tracing::error!(response = resp_str, "SSP missing protected_challenge");
                SspError::InvalidResponse
            })?;

        tracing::debug!(
            len = protected_challenge.len(),
            "SSP got protected_challenge"
        );

        // Step 2: Base64url-decode the ProtectedChallenge, SHA256-hash
        //         the **full** protobuf bytes, and ECDSA-sign.
        //         (The SSP verifies against SHA256(full_protobuf), not the inner Challenge.)
        let protobuf_bytes = base64::base64url_decode(protected_challenge).ok_or_else(|| {
            tracing::error!("SSP failed to base64url-decode protected_challenge");
            SspError::InvalidResponse
        })?;

        let signature_der = sign_fn(&protobuf_bytes).map_err(|e| {
            tracing::error!(?e, "SSP sign_challenge failed");
            SspError::SigningFailed
        })?;

        // The SSP expects the signature as standard base64-encoded DER.
        let signature_b64 = base64::base64_encode(&signature_der);

        // Step 3: verify_challenge
        let verify_body = format!(
            r#"{{"query":"mutation VerifyChallenge($input: VerifyChallengeInput!) {{ verify_challenge(input: $input) {{ session_token }} }}","variables":{{"input":{{"protected_challenge":"{}","signature":"{}","identity_public_key":"{}"}}}}}}"#,
            protected_challenge, signature_b64, identity_pubkey_hex,
        );

        tracing::debug!(body = %verify_body, "SSP verify_challenge request");
        let verify_resp = self.graphql_post(&client, verify_body, None).await?;
        tracing::debug!(response = verify_resp, "SSP verify_challenge response");

        let session_token =
            json::extract_string_field(&verify_resp, "session_token").ok_or_else(|| {
                tracing::error!(response = verify_resp, "SSP missing session_token");
                SspError::InvalidResponse
            })?;

        tracing::info!("SSP authenticated successfully");
        Ok(session_token.to_owned())
    }

    /// Requests a leaf swap from the SSP.
    pub async fn request_swap(&self, input: SwapRequest) -> Result<SwapResponse, SspError> {
        let client = self.make_https_client()?;

        // Build the GraphQL mutation payload.
        let user_leaves_json: Vec<String> = input
            .user_leaves
            .iter()
            .map(|l| {
                format!(
                    r#"{{"leaf_id":"{}","raw_unsigned_refund_transaction":"{}","adaptor_added_signature":"{}"}}"#,
                    l.leaf_id, l.raw_unsigned_refund_transaction, l.adaptor_added_signature,
                )
            })
            .collect();

        let target_amounts_json: String = input
            .target_amount_sats
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let variables = format!(
            r#"{{"input":{{"adaptor_pubkey":"{}","total_amount_sats":{},"target_amount_sats":[{}],"fee_sats":{},"user_leaves":[{}],"user_outbound_transfer_external_id":"{}"}}}}"#,
            input.adaptor_pubkey,
            input.total_amount_sats,
            target_amounts_json,
            input.fee_sats,
            user_leaves_json.join(","),
            input.user_outbound_transfer_external_id,
        );

        let query = format!(
            r#"{{"query":"mutation RequestSwap($input: RequestSwapInput!) {{ request_swap(input: $input) {{ request {{ inbound_transfer {{ spark_id }} }} }} }}","variables":{}}}"#,
            variables,
        );

        tracing::debug!(body = %query, "SSP request_swap request");

        let body_str = self
            .graphql_post(&client, query, Some(&input.auth_token))
            .await?;

        tracing::debug!(response = body_str, "SSP request_swap response");
        let spark_id =
            json::extract_string_field(&body_str, "spark_id").ok_or(SspError::InvalidResponse)?;

        Ok(SwapResponse {
            inbound_transfer_id: spark_id.to_owned(),
        })
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Build a TLS-enabled hyper client.
    fn make_https_client(
        &self,
    ) -> Result<
        hyper_util::client::legacy::Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            http_body_util::Full<hyper::body::Bytes>,
        >,
        SspError,
    > {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| SspError::TlsFailed)?
            .https_or_http()
            .enable_http2()
            .build();

        Ok(
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https),
        )
    }

    /// Send a GraphQL POST and return the response body as a string.
    async fn graphql_post(
        &self,
        client: &hyper_util::client::legacy::Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            http_body_util::Full<hyper::body::Bytes>,
        >,
        body_json: String,
        auth_token: Option<&str>,
    ) -> Result<String, SspError> {
        let body = hyper::body::Bytes::from(body_json);

        let mut builder = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&self.url)
            .header("content-type", "application/json");

        if let Some(token) = auth_token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }

        let req = builder
            .body(http_body_util::Full::new(body))
            .map_err(|_| SspError::RequestFailed)?;

        let resp = client.request(req).await.map_err(|e| {
            tracing::error!(?e, "SSP HTTP request failed");
            SspError::RequestFailed
        })?;

        let status = resp.status();
        use http_body_util::BodyExt;
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| SspError::RequestFailed)?
            .to_bytes();

        let body_str = std::str::from_utf8(&body_bytes).map_err(|_| SspError::InvalidResponse)?;

        if !status.is_success() {
            tracing::error!(%status, body = body_str, "SSP HTTP error response");
            return Err(SspError::RequestFailed);
        }

        Ok(body_str.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Hex helper (minimal, no external dep)
// ---------------------------------------------------------------------------

/// Decode a hex-encoded 33-byte compressed public key (66 hex chars).
fn hex_decode_pubkey(hex: &str) -> Option<[u8; 33]> {
    if hex.len() != 66 {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
