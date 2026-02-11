//! Spark Service Provider (SSP) client trait and types.
//!
//! The SSP provides swap services: the user sends oversized leaves and
//! receives back leaves with exact target denominations.  Communication
//! is via a GraphQL API (not gRPC).
//!
//! # Architecture
//!
//! [`SspClient`] is a trait so callers can swap in a mock for testing.
//! [`GraphqlSspClient`] is the concrete implementation that speaks
//! GraphQL over HTTPS using hyper (already in the dep tree via tonic).

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
/// Implementors speak the SSP GraphQL protocol.  The trait is object-safe
/// only via `async_trait`-style desugaring; for the generic approach used
/// here we require `Send + Sync` bounds.
pub trait SspClient: Send + Sync {
    /// Returns the SSP's identity public key.
    fn identity_public_key(&self) -> PublicKey;

    /// Authenticates with the SSP and returns a session token.
    ///
    /// The flow is challenge-response:
    /// 1. `get_challenge(public_key)` -> `protected_challenge`
    /// 2. Decode challenge, sign with `sign_fn`
    /// 3. `verify_challenge(protected_challenge, signature, public_key)` -> `session_token`
    fn authenticate(
        &self,
        identity_pubkey_hex: &str,
        sign_fn: SignChallengeFn<'_>,
    ) -> impl std::future::Future<Output = Result<String, SdkError>> + Send;

    /// Requests a leaf swap from the SSP.
    ///
    /// The SSP receives the user's leaves (via the outbound transfer
    /// already initiated on the coordinator) and sends back new leaves
    /// matching `target_amount_sats` via an inbound transfer.
    ///
    /// `input.auth_token` must be a valid session token from [`Self::authenticate`].
    fn request_swap(
        &self,
        input: RequestSwapInput,
    ) -> impl std::future::Future<Output = Result<RequestSwapResponse, SdkError>> + Send;
}

// ---------------------------------------------------------------------------
// No-op implementation (for SDK users who don't need SSP swaps)
// ---------------------------------------------------------------------------

/// A no-op SSP client that always returns an error.
///
/// Use this when constructing an [`Sdk`](crate::Sdk) instance that will
/// never perform SSP swaps (e.g. claim-only wallets).
pub struct NoSspClient;

impl SspClient for NoSspClient {
    fn identity_public_key(&self) -> PublicKey {
        // Dummy key -- never used because request_swap always errors.
        // This is the generator point; any valid pubkey works here.
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
// GraphQL implementation (hyper-based)
// ---------------------------------------------------------------------------

/// SSP client backed by the SSP GraphQL API.
///
/// Uses hyper (from the tonic dep tree) for HTTPS, avoiding any new
/// dependencies.  The GraphQL schema endpoint and identity public key
/// come from [`config::SspConfig`].
pub struct GraphqlSspClient {
    /// Full URL for GraphQL requests (e.g. `https://api.lightspark.com/graphql/spark/rc`).
    url: String,
    /// SSP identity public key.
    identity_pk: PublicKey,
}

impl GraphqlSspClient {
    /// Creates a new client from an [`SspConfig`](config::SspConfig).
    pub fn from_config(ssp: &config::SspConfig) -> Result<Self, SdkError> {
        let url = format!("{}/{}", ssp.base_url, ssp.schema_endpoint);

        let pk_bytes =
            crate::ssp::hex_decode_33(ssp.identity_public_key).ok_or(SdkError::InvalidRequest)?;
        let identity_pk = PublicKey::from_slice(&pk_bytes).map_err(|_| SdkError::InvalidRequest)?;

        Ok(Self { url, identity_pk })
    }

    /// Build a TLS-enabled hyper client.  Reused by `authenticate` and `request_swap`.
    fn make_https_client(
        &self,
    ) -> Result<
        hyper_util::client::legacy::Client<
            hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            http_body_util::Full<hyper::body::Bytes>,
        >,
        SdkError,
    > {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|_| SdkError::SspSwapFailed)?
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
        body_json: &str,
        auth_token: Option<&str>,
    ) -> Result<String, SdkError> {
        let body = hyper::body::Bytes::from(body_json.to_owned());

        let mut builder = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(&self.url)
            .header("content-type", "application/json");

        if let Some(token) = auth_token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }

        let req = builder
            .body(http_body_util::Full::new(body))
            .map_err(|_| SdkError::SspSwapFailed)?;

        let resp = client.request(req).await.map_err(|e| {
            eprintln!("[ssp] HTTP request failed: {e:?}");
            SdkError::SspSwapFailed
        })?;

        let status = resp.status();
        use http_body_util::BodyExt;
        let body_bytes = resp
            .into_body()
            .collect()
            .await
            .map_err(|_| SdkError::SspSwapFailed)?
            .to_bytes();

        let body_str =
            std::str::from_utf8(&body_bytes).map_err(|_| SdkError::SspInvalidResponse)?;

        if !status.is_success() {
            eprintln!("[ssp] HTTP {status}: {body_str}");
            return Err(SdkError::SspSwapFailed);
        }

        Ok(body_str.to_owned())
    }
}

impl SspClient for GraphqlSspClient {
    fn identity_public_key(&self) -> PublicKey {
        self.identity_pk
    }

    async fn authenticate(
        &self,
        identity_pubkey_hex: &str,
        sign_fn: SignChallengeFn<'_>,
    ) -> Result<String, SdkError> {
        let client = self.make_https_client()?;

        // Step 1: get_challenge
        let get_challenge_body = format!(
            r#"{{"query":"mutation GetChallenge($input: GetChallengeInput!) {{ get_challenge(input: $input) {{ protected_challenge }} }}","variables":{{"input":{{"public_key":"{identity_pubkey_hex}"}}}}}}"#,
        );
        eprintln!("[ssp-auth] get_challenge for {identity_pubkey_hex}");

        let resp_str = self
            .graphql_post(&client, &get_challenge_body, None)
            .await?;

        // Extract protected_challenge from JSON response.
        let protected_challenge = extract_json_string_field(&resp_str, "protected_challenge")
            .ok_or_else(|| {
                eprintln!("[ssp-auth] missing protected_challenge in: {resp_str}");
                SdkError::SspInvalidResponse
            })?;

        eprintln!(
            "[ssp-auth] got protected_challenge ({} chars)",
            protected_challenge.len()
        );

        // Step 2: Base64url-decode the ProtectedChallenge, SHA256-hash
        //         the **full** protobuf bytes, and ECDSA-sign.
        //         (The SSP verifies against SHA256(full_protobuf), not the inner Challenge.)
        let protobuf_bytes = base64url_decode(protected_challenge).ok_or_else(|| {
            eprintln!("[ssp-auth] failed to base64url-decode protected_challenge");
            SdkError::SspInvalidResponse
        })?;

        let signature_der = sign_fn(&protobuf_bytes).map_err(|e| {
            eprintln!("[ssp-auth] sign_challenge failed: {e}");
            SdkError::SigningFailed
        })?;

        // The SSP expects the signature as standard base64-encoded DER.
        let signature_b64 = base64_encode(&signature_der);

        // Step 3: verify_challenge
        let verify_body = format!(
            r#"{{"query":"mutation VerifyChallenge($input: VerifyChallengeInput!) {{ verify_challenge(input: $input) {{ session_token }} }}","variables":{{"input":{{"protected_challenge":"{}","signature":"{}","identity_public_key":"{}"}}}}}}"#,
            protected_challenge, signature_b64, identity_pubkey_hex,
        );

        eprintln!("[ssp-auth] verify_challenge body: {verify_body}");
        let verify_resp = self.graphql_post(&client, &verify_body, None).await?;
        eprintln!("[ssp-auth] verify_challenge response: {verify_resp}");

        let session_token =
            extract_json_string_field(&verify_resp, "session_token").ok_or_else(|| {
                eprintln!("[ssp-auth] missing session_token in: {verify_resp}");
                SdkError::SspInvalidResponse
            })?;

        eprintln!("[ssp-auth] authenticated successfully");
        Ok(session_token.to_owned())
    }

    async fn request_swap(&self, input: RequestSwapInput) -> Result<RequestSwapResponse, SdkError> {
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

        eprintln!("[ssp] request body: {query}");

        let body_str = self
            .graphql_post(&client, &query, Some(&input.auth_token))
            .await?;

        eprintln!("[ssp] response body: {body_str}");
        let spark_id = extract_spark_id(&body_str).ok_or(SdkError::SspInvalidResponse)?;

        Ok(RequestSwapResponse {
            inbound_transfer_id: spark_id.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a 33-byte hex-encoded compressed public key.
fn hex_decode_33(hex: &str) -> Option<[u8; 33]> {
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

/// Standard base64 encode (RFC 4648) with padding.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Extract the `spark_id` value from a GraphQL JSON response.
///
/// Expected shape:
/// ```json
/// {"data":{"request_swap":{"request":{"inbound_transfer":{"spark_id":"..."}}}}}
/// ```
///
/// This avoids pulling in serde_json for a single field extraction.
fn extract_spark_id(json: &str) -> Option<&str> {
    extract_json_string_field(json, "spark_id")
}

/// Extract a JSON string field value by key from a flat or nested JSON string.
///
/// Searches for `"<key>"` followed by `:` and a quoted string value.
/// Returns the inner string (without quotes).
fn extract_json_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let search = format!("\"{key}\"");
    let idx = json.find(&search)?;
    let after_key = &json[idx + search.len()..];
    let after_colon = after_key.trim_start().strip_prefix(':')?;
    let after_ws = after_colon.trim_start();
    let after_quote = after_ws.strip_prefix('"')?;
    let end = after_quote.find('"')?;
    Some(&after_quote[..end])
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

/// Decode a base64url string (without padding) into bytes.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    // Add padding if needed.
    let padded = match input.len() % 4 {
        2 => format!("{input}=="),
        3 => format!("{input}="),
        0 => input.to_owned(),
        _ => return None,
    };

    // Translate URL-safe chars to standard base64.
    let standard: String = padded
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    // Decode using a simple base64 decoder.
    base64_decode_standard(&standard)
}

/// Standard base64 decode (RFC 4648).
fn base64_decode_standard(input: &str) -> Option<Vec<u8>> {
    const TABLE: [u8; 128] = {
        let mut t = [0xFFu8; 128];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i;
            t[(b'a' + i) as usize] = i + 26;
            i += 1;
        }
        let mut d = 0u8;
        while d < 10 {
            t[(b'0' + d) as usize] = d + 52;
            d += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return None;
    }

    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks_exact(4) {
        let mut vals = [0u8; 4];
        let mut pad_count = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                pad_count += 1;
                vals[i] = 0;
            } else if b >= 128 || TABLE[b as usize] == 0xFF {
                return None;
            } else {
                vals[i] = TABLE[b as usize];
            }
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);

        out.push((n >> 16) as u8);
        if pad_count < 2 {
            out.push((n >> 8) as u8);
        }
        if pad_count < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_spark_id_from_response() {
        let json = r#"{"data":{"request_swap":{"request":{"inbound_transfer":{"spark_id":"abc-123-def"}}}}}"#;
        assert_eq!(extract_spark_id(json), Some("abc-123-def"));
    }

    #[test]
    fn extract_spark_id_missing() {
        assert_eq!(extract_spark_id(r#"{"data":{}}"#), None);
    }

    #[test]
    fn extract_json_string_field_works() {
        let json = r#"{"data":{"verify_challenge":{"session_token":"tok123"}}}"#;
        assert_eq!(
            extract_json_string_field(json, "session_token"),
            Some("tok123")
        );
    }

    #[test]
    fn extract_json_string_field_missing() {
        assert_eq!(
            extract_json_string_field(r#"{"data":{}}"#, "session_token"),
            None
        );
    }

    #[test]
    fn hex_decode_33_valid() {
        let hex = "02".to_owned() + &"ab".repeat(32);
        let result = hex_decode_33(&hex);
        assert!(result.is_some());
        assert_eq!(result.unwrap()[0], 0x02);
        assert_eq!(result.unwrap()[1], 0xab);
    }

    #[test]
    fn hex_decode_33_wrong_length() {
        assert!(hex_decode_33("0102").is_none());
    }

    #[test]
    fn base64url_decode_works() {
        // Standard base64 "AQID" = [1, 2, 3]
        assert_eq!(base64url_decode("AQID"), Some(vec![1, 2, 3]));
        // URL-safe: '-' instead of '+', '_' instead of '/'
        let result = base64url_decode("AP__");
        assert!(result.is_some());
    }

    #[test]
    fn base64_encode_round_trip() {
        let data = b"hello world";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "aGVsbG8gd29ybGQ=");
    }

    #[test]
    fn base64url_decode_real_challenge() {
        // A real protected_challenge from the SSP (base64url).
        let pc = "CAFSTwgBUNyBtMwGogEg0tppfumnJfyoYQXyTew-XPayF9c6wGnG0A_z8x_LUAPyASECaYsnrDCLJ1Zxs8olQ2NGRp0EpbuleK45_rodZYl6aryiASDZS7gAD-fZo64FiHXc2WOIel5WEg2rd9QIfMNk1yGUKw";
        let decoded = base64url_decode(pc);
        assert!(decoded.is_some(), "should base64url decode");
        // Full ProtectedChallenge is 118 bytes for this test vector.
        assert_eq!(decoded.unwrap().len(), 118);
    }
}
