//! Sparkscan REST API client.
//!
//! Provides [`SparkscanClient`] to look up Spark transfers by ID via
//! the Sparkscan block explorer API (`GET /v1/tx/{id}?network=...`).
//!
//! # Usage
//!
//! ```ignore
//! let client = SparkscanClient::new("https://api.sparkscan.io/v1", "MAINNET");
//! let transfer = client.fetch_transfer("0198b60e-d0a2-7019-8e3a-8b29b321a5bb").await?;
//! ```
//!
//! Uses the same hyper + rustls HTTP stack as the rest of the workspace
//! (no reqwest dependency). Zero external type dependencies -- the caller
//! provides the base URL and network as plain strings.

use serde::Deserialize;
use tracing::{debug, error};

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Sparkscan API client.
///
/// Initialized once with a base URL and network string, then reused for
/// all fetch calls. The HTTPS client is created lazily on first use.
///
/// The network string is the query-parameter value Sparkscan expects:
/// `"MAINNET"` or `"REGTEST"`.
pub struct SparkscanClient {
    /// Base URL (e.g. `https://api.sparkscan.io/v1`).
    base_url: String,
    /// Network query parameter (e.g. `"MAINNET"`, `"REGTEST"`).
    network: &'static str,
    /// Optional bearer token for authenticated access.
    api_key: Option<String>,
    /// Lazily-initialized HTTPS client.
    http: HttpsClient,
}

impl SparkscanClient {
    /// Create a new Sparkscan client.
    ///
    /// # Arguments
    ///
    /// * `base_url` -- API base URL (e.g. `"https://api.sparkscan.io/v1"`).
    /// * `network` -- Network query string: `"MAINNET"` or `"REGTEST"`.
    pub fn new(base_url: &str, network: &'static str) -> Result<Self, SparkscanError> {
        let http = make_https_client()?;
        Ok(Self {
            base_url: base_url.to_owned(),
            network,
            api_key: None,
            http,
        })
    }

    /// Set an API key for authenticated requests.
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Fetch transfer data by ID.
    pub async fn fetch_transfer(
        &self,
        transfer_id: &str,
    ) -> Result<SparkscanTransfer, SparkscanError> {
        let url = format!(
            "{}/tx/{}?network={}",
            self.base_url, transfer_id, self.network
        );

        debug!(%url, network = self.network, "sparkscan fetch_transfer");

        let body = http_get(&self.http, &url, self.api_key.as_deref()).await?;

        serde_json::from_str(&body).map_err(|e| SparkscanError::ParseError {
            status: 200,
            detail: e.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from Sparkscan API communication.
#[derive(Debug)]
pub enum SparkscanError {
    /// The HTTP request failed (TLS, network, timeout).
    RequestFailed,
    /// The API returned a non-2xx status code.
    ApiError {
        /// HTTP status code.
        status: u16,
        /// Response body (best-effort).
        body: String,
    },
    /// The response body could not be parsed as expected JSON.
    ParseError {
        /// HTTP status code.
        status: u16,
        /// Description of the parse failure.
        detail: String,
    },
}

impl std::fmt::Display for SparkscanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestFailed => write!(f, "Sparkscan request failed"),
            Self::ApiError { status, body } => {
                write!(f, "Sparkscan API error: status={status} body={body}")
            }
            Self::ParseError { status, detail } => {
                write!(f, "Sparkscan parse error: status={status} detail={detail}")
            }
        }
    }
}

impl std::error::Error for SparkscanError {}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Top-level response from `GET /v1/tx/{id}`.
#[derive(Debug, Deserialize)]
pub struct SparkscanTransfer {
    /// Transfer identifier.
    pub id: String,
    /// Transfer type (e.g. "SPARK", "TOKEN").
    #[serde(rename = "type")]
    pub transfer_type: String,
    /// Transfer status (e.g. "COMPLETED").
    pub status: String,
    /// ISO-8601 creation timestamp.
    #[serde(rename = "createdAt")]
    pub created_at: String,
    /// ISO-8601 last-update timestamp.
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    /// Sender party (if known).
    pub from: Option<SparkscanParty>,
    /// Receiver party (if known).
    pub to: Option<SparkscanParty>,
    /// Raw token amount (before decimals).
    pub amount: Option<u128>,
    /// Satoshi amount.
    #[serde(rename = "amountSats")]
    pub amount_sats: Option<u128>,
    /// USD value at time of transfer.
    #[serde(rename = "valueUsd")]
    pub value_usd: Option<f64>,
    /// Token metadata (for token transfers).
    #[serde(rename = "tokenMetadata")]
    pub token_metadata: Option<SparkscanTokenMetadata>,
    /// Multi-input/output breakdown.
    #[serde(rename = "multiIoDetails")]
    pub multi_io_details: Option<SparkscanMultiIoDetails>,
}

/// A party (sender or receiver) in a transfer.
#[derive(Debug, Deserialize)]
pub struct SparkscanParty {
    /// Party type (e.g. "SPARK_ADDRESS", "LIGHTNING").
    #[serde(rename = "type")]
    pub party_type: String,
    /// Human-readable identifier (address or invoice).
    pub identifier: String,
    /// Compressed public key hex.
    pub pubkey: String,
}

/// A single input or output in a multi-IO transfer.
#[derive(Debug, Deserialize)]
pub struct SparkscanIo {
    /// Spark address.
    pub address: String,
    /// Compressed public key hex.
    pub pubkey: String,
    /// Amount in smallest unit.
    pub amount: u128,
}

/// Multi-input/output details.
#[derive(Debug, Deserialize)]
pub struct SparkscanMultiIoDetails {
    /// Transfer inputs.
    pub inputs: Vec<SparkscanIo>,
    /// Transfer outputs.
    pub outputs: Vec<SparkscanIo>,
    /// Total input amount.
    #[serde(rename = "totalInputAmount")]
    pub total_input_amount: u128,
    /// Total output amount.
    #[serde(rename = "totalOutputAmount")]
    pub total_output_amount: u128,
}

/// Token metadata attached to a token transfer.
#[derive(Debug, Deserialize)]
pub struct SparkscanTokenMetadata {
    /// Token identifier (hash).
    #[serde(rename = "tokenIdentifier")]
    pub token_identifier: String,
    /// Human-readable token address.
    #[serde(rename = "tokenAddress")]
    pub token_address: String,
    /// Token display name.
    pub name: String,
    /// Token ticker symbol.
    pub ticker: String,
    /// Decimal places.
    pub decimals: u8,
    /// Hex-encoded issuer public key.
    #[serde(rename = "issuerPublicKey")]
    pub issuer_public_key: String,
    /// Maximum supply.
    #[serde(rename = "maxSupply")]
    pub max_supply: u128,
    /// Whether the token can be frozen by the issuer.
    #[serde(rename = "isFreezable")]
    pub is_freezable: bool,
}

// ---------------------------------------------------------------------------
// HTTP transport (hyper + rustls, same stack as crates/graphql)
// ---------------------------------------------------------------------------

/// Hyper client type alias.
type HttpsClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<hyper::body::Bytes>,
>;

/// Build a TLS-enabled hyper client.
fn make_https_client() -> Result<HttpsClient, SparkscanError> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .map_err(|e| {
            error!(?e, "sparkscan TLS setup failed");
            SparkscanError::RequestFailed
        })?
        .https_or_http()
        .enable_http2()
        .build();

    Ok(
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(https),
    )
}

/// Send an HTTP GET and return the response body as a string.
async fn http_get(
    client: &HttpsClient,
    url: &str,
    api_key: Option<&str>,
) -> Result<String, SparkscanError> {
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(url);

    if let Some(key) = api_key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }

    let req = builder.body(http_body_util::Full::default()).map_err(|e| {
        error!(?e, "sparkscan failed to build request");
        SparkscanError::RequestFailed
    })?;

    let resp = client.request(req).await.map_err(|e| {
        error!(?e, "sparkscan HTTP request failed");
        SparkscanError::RequestFailed
    })?;

    let status = resp.status();

    use http_body_util::BodyExt;
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|_| SparkscanError::RequestFailed)?
        .to_bytes();

    let body_str = std::str::from_utf8(&body_bytes).map_err(|_| SparkscanError::ParseError {
        status: status.as_u16(),
        detail: "response body is not valid UTF-8".to_owned(),
    })?;

    if !status.is_success() {
        error!(%status, body = body_str, "sparkscan API error response");
        return Err(SparkscanError::ApiError {
            status: status.as_u16(),
            body: body_str.to_owned(),
        });
    }

    Ok(body_str.to_owned())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_URL: &str = "https://api.sparkscan.io/v1";

    const TOKEN_TRANSFER_MAINNET: &str =
        "696d419cac75150c46a3466c304e1a45588538a00e657a1a0e2415ee99987112";
    const TOKEN_TRANSFER_REGTEST: &str =
        "1c2784446e3741b9b8105f52b4b432f84295fd92f84c9e2277b65f898f2757db";
    const SATS_TRANSFER_MAINNET: &str = "0198b60e-d0a2-7019-8e3a-8b29b321a5bb";
    const SATS_TRANSFER_REGTEST: &str = "0198b5f2-6b72-71e6-8d90-bdfd5bd64c5b";

    #[tokio::test]
    #[ignore] // Hits live API -- run manually with `cargo test -p sparkscan-client -- --ignored`
    async fn fetch_transfers_sequential() {
        let mainnet = SparkscanClient::new(BASE_URL, "MAINNET").unwrap();
        let regtest = SparkscanClient::new(BASE_URL, "REGTEST").unwrap();

        let mainnet_token = mainnet.fetch_transfer(TOKEN_TRANSFER_MAINNET).await;
        let regtest_token = regtest.fetch_transfer(TOKEN_TRANSFER_REGTEST).await;
        let mainnet_sats = mainnet.fetch_transfer(SATS_TRANSFER_MAINNET).await;
        let regtest_sats = regtest.fetch_transfer(SATS_TRANSFER_REGTEST).await;

        println!("{mainnet_token:?}");
        println!("{regtest_token:?}");
        println!("{mainnet_sats:?}");
        println!("{regtest_sats:?}");
    }

    #[tokio::test]
    #[ignore] // Hits live API
    async fn fetch_transfers_parallel() {
        let mainnet = SparkscanClient::new(BASE_URL, "MAINNET").unwrap();
        let regtest = SparkscanClient::new(BASE_URL, "REGTEST").unwrap();

        let (mainnet_token, regtest_token, mainnet_sats, regtest_sats) = tokio::join!(
            mainnet.fetch_transfer(TOKEN_TRANSFER_MAINNET),
            regtest.fetch_transfer(TOKEN_TRANSFER_REGTEST),
            mainnet.fetch_transfer(SATS_TRANSFER_MAINNET),
            regtest.fetch_transfer(SATS_TRANSFER_REGTEST),
        );

        println!("{mainnet_token:?}");
        println!("{regtest_token:?}");
        println!("{mainnet_sats:?}");
        println!("{regtest_sats:?}");
    }
}
