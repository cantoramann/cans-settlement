//! gRPC transport for Spark protocol communication.
//!
//! Provides [`GrpcTransport`] -- a connection-pooled, TLS-enabled gRPC client
//! for Spark signing operators. Connections are established lazily on first use
//! via [`tonic::transport::Endpoint::connect_lazy`] and automatically reconnect
//! on failure.
//!
//! # Connection Model
//!
//! Each operator gets a single [`tonic::transport::Channel`] created at
//! construction time. Channels are HTTP/2 multiplexed and handle reconnection
//! internally, so there is no runtime pool management or health tracking.
//!
//! # Authentication
//!
//! The [`GrpcTransport::get_challenge`] and [`GrpcTransport::verify_challenge`]
//! methods implement the Spark authentication handshake:
//!
//! 1. Request a challenge for a public key
//! 2. Sign the challenge with the corresponding private key (ECDSA)
//! 3. Submit the signed challenge to receive a session token
//!
//! # Example
//!
//! ```no_run
//! use transport::grpc::{GrpcTransport, GrpcConfig, OperatorConfig};
//!
//! # fn example() -> Result<(), transport::grpc::GrpcError> {
//! let transport = GrpcTransport::new(
//!     &[OperatorConfig {
//!         id: "coordinator".into(),
//!         address: "https://0.spark.lightspark.com".into(),
//!         identity_public_key: "03dfbd...".into(),
//!         is_coordinator: true,
//!     }],
//!     GrpcConfig::default(),
//! )?;
//!
//! assert_eq!(transport.coordinator_id(), "coordinator");
//! # Ok(())
//! # }
//! ```

use std::fmt;
use std::time::Duration;

use bytes::Bytes;
use prost::Message as ProstMessage;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::session::SessionCache;
use crate::spark_authn::{
    self, GetChallengeResponse, ProtectedChallenge, VerifyChallengeResponse,
    spark_authn_service_client::SparkAuthnServiceClient,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from the gRPC transport layer.
#[derive(Debug)]
pub enum GrpcError {
    /// No operators were provided.
    NoOperators,

    /// No coordinator operator was designated.
    NoCoordinator,

    /// Multiple coordinators were found (expected exactly 1).
    MultipleCoordinators(usize),

    /// The operator ID was not found.
    UnknownOperator(String),

    /// The endpoint URL is invalid.
    InvalidEndpoint { url: String, reason: String },

    /// A gRPC call returned an error status.
    Status { code: tonic::Code, message: String },

    /// The signer failed to produce a signature.
    SigningFailed(String),

    /// The session token is not valid ASCII or cannot be formatted as a Bearer header.
    InvalidToken,
}

impl fmt::Display for GrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOperators => write!(f, "no operators configured"),
            Self::NoCoordinator => write!(f, "no coordinator operator configured"),
            Self::MultipleCoordinators(n) => {
                write!(f, "expected 1 coordinator, found {n}")
            }
            Self::UnknownOperator(id) => write!(f, "unknown operator: {id}"),
            Self::InvalidEndpoint { url, reason } => {
                write!(f, "invalid endpoint '{url}': {reason}")
            }
            Self::Status { code, message } => {
                write!(f, "gRPC error ({code}): {message}")
            }
            Self::SigningFailed(reason) => write!(f, "signing failed: {reason}"),
            Self::InvalidToken => write!(f, "invalid session token"),
        }
    }
}

impl std::error::Error for GrpcError {}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Input configuration for a single Spark signing operator.
#[derive(Debug, Clone)]
pub struct OperatorConfig {
    /// Unique identifier for this operator.
    pub id: String,

    /// gRPC endpoint URL (e.g. `https://0.spark.lightspark.com`).
    pub address: String,

    /// Hex-encoded identity public key of the operator.
    pub identity_public_key: String,

    /// Whether this operator is the coordinator.
    ///
    /// Exactly one operator must be designated as coordinator.
    pub is_coordinator: bool,
}

/// Configuration for the gRPC transport.
///
/// All timeouts have sensible defaults. Adjust based on network conditions
/// and operator SLAs.
#[derive(Debug, Clone)]
pub struct GrpcConfig {
    /// TCP + TLS handshake timeout. Default: 10 s.
    pub connect_timeout: Duration,

    /// Per-request timeout. Default: 30 s.
    pub request_timeout: Duration,

    /// HTTP/2 keep-alive ping interval. Default: 30 s.
    pub keep_alive_interval: Duration,

    /// Keep-alive ping response timeout. Default: 10 s.
    pub keep_alive_timeout: Duration,

    /// Enable TLS for `https://` endpoints. Default: true.
    pub use_tls: bool,

    /// Maximum decoded gRPC message size in bytes. Default: 50 MiB.
    pub max_decoding_message_size: usize,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(30),
            keep_alive_timeout: Duration::from_secs(10),
            use_tls: true,
            max_decoding_message_size: 50 * 1024 * 1024,
        }
    }
}

impl GrpcConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> GrpcConfigBuilder {
        GrpcConfigBuilder::default()
    }
}

/// Builder for [`GrpcConfig`].
#[derive(Debug, Default)]
pub struct GrpcConfigBuilder {
    connect_timeout: Option<Duration>,
    request_timeout: Option<Duration>,
    keep_alive_interval: Option<Duration>,
    keep_alive_timeout: Option<Duration>,
    use_tls: Option<bool>,
    max_decoding_message_size: Option<usize>,
}

impl GrpcConfigBuilder {
    /// Sets the TCP + TLS connection timeout.
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    /// Sets the per-request timeout.
    pub fn request_timeout(mut self, d: Duration) -> Self {
        self.request_timeout = Some(d);
        self
    }

    /// Sets the HTTP/2 keep-alive ping interval.
    pub fn keep_alive_interval(mut self, d: Duration) -> Self {
        self.keep_alive_interval = Some(d);
        self
    }

    /// Sets the keep-alive response timeout.
    pub fn keep_alive_timeout(mut self, d: Duration) -> Self {
        self.keep_alive_timeout = Some(d);
        self
    }

    /// Enables or disables TLS.
    pub fn use_tls(mut self, v: bool) -> Self {
        self.use_tls = Some(v);
        self
    }

    /// Sets the maximum decoded message size in bytes.
    pub fn max_decoding_message_size(mut self, n: usize) -> Self {
        self.max_decoding_message_size = Some(n);
        self
    }

    /// Builds the configuration, filling unset values with defaults.
    pub fn build(self) -> GrpcConfig {
        let d = GrpcConfig::default();
        GrpcConfig {
            connect_timeout: self.connect_timeout.unwrap_or(d.connect_timeout),
            request_timeout: self.request_timeout.unwrap_or(d.request_timeout),
            keep_alive_interval: self.keep_alive_interval.unwrap_or(d.keep_alive_interval),
            keep_alive_timeout: self.keep_alive_timeout.unwrap_or(d.keep_alive_timeout),
            use_tls: self.use_tls.unwrap_or(d.use_tls),
            max_decoding_message_size: self
                .max_decoding_message_size
                .unwrap_or(d.max_decoding_message_size),
        }
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Internal entry for a connected operator.
struct OperatorEntry {
    id: String,
    channel: Channel,
}

/// gRPC transport for Spark protocol communication.
///
/// Maintains lazily-connected channels to Spark signing operators. Channels
/// are created at construction time via [`Endpoint::connect_lazy`] and defer
/// the actual TCP/TLS handshake until the first RPC. Reconnection is handled
/// automatically by tonic.
///
/// # Thread Safety
///
/// `GrpcTransport` is `Send + Sync`. Channels are internally
/// reference-counted and safe to clone across tasks.
///
/// `Debug` is implemented manually because [`Channel`] does not derive it.
pub struct GrpcTransport {
    /// Operator entries. The coordinator is at `operators[coordinator_idx]`.
    operators: Vec<OperatorEntry>,

    /// Index of the coordinator in `operators`.
    coordinator_idx: usize,

    /// Transport configuration (kept for client construction).
    config: GrpcConfig,

    /// In-memory session cache keyed by (operator index, public key).
    sessions: SessionCache,
}

impl fmt::Debug for GrpcTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcTransport")
            .field(
                "operators",
                &self.operators.iter().map(|o| &o.id).collect::<Vec<_>>(),
            )
            .field("coordinator_idx", &self.coordinator_idx)
            .finish()
    }
}

impl GrpcTransport {
    /// Creates a new transport with lazy connections to all operators.
    ///
    /// Channels are created immediately but defer the TCP/TLS handshake
    /// until the first RPC call. This makes construction fast -- no
    /// network I/O happens here.
    ///
    /// # Panics
    ///
    /// Must be called from within a tokio runtime context (the lazy
    /// channel requires a reactor). This is automatically satisfied
    /// in `async fn` blocks and `#[tokio::main]` / `#[tokio::test]`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `configs` is empty
    /// - No operator has `is_coordinator == true`
    /// - More than one operator has `is_coordinator == true`
    /// - An operator's `address` cannot be parsed as a valid endpoint
    pub fn new(configs: &[OperatorConfig], config: GrpcConfig) -> Result<Self, GrpcError> {
        if configs.is_empty() {
            return Err(GrpcError::NoOperators);
        }

        let coord_count = configs.iter().filter(|c| c.is_coordinator).count();
        match coord_count {
            0 => return Err(GrpcError::NoCoordinator),
            1 => {}
            n => return Err(GrpcError::MultipleCoordinators(n)),
        }

        let mut operators = Vec::with_capacity(configs.len());
        let mut coordinator_idx = 0;

        for (i, op) in configs.iter().enumerate() {
            let channel = build_lazy_channel(&op.address, &config)?;
            if op.is_coordinator {
                coordinator_idx = i;
            }
            operators.push(OperatorEntry {
                id: op.id.clone(),
                channel,
            });
        }

        let sessions = SessionCache::new(operators.len());

        Ok(Self {
            operators,
            coordinator_idx,
            config,
            sessions,
        })
    }

    /// Returns the coordinator operator's ID.
    pub fn coordinator_id(&self) -> &str {
        &self.operators[self.coordinator_idx].id
    }

    /// Returns all operator IDs in their original order.
    pub fn operator_ids(&self) -> Vec<&str> {
        self.operators.iter().map(|o| o.id.as_str()).collect()
    }

    /// Returns a cloned channel for the given operator, if it exists.
    ///
    /// Cloning a [`Channel`] is cheap (internally reference-counted).
    pub fn channel(&self, operator_id: &str) -> Option<Channel> {
        self.find_operator(operator_id).map(|o| o.channel.clone())
    }

    /// Requests an authentication challenge from an operator.
    ///
    /// This is step 1 of the Spark authentication handshake. The returned
    /// challenge must be signed with the corresponding private key and
    /// submitted via [`Self::verify_challenge`].
    ///
    /// # Arguments
    ///
    /// * `operator_id` -- Which operator to request the challenge from.
    /// * `public_key` -- Uncompressed secp256k1 public key (65 bytes,
    ///   `0x04` prefix).
    pub async fn get_challenge(
        &self,
        operator_id: &str,
        public_key: &[u8],
    ) -> Result<GetChallengeResponse, GrpcError> {
        let channel = self.require_channel(operator_id)?;
        let mut client = SparkAuthnServiceClient::new(channel)
            .max_decoding_message_size(self.config.max_decoding_message_size);

        let request = spark_authn::GetChallengeRequest {
            public_key: Bytes::copy_from_slice(public_key),
        };

        let response = client
            .get_challenge(request)
            .await
            .map_err(grpc_status_to_error)?;

        Ok(response.into_inner())
    }

    /// Verifies a signed challenge and returns a session token.
    ///
    /// This is step 2 of the Spark authentication handshake. The
    /// `protected_challenge` comes from [`Self::get_challenge`], signed
    /// with the private key that corresponds to the public key used in
    /// step 1.
    ///
    /// # Arguments
    ///
    /// * `operator_id` -- The same operator used in `get_challenge`.
    /// * `protected_challenge` -- From the `get_challenge` response.
    /// * `signature` -- ECDSA DER-encoded signature over the
    ///   protobuf-encoded [`Challenge`](spark_authn::Challenge) bytes.
    /// * `public_key` -- Uncompressed secp256k1 public key (65 bytes).
    pub async fn verify_challenge(
        &self,
        operator_id: &str,
        protected_challenge: ProtectedChallenge,
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<VerifyChallengeResponse, GrpcError> {
        let channel = self.require_channel(operator_id)?;
        let mut client = SparkAuthnServiceClient::new(channel)
            .max_decoding_message_size(self.config.max_decoding_message_size);

        let request = spark_authn::VerifyChallengeRequest {
            protected_challenge: Some(protected_challenge),
            signature: Bytes::copy_from_slice(signature),
            public_key: Bytes::copy_from_slice(public_key),
        };

        let response = client
            .verify_challenge(request)
            .await
            .map_err(grpc_status_to_error)?;

        Ok(response.into_inner())
    }

    // -- session management --------------------------------------------------

    /// Returns the index of the given operator in the internal array.
    ///
    /// This is useful for callers that need to batch-operate on a known
    /// operator without repeated linear scans.
    pub fn operator_index(&self, operator_id: &str) -> Result<usize, GrpcError> {
        self.operators
            .iter()
            .position(|o| o.id == operator_id)
            .ok_or_else(|| GrpcError::UnknownOperator(operator_id.to_owned()))
    }

    /// Returns a valid session token for the given operator, using the
    /// provided [`Signer`](signer::Signer) for automatic (re-)authentication.
    ///
    /// **Hot path (cache hit):** one `RwLock` read + one `HashMap::get` +
    /// one `Bytes::clone` -- zero heap allocations.
    ///
    /// **Cold path (cache miss):** full `get_challenge` / `sign` /
    /// `verify_challenge` handshake, then caches the result.
    pub async fn session_token(
        &self,
        operator_id: &str,
        signer: &impl signer::Signer,
    ) -> Result<Bytes, GrpcError> {
        let idx = self.operator_index(operator_id)?;
        let pubkey = signer.public_key();

        // Hot path: check cache.
        if let Some(token) = self.sessions.get(idx, &pubkey) {
            return Ok(token);
        }

        // Cold path: full auth handshake.
        let resp = self.get_challenge(operator_id, &pubkey).await?;

        let protected = resp.protected_challenge.ok_or_else(|| GrpcError::Status {
            code: tonic::Code::Internal,
            message: "missing protected_challenge in response".into(),
        })?;

        let challenge = protected
            .challenge
            .as_ref()
            .ok_or_else(|| GrpcError::Status {
                code: tonic::Code::Internal,
                message: "missing challenge in protected_challenge".into(),
            })?;

        // Encode the Challenge to protobuf bytes for signing.
        let mut challenge_bytes = Vec::with_capacity(challenge.encoded_len());
        challenge
            .encode(&mut challenge_bytes)
            .map_err(|e| GrpcError::SigningFailed(format!("challenge encoding failed: {e}")))?;

        // Delegate hashing + signing to the caller-provided signer.
        let signature = signer
            .sign_challenge(&challenge_bytes)
            .map_err(|e| GrpcError::SigningFailed(e.to_string()))?;

        // Verify challenge and receive session token.
        let verify_resp = self
            .verify_challenge(operator_id, protected, &signature, &pubkey)
            .await?;

        let token = Bytes::from(verify_resp.session_token);
        let expires_at = verify_resp.expiration_timestamp;

        // Cache for subsequent calls.
        self.sessions.insert(idx, pubkey, token.clone(), expires_at);

        Ok(token)
    }

    // -- SparkService RPC methods --------------------------------------------

    /// Returns a `SparkServiceClient` for the given operator.
    fn spark_client(
        &self,
        operator_id: &str,
    ) -> Result<crate::spark::spark_service_client::SparkServiceClient<Channel>, GrpcError> {
        let channel = self.require_channel(operator_id)?;
        Ok(
            crate::spark::spark_service_client::SparkServiceClient::new(channel)
                .max_decoding_message_size(self.config.max_decoding_message_size),
        )
    }

    /// Returns a `SparkServiceClient` for the coordinator.
    fn spark_coordinator_client(
        &self,
    ) -> crate::spark::spark_service_client::SparkServiceClient<Channel> {
        let channel = self.operators[self.coordinator_idx].channel.clone();
        crate::spark::spark_service_client::SparkServiceClient::new(channel)
            .max_decoding_message_size(self.config.max_decoding_message_size)
    }

    /// Returns a `SparkTokenServiceClient` for the coordinator.
    fn spark_token_coordinator_client(
        &self,
    ) -> crate::spark_token::spark_token_service_client::SparkTokenServiceClient<Channel> {
        let channel = self.operators[self.coordinator_idx].channel.clone();
        crate::spark_token::spark_token_service_client::SparkTokenServiceClient::new(channel)
            .max_decoding_message_size(self.config.max_decoding_message_size)
    }

    /// Get FROST signing commitments from the coordinator.
    pub async fn get_signing_commitments(
        &self,
        request: crate::spark::GetSigningCommitmentsRequest,
    ) -> Result<crate::spark::GetSigningCommitmentsResponse, GrpcError> {
        self.spark_coordinator_client()
            .get_signing_commitments(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Start a BTC transfer (v2) on the coordinator.
    pub async fn start_transfer_v2(
        &self,
        request: crate::spark::StartTransferRequest,
    ) -> Result<crate::spark::StartTransferResponse, GrpcError> {
        self.spark_coordinator_client()
            .start_transfer_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query pending transfers from the coordinator.
    pub async fn query_pending_transfers(
        &self,
        request: crate::spark::TransferFilter,
    ) -> Result<crate::spark::QueryTransfersResponse, GrpcError> {
        self.spark_coordinator_client()
            .query_pending_transfers(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Claim transfer tweak keys on a specific operator.
    ///
    /// Returns `()` (server returns `google.protobuf.Empty`).
    pub async fn claim_transfer_tweak_keys(
        &self,
        operator_id: &str,
        request: crate::spark::ClaimTransferTweakKeysRequest,
    ) -> Result<(), GrpcError> {
        self.spark_client(operator_id)?
            .claim_transfer_tweak_keys(request)
            .await
            .map(|_| ())
            .map_err(grpc_status_to_error)
    }

    /// Sign refunds for a claimed transfer (v2) on the coordinator.
    pub async fn claim_transfer_sign_refunds(
        &self,
        request: crate::spark::ClaimTransferSignRefundsRequest,
    ) -> Result<crate::spark::ClaimTransferSignRefundsResponse, GrpcError> {
        self.spark_coordinator_client()
            .claim_transfer_sign_refunds_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize node signatures (v2) on the coordinator.
    pub async fn finalize_node_signatures(
        &self,
        request: crate::spark::FinalizeNodeSignaturesRequest,
    ) -> Result<crate::spark::FinalizeNodeSignaturesResponse, GrpcError> {
        self.spark_coordinator_client()
            .finalize_node_signatures_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Generate a deposit address from the coordinator.
    pub async fn generate_deposit_address(
        &self,
        request: crate::spark::GenerateDepositAddressRequest,
    ) -> Result<crate::spark::GenerateDepositAddressResponse, GrpcError> {
        self.spark_coordinator_client()
            .generate_deposit_address(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize deposit tree creation on the coordinator.
    pub async fn finalize_deposit_tree_creation(
        &self,
        request: crate::spark::FinalizeDepositTreeCreationRequest,
    ) -> Result<crate::spark::FinalizeDepositTreeCreationResponse, GrpcError> {
        self.spark_coordinator_client()
            .finalize_deposit_tree_creation(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize transfer with transfer package on the coordinator.
    pub async fn finalize_transfer_with_transfer_package(
        &self,
        request: crate::spark::FinalizeTransferWithTransferPackageRequest,
    ) -> Result<crate::spark::FinalizeTransferResponse, GrpcError> {
        self.spark_coordinator_client()
            .finalize_transfer_with_transfer_package(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Initiate a preimage swap (v3) on the coordinator (Lightning send).
    pub async fn initiate_preimage_swap_v3(
        &self,
        request: crate::spark::InitiatePreimageSwapRequest,
    ) -> Result<crate::spark::InitiatePreimageSwapResponse, GrpcError> {
        self.spark_coordinator_client()
            .initiate_preimage_swap_v3(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Store a preimage share on a specific operator (Lightning receive).
    ///
    /// Returns `()` (server returns `google.protobuf.Empty`).
    pub async fn store_preimage_share(
        &self,
        operator_id: &str,
        request: crate::spark::StorePreimageShareRequest,
    ) -> Result<(), GrpcError> {
        self.spark_client(operator_id)?
            .store_preimage_share(request)
            .await
            .map(|_| ())
            .map_err(grpc_status_to_error)
    }

    /// Initiate a swap primary transfer on the coordinator.
    ///
    /// This is the first step of a V3 SSP swap: the user sends their
    /// leaves to the coordinator with adaptor public keys, and the
    /// coordinator returns signing results for FROST aggregation.
    pub async fn initiate_swap_primary_transfer(
        &self,
        request: crate::spark::InitiateSwapPrimaryTransferRequest,
    ) -> Result<crate::spark::InitiateSwapPrimaryTransferResponse, GrpcError> {
        self.spark_coordinator_client()
            .initiate_swap_primary_transfer(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Cooperative exit (v2) on the coordinator.
    pub async fn cooperative_exit_v2(
        &self,
        request: crate::spark::CooperativeExitRequest,
    ) -> Result<crate::spark::CooperativeExitResponse, GrpcError> {
        self.spark_coordinator_client()
            .cooperative_exit_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query nodes on a specific operator.
    pub async fn query_nodes(
        &self,
        operator_id: &str,
        request: crate::spark::QueryNodesRequest,
    ) -> Result<crate::spark::QueryNodesResponse, GrpcError> {
        self.spark_client(operator_id)?
            .query_nodes(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query balance on the coordinator.
    pub async fn query_balance(
        &self,
        request: crate::spark::QueryBalanceRequest,
    ) -> Result<crate::spark::QueryBalanceResponse, GrpcError> {
        self.spark_coordinator_client()
            .query_balance(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Subscribe to events from the coordinator.
    pub async fn subscribe_to_events(
        &self,
        request: crate::spark::SubscribeToEventsRequest,
    ) -> Result<tonic::Streaming<crate::spark::SubscribeToEventsResponse>, GrpcError> {
        self.spark_coordinator_client()
            .subscribe_to_events(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    // -- SparkTokenService RPC methods ---------------------------------------

    /// Broadcast a token transaction on the coordinator.
    pub async fn broadcast_transaction(
        &self,
        request: crate::spark_token::BroadcastTransactionRequest,
    ) -> Result<crate::spark_token::BroadcastTransactionResponse, GrpcError> {
        self.spark_token_coordinator_client()
            .broadcast_transaction(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query token outputs on the coordinator.
    pub async fn query_token_outputs(
        &self,
        request: crate::spark_token::QueryTokenOutputsRequest,
    ) -> Result<crate::spark_token::QueryTokenOutputsResponse, GrpcError> {
        self.spark_token_coordinator_client()
            .query_token_outputs(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    // -- private helpers ----------------------------------------------------

    /// Finds an operator entry by ID.
    fn find_operator(&self, id: &str) -> Option<&OperatorEntry> {
        self.operators.iter().find(|o| o.id == id)
    }

    /// Returns a cloned channel or `GrpcError::UnknownOperator`.
    fn require_channel(&self, operator_id: &str) -> Result<Channel, GrpcError> {
        self.channel(operator_id)
            .ok_or_else(|| GrpcError::UnknownOperator(operator_id.to_owned()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Builds a lazy channel for the given URL with the provided config.
fn build_lazy_channel(url: &str, config: &GrpcConfig) -> Result<Channel, GrpcError> {
    let mut endpoint = Endpoint::from_shared(url.to_owned())
        .map_err(|e| GrpcError::InvalidEndpoint {
            url: url.to_owned(),
            reason: e.to_string(),
        })?
        .connect_timeout(config.connect_timeout)
        .timeout(config.request_timeout)
        .http2_keep_alive_interval(config.keep_alive_interval)
        .keep_alive_timeout(config.keep_alive_timeout);

    if url.starts_with("https://") && config.use_tls {
        let tls = ClientTlsConfig::new().with_native_roots();
        endpoint = endpoint
            .tls_config(tls)
            .map_err(|e| GrpcError::InvalidEndpoint {
                url: url.to_owned(),
                reason: format!("TLS configuration failed: {e}"),
            })?;
    }

    Ok(endpoint.connect_lazy())
}

/// Converts a tonic `Status` into a `GrpcError`.
fn grpc_status_to_error(status: tonic::Status) -> GrpcError {
    GrpcError::Status {
        code: status.code(),
        message: status.message().to_owned(),
    }
}

// ---------------------------------------------------------------------------
// Authenticated transport
// ---------------------------------------------------------------------------

/// Interceptor that injects a `Bearer` token into gRPC request metadata.
///
/// Created by [`GrpcTransport::authenticated`] and used internally by
/// [`AuthenticatedTransport`]. The interceptor is cheap to clone (one
/// `MetadataValue` clone, which is reference-counted bytes).
#[derive(Clone)]
struct AuthInterceptor {
    token: MetadataValue<Ascii>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        req.metadata_mut()
            .insert("authorization", self.token.clone());
        Ok(req)
    }
}

/// Converts a raw session token (as returned by [`GrpcTransport::session_token`])
/// into a `Bearer <token>` [`MetadataValue`].
fn bearer_metadata(token: &[u8]) -> Result<MetadataValue<Ascii>, GrpcError> {
    let token_str = std::str::from_utf8(token).map_err(|_| GrpcError::InvalidToken)?;
    format!("Bearer {token_str}")
        .parse()
        .map_err(|_| GrpcError::InvalidToken)
}

/// An authenticated view of the transport layer.
///
/// All SparkService and SparkTokenService RPC calls made through this
/// wrapper automatically include the session token as a `Bearer`
/// authorization header in gRPC metadata.
///
/// Created via [`GrpcTransport::authenticated`]:
///
/// ```no_run
/// # use bytes::Bytes;
/// # use transport::grpc::GrpcTransport;
/// # async fn example(transport: &GrpcTransport, token: &Bytes) {
/// let authed = transport.authenticated(token).unwrap();
/// // All RPCs through `authed` include the Bearer token.
/// # }
/// ```
pub struct AuthenticatedTransport<'a> {
    transport: &'a GrpcTransport,
    token: MetadataValue<Ascii>,
}

impl GrpcTransport {
    /// Creates an authenticated transport wrapper.
    ///
    /// The returned [`AuthenticatedTransport`] injects the given session
    /// token as a `Bearer` authorization header into all SparkService and
    /// SparkTokenService RPC calls. Authentication RPCs (`get_challenge`,
    /// `verify_challenge`, `session_token`) remain on `GrpcTransport`.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcError::InvalidToken`] if the token is not valid ASCII.
    pub fn authenticated(&self, token: &Bytes) -> Result<AuthenticatedTransport<'_>, GrpcError> {
        let meta = bearer_metadata(token)?;
        Ok(AuthenticatedTransport {
            transport: self,
            token: meta,
        })
    }
}

impl<'a> AuthenticatedTransport<'a> {
    /// Returns a reference to the underlying transport.
    pub fn inner(&self) -> &GrpcTransport {
        self.transport
    }

    /// Returns the coordinator operator's ID.
    pub fn coordinator_id(&self) -> &str {
        self.transport.coordinator_id()
    }

    /// Returns all operator IDs.
    pub fn operator_ids(&self) -> Vec<&str> {
        self.transport.operator_ids()
    }

    // -- internal client constructors ----------------------------------------

    fn interceptor(&self) -> AuthInterceptor {
        AuthInterceptor {
            token: self.token.clone(),
        }
    }

    fn spark_client(
        &self,
        operator_id: &str,
    ) -> Result<
        crate::spark::spark_service_client::SparkServiceClient<
            tonic::service::interceptor::InterceptedService<Channel, AuthInterceptor>,
        >,
        GrpcError,
    > {
        let channel = self.transport.require_channel(operator_id)?;
        Ok(
            crate::spark::spark_service_client::SparkServiceClient::with_interceptor(
                channel,
                self.interceptor(),
            )
            .max_decoding_message_size(self.transport.config.max_decoding_message_size),
        )
    }

    fn coordinator_client(
        &self,
    ) -> crate::spark::spark_service_client::SparkServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, AuthInterceptor>,
    > {
        let channel = self.transport.operators[self.transport.coordinator_idx]
            .channel
            .clone();
        crate::spark::spark_service_client::SparkServiceClient::with_interceptor(
            channel,
            self.interceptor(),
        )
        .max_decoding_message_size(self.transport.config.max_decoding_message_size)
    }

    fn token_coordinator_client(
        &self,
    ) -> crate::spark_token::spark_token_service_client::SparkTokenServiceClient<
        tonic::service::interceptor::InterceptedService<Channel, AuthInterceptor>,
    > {
        let channel = self.transport.operators[self.transport.coordinator_idx]
            .channel
            .clone();
        crate::spark_token::spark_token_service_client::SparkTokenServiceClient::with_interceptor(
            channel,
            self.interceptor(),
        )
        .max_decoding_message_size(self.transport.config.max_decoding_message_size)
    }

    // -- SparkService RPC methods --------------------------------------------

    /// Get FROST signing commitments from the coordinator.
    pub async fn get_signing_commitments(
        &self,
        request: crate::spark::GetSigningCommitmentsRequest,
    ) -> Result<crate::spark::GetSigningCommitmentsResponse, GrpcError> {
        self.coordinator_client()
            .get_signing_commitments(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Start a BTC transfer (v2) on the coordinator.
    pub async fn start_transfer_v2(
        &self,
        request: crate::spark::StartTransferRequest,
    ) -> Result<crate::spark::StartTransferResponse, GrpcError> {
        self.coordinator_client()
            .start_transfer_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query pending transfers from the coordinator.
    pub async fn query_pending_transfers(
        &self,
        request: crate::spark::TransferFilter,
    ) -> Result<crate::spark::QueryTransfersResponse, GrpcError> {
        self.coordinator_client()
            .query_pending_transfers(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Claim transfer tweak keys on a specific operator.
    pub async fn claim_transfer_tweak_keys(
        &self,
        operator_id: &str,
        request: crate::spark::ClaimTransferTweakKeysRequest,
    ) -> Result<(), GrpcError> {
        self.spark_client(operator_id)?
            .claim_transfer_tweak_keys(request)
            .await
            .map(|_| ())
            .map_err(grpc_status_to_error)
    }

    /// Sign refunds for a claimed transfer (v2) on the coordinator.
    pub async fn claim_transfer_sign_refunds(
        &self,
        request: crate::spark::ClaimTransferSignRefundsRequest,
    ) -> Result<crate::spark::ClaimTransferSignRefundsResponse, GrpcError> {
        self.coordinator_client()
            .claim_transfer_sign_refunds_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize node signatures (v2) on the coordinator.
    pub async fn finalize_node_signatures(
        &self,
        request: crate::spark::FinalizeNodeSignaturesRequest,
    ) -> Result<crate::spark::FinalizeNodeSignaturesResponse, GrpcError> {
        self.coordinator_client()
            .finalize_node_signatures_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Generate a deposit address from the coordinator.
    pub async fn generate_deposit_address(
        &self,
        request: crate::spark::GenerateDepositAddressRequest,
    ) -> Result<crate::spark::GenerateDepositAddressResponse, GrpcError> {
        self.coordinator_client()
            .generate_deposit_address(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize deposit tree creation on the coordinator.
    pub async fn finalize_deposit_tree_creation(
        &self,
        request: crate::spark::FinalizeDepositTreeCreationRequest,
    ) -> Result<crate::spark::FinalizeDepositTreeCreationResponse, GrpcError> {
        self.coordinator_client()
            .finalize_deposit_tree_creation(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Finalize transfer with transfer package on the coordinator.
    pub async fn finalize_transfer_with_transfer_package(
        &self,
        request: crate::spark::FinalizeTransferWithTransferPackageRequest,
    ) -> Result<crate::spark::FinalizeTransferResponse, GrpcError> {
        self.coordinator_client()
            .finalize_transfer_with_transfer_package(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Initiate a preimage swap (v3) on the coordinator (Lightning send).
    pub async fn initiate_preimage_swap_v3(
        &self,
        request: crate::spark::InitiatePreimageSwapRequest,
    ) -> Result<crate::spark::InitiatePreimageSwapResponse, GrpcError> {
        self.coordinator_client()
            .initiate_preimage_swap_v3(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Store a preimage share on a specific operator (Lightning receive).
    pub async fn store_preimage_share(
        &self,
        operator_id: &str,
        request: crate::spark::StorePreimageShareRequest,
    ) -> Result<(), GrpcError> {
        self.spark_client(operator_id)?
            .store_preimage_share(request)
            .await
            .map(|_| ())
            .map_err(grpc_status_to_error)
    }

    /// Initiate a swap primary transfer on the coordinator.
    pub async fn initiate_swap_primary_transfer(
        &self,
        request: crate::spark::InitiateSwapPrimaryTransferRequest,
    ) -> Result<crate::spark::InitiateSwapPrimaryTransferResponse, GrpcError> {
        self.coordinator_client()
            .initiate_swap_primary_transfer(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Cooperative exit (v2) on the coordinator.
    pub async fn cooperative_exit_v2(
        &self,
        request: crate::spark::CooperativeExitRequest,
    ) -> Result<crate::spark::CooperativeExitResponse, GrpcError> {
        self.coordinator_client()
            .cooperative_exit_v2(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query nodes on a specific operator.
    pub async fn query_nodes(
        &self,
        operator_id: &str,
        request: crate::spark::QueryNodesRequest,
    ) -> Result<crate::spark::QueryNodesResponse, GrpcError> {
        self.spark_client(operator_id)?
            .query_nodes(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query balance on the coordinator.
    pub async fn query_balance(
        &self,
        request: crate::spark::QueryBalanceRequest,
    ) -> Result<crate::spark::QueryBalanceResponse, GrpcError> {
        self.coordinator_client()
            .query_balance(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Subscribe to events from the coordinator.
    pub async fn subscribe_to_events(
        &self,
        request: crate::spark::SubscribeToEventsRequest,
    ) -> Result<tonic::Streaming<crate::spark::SubscribeToEventsResponse>, GrpcError> {
        self.coordinator_client()
            .subscribe_to_events(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    // -- SparkTokenService RPC methods ---------------------------------------

    /// Broadcast a token transaction on the coordinator.
    pub async fn broadcast_transaction(
        &self,
        request: crate::spark_token::BroadcastTransactionRequest,
    ) -> Result<crate::spark_token::BroadcastTransactionResponse, GrpcError> {
        self.token_coordinator_client()
            .broadcast_transaction(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }

    /// Query token outputs on the coordinator.
    pub async fn query_token_outputs(
        &self,
        request: crate::spark_token::QueryTokenOutputsRequest,
    ) -> Result<crate::spark_token::QueryTokenOutputsResponse, GrpcError> {
        self.token_coordinator_client()
            .query_token_outputs(request)
            .await
            .map(|r| r.into_inner())
            .map_err(grpc_status_to_error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_operator(id: &str, is_coordinator: bool) -> OperatorConfig {
        OperatorConfig {
            id: id.into(),
            address: format!("https://{id}.example.com"),
            identity_public_key: format!("02{}", "00".repeat(32)),
            is_coordinator,
        }
    }

    // -- GrpcConfig builder -------------------------------------------------

    #[test]
    fn config_builder_uses_defaults() {
        let cfg = GrpcConfig::builder().build();
        assert_eq!(cfg.connect_timeout, Duration::from_secs(10));
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
        assert_eq!(cfg.keep_alive_interval, Duration::from_secs(30));
        assert_eq!(cfg.keep_alive_timeout, Duration::from_secs(10));
        assert!(cfg.use_tls);
        assert_eq!(cfg.max_decoding_message_size, 50 * 1024 * 1024);
    }

    #[test]
    fn config_builder_overrides() {
        let cfg = GrpcConfig::builder()
            .connect_timeout(Duration::from_secs(5))
            .use_tls(false)
            .max_decoding_message_size(1024)
            .build();

        assert_eq!(cfg.connect_timeout, Duration::from_secs(5));
        assert!(!cfg.use_tls);
        assert_eq!(cfg.max_decoding_message_size, 1024);
        // Unchanged defaults.
        assert_eq!(cfg.request_timeout, Duration::from_secs(30));
    }

    // -- Operator validation ------------------------------------------------

    #[test]
    fn rejects_empty_operators() {
        let err = GrpcTransport::new(&[], GrpcConfig::default()).unwrap_err();
        assert!(matches!(err, GrpcError::NoOperators));
    }

    #[test]
    fn rejects_no_coordinator() {
        let ops = [make_operator("signer1", false)];
        let err = GrpcTransport::new(&ops, GrpcConfig::default()).unwrap_err();
        assert!(matches!(err, GrpcError::NoCoordinator));
    }

    #[test]
    fn rejects_multiple_coordinators() {
        let ops = [make_operator("coord1", true), make_operator("coord2", true)];
        let err = GrpcTransport::new(&ops, GrpcConfig::default()).unwrap_err();
        assert!(matches!(err, GrpcError::MultipleCoordinators(2)));
    }

    // -- Construction (needs tokio reactor for connect_lazy) ----------------

    #[tokio::test]
    async fn valid_construction() {
        let ops = [
            make_operator("signer1", false),
            make_operator("coordinator", true),
            make_operator("signer2", false),
        ];

        let t = GrpcTransport::new(&ops, GrpcConfig::default()).expect("valid config");

        assert_eq!(t.coordinator_id(), "coordinator");
        assert_eq!(t.operator_ids(), vec!["signer1", "coordinator", "signer2"]);
    }

    #[tokio::test]
    async fn channel_lookup() {
        let ops = [
            make_operator("coordinator", true),
            make_operator("signer1", false),
        ];
        let t = GrpcTransport::new(&ops, GrpcConfig::default()).unwrap();

        assert!(t.channel("coordinator").is_some());
        assert!(t.channel("signer1").is_some());
        assert!(t.channel("nonexistent").is_none());
    }

    // -- Error display ------------------------------------------------------

    #[test]
    fn error_display() {
        let err = GrpcError::NoOperators;
        assert_eq!(err.to_string(), "no operators configured");

        let err = GrpcError::MultipleCoordinators(3);
        assert_eq!(err.to_string(), "expected 1 coordinator, found 3");

        let err = GrpcError::UnknownOperator("foo".into());
        assert_eq!(err.to_string(), "unknown operator: foo");

        let err = GrpcError::Status {
            code: tonic::Code::Unavailable,
            message: "server down".into(),
        };
        assert!(err.to_string().contains("server down"));

        let err = GrpcError::SigningFailed("HSM timeout".into());
        assert_eq!(err.to_string(), "signing failed: HSM timeout");

        let err = GrpcError::InvalidToken;
        assert_eq!(err.to_string(), "invalid session token");
    }
}
