//! Spark SDK: wallet operations, transfers, tokens, and Lightning.
//!
//! The SDK orchestrates Spark protocol operations by combining:
//! - **Transport** (`GrpcTransport`) for operator communication
//! - **Signing** (`WalletSigner`) for cryptographic operations
//! - **Tree store** (`TreeStore`) for BTC leaf state
//! - **Token store** (`TokenStore`) for token output state
//! - **Wallet store** (`WalletStore`) for wallet key resolution
//!
//! # Architecture
//!
//! Two parallel state subsystems:
//! - **BTC Leaf Tree**: Bitcoin UTXOs controlled by threshold FROST keys
//!   shared with operators. Operations require FROST signing.
//! - **Token Outputs**: Token ledger entries signed by the owner's ECDSA
//!   identity key. Operations are single-RPC calls.
//!
//! # Usage
//!
//! ```no_run
//! use sdk::{Sdk, SdkConfig};
//! use sdk::wallet_store::InMemoryWalletStore;
//! use sdk::tree::InMemoryTreeStore;
//! use sdk::token::InMemoryTokenStore;
//! use config::NetworkConfig;
//! use sdk_core::Network;
//! use tokio_util::sync::CancellationToken;
//!
//! # async fn example() -> Result<(), sdk::SdkError> {
//! let config = SdkConfig {
//!     network: NetworkConfig::for_network(Network::Mainnet),
//!     retry_policy: sdk::tracking::RetryPolicy::default(),
//! };
//! let cancel = CancellationToken::new();
//!
//! let sdk = Sdk::new(
//!     config,
//!     InMemoryWalletStore::new(),
//!     InMemoryTreeStore::new(),
//!     InMemoryTokenStore::new(),
//!     sdk::ssp::NoSspClient,
//!     cancel.clone(),
//! )?;
//!
//! // SDK is Clone -- share across tasks.
//! let sdk2 = sdk.clone();
//!
//! // Graceful shutdown.
//! cancel.cancel();
//! sdk.shutdown().await;
//! # Ok(())
//! # }
//! ```

pub mod bitcoin_tx;
pub mod error;
pub mod frost_bridge;
pub mod hooks;
#[cfg(feature = "ledger")]
pub mod ledger;
pub mod network;
pub mod operations;
pub mod ssp;
pub mod token;
pub mod tree;
pub(crate) mod utils;
pub mod wallet_store;

pub use error::SdkError;
pub use operations::tracking;

use std::sync::Arc;

use config::NetworkConfig;
use tokio_util::sync::CancellationToken;
use transport::grpc::{AuthenticatedTransport, GrpcConfig, GrpcTransport, OperatorConfig};

use crate::hooks::{Hook, HookPoint, Hooks};
use crate::operations::tracking::{
    NoopOperationStore, OperationStore, OperationTracker, RetryPolicy,
};
use crate::ssp::SspClient;
use crate::token::TokenStore;
use crate::tree::{GreedySelector, LeafSelector, TreeStore};
use crate::wallet_store::WalletStore;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// SDK configuration.
#[derive(Debug, Clone)]
pub struct SdkConfig {
    /// Network-specific operator and SSP configuration.
    pub network: NetworkConfig,
    /// Retry policy for transient errors. Defaults to 3 attempts with
    /// exponential backoff (500ms initial, 2x multiplier, 10s cap).
    pub retry_policy: RetryPolicy,
}

// ---------------------------------------------------------------------------
// Sdk
// ---------------------------------------------------------------------------

/// Shared state across all SDK operations.
pub(crate) struct SdkInner<W, T, K, S> {
    pub config: SdkConfig,
    pub transport: GrpcTransport,
    pub hooks: Hooks,
    pub leaf_selector: std::sync::RwLock<Arc<dyn LeafSelector>>,
    pub operation_store: std::sync::RwLock<Arc<dyn OperationStore>>,
    pub wallet_store: W,
    pub tree_store: T,
    pub token_store: K,
    pub ssp: S,
    pub cancel: CancellationToken,
}

/// The Spark SDK entry point.
///
/// `Clone`-able (wraps an `Arc<SdkInner>`). All stores are trait-based
/// with in-memory defaults.
///
/// # Type Parameters
///
/// - `W`: Wallet key storage (resolves public key -> wallet entry)
/// - `T`: BTC leaf storage (insert, reserve, finalize leaves)
/// - `K`: Token output storage (acquire, release, track balances)
/// - `S`: SSP client for leaf swaps (use [`ssp::NoSspClient`] if unused)
pub struct Sdk<W, T, K, S = crate::ssp::NoSspClient> {
    pub(crate) inner: Arc<SdkInner<W, T, K, S>>,
}

// Manual Clone: we don't require W, T, K, S to be Clone.
impl<W, T, K, S> Clone for Sdk<W, T, K, S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<W, T, K, S> std::fmt::Debug for Sdk<W, T, K, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sdk")
            .field("transport", &self.inner.transport)
            .finish()
    }
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: TokenStore,
    S: SspClient,
{
    /// Creates a new SDK instance.
    ///
    /// Initializes lazy gRPC connections to all operators from the network
    /// config. No network I/O happens during construction.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::TransportFailed`] if operator config is invalid.
    pub fn new(
        config: SdkConfig,
        wallet_store: W,
        tree_store: T,
        token_store: K,
        ssp: S,
        cancel: CancellationToken,
    ) -> Result<Self, SdkError> {
        let operators: Vec<OperatorConfig> = config
            .network
            .operators()
            .iter()
            .enumerate()
            .map(|(i, op)| OperatorConfig {
                id: op.id.to_owned(),
                address: op.address.to_owned(),
                identity_public_key: op.identity_public_key.to_owned(),
                is_coordinator: i == config.network.coordinator().index as usize,
            })
            .collect();

        let transport = GrpcTransport::new(&operators, GrpcConfig::default())
            .map_err(|_| SdkError::TransportFailed)?;

        Ok(Self {
            inner: Arc::new(SdkInner {
                config,
                transport,
                hooks: Hooks::new(),
                leaf_selector: std::sync::RwLock::new(Arc::new(GreedySelector)),
                operation_store: std::sync::RwLock::new(Arc::new(NoopOperationStore)),
                wallet_store,
                tree_store,
                token_store,
                ssp,
                cancel,
            }),
        })
    }

    /// Returns a reference to the network configuration.
    pub fn config(&self) -> &SdkConfig {
        &self.inner.config
    }

    /// Returns a reference to the gRPC transport.
    pub fn transport(&self) -> &GrpcTransport {
        &self.inner.transport
    }

    /// Returns a reference to the cancellation token.
    pub fn cancel(&self) -> &CancellationToken {
        &self.inner.cancel
    }

    /// Graceful shutdown: signals cancellation and waits for in-flight
    /// operations to drain.
    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        // Allow a brief period for operations checking the token to exit.
        tokio::task::yield_now().await;
    }

    /// Checks whether the SDK has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancel.is_cancelled()
    }

    /// Returns [`SdkError::Cancelled`] if the cancellation token has fired.
    pub(crate) fn check_cancelled(&self) -> Result<(), SdkError> {
        if self.inner.cancel.is_cancelled() {
            Err(SdkError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Authenticates with the coordinator and returns an [`AuthenticatedTransport`].
    ///
    /// This is the standard way for SDK operations to get an auth-injected
    /// transport handle. The session token is cached after the first call.
    pub(crate) async fn authenticate(
        &self,
        signer: &impl signer::Signer,
    ) -> Result<AuthenticatedTransport<'_>, SdkError> {
        let coordinator_id = self.inner.transport.coordinator_id().to_owned();
        let token = self
            .inner
            .transport
            .session_token(&coordinator_id, signer)
            .await
            .map_err(|_| SdkError::AuthFailed)?;
        self.inner
            .transport
            .authenticated(&token)
            .map_err(|_| SdkError::AuthFailed)
    }

    // -----------------------------------------------------------------------
    // Operation tracking
    // -----------------------------------------------------------------------

    /// Replace the operation store at runtime.
    ///
    /// Use [`tracking::InMemoryOperationStore`] for observability, or
    /// implement [`OperationStore`] for persistent crash recovery.
    pub fn set_operation_store(&self, store: Arc<dyn OperationStore>) {
        *self.inner.operation_store.write().unwrap() = store;
    }

    /// Get the current operation store (cheap `Arc` clone).
    pub fn operation_store(&self) -> Arc<dyn OperationStore> {
        self.inner.operation_store.read().unwrap().clone()
    }

    /// Start tracking a new operation.
    pub(crate) fn tracker(&self, kind: tracking::OperationKind) -> OperationTracker {
        OperationTracker::start(self.operation_store(), kind)
    }

    /// The configured retry policy.
    pub(crate) fn retry_policy(&self) -> &RetryPolicy {
        &self.inner.config.retry_policy
    }

    /// Query a tracked operation by ID.
    ///
    /// Returns `None` if the operation was not found (e.g. using
    /// [`tracking::NoopOperationStore`]).
    pub fn query_operation(&self, id: tracking::OperationId) -> Option<tracking::Operation> {
        self.operation_store().get(id)
    }

    /// List all in-progress operations.
    pub fn active_operations(&self) -> Vec<tracking::Operation> {
        self.operation_store().list_active()
    }

    /// Resume a previously failed or partially-completed claim.
    ///
    /// This is a convenience method: it simply re-invokes `claim_transfer`
    /// which is already idempotent (the coordinator tracks which transfers
    /// are pending vs. already claimed). Transfers that were claimed on
    /// the prior attempt won't be re-claimed.
    ///
    /// For swap resume, the coordinator's transfer state determines what
    /// happens -- if the outbound was already sent, re-claiming the
    /// inbound is safe.
    pub async fn resume_claim(
        &self,
        receiver_pubkey: &crate::wallet_store::IdentityPubKey,
        signer: &impl signer::WalletSigner,
    ) -> Result<crate::operations::btc::claim::ClaimTransferResult, tracking::OperationError> {
        self.claim_transfer(receiver_pubkey, signer).await
    }

    // -----------------------------------------------------------------------
    // Hook management
    // -----------------------------------------------------------------------

    /// Register a named hook at the given operation point.
    ///
    /// If a hook with the same `name` already exists at that point, it is
    /// replaced in-place (preserving execution order). Otherwise the hook
    /// is appended to the end of the chain.
    ///
    /// Hooks can be added and removed at any time without recompilation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use sdk::hooks::{Hook, HookPoint};
    ///
    /// sdk.add_hook(HookPoint::PreClaim, "sparkscan", Hook::PreClaim(Arc::new(validator)));
    /// ```
    pub async fn add_hook(&self, point: HookPoint, name: &'static str, hook: Hook) {
        match (point, hook) {
            (HookPoint::PreClaim, Hook::PreClaim(h)) => {
                self.inner.hooks.add_pre_claim(name, h).await;
            }
        }
    }

    /// Remove a named hook from the given operation point.
    ///
    /// Returns `true` if a hook with that name was found and removed.
    pub async fn remove_hook(&self, point: HookPoint, name: &'static str) -> bool {
        match point {
            HookPoint::PreClaim => self.inner.hooks.remove_pre_claim(name).await,
        }
    }

    // -----------------------------------------------------------------------
    // Leaf selection
    // -----------------------------------------------------------------------

    /// Replace the leaf selection strategy at runtime.
    ///
    /// The new strategy takes effect for all subsequent operations.
    /// In-flight operations that already cloned the previous strategy
    /// will complete with the old one.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use sdk::tree::GreedySelector;
    ///
    /// sdk.set_leaf_selector(Arc::new(GreedySelector));
    /// ```
    pub fn set_leaf_selector(&self, selector: Arc<dyn LeafSelector>) {
        *self.inner.leaf_selector.write().unwrap() = selector;
    }

    /// Get the current leaf selector (cheap `Arc` clone).
    ///
    /// The read lock is held only long enough to clone the `Arc`.
    /// Operations call `.select()` on the returned handle outside
    /// the lock.
    pub(crate) fn leaf_selector(&self) -> Arc<dyn LeafSelector> {
        self.inner.leaf_selector.read().unwrap().clone()
    }
}
