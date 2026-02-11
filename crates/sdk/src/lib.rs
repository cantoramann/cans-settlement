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
//! };
//! let cancel = CancellationToken::new();
//!
//! let sdk = Sdk::new(
//!     config,
//!     InMemoryWalletStore::new(),
//!     InMemoryTreeStore::new(),
//!     InMemoryTokenStore::new(),
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
pub mod network;
pub mod operations;
pub mod token;
pub mod tree;
pub mod wallet_store;

pub use error::SdkError;

use std::sync::Arc;

use config::NetworkConfig;
use tokio_util::sync::CancellationToken;
use transport::grpc::{AuthenticatedTransport, GrpcConfig, GrpcTransport, OperatorConfig};

use crate::token::TokenStore;
use crate::tree::TreeStore;
use crate::wallet_store::WalletStore;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// SDK configuration.
#[derive(Debug, Clone, Copy)]
pub struct SdkConfig {
    /// Network-specific operator and SSP configuration.
    pub network: NetworkConfig,
}

// ---------------------------------------------------------------------------
// Sdk
// ---------------------------------------------------------------------------

/// Shared state across all SDK operations.
pub(crate) struct SdkInner<W, T, K> {
    pub config: SdkConfig,
    pub transport: GrpcTransport,
    pub wallet_store: W,
    pub tree_store: T,
    pub token_store: K,
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
pub struct Sdk<W, T, K> {
    pub(crate) inner: Arc<SdkInner<W, T, K>>,
}

// Manual Clone: we don't require W, T, K to be Clone.
impl<W, T, K> Clone for Sdk<W, T, K> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<W, T, K> std::fmt::Debug for Sdk<W, T, K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sdk")
            .field("transport", &self.inner.transport)
            .finish()
    }
}

impl<W, T, K> Sdk<W, T, K>
where
    W: WalletStore,
    T: TreeStore,
    K: TokenStore,
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
                wallet_store,
                tree_store,
                token_store,
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
}
