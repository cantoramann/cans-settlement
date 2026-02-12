//! Wallet server with automatic background transfer claims.
//!
//! Initializes the Spark SDK, logs the wallet's Spark address and identity
//! public key, then subscribes to the coordinator event stream. Incoming
//! transfers are auto-claimed in the background.
//!
//! # Configuration
//!
//! Set `WALLET_MNEMONIC` to use a specific BIP39 mnemonic. If unset, a
//! fresh 12-word mnemonic is generated on each run.
//!
//! ```bash
//! export WALLET_MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
//! RUST_LOG=info cargo run --release -p wallet-server
//! ```

use std::time::Duration;

use bip39::Mnemonic;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use config::NetworkConfig;
use sdk::token::InMemoryTokenStore;
use sdk::tree::InMemoryTreeStore;
use sdk::wallet_store::{InMemoryWalletStore, WalletEntry, WalletStore};
use sdk::{Sdk, SdkConfig};
use sdk_core::{Network, encode_spark_address};
use signer::{SparkWalletSigner, WalletSigner};

const NETWORK: NetworkConfig = NetworkConfig::DEV_REGTEST;
const ACCOUNT: u32 = 0;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("wallet-server starting");

    // -----------------------------------------------------------------------
    // Wallet setup
    // -----------------------------------------------------------------------

    let mnemonic = resolve_mnemonic("WALLET_MNEMONIC");
    let seed = mnemonic.to_seed("");
    let signer = SparkWalletSigner::from_seed(&seed, bitcoin::Network::Regtest, ACCOUNT)
        .expect("signer from seed");
    let pubkey = signer.identity_public_key_compressed();
    let spark_address = encode_spark_address(Network::Regtest, &pubkey);

    tracing::info!(%spark_address, "wallet ready");
    tracing::info!(pubkey = hex_encode(&pubkey), "identity public key");
    tracing::info!(%mnemonic, "mnemonic (keep this to restore the wallet)");

    // -----------------------------------------------------------------------
    // SDK init
    // -----------------------------------------------------------------------

    let wallet_store = InMemoryWalletStore::new();
    wallet_store
        .insert(
            pubkey,
            WalletEntry {
                seed: seed.to_vec(),
                account: ACCOUNT,
            },
        )
        .expect("insert wallet");

    let ssp_client =
        graphql::GraphqlSspClient::from_config(&NETWORK.ssp).expect("valid SSP config");

    let cancel = CancellationToken::new();

    let sdk = Sdk::new(
        SdkConfig {
            network: NETWORK,
            retry_policy: sdk::tracking::RetryPolicy::default(),
        },
        wallet_store,
        InMemoryTreeStore::new(),
        InMemoryTokenStore::new(),
        ssp_client,
        cancel.clone(),
    )
    .expect("SDK init");

    tracing::info!("SDK initialized");

    // -----------------------------------------------------------------------
    // Initial sync
    // -----------------------------------------------------------------------

    tracing::info!("syncing wallet...");
    match sdk.sync_wallet(&pubkey, &signer).await {
        Ok(sync) => tracing::info!(
            leaves = sync.leaf_count,
            balance_sats = sync.balance_sats,
            "wallet synced"
        ),
        Err(e) => tracing::warn!(?e, "initial sync failed (continuing)"),
    }

    // -----------------------------------------------------------------------
    // Background auto-claim event loop
    // -----------------------------------------------------------------------

    let event_sdk = sdk.clone();
    let event_cancel = cancel.clone();
    tokio::spawn(async move {
        tracing::info!("starting background auto-claim event loop");

        loop {
            if event_cancel.is_cancelled() {
                break;
            }

            match event_sdk
                .subscribe_and_handle_events(&pubkey, &signer)
                .await
            {
                Ok(n) => {
                    tracing::info!(events = n, "event stream ended normally");
                }
                Err(sdk::SdkError::Cancelled) => {
                    tracing::info!("event loop cancelled");
                    break;
                }
                Err(e) => {
                    tracing::warn!(?e, "event stream error, reconnecting in 5s");
                }
            }

            // Backoff before reconnecting.
            tokio::select! {
                _ = event_cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }

        tracing::info!("auto-claim event loop exited");
    });

    // -----------------------------------------------------------------------
    // Wait for shutdown
    // -----------------------------------------------------------------------

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
            cancel.cancel();
        }
        _ = cancel.cancelled() => {}
    }

    sdk.shutdown().await;
    tracing::info!("wallet-server stopped");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a BIP39 mnemonic from an env var, or generate a fresh one.
fn resolve_mnemonic(env_key: &str) -> Mnemonic {
    if let Ok(phrase) = std::env::var(env_key) {
        phrase
            .parse::<Mnemonic>()
            .unwrap_or_else(|e| panic!("{env_key} is not a valid BIP39 mnemonic: {e}"))
    } else {
        let mut entropy = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut entropy);
        Mnemonic::from_entropy(&entropy).expect("valid entropy")
    }
}

/// Minimal hex encoding (no extra deps).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}
