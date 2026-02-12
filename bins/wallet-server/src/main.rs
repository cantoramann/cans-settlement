//! Minimal wallet server that initializes the Spark SDK.
//!
//! This binary exists to measure the stripped release binary size
//! when linking the full SDK dependency tree.

use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use config::NetworkConfig;
use sdk::token::InMemoryTokenStore;
use sdk::tree::InMemoryTreeStore;
use sdk::wallet_store::{InMemoryWalletStore, WalletEntry, WalletStore};
use sdk::{Sdk, SdkConfig};
use signer::{SparkWalletSigner, WalletSigner};

const NETWORK: NetworkConfig = NetworkConfig::DEV_REGTEST;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("wallet-server starting");

    // Derive a throwaway identity key from a fixed seed (demo only).
    let seed = [0xABu8; 64];
    let signer = SparkWalletSigner::from_seed(&seed, bitcoin::Network::Regtest, 0)
        .expect("signer from seed");
    let pubkey = signer.identity_public_key_compressed();

    // Set up in-memory stores.
    let wallet_store = InMemoryWalletStore::new();
    wallet_store
        .insert(
            pubkey,
            WalletEntry {
                seed: seed.to_vec(),
                account: 0,
            },
        )
        .expect("insert wallet");

    let ssp_client =
        graphql::GraphqlSspClient::from_config(&NETWORK.ssp).expect("valid SSP config");

    let cancel = CancellationToken::new();

    let _sdk = Sdk::new(
        SdkConfig { network: NETWORK },
        wallet_store,
        InMemoryTreeStore::new(),
        InMemoryTokenStore::new(),
        ssp_client,
        cancel.clone(),
    )
    .expect("SDK init");

    tracing::info!("SDK initialized, identity = {:?}", pubkey);

    // Wait for shutdown signal.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down");
            cancel.cancel();
        }
        _ = cancel.cancelled() => {}
    }
}
