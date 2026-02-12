//! Wallet server with automatic claims, chaos sending, and an LMDB-backed
//! hash-chained balance ledger.
//!
//! # What this does
//!
//! 1. Boots with a fresh BIP39 mnemonic
//! 2. Creates a token and mints 21 000 000 units to self
//! 3. Starts an auto-claim event loop (incoming sats)
//! 4. Starts a "chaos" loop that sends random sats (1-10) and random token
//!    amounts to randomly generated Spark addresses
//! 5. Every state transition (claim, transfer, token op) is recorded in a
//!    hash-chained ledger backed by LMDB (heed)
//! 6. After 5 minutes, dumps the ledger to JSON, verifies the hash chain,
//!    and exits
//!
//! ```bash
//! RUST_LOG=info cargo run --release -p wallet-server
//! ```

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bip39::Mnemonic;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use config::NetworkConfig;
use sdk::ledger::{BalanceState, Ledger, LedgerEvent};
use sdk::token::InMemoryTokenStore;
use sdk::tree::InMemoryTreeStore;
use sdk::wallet_store::{InMemoryWalletStore, WalletEntry, WalletStore};
use sdk::{Sdk, SdkConfig};
use sdk_core::{Network, encode_spark_address};
use signer::{SparkWalletSigner, WalletSigner};

const NETWORK: NetworkConfig = NetworkConfig::DEV_REGTEST;
const ACCOUNT: u32 = 0;
const RUN_DURATION: Duration = Duration::from_secs(5 * 60);
const CHAOS_INTERVAL: Duration = Duration::from_millis(2000);

type WalletSdk =
    Sdk<InMemoryWalletStore, InMemoryTreeStore, InMemoryTokenStore, graphql::GraphqlSspClient>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("wallet-server starting (5-minute run with ledger)");

    // -----------------------------------------------------------------------
    // Wallet setup (fresh mnemonic every boot)
    // -----------------------------------------------------------------------

    let mnemonic = fresh_mnemonic();
    let seed = mnemonic.to_seed("");
    let signer = SparkWalletSigner::from_seed(&seed, bitcoin::Network::Regtest, ACCOUNT)
        .expect("signer from seed");
    let pubkey = signer.identity_public_key_compressed();
    let spark_address = encode_spark_address(Network::Regtest, &pubkey);

    tracing::info!(%spark_address, "wallet ready");
    tracing::info!(pubkey = hex_encode(&pubkey), "identity public key");
    tracing::info!(%mnemonic, "mnemonic (fresh, not persisted)");

    // -----------------------------------------------------------------------
    // Ledger setup
    // -----------------------------------------------------------------------

    let ledger_dir = PathBuf::from("./data/ledger");
    let ledger = Ledger::open(&ledger_dir).expect("open ledger");
    ledger.init_pubkey(&pubkey).expect("init pubkey in ledger");
    tracing::info!(path = %ledger_dir.display(), "ledger opened");

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
        Ok(sync) => {
            tracing::info!(
                leaves = sync.leaf_count,
                balance_sats = sync.balance_sats,
                "wallet synced"
            );
            let balance = sync.balance_sats;
            let leaves = sync.leaf_count;
            let _ = ledger.append(
                &pubkey,
                LedgerEvent::SyncCompleted {
                    balance_sats: balance,
                    leaf_count: leaves,
                },
                |s| BalanceState {
                    btc_balance_sats: balance,
                    ..s.clone()
                },
            );
        }
        Err(e) => tracing::warn!(?e, "initial sync failed (continuing with zero balance)"),
    }

    // -----------------------------------------------------------------------
    // Create token + mint 21M to self
    // -----------------------------------------------------------------------

    let token_id = match create_and_mint_token(&sdk, &pubkey, &signer, &ledger).await {
        Ok(id) => {
            tracing::info!(token_id = %hex_encode(&id), "token created and minted");
            Some(id)
        }
        Err(e) => {
            tracing::warn!(%e, "token create/mint failed (continuing without tokens)");
            None
        }
    };

    // -----------------------------------------------------------------------
    // Background auto-claim event loop
    // -----------------------------------------------------------------------

    let claim_sdk = sdk.clone();
    let claim_cancel = cancel.clone();
    let claim_ledger = Arc::clone(&ledger);
    let claim_pubkey = pubkey;
    tokio::spawn(async move {
        tracing::info!("starting background auto-claim event loop");

        loop {
            if claim_cancel.is_cancelled() {
                break;
            }

            match claim_sdk
                .subscribe_and_handle_events(&claim_pubkey, &signer)
                .await
            {
                Ok(n) => {
                    tracing::info!(events = n, "event stream ended normally");
                    // Record any balance change from claims.
                    record_post_claim_balance(&claim_sdk, &claim_pubkey, &signer, &claim_ledger)
                        .await;
                }
                Err(sdk::SdkError::Cancelled) => {
                    tracing::info!("event loop cancelled");
                    break;
                }
                Err(e) => {
                    tracing::warn!(?e, "event stream error, reconnecting in 5s");
                }
            }

            tokio::select! {
                _ = claim_cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }

        tracing::info!("auto-claim event loop exited");
    });

    // -----------------------------------------------------------------------
    // Chaos sending loop
    // -----------------------------------------------------------------------

    let chaos_sdk = sdk.clone();
    let chaos_cancel = cancel.clone();
    let chaos_ledger = Arc::clone(&ledger);
    let chaos_token_id = token_id;
    // Clone signer material for the chaos task.
    let chaos_signer = SparkWalletSigner::from_seed(&seed, bitcoin::Network::Regtest, ACCOUNT)
        .expect("chaos signer");
    tokio::spawn(async move {
        tracing::info!("starting chaos sending loop");

        // Give the wallet some time to receive initial funds.
        tokio::time::sleep(Duration::from_secs(10)).await;

        let mut rng_state: u64 = 0xdeadbeef;

        loop {
            if chaos_cancel.is_cancelled() {
                break;
            }

            // Simple xorshift for deterministic-ish randomness.
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;

            // Generate a random receiver (fake Spark pubkey).
            let receiver_pubkey = random_pubkey(rng_state);

            // Random BTC amount: 1-10 sats.
            let sats = (rng_state % 10) + 1;

            // Try sending BTC.
            send_btc_with_ledger(
                &chaos_sdk,
                &pubkey,
                &receiver_pubkey,
                sats,
                &chaos_signer,
                &chaos_ledger,
            )
            .await;

            // Try sending tokens (if we have a token ID).
            if let Some(ref tid) = chaos_token_id {
                let token_amount = ((rng_state >> 8) % 1000) + 1;
                send_token_with_ledger(
                    &chaos_sdk,
                    &pubkey,
                    &receiver_pubkey,
                    tid,
                    token_amount as u128,
                    &chaos_signer,
                    &chaos_ledger,
                )
                .await;
            }

            tokio::select! {
                _ = chaos_cancel.cancelled() => break,
                _ = tokio::time::sleep(CHAOS_INTERVAL) => {}
            }
        }

        tracing::info!("chaos sending loop exited");
    });

    // -----------------------------------------------------------------------
    // Run for 5 minutes, then dump and exit
    // -----------------------------------------------------------------------

    let deadline = Instant::now() + RUN_DURATION;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received ctrl-c, shutting down early");
        }
        _ = tokio::time::sleep_until(tokio::time::Instant::now() + RUN_DURATION) => {
            tracing::info!("5-minute run complete");
        }
        _ = cancel.cancelled() => {}
    }

    cancel.cancel();
    sdk.shutdown().await;

    // -----------------------------------------------------------------------
    // Dump ledger
    // -----------------------------------------------------------------------

    tracing::info!("dumping ledger...");

    let dump_path = PathBuf::from("./data/ledger_dump.json");
    match ledger.dump_to_file(&pubkey, &dump_path) {
        Ok(count) => tracing::info!(entries = count, path = %dump_path.display(), "ledger dumped"),
        Err(e) => tracing::error!(%e, "failed to dump ledger"),
    }

    match ledger.verify_chain(&pubkey) {
        Ok(count) => tracing::info!(entries = count, "hash chain verified"),
        Err(e) => tracing::error!(%e, "hash chain verification FAILED"),
    }

    let elapsed =
        Instant::now().duration_since(deadline.checked_sub(RUN_DURATION).unwrap_or(deadline));
    tracing::info!(?elapsed, "wallet-server stopped");
}

// ---------------------------------------------------------------------------
// Token create + mint
// ---------------------------------------------------------------------------

async fn create_and_mint_token(
    sdk: &WalletSdk,
    pubkey: &[u8; 33],
    signer: &SparkWalletSigner,
    ledger: &Ledger,
) -> Result<[u8; 32], String> {
    use sdk::operations::token::ops::CreateTokenParams;

    tracing::info!("creating token...");
    let create_result = sdk
        .create_token(
            pubkey,
            &CreateTokenParams {
                name: "TestCoin",
                ticker: "TST",
                decimals: 0,
                max_supply: 21_000_000,
                is_freezable: false,
            },
            signer,
        )
        .await
        .map_err(|e| format!("create_token: {e}"))?;

    let raw_id = &create_result.token_identifier;
    let mut token_id = [0u8; 32];
    if raw_id.len() == 32 {
        token_id.copy_from_slice(raw_id);
    } else {
        return Err(format!(
            "unexpected token_identifier length: {}",
            raw_id.len()
        ));
    }

    let token_id_hex = hex_encode(&token_id);

    let _ = ledger.append(
        pubkey,
        LedgerEvent::TokenCreated {
            operation_id: 0,
            token_id: token_id_hex.clone(),
        },
        |s| s.clone(),
    );

    tracing::info!(%token_id_hex, "minting 21M tokens to self...");
    sdk.mint_token(pubkey, &token_id, &[(*pubkey, 21_000_000)], signer)
        .await
        .map_err(|e| format!("mint_token: {e}"))?;

    let _ = ledger.append(
        pubkey,
        LedgerEvent::TokenMinted {
            operation_id: 0,
            token_id: token_id_hex.clone(),
            amount: 21_000_000,
        },
        |s| {
            let mut new = s.clone();
            new.token_balances.insert(token_id_hex.clone(), 21_000_000);
            new
        },
    );

    Ok(token_id)
}

// ---------------------------------------------------------------------------
// Chaos send helpers
// ---------------------------------------------------------------------------

async fn send_btc_with_ledger(
    sdk: &WalletSdk,
    sender: &[u8; 33],
    receiver: &[u8; 33],
    sats: u64,
    signer: &SparkWalletSigner,
    ledger: &Ledger,
) {
    // Record transfer start.
    let op_id = rand_op_id();
    let _ = ledger.append(
        sender,
        LedgerEvent::TransferStarted {
            operation_id: op_id,
            amount_sats: sats,
        },
        |s| {
            let mut new = s.clone();
            new.btc_reserved_sats += sats;
            new
        },
    );

    match sdk.send_transfer(sender, receiver, sats, signer).await {
        Ok(_) => {
            tracing::info!(sats, op_id, "btc transfer succeeded");
            let _ = ledger.append(
                sender,
                LedgerEvent::TransferCompleted {
                    operation_id: op_id,
                    sent_sats: sats,
                    change_sats: 0,
                },
                |s| {
                    let mut new = s.clone();
                    new.btc_balance_sats = new.btc_balance_sats.saturating_sub(sats);
                    new.btc_reserved_sats = new.btc_reserved_sats.saturating_sub(sats);
                    new
                },
            );
        }
        Err(e) => {
            tracing::warn!(sats, op_id, %e, "btc transfer failed");
            let _ = ledger.append(
                sender,
                LedgerEvent::TransferFailed {
                    operation_id: op_id,
                    reason: e.to_string(),
                },
                |s| {
                    let mut new = s.clone();
                    new.btc_reserved_sats = new.btc_reserved_sats.saturating_sub(sats);
                    new
                },
            );
        }
    }
}

async fn send_token_with_ledger(
    sdk: &WalletSdk,
    sender: &[u8; 33],
    receiver: &[u8; 33],
    token_id: &[u8; 32],
    amount: u128,
    signer: &SparkWalletSigner,
    ledger: &Ledger,
) {
    let token_id_hex = hex_encode(token_id);
    let op_id = rand_op_id();

    let _ = ledger.append(
        sender,
        LedgerEvent::TokenSendStarted {
            operation_id: op_id,
            token_id: token_id_hex.clone(),
            amount,
        },
        |s| {
            let mut new = s.clone();
            *new.token_in_transit
                .entry(token_id_hex.clone())
                .or_insert(0) += amount;
            new
        },
    );

    match sdk
        .send_token(sender, receiver, token_id, amount, signer)
        .await
    {
        Ok(_) => {
            tracing::info!(amount, op_id, "token transfer succeeded");
            let _ = ledger.append(
                sender,
                LedgerEvent::TokenSendCompleted {
                    operation_id: op_id,
                    token_id: token_id_hex.clone(),
                    sent_amount: amount,
                },
                |s| {
                    let mut new = s.clone();
                    let bal = new.token_balances.entry(token_id_hex.clone()).or_insert(0);
                    *bal = bal.saturating_sub(amount);
                    let transit = new
                        .token_in_transit
                        .entry(token_id_hex.clone())
                        .or_insert(0);
                    *transit = transit.saturating_sub(amount);
                    new
                },
            );
        }
        Err(e) => {
            tracing::warn!(amount, op_id, %e, "token transfer failed");
            let _ = ledger.append(
                sender,
                LedgerEvent::TokenSendFailed {
                    operation_id: op_id,
                    token_id: token_id_hex.clone(),
                    reason: e.to_string(),
                },
                |s| {
                    let mut new = s.clone();
                    let transit = new
                        .token_in_transit
                        .entry(token_id_hex.clone())
                        .or_insert(0);
                    *transit = transit.saturating_sub(amount);
                    new
                },
            );
        }
    }
}

/// After auto-claim events, sync and record the new balance.
async fn record_post_claim_balance(
    sdk: &WalletSdk,
    pubkey: &[u8; 33],
    signer: &SparkWalletSigner,
    ledger: &Ledger,
) {
    match sdk.sync_wallet(pubkey, signer).await {
        Ok(sync) => {
            let op_id = rand_op_id();
            let _ = ledger.append(
                pubkey,
                LedgerEvent::ClaimCompleted {
                    operation_id: op_id,
                    claimed_sats: sync.balance_sats,
                    leaves_claimed: sync.leaf_count,
                },
                |s| {
                    let mut new = s.clone();
                    new.btc_balance_sats = sync.balance_sats;
                    new.btc_in_transit_sats = 0;
                    new
                },
            );
        }
        Err(e) => {
            tracing::warn!(?e, "post-claim sync failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fresh_mnemonic() -> Mnemonic {
    let mut entropy = [0u8; 16];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut entropy);
    Mnemonic::from_entropy(&entropy).expect("valid entropy")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn random_pubkey(seed: u64) -> [u8; 33] {
    // Simple deterministic byte generation (not cryptographic -- just for
    // generating diverse receiver addresses in the chaos loop).
    let mut pk = [0u8; 33];
    pk[0] = 0x02; // compressed pubkey prefix
    let mut s = seed;
    for chunk in pk[1..].chunks_mut(8) {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let bytes = s.to_le_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&bytes[..len]);
    }
    pk
}

fn rand_op_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
