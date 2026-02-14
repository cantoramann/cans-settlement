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

mod ledger_store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

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

use ledger_store::HeedLedgerStore;

const NETWORK: NetworkConfig = NetworkConfig::DEV_REGTEST;
const ACCOUNT: u32 = 0;
const RUN_DURATION: Duration = Duration::from_secs(5 * 60);
/// Number of concurrent chaos workers firing transfers in parallel.
const CHAOS_WORKERS: usize = 4;
/// Delay between iterations *per worker* (staggered start ensures overlap).
const CHAOS_INTERVAL: Duration = Duration::from_millis(500);

/// Data directory relative to the wallet-server crate root.
const DATA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/data");

type WalletSdk =
    Sdk<InMemoryWalletStore, InMemoryTreeStore, InMemoryTokenStore, graphql::GraphqlSspClient>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
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

    let ledger_dir = PathBuf::from(DATA_DIR).join("ledger");
    let store = HeedLedgerStore::open(&ledger_dir).expect("open ledger store");
    let ledger = Arc::new(Ledger::new(store));
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
    // Fund wallet via faucet
    // -----------------------------------------------------------------------

    let funding_amount = 10_000u64; // 10 000 sats to sustain the chaos loop
    tracing::info!(sats = funding_amount, "requesting funds from faucet...");

    let faucet = funding_client::FundingClient::new().await;
    match faucet
        .request_funds(vec![funding_client::FundingTask {
            amount_sats: funding_amount,
            recipient: spark_address.clone(),
        }])
        .await
    {
        Ok(results) => {
            for r in &results {
                tracing::info!(
                    recipient = %r.recipient,
                    amount_sent = r.amount_sent,
                    status = %r.status,
                    "faucet funded"
                );
            }
        }
        Err(e) => {
            tracing::error!(%e, "faucet request failed -- chaos loop will fail on btc sends");
        }
    }

    // Claim the incoming funds.  The faucet transfer may take a while to
    // propagate, so we retry with increasing backoff until we successfully
    // claim at least one leaf.
    tracing::info!("waiting for funding transfer to become claimable...");
    let claim_backoffs = [5, 5, 10, 10, 15, 15]; // seconds between attempts
    let mut claimed_any = false;
    for (attempt, &wait_secs) in claim_backoffs.iter().enumerate() {
        tokio::time::sleep(Duration::from_secs(wait_secs)).await;
        tracing::info!(attempt = attempt + 1, "claiming incoming funds...");
        match sdk.claim_transfer(&pubkey, &signer).await {
            Ok(claim) if claim.leaves_claimed > 0 => {
                tracing::info!(leaves_claimed = claim.leaves_claimed, "funds claimed");
                let _ = ledger.append(
                    &pubkey,
                    LedgerEvent::ClaimCompleted {
                        operation_id: 0,
                        claimed_sats: funding_amount,
                        leaves_claimed: claim.leaves_claimed,
                    },
                    |s| {
                        let mut new = s.clone();
                        new.btc_balance_sats += funding_amount;
                        new
                    },
                );
                claimed_any = true;
                break;
            }
            Ok(_) => {
                tracing::info!(attempt = attempt + 1, "no leaves yet, retrying...");
            }
            Err(e) => {
                tracing::warn!(attempt = attempt + 1, %e, "claim attempt failed, retrying...");
            }
        }
    }
    if !claimed_any {
        tracing::warn!("could not claim faucet funds after all attempts -- btc sends will fail");
    }

    // Read local balance (claim already inserted leaves into tree store;
    // do NOT sync_wallet here -- coordinator state may lag behind and
    // would overwrite the locally-correct leaves).
    if let Ok(bal) = sdk.query_balance(&pubkey).await {
        tracing::info!(
            btc_sats = bal.btc_available_sats,
            tokens = bal.token_balances.len(),
            "local balance after claim"
        );
        let _ = ledger.append(
            &pubkey,
            LedgerEvent::SyncCompleted {
                balance_sats: bal.btc_available_sats,
                leaf_count: 0,
            },
            |s| BalanceState {
                btc_balance_sats: bal.btc_available_sats,
                ..s.clone()
            },
        );
    }

    // -----------------------------------------------------------------------
    // Create token + mint 21M to self
    // -----------------------------------------------------------------------

    let token_id = match create_and_mint_token(&sdk, &pubkey, &signer, &ledger).await {
        Ok(id) => {
            tracing::info!(token_id = %hex_encode(&id), "token created and minted");

            // Read local balance to verify (do NOT sync_wallet -- it would
            // overwrite the token store with stale coordinator state).
            if let Ok(bal) = sdk.query_balance(&pubkey).await {
                tracing::info!(
                    btc_sats = bal.btc_available_sats,
                    token_count = bal.token_balances.len(),
                    "local balance after mint"
                );
                for (tid, amount) in &bal.token_balances {
                    tracing::info!(token_id = %hex_encode(tid), amount, "token balance");
                }
            }

            // Split the single 21M token output into a handful of outputs so
            // chaos workers have independent UTXOs to acquire.  We only do a
            // small number of splits (one per worker) because each split peels
            // off a chunk and leaves the remainder.  All peeled-off chunks stay
            // as unspent outputs on the coordinator.  A token semaphore still
            // serialises sends so we don't try to spend the same output twice.
            let target_outputs = CHAOS_WORKERS + 1; // one per worker + remainder
            tracing::info!(
                target_outputs,
                "consolidating tokens into smaller outputs..."
            );
            match consolidate_tokens(&sdk, &pubkey, &id, target_outputs, &signer).await {
                Ok(n) => tracing::info!(outputs = n, "token consolidation complete"),
                Err(e) => {
                    tracing::warn!(%e, "token consolidation failed (continuing with 1 output)")
                }
            }

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
    //
    // The event loop auto-claims incoming transfers. SSP swap inbound
    // transfers are automatically skipped at the SDK level (events.rs
    // compares sender_identity_public_key against the SSP's key), so they
    // don't race with `ssp_swap`'s own `claim_by_transfer_id`.

    let claim_sdk = sdk.clone();
    let claim_cancel = cancel.clone();
    tokio::spawn(async move {
        tracing::info!("starting background auto-claim event loop");

        loop {
            if claim_cancel.is_cancelled() {
                break;
            }

            match claim_sdk
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

            tokio::select! {
                _ = claim_cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
            }
        }

        tracing::info!("auto-claim event loop exited");
    });

    // -----------------------------------------------------------------------
    // Chaos sending workers (N concurrent)
    // -----------------------------------------------------------------------

    // Serialize BTC sends across all workers so only one SSP swap runs at a
    // time. Without this, concurrent swap attempts contend on the same leaves
    // and saturate the SSP transport, causing a thundering-herd of failures.
    let btc_semaphore = Arc::new(Semaphore::new(1));

    // Token sends are also serialized via a semaphore.  Even after
    // consolidation the number of outputs is small, and each send consumes
    // one output and produces two new ones (receiver + change).  The
    // sync_tokens call inside send_token_with_ledger refreshes the local
    // store after each send so the next iteration sees the fresh outputs.
    let token_semaphore = Arc::new(Semaphore::new(1));

    for worker_id in 0..CHAOS_WORKERS {
        let w_sdk = sdk.clone();
        let w_cancel = cancel.clone();
        let w_ledger = Arc::clone(&ledger);
        let w_token_id = token_id;
        let w_btc_sem = Arc::clone(&btc_semaphore);
        let w_tok_sem = Arc::clone(&token_semaphore);
        let w_signer = SparkWalletSigner::from_seed(&seed, bitcoin::Network::Regtest, ACCOUNT)
            .expect("chaos signer");

        tokio::spawn(async move {
            // Stagger workers so they don't all fire at the exact same instant.
            tokio::time::sleep(Duration::from_millis(worker_id as u64 * 120)).await;
            tracing::info!(worker_id, "chaos worker started");

            let mut rng_state: u64 =
                0xdeadbeef ^ (worker_id as u64).wrapping_mul(0x9e3779b97f4a7c15);

            loop {
                if w_cancel.is_cancelled() {
                    break;
                }

                // Advance RNG.
                rng_state ^= rng_state << 13;
                rng_state ^= rng_state >> 7;
                rng_state ^= rng_state << 17;

                let receiver = random_pubkey(rng_state);
                let sats = (rng_state % 10) + 1;

                // BTC send (serialized via semaphore to avoid SSP swap contention)
                // and token send (unconstrained) run concurrently.
                let btc_fut = {
                    let sem = Arc::clone(&w_btc_sem);
                    let sdk = &w_sdk;
                    let ledger = &w_ledger;
                    let signer = &w_signer;
                    async move {
                        let _permit = sem.acquire().await;
                        send_btc_with_ledger(sdk, &pubkey, &receiver, sats, signer, ledger).await;
                    }
                };

                if let Some(ref tid) = w_token_id {
                    let token_amount = ((rng_state >> 8) % 1000) + 1;
                    let tok_sem = Arc::clone(&w_tok_sem);
                    let tok_fut = {
                        let sdk = &w_sdk;
                        let ledger = &w_ledger;
                        let signer = &w_signer;
                        async move {
                            let _permit = tok_sem.acquire().await;
                            send_token_with_ledger(
                                sdk,
                                &pubkey,
                                &receiver,
                                tid,
                                token_amount as u128,
                                signer,
                                ledger,
                            )
                            .await;
                        }
                    };
                    // Both BTC and token sends gate on their respective
                    // semaphores but run concurrently with each other.
                    tokio::join!(btc_fut, tok_fut);
                } else {
                    btc_fut.await;
                }

                tokio::select! {
                    _ = w_cancel.cancelled() => break,
                    _ = tokio::time::sleep(CHAOS_INTERVAL) => {}
                }
            }

            tracing::info!(worker_id, "chaos worker exited");
        });
    }

    tracing::info!(workers = CHAOS_WORKERS, "chaos workers spawned");

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

    let dump_path = PathBuf::from(DATA_DIR).join("ledger_dump.json");
    match ledger.store().dump_to_file(&pubkey, &dump_path) {
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
    ledger: &Ledger<HeedLedgerStore>,
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

    // mint_token is a server-side op -- the local TokenStore is still empty.
    // sync_tokens queries the coordinator's token service and populates the
    // local store without touching the BTC tree store.
    tracing::info!("syncing token outputs from coordinator...");
    match sdk.sync_tokens(pubkey, signer).await {
        Ok(sync) => {
            tracing::info!(
                outputs = sync.output_count,
                types = sync.token_types,
                "token store populated"
            );
        }
        Err(e) => {
            tracing::warn!(%e, "sync_tokens failed -- token sends will fail");
        }
    }

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
// Token consolidation (split one large output into many small ones)
// ---------------------------------------------------------------------------

/// Split token outputs into `target_count` roughly-equal pieces by making
/// sequential self-transfers. Each call to `send_token(self -> self, chunk)`
/// produces two outputs: `chunk` (to self) + change (to self).  After `N-1`
/// sends the store contains `N` independent outputs.
///
/// This runs once at startup so the chaos workers can acquire outputs in
/// parallel without UTXO contention.
async fn consolidate_tokens(
    sdk: &WalletSdk,
    pubkey: &[u8; 33],
    token_id: &[u8; 32],
    target_count: usize,
    signer: &SparkWalletSigner,
) -> Result<usize, String> {
    if target_count <= 1 {
        return Ok(1);
    }

    // Query current balance.
    let balance = sdk
        .query_token_balances(pubkey)
        .await
        .map_err(|e| format!("query_token_balances: {e}"))?;

    let total = balance
        .iter()
        .find(|b| b.token_id == *token_id)
        .map(|b| b.amount)
        .unwrap_or(0);

    if total == 0 {
        return Err("no token balance to consolidate".into());
    }

    let chunk_size = total / target_count as u128;
    if chunk_size == 0 {
        return Err("total balance too small for requested output count".into());
    }

    // We need (target_count - 1) self-transfers to produce target_count
    // outputs. Each transfer peels off one `chunk_size` output; the
    // remainder stays as change.
    let splits = target_count - 1;

    for i in 0..splits {
        // Sync before each send so the store has the latest outputs
        // (previous send consumed the old output and created two new ones).
        sdk.sync_tokens(pubkey, signer)
            .await
            .map_err(|e| format!("sync_tokens[{i}]: {e}"))?;

        match sdk
            .send_token(pubkey, pubkey, token_id, chunk_size, signer)
            .await
        {
            Ok(_) => {
                tracing::debug!(split = i + 1, chunk_size, "token split ok");
            }
            Err(e) => {
                // Partial success is fine -- we just have fewer outputs.
                tracing::warn!(split = i + 1, %e, "token split failed, stopping early");
                break;
            }
        }
    }

    // Final sync to pick up all outputs.
    let sync = sdk
        .sync_tokens(pubkey, signer)
        .await
        .map_err(|e| format!("final sync_tokens: {e}"))?;

    Ok(sync.output_count)
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
    ledger: &Ledger<HeedLedgerStore>,
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
    ledger: &Ledger<HeedLedgerStore>,
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
            // Refresh the local token store so the change output from this
            // send is available for the next acquire.
            let _ = sdk.sync_tokens(sender, signer).await;
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
    // Derive a valid secp256k1 compressed public key from the seed.
    // We hash the seed to get 32 bytes suitable as a secret key scalar,
    // then compute the corresponding public key point on the curve.
    use bitcoin::hashes::{Hash, sha256};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let seed_bytes = seed.to_le_bytes();
    let hash = sha256::Hash::hash(&seed_bytes);
    // Ensure the scalar is valid (non-zero, within group order).
    // SHA-256 output is essentially always a valid secret key since
    // the group order is ~2^256 - 4.3e38, so collision is negligible.
    let sk = SecretKey::from_slice(hash.as_ref())
        .unwrap_or_else(|_| SecretKey::from_slice(&[1u8; 32]).expect("fallback key"));
    let secp = Secp256k1::new();
    let pk = sk.public_key(&secp);
    pk.serialize()
}

fn rand_op_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1000);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
