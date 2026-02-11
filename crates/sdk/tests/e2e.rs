//! End-to-end integration tests for the Spark SDK.
//!
//! Tests connect to the Spark production regtest (DEV_REGTEST config),
//! which uses the live Lightspark operators with the regtest network.
//!
//! # Wallet Setup
//!
//! Tests use two wallets derived from BIP39 mnemonics. By default,
//! fresh mnemonics are generated. To use pre-funded wallets, set:
//!
//! ```bash
//! export E2E_WALLET_A_MNEMONIC="word1 word2 ... word12"
//! export E2E_WALLET_B_MNEMONIC="word1 word2 ... word12"
//! ```
//!
//! # Running
//!
//! ```bash
//! # Auth + sync + balance tests (requires network):
//! cargo test -p sdk --test e2e -- --nocapture
//!
//! # All tests including transfers (requires funded wallets):
//! cargo test -p sdk --test e2e -- --ignored --nocapture
//! ```

use std::env;

use bip39::Mnemonic;
use config::NetworkConfig;
use sdk::token::InMemoryTokenStore;
use sdk::tree::InMemoryTreeStore;
use sdk::wallet_store::{IdentityPubKey, InMemoryWalletStore, WalletEntry, WalletStore};
use sdk::{Sdk, SdkConfig, SdkError};
use sdk_core::{Network, encode_spark_address};
use signer::{SparkWalletSigner, WalletSigner};
use tokio_util::sync::CancellationToken;

// ---------------------------------------------------------------------------
// Test configuration
// ---------------------------------------------------------------------------

/// Spark network for E2E tests: production regtest (mainnet operators, regtest network).
const NETWORK_CONFIG: NetworkConfig = NetworkConfig::DEV_REGTEST;

/// Bitcoin network for BIP32 key derivation.
const BITCOIN_NETWORK: bitcoin::Network = bitcoin::Network::Regtest;

/// BIP32 account index for wallet A.
const ACCOUNT_A: u32 = 0;

/// BIP32 account index for wallet B.
const ACCOUNT_B: u32 = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolves a mnemonic from an environment variable, falling back to a
/// freshly generated 12-word mnemonic.
fn resolve_mnemonic(env_key: &str) -> Mnemonic {
    if let Ok(phrase) = env::var(env_key) {
        phrase
            .parse::<Mnemonic>()
            .unwrap_or_else(|e| panic!("{env_key} is not a valid BIP39 mnemonic: {e}"))
    } else {
        // 12 words = 128 bits = 16 bytes of entropy.
        let mut entropy = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut entropy);
        Mnemonic::from_entropy(&entropy).expect("valid entropy")
    }
}

/// Derives a wallet signer and identity public key from a mnemonic.
fn wallet_from_mnemonic(mnemonic: &Mnemonic, account: u32) -> (SparkWalletSigner, IdentityPubKey) {
    let seed = mnemonic.to_seed("");
    let signer = SparkWalletSigner::from_seed(&seed, BITCOIN_NETWORK, account).expect("valid seed");
    let pubkey = signer.identity_public_key_compressed();
    (signer, pubkey)
}

/// Constructs an SDK with both wallets pre-registered in the wallet store.
fn make_sdk_with_wallets(
    mnemonic_a: &Mnemonic,
    pubkey_a: &IdentityPubKey,
    mnemonic_b: &Mnemonic,
    pubkey_b: &IdentityPubKey,
) -> Sdk<InMemoryWalletStore, InMemoryTreeStore, InMemoryTokenStore> {
    let wallet_store = InMemoryWalletStore::new();
    wallet_store
        .insert(
            *pubkey_a,
            WalletEntry {
                seed: mnemonic_a.to_seed("").to_vec(),
                account: ACCOUNT_A,
            },
        )
        .expect("insert A");
    wallet_store
        .insert(
            *pubkey_b,
            WalletEntry {
                seed: mnemonic_b.to_seed("").to_vec(),
                account: ACCOUNT_B,
            },
        )
        .expect("insert B");

    let config = SdkConfig {
        network: NETWORK_CONFIG,
    };

    Sdk::new(
        config,
        wallet_store,
        InMemoryTreeStore::new(),
        InMemoryTokenStore::new(),
        sdk::ssp::NoSspClient,
        CancellationToken::new(),
    )
    .expect("SDK construction should succeed")
}

/// Constructs an SDK with a single wallet pre-registered.
fn make_sdk_with_wallet(
    mnemonic: &Mnemonic,
    pubkey: &IdentityPubKey,
    account: u32,
) -> Sdk<InMemoryWalletStore, InMemoryTreeStore, InMemoryTokenStore> {
    let wallet_store = InMemoryWalletStore::new();
    wallet_store
        .insert(
            *pubkey,
            WalletEntry {
                seed: mnemonic.to_seed("").to_vec(),
                account,
            },
        )
        .expect("insert wallet");

    let config = SdkConfig {
        network: NETWORK_CONFIG,
    };

    Sdk::new(
        config,
        wallet_store,
        InMemoryTreeStore::new(),
        InMemoryTokenStore::new(),
        sdk::ssp::NoSspClient,
        CancellationToken::new(),
    )
    .expect("SDK construction should succeed")
}

/// Constructs an SDK with a single wallet and a real SSP client.
fn make_sdk_with_ssp(
    mnemonic: &Mnemonic,
    pubkey: &IdentityPubKey,
    account: u32,
) -> Sdk<InMemoryWalletStore, InMemoryTreeStore, InMemoryTokenStore, graphql::GraphqlSspClient> {
    let wallet_store = InMemoryWalletStore::new();
    wallet_store
        .insert(
            *pubkey,
            WalletEntry {
                seed: mnemonic.to_seed("").to_vec(),
                account,
            },
        )
        .expect("insert wallet");

    let config = SdkConfig {
        network: NETWORK_CONFIG,
    };

    let ssp_client =
        graphql::GraphqlSspClient::from_config(&NETWORK_CONFIG.ssp).expect("valid SSP config");

    Sdk::new(
        config,
        wallet_store,
        InMemoryTreeStore::new(),
        InMemoryTokenStore::new(),
        ssp_client,
        CancellationToken::new(),
    )
    .expect("SDK construction should succeed")
}

// ===========================================================================
// Tests: Wallet Info (always runs, no network)
// ===========================================================================

/// Prints wallet mnemonics, identity public keys, and Spark addresses.
///
/// Run with `--nocapture` to see output:
/// ```bash
/// cargo test -p sdk --test e2e generate_wallet_info -- --nocapture
/// ```
#[tokio::test]
async fn generate_wallet_info() {
    unsafe {
        env::set_var(
            "E2E_WALLET_A_MNEMONIC",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        env::set_var(
            "E2E_WALLET_B_MNEMONIC",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        );
    }

    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let mnemonic_b = resolve_mnemonic("E2E_WALLET_B_MNEMONIC");

    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);
    let (signer_b, pubkey_b) = wallet_from_mnemonic(&mnemonic_b, ACCOUNT_B);

    let addr_a = encode_spark_address(Network::Regtest, &pubkey_a);
    let addr_b = encode_spark_address(Network::Regtest, &pubkey_b);

    println!("\n========== E2E Wallet Info ==========");
    println!("Wallet A:");
    println!("  Mnemonic:    {mnemonic_a}");
    println!("  Identity PK: {}", hex_encode(&pubkey_a));
    println!("  Spark Addr:  {addr_a}");
    println!();
    println!("Wallet B:");
    println!("  Mnemonic:    {mnemonic_b}");
    println!("  Identity PK: {}", hex_encode(&pubkey_b));
    println!("  Spark Addr:  {addr_b}");
    println!("=====================================\n");

    // Verify keys are distinct.
    assert_ne!(
        signer_a.identity_public_key_compressed(),
        signer_b.identity_public_key_compressed(),
        "wallets must have distinct identity keys"
    );
}

// ===========================================================================
// Tests: Authentication (requires network)
// ===========================================================================

/// Authenticates with all operators using wallet A.
#[tokio::test]
async fn auth_all_operators() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);
    let operator_ids = sdk.transport().operator_ids();

    println!("\nAuthenticating with {} operators...", operator_ids.len());

    for op_id in &operator_ids {
        let result = sdk.transport().session_token(op_id, &signer_a).await;
        match &result {
            Ok(token) => println!("  {op_id}: OK (token {} bytes)", token.len()),
            Err(e) => println!("  {op_id}: FAILED ({e})"),
        }
        assert!(result.is_ok(), "authentication with {op_id} should succeed");
    }

    // Second call should hit cache.
    let coordinator_id = sdk.transport().coordinator_id().to_owned();
    let token1 = sdk
        .transport()
        .session_token(&coordinator_id, &signer_a)
        .await
        .unwrap();
    let token2 = sdk
        .transport()
        .session_token(&coordinator_id, &signer_a)
        .await
        .unwrap();
    assert_eq!(token1, token2, "cached token should match");
    println!("  Session cache: OK\n");
}

// ===========================================================================
// Tests: Sync + Balance (requires network + funded wallets)
// ===========================================================================

/// Syncs wallet A and verifies leaf count.
#[tokio::test]
async fn sync_wallet_a() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);

    println!("\nSyncing wallet A...");
    let result = sdk.sync_wallet(&pubkey_a, &signer_a).await;

    match &result {
        Ok(sync) => println!(
            "  Synced: {} leaves, {} sats",
            sync.leaf_count, sync.balance_sats
        ),
        Err(e) => println!("  Sync failed: {e}"),
    }

    let sync = result.expect("sync should succeed");
    println!(
        "  Wallet A: {} leaves, {} sats\n",
        sync.leaf_count, sync.balance_sats
    );
}

/// Syncs wallet B and verifies leaf count.
#[tokio::test]
async fn sync_wallet_b() {
    let mnemonic_b = resolve_mnemonic("E2E_WALLET_B_MNEMONIC");
    let (signer_b, pubkey_b) = wallet_from_mnemonic(&mnemonic_b, ACCOUNT_B);

    let sdk = make_sdk_with_wallet(&mnemonic_b, &pubkey_b, ACCOUNT_B);

    println!("\nSyncing wallet B...");
    let result = sdk.sync_wallet(&pubkey_b, &signer_b).await;

    match &result {
        Ok(sync) => println!(
            "  Synced: {} leaves, {} sats",
            sync.leaf_count, sync.balance_sats
        ),
        Err(e) => println!("  Sync failed: {e}"),
    }

    let sync = result.expect("sync should succeed");
    println!(
        "  Wallet B: {} leaves, {} sats\n",
        sync.leaf_count, sync.balance_sats
    );
}

/// Queries balance after sync and verifies consistency.
#[tokio::test]
async fn query_balance_after_sync() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);

    // Sync first.
    let sync = sdk
        .sync_wallet(&pubkey_a, &signer_a)
        .await
        .expect("sync should succeed");

    // Query balance.
    let balance = sdk
        .query_balance(&pubkey_a)
        .await
        .expect("balance query should succeed");

    println!("\nBalance after sync:");
    println!("  BTC available: {} sats", balance.btc_available_sats);
    println!("  Tokens: {} types", balance.token_balances.len());

    // Balance should match what sync reported.
    assert_eq!(
        balance.btc_available_sats, sync.balance_sats,
        "balance should match sync result"
    );
    println!("  Consistency check: OK\n");
}

// ===========================================================================
// Tests: Pending Transfers (requires network)
// ===========================================================================

/// Query pending transfers for wallet A (diagnostic -- no FROST needed).
#[tokio::test]
async fn query_pending_transfers_a() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);

    // Authenticate.
    let token = sdk
        .transport()
        .session_token(sdk.transport().coordinator_id(), &signer_a)
        .await
        .expect("auth should succeed");

    let authed = sdk
        .transport()
        .authenticated(&token)
        .expect("token should be valid");

    // Spark regtest network enum value.
    let network = transport::spark::Network::Regtest as i32;

    // Query pending transfers where wallet A is the receiver.
    let resp = authed
        .query_pending_transfers(transport::spark::TransferFilter {
            participant: Some(
                transport::spark::transfer_filter::Participant::ReceiverIdentityPublicKey(
                    bytes::Bytes::copy_from_slice(&pubkey_a),
                ),
            ),
            network,
            ..Default::default()
        })
        .await
        .expect("query should succeed");

    println!("\n========== Pending Transfers for Wallet A ==========");
    println!("  Wallet A pubkey: {}", hex_encode(&pubkey_a));
    println!("  --- By receiver filter (regtest) ---");
    print_transfers(&resp.transfers);

    // Also try sender-or-receiver filter for broader coverage.
    let resp2 = authed
        .query_pending_transfers(transport::spark::TransferFilter {
            participant: Some(
                transport::spark::transfer_filter::Participant::SenderOrReceiverIdentityPublicKey(
                    bytes::Bytes::copy_from_slice(&pubkey_a),
                ),
            ),
            network,
            ..Default::default()
        })
        .await
        .expect("query should succeed");

    println!("  --- By sender-or-receiver filter (regtest) ---");
    print_transfers(&resp2.transfers);

    // Query the specific transfer by ID.
    let resp3 = authed
        .query_pending_transfers(transport::spark::TransferFilter {
            transfer_ids: vec!["019c49b2efef727383f8e105e1c495eb".to_string()],
            network,
            ..Default::default()
        })
        .await
        .expect("query by ID should succeed");

    println!("  --- By transfer ID (019c49b2...) ---");
    print_transfers(&resp3.transfers);

    println!("=====================================================\n");
}

// ===========================================================================
// Tests: Transfers (requires funded wallets + complete FROST signing)
// ===========================================================================

/// Transfer BTC from wallet A to wallet B.
#[tokio::test]
#[ignore = "requires funded wallets and complete FROST signing implementation"]
async fn transfer_a_to_b() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let mnemonic_b = resolve_mnemonic("E2E_WALLET_B_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);
    let (_signer_b, pubkey_b) = wallet_from_mnemonic(&mnemonic_b, ACCOUNT_B);

    let sdk = make_sdk_with_wallets(&mnemonic_a, &pubkey_a, &mnemonic_b, &pubkey_b);

    // Sync wallet A.
    let sync = sdk
        .sync_wallet(&pubkey_a, &signer_a)
        .await
        .expect("sync A should succeed");
    assert!(sync.balance_sats > 0, "wallet A must have funds");

    let transfer_amount = 1000; // 1000 sats
    assert!(
        sync.balance_sats >= transfer_amount,
        "wallet A must have at least {transfer_amount} sats"
    );

    println!("\nTransferring {transfer_amount} sats from A to B...");
    let result = sdk
        .send_transfer(&pubkey_a, &pubkey_b, transfer_amount, &signer_a)
        .await;

    match &result {
        Ok(r) => println!(
            "  Transfer started: {:?}",
            r.transfer.as_ref().map(|t| &t.id)
        ),
        Err(e) => println!("  Transfer failed: {e}"),
    }
    result.expect("send_transfer should succeed");
    println!("  Transfer: OK\n");
}

/// Claim a pending transfer on wallet B.
#[tokio::test]
#[ignore = "requires funded wallets and complete FROST signing implementation"]
async fn claim_transfer_on_b() {
    let mnemonic_b = resolve_mnemonic("E2E_WALLET_B_MNEMONIC");
    let (signer_b, pubkey_b) = wallet_from_mnemonic(&mnemonic_b, ACCOUNT_B);

    let sdk = make_sdk_with_wallet(&mnemonic_b, &pubkey_b, ACCOUNT_B);

    println!("\nClaiming transfers on wallet B...");
    let result = sdk.claim_transfer(&pubkey_b, &signer_b).await;

    match &result {
        Ok(r) => println!("  Claimed: {} leaves", r.leaves_claimed),
        Err(e) => println!("  Claim failed: {e}"),
    }
    result.expect("claim_transfer should succeed");
    println!("  Claim: OK\n");
}

/// Claim the pending 1,456-sat transfer on wallet A.
///
/// This exercises the full claim flow:
/// 1. Query pending transfers
/// 2. Verify sender ECDSA signature + ECIES decrypt leaf keys
/// 3. Compute key tweaks, VSS-split, send to all operators
/// 4. Construct refund txs, FROST sign + aggregate
/// 5. Finalize with coordinator
/// 6. Verify leaves appear in tree store
///
/// Run:
/// ```bash
/// export E2E_WALLET_A_MNEMONIC="abandon abandon ... about"
/// cargo test -p sdk --test e2e claim_pending_transfer_a -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "requires pre-funded wallet A with pending transfer"]
async fn claim_pending_transfer_a() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);

    println!("\n========== Claiming Pending Transfer on Wallet A ==========");
    println!("  Wallet A pubkey: {}", hex_encode(&pubkey_a));

    // Step 1: Verify there are pending transfers before claiming.
    let token = sdk
        .transport()
        .session_token(sdk.transport().coordinator_id(), &signer_a)
        .await
        .expect("auth should succeed");

    let authed = sdk
        .transport()
        .authenticated(&token)
        .expect("token should be valid");

    let network = transport::spark::Network::Regtest as i32;
    let pending_before = authed
        .query_pending_transfers(transport::spark::TransferFilter {
            participant: Some(
                transport::spark::transfer_filter::Participant::ReceiverIdentityPublicKey(
                    bytes::Bytes::copy_from_slice(&pubkey_a),
                ),
            ),
            network,
            ..Default::default()
        })
        .await
        .expect("query should succeed");

    println!(
        "  Pending transfers before claim: {}",
        pending_before.transfers.len()
    );
    if pending_before.transfers.is_empty() {
        println!("  No pending transfers to claim -- skipping.");
        println!("=========================================================\n");
        return;
    }

    for t in &pending_before.transfers {
        println!(
            "    Transfer {}: {} sats ({} leaves)",
            t.id,
            t.total_value,
            t.leaves.len()
        );
    }

    // Step 2: Claim.
    println!("  Executing claim...");
    let result = sdk.claim_transfer(&pubkey_a, &signer_a).await;

    match &result {
        Ok(r) => println!("  Claimed: {} leaves", r.leaves_claimed),
        Err(e) => println!("  Claim failed: {e}"),
    }

    let claim_result = result.expect("claim_transfer should succeed");
    assert!(
        claim_result.leaves_claimed > 0,
        "should claim at least one leaf"
    );

    // Step 3: Verify balance increased after sync.
    println!("  Re-syncing wallet A...");
    let sync = sdk
        .sync_wallet(&pubkey_a, &signer_a)
        .await
        .expect("sync should succeed");

    println!(
        "  After claim: {} leaves, {} sats",
        sync.leaf_count, sync.balance_sats
    );
    assert!(
        sync.balance_sats > 0,
        "balance should be positive after claiming"
    );

    // Step 4: Verify no more pending transfers.
    let pending_after = authed
        .query_pending_transfers(transport::spark::TransferFilter {
            participant: Some(
                transport::spark::transfer_filter::Participant::ReceiverIdentityPublicKey(
                    bytes::Bytes::copy_from_slice(&pubkey_a),
                ),
            ),
            network,
            ..Default::default()
        })
        .await
        .expect("query should succeed");

    println!(
        "  Pending transfers after claim: {}",
        pending_after.transfers.len()
    );
    assert_eq!(
        pending_after.transfers.len(),
        0,
        "no pending transfers should remain"
    );

    println!("=========================================================\n");
}

/// Subscribe to events and receive at least a ConnectedEvent.
#[tokio::test]
#[ignore = "requires network and long-running stream"]
async fn event_subscription() {
    let mnemonic_a = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer_a, pubkey_a) = wallet_from_mnemonic(&mnemonic_a, ACCOUNT_A);

    let sdk = make_sdk_with_wallet(&mnemonic_a, &pubkey_a, ACCOUNT_A);

    // Cancel after 5 seconds to avoid hanging.
    let cancel = sdk.cancel().clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        cancel.cancel();
    });

    println!("\nSubscribing to events (5s timeout)...");
    let result = sdk.subscribe_and_handle_events(&pubkey_a, &signer_a).await;

    match &result {
        Ok(count) => println!("  Processed {count} events before shutdown"),
        Err(SdkError::Cancelled) => println!("  Cancelled (expected)"),
        Err(e) => println!("  Error: {e}"),
    }
    println!("  Events: OK\n");
}

// ---------------------------------------------------------------------------
// Hex helper (minimal, no extra dep)
// ---------------------------------------------------------------------------

fn print_transfers(transfers: &[transport::spark::Transfer]) {
    println!("    Count: {}", transfers.len());
    for (i, transfer) in transfers.iter().enumerate() {
        println!("    Transfer #{i}:");
        println!("      ID:     {}", transfer.id);
        println!("      Status: {}", transfer.status);
        println!("      Type:   {}", transfer.r#type);
        println!("      Value:  {} sats", transfer.total_value);
        println!("      Leaves: {}", transfer.leaves.len());

        let sender_pk = &transfer.sender_identity_public_key;
        if !sender_pk.is_empty() {
            println!("      Sender: {}", hex_encode(sender_pk));
        }

        let recv_pk = &transfer.receiver_identity_public_key;
        if !recv_pk.is_empty() {
            println!("      Recvr:  {}", hex_encode(recv_pk));
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    s
}

// ===========================================================================
// Tests: Fund → Claim → Send-to-self (full round-trip)
// ===========================================================================

/// End-to-end: request funds via faucet, claim, then send to self.
///
/// Flow:
/// 1. Generate a fresh wallet.
/// 2. Request funds from the funding-client faucet.
/// 3. Wait 3 seconds for the transfer to propagate.
/// 4. Claim the incoming transfer.
/// 5. Send the claimed balance back to self.
/// 6. Wait 3 seconds, then claim the self-transfer.
/// 7. Verify balance is preserved.
///
/// Run:
/// ```bash
/// cargo test -p sdk --test e2e fund_claim_send_to_self -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "requires network access and funding-client faucet"]
async fn fund_claim_send_to_self() {
    // 1. Generate a fresh wallet.
    let mnemonic = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer, pubkey) = wallet_from_mnemonic(&mnemonic, ACCOUNT_A);
    let spark_address = encode_spark_address(Network::Regtest, &pubkey);

    let sdk = make_sdk_with_wallet(&mnemonic, &pubkey, ACCOUNT_A);

    println!("\n========== Fund → Claim → Send-to-self ==========");
    println!("  Wallet pubkey:  {}", hex_encode(&pubkey));
    println!("  Spark address:  {spark_address}");

    // 2. Request funds from the faucet.
    let funding_amount = 1_000u64; // 1000 sats
    println!("\n  [Step 1] Requesting {funding_amount} sats from faucet...");

    let faucet = funding_client::FundingClient::new().await;
    let fund_results = faucet
        .request_funds(vec![funding_client::FundingTask {
            amount_sats: funding_amount,
            recipient: spark_address.clone(),
        }])
        .await
        .expect("funding request should succeed");

    assert_eq!(
        fund_results.len(),
        1,
        "should get exactly one funding result"
    );
    println!(
        "    Funded: {} sats, status: {}, txids: {:?}",
        fund_results[0].amount_sent, fund_results[0].status, fund_results[0].txids
    );

    // 3. Wait for the transfer to propagate.
    println!("\n  [Step 2] Waiting 10 seconds for transfer propagation...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // 4. Claim the incoming transfer.
    println!("  [Step 3] Claiming incoming transfer...");
    let claim_result = sdk
        .claim_transfer(&pubkey, &signer)
        .await
        .expect("claim should succeed");

    println!("    Claimed: {} leaves", claim_result.leaves_claimed);
    assert!(
        claim_result.leaves_claimed > 0,
        "should claim at least one leaf"
    );

    // Read balance from local store (claim already inserted leaves; sync
    // would query the coordinator which may not yet reflect new ownership).
    let balance_after_claim = sdk
        .query_balance(&pubkey)
        .await
        .expect("balance query should succeed");

    println!(
        "    After claim: {} sats",
        balance_after_claim.btc_available_sats
    );
    assert!(
        balance_after_claim.btc_available_sats > 0,
        "balance should be positive after claim"
    );

    // 5. Send the full claimed balance to self.
    let send_amount = balance_after_claim.btc_available_sats;
    println!("\n  [Step 4] Sending {send_amount} sats to self...");

    let send_result = sdk
        .send_transfer(&pubkey, &pubkey, send_amount, &signer)
        .await
        .expect("send_transfer to self should succeed");

    println!(
        "    Transfer submitted: {:?}",
        send_result.transfer.as_ref().map(|t| &t.id)
    );

    // 6. Wait for the self-transfer to propagate, then claim it.
    println!("\n  [Step 5] Waiting 3 seconds for self-transfer propagation...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    println!("  [Step 6] Claiming self-transfer...");
    let self_claim = sdk
        .claim_transfer(&pubkey, &signer)
        .await
        .expect("self-claim should succeed");

    println!("    Claimed: {} leaves", self_claim.leaves_claimed);
    assert!(
        self_claim.leaves_claimed > 0,
        "should claim the self-transfer leaf(s)"
    );

    // 7. Verify balance is preserved (read from local store).
    let final_balance = sdk
        .query_balance(&pubkey)
        .await
        .expect("final balance query should succeed");

    println!(
        "\n  [Step 7] Final balance: {} sats",
        final_balance.btc_available_sats
    );
    assert!(
        final_balance.btc_available_sats > 0,
        "final balance should be positive"
    );

    println!(
        "    Balance: {} sats (started with {} sats)",
        final_balance.btc_available_sats, balance_after_claim.btc_available_sats
    );

    println!("===================================================\n");
}

// ===========================================================================
// Tests: SSP Swap (requires network + funding-client faucet)
// ===========================================================================

/// End-to-end: fund with 2 sats, then trigger SSP swap via send_transfer.
///
/// The faucet sends us 2 sats (typically as a single 2-sat leaf).
/// We then `send_transfer` 1 sat to self.  Since the selected leaf (2 sat)
/// exceeds the send amount (1 sat), `send_transfer` automatically triggers
/// an SSP swap, claims the inbound, and re-sends with exact leaves.
///
/// If the faucet sends two 1-sat leaves instead, `select_leaves_greedy`
/// picks one exact leaf (no change) and the non-swap path executes.
/// Both paths are valid and the test adapts accordingly.
///
/// Run:
/// ```bash
/// cargo test -p sdk --test e2e ssp_swap_via_send -- --ignored --nocapture
/// ```
#[tokio::test]
#[ignore = "requires network access and funding-client faucet"]
async fn ssp_swap_via_send() {
    // 1. Generate wallet with SSP client.
    let mnemonic = resolve_mnemonic("E2E_WALLET_A_MNEMONIC");
    let (signer, pubkey) = wallet_from_mnemonic(&mnemonic, ACCOUNT_A);
    let spark_address = encode_spark_address(Network::Regtest, &pubkey);

    let sdk = make_sdk_with_ssp(&mnemonic, &pubkey, ACCOUNT_A);

    println!("\n========== SSP Swap via send_transfer ==========");
    println!("  Wallet pubkey:  {}", hex_encode(&pubkey));
    println!("  Spark address:  {spark_address}");

    // 2. Request 2 sats from the faucet.
    println!("\n  [Step 1] Requesting 2 sats from faucet...");

    let faucet = funding_client::FundingClient::new().await;
    let fund_results = faucet
        .request_funds(vec![funding_client::FundingTask {
            amount_sats: 2,
            recipient: spark_address.clone(),
        }])
        .await
        .expect("funding request should succeed");

    assert_eq!(fund_results.len(), 1);
    println!(
        "    Funded: {} sats, status: {}",
        fund_results[0].amount_sent, fund_results[0].status
    );

    // 3. Wait for propagation, then claim.
    println!("\n  [Step 2] Waiting 10 seconds for transfer propagation...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    println!("  [Step 3] Claiming incoming transfer...");
    let claim_result = sdk
        .claim_transfer(&pubkey, &signer)
        .await
        .expect("claim should succeed");

    println!("    Claimed: {} leaves", claim_result.leaves_claimed);
    assert!(
        claim_result.leaves_claimed > 0,
        "should claim at least one leaf"
    );

    // 4. Verify balance.
    let balance = sdk
        .query_balance(&pubkey)
        .await
        .expect("balance query should succeed");

    println!("    Balance: {} sats", balance.btc_available_sats);
    assert!(
        balance.btc_available_sats >= 2,
        "should have at least 2 sats"
    );

    // 5. Send 1 sat to self.
    //    send_transfer now handles the SSP swap + claim + re-send transparently.
    //    If change > 0, it swaps via SSP, claims by transfer ID, re-selects
    //    exact leaves, and completes the direct transfer -- all in one call.
    println!("\n  [Step 4] Sending 1 sat to self (SSP swap handled inline)...");

    let result = sdk
        .send_transfer(&pubkey, &pubkey, 1, &signer)
        .await
        .expect("send_transfer should succeed");

    println!(
        "    Transfer ID: {:?}",
        result.transfer.as_ref().map(|t| &t.id)
    );

    // 6. Verify final balance.
    //    After claiming the SSP inbound (which send_transfer does inline),
    //    the receiver gets 1 sat as a direct transfer. The sender keeps the
    //    change leaf from the SSP swap (already in the tree store).
    let final_balance = sdk
        .query_balance(&pubkey)
        .await
        .expect("final balance query should succeed");

    println!(
        "\n  [Step 5] Final: {} sats",
        final_balance.btc_available_sats
    );

    println!("=================================================\n");
}
