//! Integration tests for the Spark authentication gRPC flow.
//!
//! These tests connect to a live Spark operator and exercise the
//! `get_challenge` / `verify_challenge` handshake. They are marked
//! `#[ignore]` because they require network access.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p transport --test auth_integration -- --ignored --nocapture
//! ```

use bitcoin::secp256k1::SecretKey;
use prost::Message as ProstMessage;
use signer::{Signer, SparkSigner};
use transport::grpc::{GrpcConfig, GrpcTransport, OperatorConfig};

// ---------------------------------------------------------------------------
// Spark operator configuration (production, shared by regtest & mainnet)
// ---------------------------------------------------------------------------

/// Lightspark coordinator operator.
const COORDINATOR_URL: &str = "https://0.spark.lightspark.com";
const COORDINATOR_ID: &str = "coordinator";

/// Builds a [`GrpcTransport`] connected to the Lightspark coordinator.
fn make_transport() -> GrpcTransport {
    let ops = [OperatorConfig {
        id: COORDINATOR_ID.into(),
        address: COORDINATOR_URL.into(),
        identity_public_key: "03dfbdff4b6332c220f8fa2ba8ed496c698ceada563fa01b67d9983bfc5c95e763"
            .into(),
        is_coordinator: true,
    }];

    GrpcTransport::new(&ops, GrpcConfig::default()).expect("valid operator config")
}

/// Creates a random [`SparkSigner`] for testing.
fn random_signer() -> SparkSigner {
    let mut rng = rand::thread_rng();
    let sk = SecretKey::new(&mut rng);
    SparkSigner::new(sk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Step 1: `get_challenge` returns a valid protected challenge.
#[tokio::test]
#[ignore = "requires network access to Spark operator"]
async fn get_challenge_returns_valid_response() {
    let transport = make_transport();
    let signer = random_signer();
    let pubkey = signer.public_key();

    let resp = transport
        .get_challenge(COORDINATOR_ID, &pubkey)
        .await
        .expect("get_challenge should succeed");

    let protected = resp
        .protected_challenge
        .expect("response should contain protected_challenge");

    let challenge = protected
        .challenge
        .as_ref()
        .expect("protected_challenge should contain challenge");

    // Nonce should be 32 random bytes.
    assert_eq!(
        challenge.nonce.len(),
        32,
        "nonce should be 32 bytes, got {}",
        challenge.nonce.len()
    );

    // The challenge should echo back the public key we sent.
    assert_eq!(
        &challenge.public_key[..],
        &pubkey[..],
        "challenge public_key should match the request"
    );

    // Server HMAC should be non-empty.
    assert!(
        !protected.server_hmac.is_empty(),
        "server_hmac should be non-empty"
    );
}

/// Steps 1-2: Full auth flow -- get challenge, sign, verify, get session token.
#[tokio::test]
#[ignore = "requires network access to Spark operator"]
async fn full_auth_flow_with_valid_signature() {
    let transport = make_transport();
    let signer = random_signer();
    let pubkey = signer.public_key();

    // Step 1: Get challenge.
    let resp = transport
        .get_challenge(COORDINATOR_ID, &pubkey)
        .await
        .expect("get_challenge should succeed");

    let protected = resp
        .protected_challenge
        .expect("response should contain protected_challenge");

    let challenge = protected
        .challenge
        .as_ref()
        .expect("protected_challenge should contain challenge");

    // Step 2: Sign the protobuf-encoded Challenge via SparkSigner.
    let mut challenge_bytes = Vec::with_capacity(challenge.encoded_len());
    challenge
        .encode(&mut challenge_bytes)
        .expect("challenge encoding should not fail");

    let signature = signer
        .sign_challenge(&challenge_bytes)
        .expect("signing should succeed");

    // Step 3: Verify challenge.
    let verify_resp = transport
        .verify_challenge(COORDINATOR_ID, protected, &signature, &pubkey)
        .await
        .expect("verify_challenge should succeed");

    assert!(
        !verify_resp.session_token.is_empty(),
        "session_token should be non-empty"
    );
    assert!(
        verify_resp.expiration_timestamp > 0,
        "expiration_timestamp should be positive"
    );
}

/// `session_token` performs the full handshake and caches the result.
#[tokio::test]
#[ignore = "requires network access to Spark operator"]
async fn session_token_caches_result() {
    let transport = make_transport();
    let signer = random_signer();

    // First call: cold path (full handshake).
    let token1 = transport
        .session_token(COORDINATOR_ID, &signer)
        .await
        .expect("session_token should succeed");
    assert!(!token1.is_empty(), "token should be non-empty");

    // Second call: hot path (cached).
    let token2 = transport
        .session_token(COORDINATOR_ID, &signer)
        .await
        .expect("cached session_token should succeed");

    assert_eq!(token1, token2, "cached token should match original");
}

/// `get_challenge` should reject an invalid public key.
#[tokio::test]
#[ignore = "requires network access to Spark operator"]
async fn get_challenge_rejects_invalid_pubkey() {
    let transport = make_transport();

    // 32 random bytes is not a valid uncompressed secp256k1 public key.
    let bad_pubkey = [0xab_u8; 32];

    let result = transport.get_challenge(COORDINATOR_ID, &bad_pubkey).await;

    assert!(
        result.is_err(),
        "get_challenge should reject an invalid public key"
    );
}
