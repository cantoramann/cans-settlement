//! Token operations: send, create, mint, freeze, and query.
//!
//! Token operations use ECDSA identity key signatures (not FROST).
//! V3 protocol: build `PartialTokenTransaction`, hash via protoreflecthash,
//! ECDSA-sign the hash, and broadcast via `SparkTokenService`.
//!
//! # Send Token Flow
//!
//! 1. Resolve wallet and authenticate
//! 2. Acquire token outputs from `TokenStore`
//! 3. Build `PartialTokenTransaction` with `TransferInput`
//! 4. Hash via protoreflecthash
//! 5. ECDSA-sign hash per input (DER encoding)
//! 6. Broadcast via `broadcast_transaction`
//! 7. Release/update token outputs in store
//!
//! # Create / Mint Token Flow
//!
//! 1. Authenticate
//! 2. Build `PartialTokenTransaction` with `CreateInput` or `MintInput`
//! 3. Hash, sign (single signature, input_index = 0)
//! 4. Broadcast
//! 5. Return `token_identifier` (create) or final tx (mint)

use std::time::Instant;

use bytes::Bytes;
use signer::WalletSigner;
use tracing::{error, info};
use transport::spark_token::{
    self, BroadcastTransactionRequest, FreezeTokensPayload, FreezeTokensRequest,
    PartialTokenOutput, PartialTokenTransaction, QueryTokenMetadataRequest,
    QueryTokenMetadataResponse, QueryTokenTransactionsRequest, QueryTokenTransactionsResponse,
    SignatureWithIndex, TokenCreateInput, TokenMintInput, TokenOutputToSpend, TokenTransferInput,
};

use super::hash;
use super::helpers::{TOKEN_TX_VERSION, build_metadata, sign_digest_der, u128_to_bytes};
use crate::operations::tracking::{OperationError, OperationKind, OperationStep};
use crate::token::TokenStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Public result types
// ---------------------------------------------------------------------------

/// Response from a send token operation.
pub struct SendTokenResult {
    /// Final token transaction, if returned by the coordinator.
    pub final_tx: Option<spark_token::FinalTokenTransaction>,
}

/// Parameters for creating a new token type.
pub struct CreateTokenParams<'a> {
    /// Token display name.
    pub name: &'a str,
    /// Token ticker symbol.
    pub ticker: &'a str,
    /// Number of decimal places for display.
    pub decimals: u32,
    /// Maximum supply (uint128).
    pub max_supply: u128,
    /// Whether the issuer can freeze token outputs.
    pub is_freezable: bool,
}

/// Response from a create token operation.
pub struct CreateTokenResult {
    /// The token identifier assigned by the coordinator (32 bytes).
    pub token_identifier: Vec<u8>,
}

/// Response from a mint token operation.
pub struct MintTokenResult {
    /// Final token transaction, if returned by the coordinator.
    pub final_tx: Option<spark_token::FinalTokenTransaction>,
}

/// Response from a freeze/unfreeze operation.
pub struct FreezeTokensResult {
    /// Output IDs that were affected by the freeze/unfreeze.
    pub impacted_output_ids: Vec<String>,
    /// Total token amount affected (big-endian uint128 bytes).
    pub impacted_token_amount: Vec<u8>,
}

/// Token balance for a specific token.
pub struct TokenBalance {
    /// Token identifier (32 bytes).
    pub token_id: [u8; 32],
    /// Available (unlocked) balance.
    pub amount: u128,
}

// ---------------------------------------------------------------------------
// Sdk impl -- token operations
// ---------------------------------------------------------------------------

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: crate::tree::TreeStore,
    K: TokenStore,
    S: crate::ssp::SspClient,
{
    // -----------------------------------------------------------------------
    // send_token (transfer)
    // -----------------------------------------------------------------------

    /// Send tokens to a receiver.
    ///
    /// Acquires token outputs covering the requested amount, builds a
    /// `PartialTokenTransaction` with `TransferInput`, hashes it via
    /// protoreflecthash, ECDSA-signs the hash per input, and broadcasts.
    ///
    /// If the acquired outputs exceed `amount`, a change output is created
    /// back to the sender.
    pub async fn send_token(
        &self,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        token_id: &[u8; 32],
        amount: u128,
        signer: &impl WalletSigner,
    ) -> Result<SendTokenResult, OperationError> {
        let mut tracker = self.tracker(OperationKind::SendToken);
        let op_id = tracker.id();

        if let Err(e) = self.check_cancelled() {
            return Err(tracker.fail(OperationStep::Auth, e));
        }

        if self.inner.wallet_store.resolve(sender_pubkey).is_none() {
            return Err(tracker.fail(OperationStep::Auth, SdkError::WalletNotFound));
        }

        let t = Instant::now();
        let authed = match self.authenticate(signer).await {
            Ok(a) => a,
            Err(e) => return Err(tracker.fail(OperationStep::Auth, e)),
        };
        tracker.step_ok(OperationStep::Auth, t.elapsed());

        // 1. Acquire token outputs.
        let t = Instant::now();
        let acquired = match self.inner.token_store.acquire_outputs(token_id, amount) {
            Ok(a) => a,
            Err(_) => {
                return Err(tracker.fail(
                    OperationStep::TokenAcquire,
                    SdkError::InsufficientTokenBalance,
                ))
            }
        };
        tracker.step_ok(OperationStep::TokenAcquire, t.elapsed());

        // 2. Build PartialTokenTransaction.
        let token_id_bytes = Bytes::copy_from_slice(token_id);

        let outputs_to_spend: Vec<TokenOutputToSpend> = acquired
            .outputs
            .iter()
            .map(|o| TokenOutputToSpend {
                prev_token_transaction_hash: Bytes::copy_from_slice(&o.previous_transaction_hash),
                prev_token_transaction_vout: o.previous_transaction_vout,
            })
            .collect();

        let transfer_input = TokenTransferInput { outputs_to_spend };

        let mut partial_outputs = vec![PartialTokenOutput {
            owner_public_key: Bytes::copy_from_slice(receiver_pubkey),
            withdraw_bond_sats: config::constants::DEFAULT_WITHDRAW_BOND_SATS,
            withdraw_relative_block_locktime: config::constants::DEFAULT_WITHDRAW_RELATIVE_LOCKTIME,
            token_identifier: token_id_bytes.clone(),
            token_amount: u128_to_bytes(amount),
        }];

        if acquired.total_amount > amount {
            let change = acquired.total_amount - amount;
            partial_outputs.push(PartialTokenOutput {
                owner_public_key: Bytes::copy_from_slice(sender_pubkey),
                withdraw_bond_sats: config::constants::DEFAULT_WITHDRAW_BOND_SATS,
                withdraw_relative_block_locktime:
                    config::constants::DEFAULT_WITHDRAW_RELATIVE_LOCKTIME,
                token_identifier: token_id_bytes,
                token_amount: u128_to_bytes(change),
            });
        }

        let partial_tx = PartialTokenTransaction {
            version: TOKEN_TX_VERSION,
            token_transaction_metadata: Some(build_metadata(&self.inner.config.network)),
            token_inputs: Some(
                spark_token::partial_token_transaction::TokenInputs::TransferInput(transfer_input),
            ),
            partial_token_outputs: partial_outputs,
        };

        // 3. Hash and sign.
        let t = Instant::now();
        let tx_hash = hash::hash_partial_token_transaction(&partial_tx);

        let signatures: Vec<SignatureWithIndex> = match acquired
            .outputs
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let der = sign_digest_der(signer, &tx_hash)?;
                Ok(SignatureWithIndex {
                    signature: Bytes::from(der),
                    input_index: i as u32,
                })
            })
            .collect::<Result<Vec<_>, SdkError>>()
        {
            Ok(s) => s,
            Err(e) => return Err(tracker.fail(OperationStep::Signing, e)),
        };
        tracker.step_ok(OperationStep::Signing, t.elapsed());

        // 4. Broadcast.
        let t = Instant::now();
        let resp = match authed
            .broadcast_transaction(BroadcastTransactionRequest {
                identity_public_key: Bytes::copy_from_slice(sender_pubkey),
                partial_token_transaction: Some(partial_tx),
                token_transaction_owner_signatures: signatures,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!("send_token broadcast failed: {e}");
                return Err(tracker.fail(OperationStep::TokenBroadcast, SdkError::TransportFailed));
            }
        };
        tracker.step_ok(OperationStep::TokenBroadcast, t.elapsed());

        // 5. Release lock.
        if self.inner.token_store.release_outputs(acquired.lock_id).is_err() {
            return Err(tracker.fail(OperationStep::Finalization, SdkError::StoreFailed));
        }

        info!(op_id = %op_id, %amount, "token transfer sent");
        tracker.succeed();
        Ok(SendTokenResult {
            final_tx: resp.final_token_transaction,
        })
    }

    // -----------------------------------------------------------------------
    // create_token
    // -----------------------------------------------------------------------

    /// Create a new token type.
    ///
    /// The caller becomes the token issuer. Returns the `token_identifier`
    /// assigned by the coordinator.
    pub async fn create_token(
        &self,
        issuer_pubkey: &IdentityPubKey,
        params: &CreateTokenParams<'_>,
        signer: &impl WalletSigner,
    ) -> Result<CreateTokenResult, OperationError> {
        let mut tracker = self.tracker(OperationKind::CreateToken);
        let op_id = tracker.id();

        if let Err(e) = self.check_cancelled() {
            return Err(tracker.fail(OperationStep::Auth, e));
        }

        if self.inner.wallet_store.resolve(issuer_pubkey).is_none() {
            return Err(tracker.fail(OperationStep::Auth, SdkError::WalletNotFound));
        }

        let t = Instant::now();
        let authed = match self.authenticate(signer).await {
            Ok(a) => a,
            Err(e) => return Err(tracker.fail(OperationStep::Auth, e)),
        };
        tracker.step_ok(OperationStep::Auth, t.elapsed());

        let create_input = TokenCreateInput {
            issuer_public_key: Bytes::copy_from_slice(issuer_pubkey),
            token_name: params.name.to_owned(),
            token_ticker: params.ticker.to_owned(),
            decimals: params.decimals,
            max_supply: u128_to_bytes(params.max_supply),
            is_freezable: params.is_freezable,
            creation_entity_public_key: None,
            extra_metadata: None,
        };

        let partial_tx = PartialTokenTransaction {
            version: TOKEN_TX_VERSION,
            token_transaction_metadata: Some(build_metadata(&self.inner.config.network)),
            token_inputs: Some(
                spark_token::partial_token_transaction::TokenInputs::CreateInput(create_input),
            ),
            partial_token_outputs: vec![],
        };

        let t = Instant::now();
        let tx_hash = hash::hash_partial_token_transaction(&partial_tx);
        let der = match sign_digest_der(signer, &tx_hash) {
            Ok(d) => d,
            Err(e) => return Err(tracker.fail(OperationStep::Signing, e)),
        };
        tracker.step_ok(OperationStep::Signing, t.elapsed());

        let t = Instant::now();
        let resp = match authed
            .broadcast_transaction(BroadcastTransactionRequest {
                identity_public_key: Bytes::copy_from_slice(issuer_pubkey),
                partial_token_transaction: Some(partial_tx),
                token_transaction_owner_signatures: vec![SignatureWithIndex {
                    signature: Bytes::from(der),
                    input_index: 0,
                }],
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!("create_token broadcast failed: {e}");
                return Err(tracker.fail(OperationStep::TokenBroadcast, SdkError::TransportFailed));
            }
        };
        tracker.step_ok(OperationStep::TokenBroadcast, t.elapsed());

        let token_identifier = match resp.token_identifier.map(|b| b.to_vec()) {
            Some(id) => id,
            None => {
                return Err(tracker.fail(
                    OperationStep::TokenBroadcast,
                    SdkError::InvalidOperatorResponse,
                ))
            }
        };

        info!(op_id = %op_id, "token created");
        tracker.succeed();
        Ok(CreateTokenResult { token_identifier })
    }

    // -----------------------------------------------------------------------
    // mint_token
    // -----------------------------------------------------------------------

    /// Mint new token outputs.
    ///
    /// Only the issuer can mint. The `outputs` specify recipient public keys
    /// and amounts.
    pub async fn mint_token(
        &self,
        issuer_pubkey: &IdentityPubKey,
        token_identifier: &[u8],
        outputs: &[(IdentityPubKey, u128)],
        signer: &impl WalletSigner,
    ) -> Result<MintTokenResult, OperationError> {
        let mut tracker = self.tracker(OperationKind::MintToken);
        let op_id = tracker.id();

        if let Err(e) = self.check_cancelled() {
            return Err(tracker.fail(OperationStep::Auth, e));
        }

        if self.inner.wallet_store.resolve(issuer_pubkey).is_none() {
            return Err(tracker.fail(OperationStep::Auth, SdkError::WalletNotFound));
        }

        let t = Instant::now();
        let authed = match self.authenticate(signer).await {
            Ok(a) => a,
            Err(e) => return Err(tracker.fail(OperationStep::Auth, e)),
        };
        tracker.step_ok(OperationStep::Auth, t.elapsed());

        let token_id_bytes = Bytes::copy_from_slice(token_identifier);

        let mint_input = TokenMintInput {
            issuer_public_key: Bytes::copy_from_slice(issuer_pubkey),
            token_identifier: Some(token_id_bytes.clone()),
        };

        let partial_outputs: Vec<PartialTokenOutput> = outputs
            .iter()
            .map(|(recipient_pk, amount)| PartialTokenOutput {
                owner_public_key: Bytes::copy_from_slice(recipient_pk),
                withdraw_bond_sats: config::constants::DEFAULT_WITHDRAW_BOND_SATS,
                withdraw_relative_block_locktime:
                    config::constants::DEFAULT_WITHDRAW_RELATIVE_LOCKTIME,
                token_identifier: token_id_bytes.clone(),
                token_amount: u128_to_bytes(*amount),
            })
            .collect();

        let partial_tx = PartialTokenTransaction {
            version: TOKEN_TX_VERSION,
            token_transaction_metadata: Some(build_metadata(&self.inner.config.network)),
            token_inputs: Some(
                spark_token::partial_token_transaction::TokenInputs::MintInput(mint_input),
            ),
            partial_token_outputs: partial_outputs,
        };

        let t = Instant::now();
        let tx_hash = hash::hash_partial_token_transaction(&partial_tx);
        let der = match sign_digest_der(signer, &tx_hash) {
            Ok(d) => d,
            Err(e) => return Err(tracker.fail(OperationStep::Signing, e)),
        };
        tracker.step_ok(OperationStep::Signing, t.elapsed());

        let t = Instant::now();
        let resp = match authed
            .broadcast_transaction(BroadcastTransactionRequest {
                identity_public_key: Bytes::copy_from_slice(issuer_pubkey),
                partial_token_transaction: Some(partial_tx),
                token_transaction_owner_signatures: vec![SignatureWithIndex {
                    signature: Bytes::from(der),
                    input_index: 0,
                }],
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                error!("mint_token broadcast failed: {e}");
                return Err(tracker.fail(OperationStep::TokenBroadcast, SdkError::TransportFailed));
            }
        };
        tracker.step_ok(OperationStep::TokenBroadcast, t.elapsed());

        info!(op_id = %op_id, recipients = outputs.len(), "tokens minted");
        tracker.succeed();
        Ok(MintTokenResult {
            final_tx: resp.final_token_transaction,
        })
    }

    // -----------------------------------------------------------------------
    // freeze_tokens
    // -----------------------------------------------------------------------

    /// Freeze (or unfreeze) tokens owned by a target public key.
    ///
    /// Only the token issuer can freeze. The issuer signs the freeze payload
    /// with their identity key.
    pub async fn freeze_tokens(
        &self,
        issuer_pubkey: &IdentityPubKey,
        target_owner_pubkey: &IdentityPubKey,
        token_identifier: &[u8],
        should_unfreeze: bool,
        signer: &impl WalletSigner,
    ) -> Result<FreezeTokensResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(issuer_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();

        // The coordinator is the operator whose identity key we use in the payload.
        let coordinator = self.inner.config.network.coordinator();
        let coordinator_pk = crate::utils::hex_decode(coordinator.identity_public_key)
            .ok_or(SdkError::InvalidRequest)?;

        let payload = FreezeTokensPayload {
            version: 1,
            owner_public_key: Bytes::copy_from_slice(target_owner_pubkey),
            token_public_key: None,
            token_identifier: Some(Bytes::copy_from_slice(token_identifier)),
            issuer_provided_timestamp: now.as_secs(),
            operator_identity_public_key: Bytes::from(coordinator_pk),
            should_unfreeze,
        };

        // Serialize the payload and sign.
        let payload_bytes = prost::Message::encode_to_vec(&payload);
        let sig_der = signer.sign_ecdsa_message(&payload_bytes);

        let resp = authed
            .freeze_tokens(FreezeTokensRequest {
                freeze_tokens_payload: Some(payload),
                issuer_signature: Bytes::from(sig_der),
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        Ok(FreezeTokensResult {
            impacted_output_ids: resp.impacted_output_ids,
            impacted_token_amount: resp.impacted_token_amount.to_vec(),
        })
    }

    // -----------------------------------------------------------------------
    // query_token_metadata
    // -----------------------------------------------------------------------

    /// Query metadata for one or more tokens by identifier.
    pub async fn query_token_metadata(
        &self,
        token_identifiers: Vec<Bytes>,
        signer: &impl WalletSigner,
    ) -> Result<QueryTokenMetadataResponse, SdkError> {
        self.check_cancelled()?;

        let authed = self.authenticate(signer).await?;

        authed
            .query_token_metadata(QueryTokenMetadataRequest {
                token_identifiers,
                issuer_public_keys: vec![],
            })
            .await
            .map_err(|_| SdkError::TransportFailed)
    }

    // -----------------------------------------------------------------------
    // query_token_transactions
    // -----------------------------------------------------------------------

    /// Query token transaction history.
    pub async fn query_token_transactions(
        &self,
        request: QueryTokenTransactionsRequest,
        signer: &impl WalletSigner,
    ) -> Result<QueryTokenTransactionsResponse, SdkError> {
        self.check_cancelled()?;

        let authed = self.authenticate(signer).await?;

        authed
            .query_token_transactions(request)
            .await
            .map_err(|_| SdkError::TransportFailed)
    }

    // -----------------------------------------------------------------------
    // query_token_balances (local)
    // -----------------------------------------------------------------------

    /// Query token balances for all tokens held by the wallet.
    pub async fn query_token_balances(
        &self,
        pubkey: &IdentityPubKey,
    ) -> Result<Vec<TokenBalance>, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        // Query from local store.
        let token_ids = self.inner.token_store.list_token_ids()?;
        let mut balances = Vec::with_capacity(token_ids.len());

        for tid in token_ids {
            let amount = self.inner.token_store.get_balance(&tid)?;
            if amount > 0 {
                balances.push(TokenBalance {
                    token_id: tid,
                    amount,
                });
            }
        }

        Ok(balances)
    }
}
