//! BTC leaf transfers: send.
//!
//! # Send Transfer Flow
//!
//! A Spark transfer is a **two-phase key rotation** through an ephemeral
//! intermediate key:
//!
//! 1. **Select and reserve** leaves covering the amount.
//! 2. **Ephemeral key generation**: Per leaf, generate a random ephemeral
//!    keypair. The ephemeral key bridges sender → receiver.
//! 3. **Key tweak**: `tweak = current_key - ephemeral_key`. VSS-split the
//!    tweak and build `SendLeafKeyTweak` per operator.
//! 4. **`secret_cipher`**: ECIES-encrypt the ephemeral private key to the
//!    receiver's identity public key.
//! 5. **Refund transactions**: Build CPFP, direct-from-CPFP, and direct
//!    refund txs paying to the **ephemeral** public key.
//! 6. **FROST signing**: Get operator signing commitments, then FROST-sign
//!    each refund tx with the sender's **current** key.
//! 7. **`TransferPackage`**: Assemble `UserSignedTxSigningJob`s, encrypted
//!    `key_tweak_package`, and package-level user signature.
//! 8. **Submit**: Call `start_transfer_v2` with the `TransferPackage`.
//! 9. **Finalize**: Mark reserved leaves as spent.
//!
//! The receiver later claims the transfer (Phase 2) by decrypting the
//! ephemeral key and rotating from ephemeral → receiver-derived key.
//!
//! See [`crate::operations::claim`] for the claim (receive) flow.

use std::collections::HashMap;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use signer::WalletSigner;
use transport::spark;

use crate::bitcoin_tx::{
    compressed_to_xonly, create_cpfp_refund_tx, create_direct_refund_tx, parse_tx, serialize_tx,
    taproot_sighash,
};
use crate::frost_bridge::commitment_to_proto;
use crate::tree::{TreeStore, select_leaves_greedy};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

// ---------------------------------------------------------------------------
// Result type
// ---------------------------------------------------------------------------

/// Response from a send transfer operation.
pub struct SendTransferResult {
    /// The transfer proto returned by the coordinator.
    pub transfer: Option<spark::Transfer>,
}

// ---------------------------------------------------------------------------
// Internal: per-leaf send data
// ---------------------------------------------------------------------------

/// Prepared send data for a single leaf before FROST signing.
#[allow(dead_code)] // ephemeral_sk/pk stored for potential retry/debug paths.
struct LeafSendContext {
    leaf_id: String,
    /// Sender's current signing secret key for this leaf.
    current_sk: SecretKey,
    /// Sender's current signing public key for this leaf.
    current_pk: PublicKey,
    /// Randomly generated ephemeral secret key.
    ephemeral_sk: SecretKey,
    /// Ephemeral public key (refund outputs pay here).
    ephemeral_pk: PublicKey,
    /// The verifying (group aggregate) public key for FROST.
    verifying_public_key: [u8; 33],
    /// CPFP refund transaction.
    cpfp_refund_tx: bitcoin::Transaction,
    /// Direct-from-CPFP refund transaction.
    direct_from_cpfp_refund_tx: bitcoin::Transaction,
    /// Direct refund transaction (if direct_tx exists on the leaf).
    direct_refund_tx: Option<bitcoin::Transaction>,
    /// Prev out from node_tx (for CPFP and direct-from-CPFP sighash).
    prev_out: bitcoin::TxOut,
    /// Prev out from direct_tx (for direct sighash), if present.
    direct_prev_out: Option<bitcoin::TxOut>,
    /// FROST nonces for CPFP refund.
    cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    /// FROST nonces for direct-from-CPFP refund.
    direct_from_cpfp_nonce_pair: spark_crypto::frost::FrostNoncePair,
    /// FROST nonces for direct refund (if applicable).
    direct_nonce_pair: Option<spark_crypto::frost::FrostNoncePair>,
    /// ECIES-encrypted ephemeral key for receiver.
    secret_cipher: Vec<u8>,
    /// Per-operator SendLeafKeyTweak data (before ECDSA signature over leaf_id||transfer_id||secret_cipher).
    per_operator_tweaks: Vec<PerOperatorTweak>,
}

/// Per-operator tweak data for a single leaf.
struct PerOperatorTweak {
    secret_share_tweak: spark::SecretShare,
    pubkey_shares_tweak: HashMap<String, Bytes>,
}

// ---------------------------------------------------------------------------
// Sdk::send_transfer
// ---------------------------------------------------------------------------

impl<W, T, K> Sdk<W, T, K>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
{
    /// Send BTC to a receiver via a Spark transfer.
    ///
    /// Implements the full Phase 1 of the two-phase transfer protocol:
    /// key rotation from sender's current key to a randomly generated
    /// ephemeral key, with the ephemeral private key ECIES-encrypted
    /// for the receiver.
    pub async fn send_transfer(
        &self,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        amount_sats: u64,
        signer: &impl WalletSigner,
    ) -> Result<SendTransferResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;
        let network = bitcoin_network(self.inner.config.network.network);

        // 1. Select and reserve leaves.
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, _total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        // From here, any error should cancel the reservation.
        let result = self
            .send_transfer_inner(
                &authed,
                &reservation,
                sender_pubkey,
                receiver_pubkey,
                signer,
                network,
            )
            .await;

        match result {
            Ok(resp) => {
                // Finalize: remove spent leaves.
                self.inner
                    .tree_store
                    .finalize_reservation(reservation.id, None)?;
                Ok(resp)
            }
            Err(e) => {
                // Cancel reservation on failure.
                let _ = self.inner.tree_store.cancel_reservation(reservation.id);
                Err(e)
            }
        }
    }

    /// Inner send logic, separated for clean reservation error handling.
    async fn send_transfer_inner(
        &self,
        authed: &transport::grpc::AuthenticatedTransport<'_>,
        reservation: &crate::tree::LeafReservation,
        sender_pubkey: &IdentityPubKey,
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
        network: bitcoin::Network,
    ) -> Result<SendTransferResult, SdkError> {
        let secp = Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let mut rng = rand::thread_rng();

        // 2. Prepare per-leaf send contexts: ephemeral key, tweaks, refund txs, nonces.
        let mut leaf_contexts: Vec<LeafSendContext> = Vec::with_capacity(reservation.leaves.len());

        for leaf in &reservation.leaves {
            let (current_sk, current_pk) = signer
                .derive_signing_keypair(&leaf.id)
                .map_err(|_| SdkError::SigningFailed)?;

            // Generate random ephemeral keypair.
            let ephemeral_sk = SecretKey::new(&mut rng);
            let ephemeral_pk = PublicKey::from_secret_key(&secp, &ephemeral_sk);

            // Compute key tweak: current - ephemeral.
            let key_tweak = signer
                .subtract_secret_keys(&current_sk, &ephemeral_sk)
                .map_err(|_| SdkError::SigningFailed)?;

            // VSS-split the tweak.
            let shares = signer
                .vss_split(
                    &key_tweak.secret_bytes(),
                    threshold,
                    num_operators,
                    &mut rng,
                )
                .map_err(|_| SdkError::SigningFailed)?;

            // Build pubkey_shares_tweak: operator ID -> compressed pubkey of their share.
            let mut pubkey_shares_tweak: HashMap<String, Bytes> = HashMap::new();
            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let share_sk =
                    SecretKey::from_slice(&share_bytes).map_err(|_| SdkError::SigningFailed)?;
                let share_pk = PublicKey::from_secret_key(&secp, &share_sk);
                pubkey_shares_tweak
                    .insert(operators[i].id.to_string(), Bytes::copy_from_slice(&share_pk.serialize()));
            }

            // Build per-operator tweak data.
            let mut per_operator_tweaks = Vec::with_capacity(num_operators);
            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let proofs: Vec<Bytes> = share
                    .proofs
                    .iter()
                    .map(|p| {
                        let point = p.to_encoded_point(true);
                        Bytes::copy_from_slice(point.as_bytes())
                    })
                    .collect();

                let _ = i; // index used for operator ordering
                per_operator_tweaks.push(PerOperatorTweak {
                    secret_share_tweak: spark::SecretShare {
                        secret_share: Bytes::copy_from_slice(&share_bytes),
                        proofs,
                    },
                    pubkey_shares_tweak: pubkey_shares_tweak.clone(),
                });
            }

            // ECIES-encrypt ephemeral key for receiver.
            let secret_cipher = signer
                .ecies_encrypt(receiver_pubkey, &ephemeral_sk.secret_bytes(), &mut rng)
                .map_err(|_| SdkError::SigningFailed)?;

            // Build refund transactions paying to ephemeral pubkey.
            let ephemeral_xonly =
                compressed_to_xonly(&ephemeral_pk.serialize()).ok_or(SdkError::SigningFailed)?;

            let node_tx = parse_tx(&leaf.node_tx).map_err(|_| SdkError::InvalidRequest)?;
            let prev_out = node_tx
                .output
                .first()
                .ok_or(SdkError::InvalidRequest)?
                .clone();
            let node_txid = node_tx.compute_txid();

            // Extract sequences from existing refund txs.
            let cpfp_seq = extract_sequence(leaf.refund_tx.as_deref());
            let direct_from_cpfp_seq = extract_sequence(leaf.direct_from_cpfp_refund_tx.as_deref());

            let cpfp_refund_tx = create_cpfp_refund_tx(
                node_txid,
                leaf.vout,
                prev_out.value,
                cpfp_seq,
                &ephemeral_xonly,
                network,
            );

            let direct_from_cpfp_refund_tx = create_direct_refund_tx(
                node_txid,
                leaf.vout,
                prev_out.value,
                direct_from_cpfp_seq,
                &ephemeral_xonly,
                network,
            );

            // Direct refund tx (if direct_tx exists on the leaf).
            let direct_seq = extract_sequence(leaf.direct_refund_tx.as_deref());
            let (direct_refund_tx, direct_prev_out) = if let Some(ref direct_tx_raw) = leaf.direct_tx
            {
                let direct_tx =
                    parse_tx(direct_tx_raw).map_err(|_| SdkError::InvalidRequest)?;
                let dpo = direct_tx
                    .output
                    .first()
                    .ok_or(SdkError::InvalidRequest)?
                    .clone();
                let dtx = create_direct_refund_tx(
                    direct_tx.compute_txid(),
                    0,
                    dpo.value,
                    direct_seq,
                    &ephemeral_xonly,
                    network,
                );
                (Some(dtx), Some(dpo))
            } else {
                (None, None)
            };

            // Generate FROST nonces with the sender's **current** key.
            let signing_share =
                spark_crypto::frost::deserialize_signing_share(&current_sk.secret_bytes())
                    .map_err(|_| SdkError::SigningFailed)?;

            let cpfp_nonce_pair =
                spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
            let direct_from_cpfp_nonce_pair =
                spark_crypto::frost::generate_nonces(&signing_share, &mut rng);
            let direct_nonce_pair = if direct_refund_tx.is_some() {
                Some(spark_crypto::frost::generate_nonces(&signing_share, &mut rng))
            } else {
                None
            };

            leaf_contexts.push(LeafSendContext {
                leaf_id: leaf.id.clone(),
                current_sk,
                current_pk,
                ephemeral_sk,
                ephemeral_pk,
                verifying_public_key: leaf.verifying_public_key,
                cpfp_refund_tx,
                direct_from_cpfp_refund_tx,
                direct_refund_tx,
                prev_out,
                direct_prev_out,
                cpfp_nonce_pair,
                direct_from_cpfp_nonce_pair,
                direct_nonce_pair,
                secret_cipher,
                per_operator_tweaks,
            });
        }

        // 3. Get signing commitments from coordinator.
        //    count = 3: one for CPFP, one for direct, one for direct-from-CPFP.
        let node_ids: Vec<String> = leaf_contexts.iter().map(|c| c.leaf_id.clone()).collect();
        let commitments_resp = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids: node_ids.clone(),
                count: 3,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // Parse the commitment ordering:
        // For node_ids = [A, B] and count = 3, response is:
        //   [commitment_A_0, commitment_B_0, commitment_A_1, commitment_B_1, commitment_A_2, commitment_B_2]
        // Index 0 = CPFP, index 1 = direct, index 2 = direct-from-CPFP.
        let n_leaves = leaf_contexts.len();
        let commitments = &commitments_resp.signing_commitments;

        // 4. Build UserSignedTxSigningJobs with FROST signatures.
        let mut cpfp_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut direct_jobs: Vec<spark::UserSignedTxSigningJob> = Vec::with_capacity(n_leaves);
        let mut direct_from_cpfp_jobs: Vec<spark::UserSignedTxSigningJob> =
            Vec::with_capacity(n_leaves);

        for (leaf_idx, ctx) in leaf_contexts.iter().enumerate() {
            let pk_bytes = Bytes::copy_from_slice(&ctx.current_pk.serialize());

            // CPFP refund: commitment at index (0 * n_leaves + leaf_idx).
            let cpfp_commitment_idx = leaf_idx;
            let cpfp_op_commitments = commitments
                .get(cpfp_commitment_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let cpfp_user_commitment = commitment_to_proto(&ctx.cpfp_nonce_pair.commitment)
                .map_err(|_| SdkError::SigningFailed)?;

            let cpfp_sig = self
                .frost_sign_and_aggregate_send(
                    ctx,
                    &ctx.cpfp_refund_tx,
                    &ctx.cpfp_nonce_pair,
                    cpfp_op_commitments,
                    &ctx.prev_out,
                    signer,
                )
                .await?;

            cpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes.clone(),
                raw_tx: Bytes::copy_from_slice(&serialize_tx(&ctx.cpfp_refund_tx)),
                signing_nonce_commitment: Some(cpfp_user_commitment),
                user_signature: Bytes::copy_from_slice(&cpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: cpfp_op_commitments
                        .signing_nonce_commitments
                        .clone(),
                }),
            });

            // Direct refund: commitment at index (1 * n_leaves + leaf_idx).
            let direct_commitment_idx = n_leaves + leaf_idx;
            if let (Some(dtx), Some(dnp), Some(dpo)) =
                (&ctx.direct_refund_tx, &ctx.direct_nonce_pair, &ctx.direct_prev_out)
            {
                let direct_op_commitments = commitments
                    .get(direct_commitment_idx)
                    .ok_or(SdkError::InvalidOperatorResponse)?;
                let direct_user_commitment = commitment_to_proto(&dnp.commitment)
                    .map_err(|_| SdkError::SigningFailed)?;

                let direct_sig = self
                    .frost_sign_and_aggregate_send(ctx, dtx, dnp, direct_op_commitments, dpo, signer)
                    .await?;

                direct_jobs.push(spark::UserSignedTxSigningJob {
                    leaf_id: ctx.leaf_id.clone(),
                    signing_public_key: pk_bytes.clone(),
                    raw_tx: Bytes::copy_from_slice(&serialize_tx(dtx)),
                    signing_nonce_commitment: Some(direct_user_commitment),
                    user_signature: Bytes::copy_from_slice(&direct_sig),
                    signing_commitments: Some(spark::SigningCommitments {
                        signing_commitments: direct_op_commitments
                            .signing_nonce_commitments
                            .clone(),
                    }),
                });
            }

            // Direct-from-CPFP refund: commitment at index (2 * n_leaves + leaf_idx).
            let dfcpfp_commitment_idx = 2 * n_leaves + leaf_idx;
            let dfcpfp_op_commitments = commitments
                .get(dfcpfp_commitment_idx)
                .ok_or(SdkError::InvalidOperatorResponse)?;
            let dfcpfp_user_commitment =
                commitment_to_proto(&ctx.direct_from_cpfp_nonce_pair.commitment)
                    .map_err(|_| SdkError::SigningFailed)?;

            let dfcpfp_sig = self
                .frost_sign_and_aggregate_send(
                    ctx,
                    &ctx.direct_from_cpfp_refund_tx,
                    &ctx.direct_from_cpfp_nonce_pair,
                    dfcpfp_op_commitments,
                    &ctx.prev_out,
                    signer,
                )
                .await?;

            direct_from_cpfp_jobs.push(spark::UserSignedTxSigningJob {
                leaf_id: ctx.leaf_id.clone(),
                signing_public_key: pk_bytes,
                raw_tx: Bytes::copy_from_slice(&serialize_tx(&ctx.direct_from_cpfp_refund_tx)),
                signing_nonce_commitment: Some(dfcpfp_user_commitment),
                user_signature: Bytes::copy_from_slice(&dfcpfp_sig),
                signing_commitments: Some(spark::SigningCommitments {
                    signing_commitments: dfcpfp_op_commitments
                        .signing_nonce_commitments
                        .clone(),
                }),
            });
        }

        // 5. Build key_tweak_package: operator_id -> ECIES(operator_pk, SendLeafTweaks).
        //    The transfer_id is not known yet (coordinator assigns it), so we use
        //    an empty string for the ECDSA signature payload initially. The
        //    coordinator will populate transfer_id in the response.
        //    For the signature over SHA256(leaf_id||transfer_id||secret_cipher),
        //    we leave transfer_id empty -- the coordinator accepts this for the
        //    TransferPackage flow where the transfer_id is assigned server-side.
        let transfer_id_bytes = b""; // Coordinator assigns transfer_id.

        let mut key_tweak_package: HashMap<String, Bytes> = HashMap::new();

        for (op_idx, op) in operators.iter().enumerate() {
            let mut tweak_list: Vec<spark::SendLeafKeyTweak> =
                Vec::with_capacity(leaf_contexts.len());

            for ctx in &leaf_contexts {
                // ECDSA signature: SHA256(leaf_id || transfer_id || secret_cipher).
                let mut sig_payload = Vec::new();
                sig_payload.extend_from_slice(ctx.leaf_id.as_bytes());
                sig_payload.extend_from_slice(transfer_id_bytes);
                sig_payload.extend_from_slice(&ctx.secret_cipher);

                let payload_hash = bitcoin::hashes::sha256::Hash::hash(&sig_payload);
                let sig_compact =
                    signer.sign_ecdsa_digest_compact(payload_hash.as_byte_array());

                let op_tweak = &ctx.per_operator_tweaks[op_idx];

                tweak_list.push(spark::SendLeafKeyTweak {
                    leaf_id: ctx.leaf_id.clone(),
                    secret_share_tweak: Some(op_tweak.secret_share_tweak.clone()),
                    pubkey_shares_tweak: op_tweak.pubkey_shares_tweak.clone(),
                    secret_cipher: Bytes::copy_from_slice(&ctx.secret_cipher),
                    signature: Bytes::copy_from_slice(&sig_compact),
                    refund_signature: Bytes::new(),
                    direct_refund_signature: Bytes::new(),
                    direct_from_cpfp_refund_signature: Bytes::new(),
                });
            }

            // Encode SendLeafKeyTweaks as proto bytes.
            let tweaks_proto = spark::SendLeafKeyTweaks {
                leaves_to_send: tweak_list,
            };
            let tweaks_bytes = prost::Message::encode_to_vec(&tweaks_proto);

            // ECIES-encrypt for this operator.
            let op_pubkey =
                hex_decode_pubkey(op.identity_public_key).ok_or(SdkError::InvalidRequest)?;
            let encrypted = signer
                .ecies_encrypt(&op_pubkey, &tweaks_bytes, &mut rng)
                .map_err(|_| SdkError::SigningFailed)?;

            key_tweak_package.insert(op.id.to_string(), Bytes::from(encrypted));
        }

        // 6. Sign the transfer package (user_signature over package hash).
        //    Build the signing payload: concatenation of all refund tx bytes in order.
        let mut package_payload = Vec::new();
        for job in &cpfp_jobs {
            package_payload.extend_from_slice(&job.raw_tx);
        }
        for job in &direct_jobs {
            package_payload.extend_from_slice(&job.raw_tx);
        }
        for job in &direct_from_cpfp_jobs {
            package_payload.extend_from_slice(&job.raw_tx);
        }
        let package_sig = signer.sign_ecdsa_message(&package_payload);

        // 7. Assemble TransferPackage.
        let transfer_package = spark::TransferPackage {
            leaves_to_send: cpfp_jobs,
            direct_leaves_to_send: direct_jobs,
            direct_from_cpfp_leaves_to_send: direct_from_cpfp_jobs,
            key_tweak_package,
            user_signature: Bytes::from(package_sig),
            hash_variant: spark::HashVariant::V2 as i32,
        };

        // 8. Build and submit StartTransferRequest.
        let expiry_time = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let expiry = now + std::time::Duration::from_secs(3600); // 1 hour
            Some(prost_types::Timestamp {
                seconds: expiry.as_secs() as i64,
                nanos: 0,
            })
        };

        let transfer_resp = authed
            .start_transfer_v2(spark::StartTransferRequest {
                transfer_id: String::new(), // Coordinator assigns.
                owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
                receiver_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                transfer_package: Some(transfer_package),
                expiry_time,
                leaves_to_send: Vec::new(),
                spark_invoice: String::new(),
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        Ok(SendTransferResult {
            transfer: transfer_resp.transfer,
        })
    }

    /// FROST sign a refund tx on the **send** side and aggregate.
    ///
    /// Uses the sender's **current** key (not tweaked), which is the key
    /// that currently controls the leaf. The FROST signature proves the
    /// sender authorized the refund tx.
    async fn frost_sign_and_aggregate_send(
        &self,
        ctx: &LeafSendContext,
        refund_tx: &bitcoin::Transaction,
        nonce_pair: &spark_crypto::frost::FrostNoncePair,
        operator_commitments: &spark::RequestedSigningCommitments,
        prev_out: &bitcoin::TxOut,
        _signer: &impl WalletSigner,
    ) -> Result<Vec<u8>, SdkError> {
        // Parse operator commitments from the proto.
        let mut op_commitments = std::collections::BTreeMap::new();
        for (hex_id, proto_commitment) in &operator_commitments.signing_nonce_commitments {
            let id = crate::frost_bridge::identifier_from_hex(hex_id)?;
            let commitment = spark_crypto::frost::commitments_from_components(
                &proto_commitment.hiding,
                &proto_commitment.binding,
            )
            .map_err(|_| SdkError::InvalidOperatorResponse)?;
            op_commitments.insert(id, commitment);
        }

        // Compute sighash for the refund tx.
        let sighash = taproot_sighash(refund_tx, 0, std::slice::from_ref(prev_out))
            .map_err(|_| SdkError::SigningFailed)?;

        let user_identifier = spark_crypto::frost::user_identifier();

        // Build complete commitments map: operator + user.
        let mut all_commitments = op_commitments;
        all_commitments.insert(user_identifier, nonce_pair.commitment);

        let verifying_key = PublicKey::from_slice(&ctx.verifying_public_key)
            .map_err(|_| SdkError::InvalidRequest)?;

        // FROST round 2: sign with sender's current key.
        let user_share = spark_crypto::frost::sign_as_user(
            &sighash,
            &ctx.current_sk,
            &ctx.current_pk,
            &verifying_key,
            &nonce_pair.nonces,
            all_commitments.clone(),
        )
        .map_err(|_| SdkError::SigningFailed)?;

        // We don't have operator signature shares at this point -- the
        // TransferPackage flow sends the user's share + commitment to the
        // coordinator, which aggregates with operator shares server-side.
        // Return the user's signature share serialized.
        let share_bytes = crate::frost_bridge::serialize_signature_share(&user_share);
        Ok(share_bytes)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract nSequence from a raw refund transaction. Returns default 2000
/// if the bytes are empty or unparseable.
fn extract_sequence(raw: Option<&[u8]>) -> bitcoin::Sequence {
    let bytes = match raw {
        Some(b) if !b.is_empty() => b,
        _ => return bitcoin::Sequence::from_consensus(2000),
    };
    deserialize::<bitcoin::Transaction>(bytes)
        .ok()
        .and_then(|tx| tx.input.first().map(|i| i.sequence))
        .unwrap_or(bitcoin::Sequence::from_consensus(2000))
}

/// Decode a hex-encoded compressed public key (66 hex chars) to 33 bytes.
fn hex_decode_pubkey(hex: &str) -> Option<[u8; 33]> {
    if hex.len() != 66 {
        return None;
    }
    let mut out = [0u8; 33];
    for (i, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Map `sdk_core::Network` to `bitcoin::Network`.
fn bitcoin_network(network: sdk_core::Network) -> bitcoin::Network {
    match network {
        sdk_core::Network::Mainnet => bitcoin::Network::Bitcoin,
        sdk_core::Network::Regtest => bitcoin::Network::Regtest,
    }
}
