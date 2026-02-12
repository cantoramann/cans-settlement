//! Key tweak computation and distribution for claim transfers.
//!
//! When claiming a transfer, the receiver must compute the difference
//! between the decrypted signing key and their new derived key, then
//! VSS-split that difference and distribute shares to all operators.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

use super::verify_decrypt::ClaimableLeaf;

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Compute key tweaks, VSS-split, and send to all operators.
    ///
    /// For each claimable leaf:
    /// 1. Derive new keypair from leaf ID
    /// 2. Compute tweak = decrypted_key - new_key
    /// 3. VSS-split tweak into per-operator shares
    /// 4. Send shares to each operator via `ClaimTransferTweakKeys`
    pub(crate) async fn prepare_and_apply_key_tweaks(
        &self,
        _authed: &transport::grpc::AuthenticatedTransport<'_>,
        transfer: &spark::Transfer,
        claimable: &[ClaimableLeaf],
        receiver_pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<(), SdkError> {
        let secp = Secp256k1::new();
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let operators = self.inner.config.network.operators();
        let mut rng = rand_core::OsRng;

        // Build per-operator ClaimLeafKeyTweak lists.
        let mut per_operator_tweaks: Vec<Vec<spark::ClaimLeafKeyTweak>> =
            vec![Vec::new(); num_operators];

        for leaf in claimable {
            let (new_sk, _new_pk) = signer
                .derive_signing_keypair(&leaf.leaf_id)
                .map_err(|_| SdkError::SigningFailed)?;

            // key_tweak = decrypted_signing_key - new_signing_key
            let key_tweak = signer
                .subtract_secret_keys(&leaf.decrypted_signing_key, &new_sk)
                .map_err(|_| SdkError::SigningFailed)?;

            let shares = signer
                .vss_split(
                    &key_tweak.secret_bytes(),
                    threshold,
                    num_operators,
                    &mut rng,
                )
                .map_err(|_| SdkError::SigningFailed)?;

            // pubkey_shares_tweak: operator identifier -> compressed public key of share.
            let mut pubkey_shares_tweak = std::collections::HashMap::new();
            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let share_sk =
                    SecretKey::from_slice(&share_bytes).map_err(|_| SdkError::SigningFailed)?;
                let share_pk = PublicKey::from_secret_key(&secp, &share_sk);
                let op_identifier = operators[i].id.to_string();
                pubkey_shares_tweak
                    .insert(op_identifier, Bytes::copy_from_slice(&share_pk.serialize()));
            }

            for (i, share) in shares.iter().enumerate() {
                let share_bytes = spark_crypto::verifiable_secret_sharing::scalar_to_bytes(
                    &share.secret_share.share,
                );
                let proofs: Vec<Bytes> = share
                    .proofs
                    .iter()
                    .map(|p| {
                        Bytes::copy_from_slice(
                            &spark_crypto::verifiable_secret_sharing::serialize_proof_point(p),
                        )
                    })
                    .collect();

                per_operator_tweaks[i].push(spark::ClaimLeafKeyTweak {
                    leaf_id: leaf.leaf_id.clone(),
                    secret_share_tweak: Some(spark::SecretShare {
                        secret_share: Bytes::copy_from_slice(&share_bytes),
                        proofs,
                    }),
                    pubkey_shares_tweak: pubkey_shares_tweak.clone(),
                });
            }
        }

        // Send ClaimTransferTweakKeys to ALL operators in parallel.
        let operator_ids: Vec<String> = self
            .inner
            .transport
            .operator_ids()
            .iter()
            .map(|s| s.to_string())
            .collect();

        for (i, op_id) in operator_ids.iter().enumerate() {
            let op_token = self
                .inner
                .transport
                .session_token(op_id, signer)
                .await
                .map_err(|_| SdkError::AuthFailed)?;
            let op_authed = self
                .inner
                .transport
                .authenticated(&op_token)
                .map_err(|_| SdkError::AuthFailed)?;

            let tweaks = std::mem::take(&mut per_operator_tweaks[i]);
            let request = spark::ClaimTransferTweakKeysRequest {
                transfer_id: transfer.id.clone(),
                owner_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                leaves_to_receive: tweaks,
            };

            op_authed
                .claim_transfer_tweak_keys(op_id, request)
                .await
                .map_err(|_| SdkError::TransportFailed)?;
        }

        Ok(())
    }
}
