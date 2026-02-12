//! Create invoice: VSS-split preimage and store shares across operators.
//!
//! Distributes the preimage to all operators so the coordinator can
//! reconstruct it when the receiver claims the Lightning payment.

use bytes::Bytes;
use signer::WalletSigner;
use spark_crypto::verifiable_secret_sharing::LagrangeInterpolatable;
use tracing::error;
use transport::spark;

use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

use super::CreateInvoiceResult;

/// VSS-split a preimage and store each share on the corresponding operator.
pub(super) async fn create_invoice_inner<W, T, K, S>(
    sdk: &Sdk<W, T, K, S>,
    receiver_pubkey: &IdentityPubKey,
    preimage: &[u8; 32],
    invoice_string: &str,
    signer: &impl WalletSigner,
) -> Result<CreateInvoiceResult, SdkError>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    sdk.check_cancelled()?;

    let _wallet = sdk
        .inner
        .wallet_store
        .resolve(receiver_pubkey)
        .ok_or(SdkError::WalletNotFound)?;

    use bitcoin::hashes::{Hash, sha256};
    let payment_hash: [u8; 32] = *sha256::Hash::hash(preimage).as_byte_array();

    // VSS-split preimage.
    let mut rng = rand_core::OsRng;
    let num_operators = sdk.inner.config.network.num_operators();
    let threshold = sdk.inner.config.network.threshold;
    let shares = signer
        .vss_split(preimage, threshold, num_operators, &mut rng)
        .map_err(|_| SdkError::SigningFailed)?;

    // Store shares on ALL operators.
    let operator_ids: Vec<String> = sdk
        .inner
        .transport
        .operator_ids()
        .iter()
        .map(|s| s.to_string())
        .collect();

    for (i, op_id) in operator_ids.iter().enumerate() {
        let op_token = sdk
            .inner
            .transport
            .session_token(op_id, signer)
            .await
            .map_err(|e| {
                error!("session_token for operator {op_id} failed: {e}");
                SdkError::AuthFailed
            })?;
        let op_authed = sdk.inner.transport.authenticated(&op_token).map_err(|e| {
            error!("authenticated for operator {op_id} failed: {e}");
            SdkError::AuthFailed
        })?;

        let share_bytes =
            spark_crypto::verifiable_secret_sharing::scalar_to_bytes(shares[i].share());
        let proofs: Vec<Bytes> = shares[i]
            .proofs
            .iter()
            .map(|p| {
                Bytes::copy_from_slice(
                    &spark_crypto::verifiable_secret_sharing::serialize_proof_point(p),
                )
            })
            .collect();

        op_authed
            .store_preimage_share(
                op_id,
                spark::StorePreimageShareRequest {
                    payment_hash: Bytes::copy_from_slice(&payment_hash),
                    preimage_share: Some(spark::SecretShare {
                        secret_share: Bytes::copy_from_slice(&share_bytes),
                        proofs,
                    }),
                    threshold: threshold as u32,
                    invoice_string: invoice_string.to_owned(),
                    user_identity_public_key: Bytes::copy_from_slice(receiver_pubkey),
                },
            )
            .await
            .map_err(|e| {
                error!("store_preimage_share for operator {op_id} failed: {e}");
                SdkError::TransportFailed
            })?;
    }

    Ok(CreateInvoiceResult { payment_hash })
}
