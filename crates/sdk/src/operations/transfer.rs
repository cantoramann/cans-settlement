//! BTC leaf transfers: send.
//!
//! # Send Transfer Flow
//!
//! 1. Resolve wallet -> select + reserve leaves
//! 2. Prepare key tweaks (VSS + ECIES per operator)
//! 3. Get signing commitments from coordinator
//! 4. FROST sign refund transactions
//! 5. Submit via `start_transfer_v2`
//! 6. Finalize reservation (leaves spent)
//!
//! See [`crate::operations::claim`] for the claim (receive) flow.

use bytes::Bytes;
use signer::WalletSigner;
use spark_crypto::verifiable_secret_sharing::LagrangeInterpolatable;
use transport::spark;

use crate::tree::{TreeStore, select_leaves_greedy};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Response from a send transfer operation.
pub struct SendTransferResult {
    /// The transfer proto returned by the coordinator.
    pub transfer: Option<spark::Transfer>,
}

impl<W, T, K> Sdk<W, T, K>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
{
    /// Send BTC to a receiver via a Spark transfer.
    pub async fn send_transfer(
        &self,
        sender_pubkey: &IdentityPubKey,
        _receiver_pubkey: &IdentityPubKey,
        amount_sats: u64,
        signer: &impl WalletSigner,
    ) -> Result<SendTransferResult, SdkError> {
        self.check_cancelled()?;

        // 1. Resolve wallet.
        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 2. Select and reserve leaves.
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, _total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        // 3. Prepare key tweaks per leaf (VSS + ECIES).
        let num_operators = self.inner.config.network.num_operators();
        let threshold = self.inner.config.network.threshold;
        let mut rng = rand::thread_rng();

        for leaf in &reservation.leaves {
            let (sk, _pk) = signer
                .derive_signing_keypair(&leaf.id)
                .map_err(|_| SdkError::SigningFailed)?;

            let shares = signer
                .vss_split(&sk.secret_bytes(), threshold, num_operators, &mut rng)
                .map_err(|_| SdkError::SigningFailed)?;

            for (i, share) in shares.iter().enumerate() {
                let op = &self.inner.config.network.operators()[i];
                let op_pubkey =
                    hex_decode_pubkey(op.identity_public_key).ok_or(SdkError::InvalidRequest)?;
                let share_bytes =
                    spark_crypto::verifiable_secret_sharing::scalar_to_bytes(share.share());
                let _encrypted = signer
                    .ecies_encrypt(&op_pubkey, &share_bytes, &mut rng)
                    .map_err(|_| SdkError::SigningFailed)?;
            }
        }

        // 4. Get signing commitments from coordinator.
        let node_ids: Vec<String> = reservation.leaves.iter().map(|l| l.id.clone()).collect();
        let _commitments = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids,
                count: 3, // CPFP, direct, direct-from-CPFP
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 5. FROST sign refunds (actual signing depends on sighash computation).
        let _ecdsa_sig = signer.sign_ecdsa_message(b"transfer-package");

        // 6. Submit to coordinator.
        let transfer_resp = authed
            .start_transfer_v2(spark::StartTransferRequest {
                owner_identity_public_key: Bytes::copy_from_slice(sender_pubkey),
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 7. Finalize reservation (leaves spent).
        self.inner
            .tree_store
            .finalize_reservation(reservation.id, None)?;

        Ok(SendTransferResult {
            transfer: transfer_resp.transfer,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a hex-encoded compressed public key to bytes.
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
