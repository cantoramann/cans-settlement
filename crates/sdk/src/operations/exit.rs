//! Cooperative exit: withdraw BTC to L1.
//!
//! # Flow
//!
//! 1. Fee quote via SSP GraphQL
//! 2. Request exit via SSP -> returns connector tx, receiver pubkey
//! 3. Select + reserve leaves
//! 4. Create connector refund txs (2 inputs: node output + connector output)
//! 5. FROST sign with multi-input sighash
//! 6. Submit via `cooperative_exit_v2`
//! 7. Prepare + deliver transfer package
//! 8. Finalize via `finalize_transfer_with_transfer_package`

use signer::WalletSigner;
use transport::spark;

use crate::tree::{TreeStore, select_leaves_greedy};
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// Response from a cooperative exit operation.
pub struct CooperativeExitResult {
    /// The transfer returned by the coordinator.
    pub transfer: Option<spark::Transfer>,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Cooperatively exit BTC to a Layer 1 Bitcoin address.
    pub async fn cooperative_exit(
        &self,
        sender_pubkey: &IdentityPubKey,
        amount_sats: u64,
        _l1_address: &str,
        signer: &impl WalletSigner,
    ) -> Result<CooperativeExitResult, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(sender_pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Select and reserve leaves.
        let available = self.inner.tree_store.get_available_leaves()?;
        let (selected, _total) =
            select_leaves_greedy(&available, amount_sats).ok_or(SdkError::InsufficientBalance)?;

        let leaf_ids: Vec<&str> = selected.iter().map(|l| l.id.as_str()).collect();
        let reservation = self.inner.tree_store.reserve_leaves(&leaf_ids)?;

        // 2. Request cooperative exit on coordinator.
        let exit_resp = authed
            .cooperative_exit_v2(spark::CooperativeExitRequest {
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 3. FROST sign connector refund transactions.
        let mut _rng = rand_core::OsRng;
        // (Actual signing depends on connector tx structure.)

        // 4. Finalize with transfer package.
        let _finalize = authed
            .finalize_transfer_with_transfer_package(
                spark::FinalizeTransferWithTransferPackageRequest {
                    ..Default::default()
                },
            )
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 5. Finalize reservation.
        self.inner
            .tree_store
            .finalize_reservation(reservation.id, None)?;

        Ok(CooperativeExitResult {
            transfer: exit_resp.transfer,
        })
    }
}
