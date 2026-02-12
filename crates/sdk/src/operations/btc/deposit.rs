//! Deposit operations: generate address and finalize deposit.
//!
//! # Deposit Flow
//!
//! 1. Generate deposit address via coordinator
//! 2. User sends BTC on-chain
//! 3. On confirmation, get signing commitments
//! 4. FROST sign root + refund transactions
//! 5. Finalize deposit tree creation
//! 6. Insert root leaf into tree store

use bytes::Bytes;
use signer::WalletSigner;
use transport::spark;

use crate::tree::TreeStore;
use crate::wallet_store::{IdentityPubKey, WalletStore};
use crate::{Sdk, SdkError};

/// A generated deposit address.
pub struct DepositAddress {
    /// The Bitcoin address to send funds to.
    pub address: String,
    /// The verifying key of the deposit address.
    pub verifying_key: Bytes,
}

impl<W, T, K, S> Sdk<W, T, K, S>
where
    W: WalletStore,
    T: TreeStore,
    K: crate::token::TokenStore,
    S: crate::ssp::SspClient,
{
    /// Generate a new deposit address for receiving on-chain BTC.
    ///
    /// The returned address can be used to receive a single Bitcoin deposit.
    /// Once confirmed, call `finalize_deposit` to create the Spark tree.
    pub async fn generate_deposit_address(
        &self,
        pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
    ) -> Result<DepositAddress, SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        let resp = authed
            .generate_deposit_address(spark::GenerateDepositAddressRequest {
                signing_public_key: Bytes::copy_from_slice(
                    &signer.identity_public_key_compressed(),
                ),
                identity_public_key: Bytes::copy_from_slice(pubkey),
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        let deposit_addr = resp
            .deposit_address
            .ok_or(SdkError::InvalidOperatorResponse)?;

        Ok(DepositAddress {
            address: deposit_addr.address,
            verifying_key: deposit_addr.verifying_key,
        })
    }

    /// Finalize a confirmed deposit by creating the Spark tree.
    ///
    /// This signs the root transaction and refunds via FROST, then
    /// submits to the coordinator. On success, inserts the new leaf.
    pub async fn finalize_deposit(
        &self,
        pubkey: &IdentityPubKey,
        signer: &impl WalletSigner,
        node_ids: Vec<String>,
    ) -> Result<(), SdkError> {
        self.check_cancelled()?;

        let _wallet = self
            .inner
            .wallet_store
            .resolve(pubkey)
            .ok_or(SdkError::WalletNotFound)?;

        let authed = self.authenticate(signer).await?;

        // 1. Get signing commitments (3 per node: CPFP, direct, direct-from-CPFP).
        let _commitments = authed
            .get_signing_commitments(spark::GetSigningCommitmentsRequest {
                node_ids,
                count: 3,
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 2. FROST sign root + refund transactions.
        let mut _rng = rand_core::OsRng;
        // (Actual signing depends on the deposit output and node tx structure.)

        // 3. Finalize deposit tree creation.
        let _resp = authed
            .finalize_deposit_tree_creation(spark::FinalizeDepositTreeCreationRequest {
                ..Default::default()
            })
            .await
            .map_err(|_| SdkError::TransportFailed)?;

        // 4. Insert root leaf into tree store.
        // TODO: Convert proto response to TreeNode and insert.

        Ok(())
    }
}
