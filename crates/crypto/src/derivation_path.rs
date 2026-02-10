//! HD key derivation for Spark wallets.
//!
//! Implements BIP32-based hierarchical deterministic key derivation with a
//! custom purpose number (`8797555'`) for Spark-specific keys.
//!
//! Path format: `m/8797555'/account'/key_type'[/leaf_index']`
//!
//! # Key Types
//!
//! | Type | Index | Purpose |
//! |------|-------|---------|
//! | Identity | 0' | Wallet authentication and identification |
//! | BaseSigning | 1' | Foundation for leaf-specific signing keys |
//! | Deposit | 2' | Deposit transaction signing |
//!
//! # Example
//!
//! ```
//! use bitcoin::Network;
//! use bitcoin::secp256k1::Secp256k1;
//! use spark_crypto::derivation_path::{SparkKeyType, derive_spark_key};
//!
//! let secp = Secp256k1::new();
//! let seed = b"0000000000000000000000000000000000000000000000000000000000000000";
//!
//! // Identity key (no leaf)
//! let sk = derive_spark_key(
//!     &secp, seed, Network::Bitcoin, 0, SparkKeyType::Identity, None,
//! ).unwrap();
//!
//! // Leaf-specific signing key
//! let leaf_sk = derive_spark_key(
//!     &secp, seed, Network::Bitcoin, 0, SparkKeyType::BaseSigning, Some("leaf-uuid"),
//! ).unwrap();
//! ```

use std::fmt;

use bitcoin::{
    Network,
    bip32::{ChildNumber, Xpriv},
    hashes::{Hash, HashEngine, sha256},
    secp256k1::{PublicKey, Secp256k1, SecretKey, Signing},
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SPARK_DERIVATION_PATH_PURPOSE: u32 = 8797555;

/// Pre-computed hardened purpose child number.
const SPARK_PURPOSE_CHILD: ChildNumber = ChildNumber::Hardened {
    index: SPARK_DERIVATION_PATH_PURPOSE,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by derivation operations.
#[derive(Debug, PartialEq, Eq)]
pub enum DerivationError {
    /// The seed is invalid for BIP32 master key derivation.
    InvalidSeed,
    /// The child index exceeds the valid BIP32 range (must be < 2^31).
    InvalidChildIndex(u32),
    /// BIP32 key derivation failed along the path.
    DerivationFailed,
}

impl fmt::Display for DerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSeed => write!(f, "invalid seed"),
            Self::InvalidChildIndex(i) => write!(f, "child index {i} out of range"),
            Self::DerivationFailed => write!(f, "key derivation failed"),
        }
    }
}

impl std::error::Error for DerivationError {}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Key types for Spark wallet derivation paths.
///
/// Encoded as the third component: `m/8797555'/account'/key_type'`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparkKeyType {
    /// Identity key (0'). Wallet authentication and Spark Operator verification.
    Identity,
    /// Base signing key (1'). Foundation for leaf-specific keys.
    BaseSigning,
    /// Deposit key (2'). Signs deposit transactions.
    Deposit,
}

impl SparkKeyType {
    /// Returns the hardened child number for this key type.
    #[inline]
    fn child_number(self) -> ChildNumber {
        let index = match self {
            Self::Identity => 0,
            Self::BaseSigning => 1,
            Self::Deposit => 2,
        };

        ChildNumber::Hardened { index }
    }
}

// ---------------------------------------------------------------------------
// Derivation path (stack-allocated)
// ---------------------------------------------------------------------------

/// A Spark BIP32 derivation path.
///
/// Always 3 segments (`purpose/account/key_type`) or 4 segments
/// (`purpose/account/key_type/leaf`). Stored entirely on the stack
/// -- no heap allocation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SparkDerivationPath {
    segments: [ChildNumber; 4],
    len: u8,
}

impl SparkDerivationPath {
    /// Creates a 3-segment path: `purpose'/account'/key_type'`.
    fn base(account: ChildNumber, key_type: ChildNumber) -> Self {
        Self {
            segments: [
                SPARK_PURPOSE_CHILD,
                account,
                key_type,
                ChildNumber::Normal { index: 0 }, // unused
            ],
            len: 3,
        }
    }

    /// Creates a 4-segment path: `purpose'/account'/key_type'/leaf'`.
    fn with_leaf(account: ChildNumber, key_type: ChildNumber, leaf: ChildNumber) -> Self {
        Self {
            segments: [SPARK_PURPOSE_CHILD, account, key_type, leaf],
            len: 4,
        }
    }
}

impl fmt::Debug for SparkDerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl std::ops::Deref for SparkDerivationPath {
    type Target = [ChildNumber];

    fn deref(&self) -> &Self::Target {
        &self.segments[..self.len as usize]
    }
}

impl AsRef<[ChildNumber]> for SparkDerivationPath {
    fn as_ref(&self) -> &[ChildNumber] {
        self
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Creates a [`ChildNumber`] from an index and hardened flag.
///
/// # Errors
///
/// Returns [`DerivationError::InvalidChildIndex`] if `index >= 2^31`.
pub fn child_number(index: u32, hardened: bool) -> Result<ChildNumber, DerivationError> {
    if hardened {
        ChildNumber::from_hardened_idx(index)
    } else {
        ChildNumber::from_normal_idx(index)
    }
    .map_err(|_| DerivationError::InvalidChildIndex(index))
}

/// Deterministically maps a leaf ID to a hardened [`ChildNumber`].
///
/// Computes `SHA-256(leaf_id)`, takes the first 4 bytes as a big-endian `u32`,
/// then reduces modulo `2^31` to ensure a valid hardened index.
pub fn get_leaf_index(leaf_id: &str) -> ChildNumber {
    let mut engine = sha256::Hash::engine();
    engine.input(leaf_id.as_bytes());
    let hash = sha256::Hash::from_engine(engine);

    let chunk = &hash[0..4];
    let index = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) % 0x80000000;

    // Safe: index is always < 2^31 after modulo.
    ChildNumber::Hardened { index }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Builds a [`SparkDerivationPath`] for the given parameters.
///
/// **Heap allocations:** zero.
pub fn build_derivation_path(
    account: u32,
    key_type: SparkKeyType,
    leaf_id: Option<&str>,
) -> Result<SparkDerivationPath, DerivationError> {
    let account_child = child_number(account, true)?;
    let key_type_child = key_type.child_number();

    match leaf_id {
        Some(id) => Ok(SparkDerivationPath::with_leaf(
            account_child,
            key_type_child,
            get_leaf_index(id),
        )),
        None => Ok(SparkDerivationPath::base(account_child, key_type_child)),
    }
}

/// Derives a Spark secret key from a seed.
///
/// **Heap allocations:** zero (caller provides the [`Secp256k1`] context).
///
/// # Arguments
///
/// * `secp` -- Pre-allocated secp256k1 context (amortize across calls).
/// * `seed` -- BIP32 seed bytes (>= 16 bytes).
/// * `network` -- Bitcoin network.
/// * `account` -- Account index (hardened).
/// * `key_type` -- Which key to derive.
/// * `leaf_id` -- Optional leaf identifier for leaf-specific keys.
pub fn derive_spark_key<C: Signing>(
    secp: &Secp256k1<C>,
    seed: &[u8],
    network: Network,
    account: u32,
    key_type: SparkKeyType,
    leaf_id: Option<&str>,
) -> Result<SecretKey, DerivationError> {
    let path = build_derivation_path(account, key_type, leaf_id)?;
    let master = Xpriv::new_master(network, seed).map_err(|_| DerivationError::InvalidSeed)?;
    let derived = master
        .derive_priv(secp, &path)
        .map_err(|_| DerivationError::DerivationFailed)?;
    Ok(derived.private_key)
}

/// Derives a Spark key pair (secret + public) from a seed.
///
/// Convenience wrapper around [`derive_spark_key`].
///
/// **Heap allocations:** zero.
pub fn derive_spark_keypair<C: Signing>(
    secp: &Secp256k1<C>,
    seed: &[u8],
    network: Network,
    account: u32,
    key_type: SparkKeyType,
    leaf_id: Option<&str>,
) -> Result<(SecretKey, PublicKey), DerivationError> {
    let sk = derive_spark_key(secp, seed, network, account, key_type, leaf_id)?;
    let pk = sk.public_key(secp);
    Ok((sk, pk))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Network, secp256k1::Secp256k1};

    const SEED: &[u8] = b"0000000000000000000000000000000000000000000000000000000000000000";

    // -- get_leaf_index --

    #[test]
    fn leaf_index_known_values() {
        let cases = [
            ("019534f0-f4e2-7845-87fe-c6ea2fa69f80", 1137822116),
            ("019534f0-f4e2-7868-b3fa-d06dc10b79e7", 1199130649),
            ("dbb5c090-dca4-47ec-9f20-41edd4594dcf", 1743780874),
        ];
        for (leaf_id, expected_index) in cases {
            assert_eq!(
                get_leaf_index(leaf_id),
                ChildNumber::from_hardened_idx(expected_index).unwrap(),
                "leaf_id={leaf_id}"
            );
        }
    }

    // -- build_derivation_path --

    #[test]
    fn path_identity_structure() {
        let path = build_derivation_path(0, SparkKeyType::Identity, None).unwrap();
        assert_eq!(path.len(), 3);
        assert_eq!(
            path[0],
            ChildNumber::from_hardened_idx(SPARK_DERIVATION_PATH_PURPOSE).unwrap()
        );
        assert_eq!(path[1], ChildNumber::from_hardened_idx(0).unwrap());
        assert_eq!(path[2], ChildNumber::from_hardened_idx(0).unwrap());
    }

    #[test]
    fn path_account_index_varies() {
        for account in [0_u32, 1, 2] {
            let path = build_derivation_path(account, SparkKeyType::Identity, None).unwrap();
            assert_eq!(path.len(), 3);
            assert_eq!(
                path[0],
                ChildNumber::from_hardened_idx(SPARK_DERIVATION_PATH_PURPOSE).unwrap()
            );
            assert_eq!(path[1], ChildNumber::from_hardened_idx(account).unwrap());
            assert_eq!(path[2], ChildNumber::from_hardened_idx(0).unwrap());
        }
    }

    #[test]
    fn path_with_leaf_has_four_segments() {
        let path = build_derivation_path(0, SparkKeyType::BaseSigning, Some("test-leaf")).unwrap();
        assert_eq!(path.len(), 4);
        assert_eq!(path[3], get_leaf_index("test-leaf"));
    }

    // -- child_number --

    #[test]
    fn child_number_valid() {
        assert!(child_number(0, true).is_ok());
        assert!(child_number(0x7FFFFFFF, true).is_ok());
        assert!(child_number(0, false).is_ok());
        assert!(child_number(0x7FFFFFFF, false).is_ok());
    }

    #[test]
    fn child_number_out_of_range() {
        assert_eq!(
            child_number(0x80000000, false),
            Err(DerivationError::InvalidChildIndex(0x80000000))
        );
        assert_eq!(
            child_number(0x80000000, true),
            Err(DerivationError::InvalidChildIndex(0x80000000))
        );
    }

    // -- SparkKeyType::child_number --

    #[test]
    fn key_type_indices() {
        assert_eq!(
            SparkKeyType::Identity.child_number(),
            ChildNumber::from_hardened_idx(0).unwrap()
        );
        assert_eq!(
            SparkKeyType::BaseSigning.child_number(),
            ChildNumber::from_hardened_idx(1).unwrap()
        );
        assert_eq!(
            SparkKeyType::Deposit.child_number(),
            ChildNumber::from_hardened_idx(2).unwrap()
        );
    }

    // -- derive_spark_key --

    #[test]
    fn derive_key_types_are_distinct() {
        let secp = Secp256k1::new();
        let ident = derive_spark_key(
            &secp,
            SEED,
            Network::Bitcoin,
            0,
            SparkKeyType::Identity,
            None,
        )
        .unwrap();
        let base = derive_spark_key(
            &secp,
            SEED,
            Network::Bitcoin,
            0,
            SparkKeyType::BaseSigning,
            None,
        )
        .unwrap();
        let deposit = derive_spark_key(
            &secp,
            SEED,
            Network::Bitcoin,
            0,
            SparkKeyType::Deposit,
            None,
        )
        .unwrap();

        let pk_i = ident.public_key(&secp);
        let pk_b = base.public_key(&secp);
        let pk_d = deposit.public_key(&secp);

        assert_ne!(pk_i, pk_b);
        assert_ne!(pk_i, pk_d);
        assert_ne!(pk_b, pk_d);
    }

    #[test]
    fn account_index_changes_key() {
        let secp = Secp256k1::new();
        let keys: Vec<_> = [0_u32, 1, 7]
            .iter()
            .map(|&acct| {
                derive_spark_key(
                    &secp,
                    SEED,
                    Network::Bitcoin,
                    acct,
                    SparkKeyType::Identity,
                    None,
                )
                .unwrap()
                .public_key(&secp)
            })
            .collect();

        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[0], keys[2]);
        assert_ne!(keys[1], keys[2]);
    }

    #[test]
    fn leaf_id_changes_key() {
        let secp = Secp256k1::new();
        let without = derive_spark_key(
            &secp,
            SEED,
            Network::Bitcoin,
            0,
            SparkKeyType::BaseSigning,
            None,
        )
        .unwrap();
        let with = derive_spark_key(
            &secp,
            SEED,
            Network::Bitcoin,
            0,
            SparkKeyType::BaseSigning,
            Some("test-leaf-id"),
        )
        .unwrap();
        assert_ne!(without, with);
    }

    // -- derive_spark_keypair --

    #[test]
    fn keypair_matches_individual_derivation() {
        let secp = Secp256k1::new();
        for account in [0_u32, 1, 7] {
            let (sk, pk) = derive_spark_keypair(
                &secp,
                SEED,
                Network::Bitcoin,
                account,
                SparkKeyType::Identity,
                None,
            )
            .unwrap();
            let sk2 = derive_spark_key(
                &secp,
                SEED,
                Network::Bitcoin,
                account,
                SparkKeyType::Identity,
                None,
            )
            .unwrap();
            let pk2 = sk2.public_key(&secp);

            assert_eq!(sk.secret_bytes(), sk2.secret_bytes(), "account={account}");
            assert_eq!(pk, pk2, "account={account}");
        }
    }

    // -- network behavior --

    #[test]
    fn networks_produce_same_key() {
        // BIP32 master key derivation ignores network for the actual key bytes;
        // network only affects serialization version bytes. This test documents
        // that expectation. If the derivation path becomes network-dependent in
        // the future, this test should be updated.
        let secp = Secp256k1::new();
        let networks = [
            Network::Bitcoin,
            Network::Testnet,
            Network::Regtest,
            Network::Signet,
        ];
        let keys: Vec<_> = networks
            .iter()
            .map(|&net| {
                derive_spark_key(&secp, SEED, net, 0, SparkKeyType::Identity, None)
                    .unwrap()
                    .public_key(&secp)
            })
            .collect();

        for pair in keys.windows(2) {
            assert_eq!(pair[0], pair[1]);
        }
    }
}
