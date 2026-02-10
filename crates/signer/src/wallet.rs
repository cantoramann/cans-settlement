//! Full wallet signer backed by HD-derived keys.
//!
//! [`SparkWalletSigner`] is constructed from a BIP32 seed and account index.
//! It pre-derives the identity key and signing master key at construction
//! time, then derives per-leaf keys on demand.

use std::collections::BTreeMap;

use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::secp256k1::ecdsa::Signature as EcdsaSignature;
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
use frost_secp256k1_tr::keys::SigningShare;
use frost_secp256k1_tr::round1::{SigningCommitments, SigningNonces};
use frost_secp256k1_tr::round2::SignatureShare;
use frost_secp256k1_tr::{Identifier, Signature as FrostSignature};
use rand_core::{CryptoRng, RngCore};
use spark_crypto::derivation_path::{self, SPARK_DERIVATION_PATH_PURPOSE};
use spark_crypto::frost::FrostNoncePair;
use spark_crypto::verifiable_secret_sharing::VerifiableSecretShare;

use crate::wallet_signer::{WalletSigner, WalletSignerError};
use crate::{PubKey, Signer};

// ---------------------------------------------------------------------------
// SparkWalletSigner
// ---------------------------------------------------------------------------

/// Full wallet signer backed by a BIP32 seed.
///
/// Holds:
/// - A `Secp256k1<All>` context (~1.7 KiB) for signing and verification.
/// - The pre-derived identity key pair.
/// - The signing master `Xpriv` at `m/8797555'/account'/1'` for per-leaf
///   key derivation.
///
/// # Construction
///
/// Use [`SparkWalletSigner::from_seed`] with a BIP32-compatible seed
/// (typically 64 bytes from a BIP39 mnemonic).
pub struct SparkWalletSigner {
    secp: Secp256k1<All>,
    identity_sk: SecretKey,
    identity_pk_uncompressed: PubKey,
    identity_pk_compressed: [u8; 33],
    signing_master: Xpriv,
}

impl SparkWalletSigner {
    /// Creates a wallet signer from a BIP32 seed.
    ///
    /// Pre-derives the identity key (`m/8797555'/account'/0'`) and the
    /// signing master key (`m/8797555'/account'/1'`).
    ///
    /// # Errors
    ///
    /// Returns [`WalletSignerError::KeyDerivationFailed`] if the seed is
    /// invalid or key derivation fails.
    pub fn from_seed(
        seed: &[u8],
        network: bitcoin::Network,
        account: u32,
    ) -> Result<Self, WalletSignerError> {
        let secp = Secp256k1::new();

        let master =
            Xpriv::new_master(network, seed).map_err(|_| WalletSignerError::KeyDerivationFailed)?;

        let account_child = ChildNumber::from_hardened_idx(account)
            .map_err(|_| WalletSignerError::KeyDerivationFailed)?;

        let purpose_child = ChildNumber::Hardened {
            index: SPARK_DERIVATION_PATH_PURPOSE,
        };

        // Identity key: m/8797555'/account'/0'
        let identity_path = [
            purpose_child,
            account_child,
            ChildNumber::Hardened { index: 0 },
        ];
        let identity_xpriv = master
            .derive_priv(&secp, &identity_path)
            .map_err(|_| WalletSignerError::KeyDerivationFailed)?;
        let identity_sk = identity_xpriv.private_key;
        let identity_pk = PublicKey::from_secret_key(&secp, &identity_sk);

        // Signing master: m/8797555'/account'/1'
        let signing_path = [
            purpose_child,
            account_child,
            ChildNumber::Hardened { index: 1 },
        ];
        let signing_master = master
            .derive_priv(&secp, &signing_path)
            .map_err(|_| WalletSignerError::KeyDerivationFailed)?;

        Ok(Self {
            identity_pk_uncompressed: identity_pk.serialize_uncompressed(),
            identity_pk_compressed: identity_pk.serialize(),
            identity_sk,
            signing_master,
            secp,
        })
    }

    /// Returns a reference to the identity secret key.
    pub fn identity_secret_key(&self) -> &SecretKey {
        &self.identity_sk
    }

    /// Returns a reference to the secp256k1 context.
    pub fn secp(&self) -> &Secp256k1<All> {
        &self.secp
    }

    /// Derive the leaf signing keypair from a node ID.
    fn derive_leaf_key(&self, node_id: &str) -> Result<(SecretKey, PublicKey), WalletSignerError> {
        let leaf_child = derivation_path::get_leaf_index(node_id);
        let leaf_xpriv = self
            .signing_master
            .derive_priv(&self.secp, &[leaf_child])
            .map_err(|_| WalletSignerError::KeyDerivationFailed)?;
        let sk = leaf_xpriv.private_key;
        let pk = PublicKey::from_secret_key(&self.secp, &sk);
        Ok((sk, pk))
    }

    /// ECDSA-sign a message with the identity key, returning the raw Signature.
    fn sign_ecdsa_raw(&self, message: &[u8]) -> EcdsaSignature {
        crate::ecdsa::sign_message(&self.secp, &self.identity_sk, message)
    }
}

// ---------------------------------------------------------------------------
// Signer (auth-only trait)
// ---------------------------------------------------------------------------

impl Signer for SparkWalletSigner {
    fn public_key(&self) -> PubKey {
        self.identity_pk_uncompressed
    }

    fn sign_challenge(
        &self,
        challenge_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let sig = self.sign_ecdsa_raw(challenge_bytes);
        Ok(sig.serialize_der().to_vec())
    }
}

// ---------------------------------------------------------------------------
// WalletSigner (full crypto trait)
// ---------------------------------------------------------------------------

impl WalletSigner for SparkWalletSigner {
    fn identity_public_key_compressed(&self) -> [u8; 33] {
        self.identity_pk_compressed
    }

    fn sign_ecdsa_message(&self, message: &[u8]) -> Vec<u8> {
        self.sign_ecdsa_raw(message).serialize_der().to_vec()
    }

    fn subtract_secret_keys(
        &self,
        a: &SecretKey,
        b: &SecretKey,
    ) -> Result<SecretKey, WalletSignerError> {
        spark_crypto::secp::subtract_secret_keys_b_from_a(a, b)
            .map_err(|_| WalletSignerError::KeySubtractionFailed)
    }

    fn derive_signing_keypair(
        &self,
        node_id: &str,
    ) -> Result<(SecretKey, PublicKey), WalletSignerError> {
        self.derive_leaf_key(node_id)
    }

    fn frost_generate_nonces(
        &self,
        node_id: &str,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<FrostNoncePair, WalletSignerError> {
        let (sk, _) = self.derive_leaf_key(node_id)?;
        let signing_share = SigningShare::deserialize(&sk.secret_bytes())
            .map_err(|_| WalletSignerError::FrostSigningFailed)?;
        Ok(spark_crypto::frost::generate_nonces(&signing_share, rng))
    }

    fn frost_sign(
        &self,
        message: &[u8],
        node_id: &str,
        verifying_key: &PublicKey,
        nonces: &SigningNonces,
        all_commitments: BTreeMap<Identifier, SigningCommitments>,
        participant_id: Identifier,
    ) -> Result<SignatureShare, WalletSignerError> {
        let (sk, pk) = self.derive_leaf_key(node_id)?;
        spark_crypto::frost::sign(
            message,
            &sk,
            &pk,
            verifying_key,
            nonces,
            all_commitments,
            participant_id,
        )
        .map_err(|_| WalletSignerError::FrostSigningFailed)
    }

    fn frost_aggregate(
        &self,
        message: &[u8],
        all_commitments: BTreeMap<Identifier, SigningCommitments>,
        signature_shares: &BTreeMap<Identifier, SignatureShare>,
        verifying_shares: &BTreeMap<Identifier, PublicKey>,
        verifying_key: &PublicKey,
    ) -> Result<FrostSignature, WalletSignerError> {
        spark_crypto::frost::aggregate(
            message,
            all_commitments,
            signature_shares,
            verifying_shares,
            verifying_key,
        )
        .map_err(|_| WalletSignerError::FrostAggregationFailed)
    }

    fn ecies_encrypt(
        &self,
        receiver_pub: &[u8],
        plaintext: &[u8],
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<u8>, WalletSignerError> {
        spark_crypto::ecies::encrypt(&self.secp, receiver_pub, plaintext, rng).map_err(
            |e| match e {
                spark_crypto::ecies::EciesError::InvalidPublicKey
                | spark_crypto::ecies::EciesError::InvalidSecretKey => {
                    WalletSignerError::EciesInvalidKey
                }
                _ => WalletSignerError::EciesEncryptionFailed,
            },
        )
    }

    fn ecies_decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, WalletSignerError> {
        spark_crypto::ecies::decrypt(&self.secp, &self.identity_sk[..], ciphertext).map_err(|e| {
            match e {
                spark_crypto::ecies::EciesError::InvalidSecretKey
                | spark_crypto::ecies::EciesError::InvalidPublicKey => {
                    WalletSignerError::EciesInvalidKey
                }
                spark_crypto::ecies::EciesError::DecryptionFailed => {
                    WalletSignerError::EciesDecryptionFailed
                }
                _ => WalletSignerError::EciesDecryptionFailed,
            }
        })
    }

    fn vss_split(
        &self,
        secret_bytes: &[u8; 32],
        threshold: usize,
        num_shares: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<VerifiableSecretShare>, WalletSignerError> {
        let scalar = spark_crypto::verifiable_secret_sharing::scalar_from_bytes(secret_bytes)
            .map_err(|_| WalletSignerError::VssScalarOutOfRange)?;
        spark_crypto::verifiable_secret_sharing::split_secret_with_proofs(
            &scalar, threshold, num_shares, rng,
        )
        .map_err(|_| WalletSignerError::VssSplitFailed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"0000000000000000000000000000000000000000000000000000000000000000";

    fn make_signer() -> SparkWalletSigner {
        SparkWalletSigner::from_seed(SEED, bitcoin::Network::Bitcoin, 0).expect("valid seed")
    }

    #[test]
    fn from_seed_succeeds() {
        let signer = make_signer();
        assert_ne!(signer.identity_pk_compressed, [0u8; 33]);
        assert_eq!(signer.identity_pk_uncompressed[0], 0x04);
    }

    #[test]
    fn compressed_and_uncompressed_keys_match() {
        let signer = make_signer();
        let pk = PublicKey::from_slice(&signer.identity_pk_compressed).unwrap();
        assert_eq!(pk.serialize_uncompressed(), signer.identity_pk_uncompressed);
    }

    #[test]
    fn identity_matches_crypto_crate_derivation() {
        let signer = make_signer();
        let secp = Secp256k1::new();
        let expected = spark_crypto::derivation_path::derive_spark_keypair(
            &secp,
            SEED,
            bitcoin::Network::Bitcoin,
            0,
            spark_crypto::derivation_path::SparkKeyType::Identity,
            None,
        )
        .unwrap();
        assert_eq!(signer.identity_pk_compressed, expected.1.serialize(),);
    }

    #[test]
    fn different_accounts_produce_different_keys() {
        let s0 = SparkWalletSigner::from_seed(SEED, bitcoin::Network::Bitcoin, 0).unwrap();
        let s1 = SparkWalletSigner::from_seed(SEED, bitcoin::Network::Bitcoin, 1).unwrap();
        assert_ne!(s0.identity_pk_compressed, s1.identity_pk_compressed);
    }

    #[test]
    fn derive_signing_keypair_deterministic() {
        let signer = make_signer();
        let (sk1, pk1) = signer.derive_signing_keypair("leaf-1").unwrap();
        let (sk2, pk2) = signer.derive_signing_keypair("leaf-1").unwrap();
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn derive_signing_keypair_distinct_per_leaf() {
        let signer = make_signer();
        let (_, pk_a) = signer.derive_signing_keypair("leaf-a").unwrap();
        let (_, pk_b) = signer.derive_signing_keypair("leaf-b").unwrap();
        assert_ne!(pk_a, pk_b);
    }

    #[test]
    fn signer_trait_sign_challenge() {
        let signer = make_signer();
        let sig = signer.sign_challenge(b"test").expect("sign should succeed");
        assert!(!sig.is_empty());

        // Verify with ecdsa module.
        let secp = Secp256k1::new();
        let parsed = crate::ecdsa::signature_from_der(&sig).unwrap();
        let pk = PublicKey::from_slice(&signer.identity_pk_compressed).unwrap();
        crate::ecdsa::verify_message(&secp, &pk, b"test", &parsed).unwrap();
    }

    #[test]
    fn sign_ecdsa_message_verifiable() {
        let signer = make_signer();
        let der = signer.sign_ecdsa_message(b"hello spark");
        let secp = Secp256k1::new();
        let sig = crate::ecdsa::signature_from_der(&der).unwrap();
        let pk = PublicKey::from_slice(&signer.identity_pk_compressed).unwrap();
        crate::ecdsa::verify_message(&secp, &pk, b"hello spark", &sig).unwrap();
    }

    #[test]
    fn ecies_roundtrip() {
        let signer = make_signer();
        let mut rng = rand::thread_rng();

        let msg = b"secret payload";
        let ct = signer
            .ecies_encrypt(&signer.identity_pk_uncompressed, msg, &mut rng)
            .unwrap();
        let pt = signer.ecies_decrypt(&ct).unwrap();
        assert_eq!(&pt, msg);
    }

    #[test]
    fn ecies_wrong_key_fails() {
        let s1 = make_signer();
        let s2 = SparkWalletSigner::from_seed(SEED, bitcoin::Network::Bitcoin, 1).unwrap();
        let mut rng = rand::thread_rng();

        let ct = s1
            .ecies_encrypt(&s1.identity_pk_uncompressed, b"secret", &mut rng)
            .unwrap();
        assert!(s2.ecies_decrypt(&ct).is_err());
    }

    #[test]
    fn vss_split_and_validate() {
        let signer = make_signer();
        let mut rng = rand::thread_rng();
        let secret = [0x42u8; 32];

        let shares = signer.vss_split(&secret, 2, 3, &mut rng).unwrap();
        assert_eq!(shares.len(), 3);

        for share in &shares {
            spark_crypto::verifiable_secret_sharing::validate_share(share).unwrap();
        }

        let recovered =
            spark_crypto::verifiable_secret_sharing::recover_secret(&shares[..2]).unwrap();
        let expected = spark_crypto::verifiable_secret_sharing::scalar_from_bytes(&secret).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn vss_invalid_threshold_rejected() {
        let signer = make_signer();
        let mut rng = rand::thread_rng();
        assert!(signer.vss_split(&[0x11; 32], 0, 3, &mut rng).is_err());
        assert!(signer.vss_split(&[0x11; 32], 4, 3, &mut rng).is_err());
    }

    #[test]
    fn frost_generate_nonces_succeeds() {
        let signer = make_signer();
        let mut rng = rand::thread_rng();

        let nonce_pair = signer.frost_generate_nonces("test-leaf", &mut rng).unwrap();

        // Commitment should be serializable.
        let bytes = spark_crypto::frost::serialize_commitment(&nonce_pair.commitment).unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn wallet_signer_error_display() {
        assert_eq!(
            WalletSignerError::FrostSigningFailed.to_string(),
            "FROST signing failed"
        );
        assert_eq!(
            WalletSignerError::KeyDerivationFailed.to_string(),
            "key derivation failed"
        );
        assert_eq!(
            WalletSignerError::EciesDecryptionFailed.to_string(),
            "ECIES decryption failed"
        );
    }
}
