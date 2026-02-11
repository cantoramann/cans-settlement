//! ECDSA signer backed by `bitcoin::secp256k1`.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly};

use crate::ecdsa;
use crate::{PubKey, Signer};

/// ECDSA signer backed by a secp256k1 secret key.
///
/// Holds a pre-computed uncompressed public key so [`Signer::public_key`]
/// is a simple copy (no elliptic curve multiplication on every call).
///
/// The [`Secp256k1<SignOnly>`] context is ~128 bytes on the stack --
/// much cheaper than a full verification context (~260 KB).
pub struct SparkSigner {
    secret_key: SecretKey,
    public_key: PubKey,
    secp: Secp256k1<SignOnly>,
}

impl SparkSigner {
    /// Creates a new signer from the given secret key.
    ///
    /// Pre-computes the uncompressed public key at construction time.
    pub fn new(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::signing_only();
        let pk = PublicKey::from_secret_key(&secp, &secret_key);
        let public_key = pk.serialize_uncompressed();
        Self {
            secret_key,
            public_key,
            secp,
        }
    }

    /// Returns a reference to the underlying secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret_key
    }
}

impl Signer for SparkSigner {
    fn public_key(&self) -> PubKey {
        self.public_key
    }

    fn sign_challenge(
        &self,
        challenge_bytes: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let sig = ecdsa::sign_message(&self.secp, &self.secret_key, challenge_bytes);
        Ok(sig.serialize_der().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_keypair() -> SecretKey {
        let mut bytes = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        SecretKey::from_slice(&bytes).expect("32 random bytes always valid")
    }

    #[test]
    fn public_key_matches_secret_key() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);

        let secp = Secp256k1::new();
        let expected = PublicKey::from_secret_key(&secp, &sk).serialize_uncompressed();

        assert_eq!(signer.public_key(), expected);
    }

    #[test]
    fn public_key_is_stable() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);
        assert_eq!(signer.public_key(), signer.public_key());
    }

    #[test]
    fn sign_challenge_produces_valid_der() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);

        let challenge = b"test challenge data for spark auth";
        let sig_bytes = signer
            .sign_challenge(challenge)
            .expect("signing should succeed");

        // DER-encoded ECDSA signatures are typically 70-72 bytes.
        assert!(
            (68..=73).contains(&sig_bytes.len()),
            "unexpected DER signature length: {}",
            sig_bytes.len()
        );

        // Verify the signature using the ecdsa module.
        let secp = Secp256k1::new();
        let sig = ecdsa::signature_from_der(&sig_bytes).expect("should be valid DER");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        ecdsa::verify_message(&secp, &pk, challenge, &sig).expect("signature should verify");
    }

    #[test]
    fn different_challenges_produce_different_signatures() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);

        let sig_a = signer.sign_challenge(b"challenge A").unwrap();
        let sig_b = signer.sign_challenge(b"challenge B").unwrap();

        assert_ne!(sig_a, sig_b);
    }

    #[test]
    fn empty_challenge_is_valid() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);

        let sig = signer
            .sign_challenge(b"")
            .expect("empty challenge should sign");
        assert!(!sig.is_empty());
    }

    #[test]
    fn secret_key_accessor() {
        let sk = test_keypair();
        let signer = SparkSigner::new(sk);
        assert_eq!(*signer.secret_key(), sk);
    }
}
