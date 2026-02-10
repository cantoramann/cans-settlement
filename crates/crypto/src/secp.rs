//! # SECP256k1
use bitcoin::secp256k1::{Error as Secp256k1Error, PublicKey, Scalar, Secp256k1, SecretKey};

/// Adds two public keys together (pk1 + pk2)
///
/// Input keys must be 33-byte compressed secp256k1 public keys
///
/// # Arguments
///
/// * `pk1` - The first public key
/// * `pk2` - The second public key
///
/// # Returns
/// The result of adding the two public keys
///
/// # Errors
/// - [`Secp256k1Error`] if the keys are not valid.
///
/// # Examples
/// ```
/// use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
/// use spark_crypto::secp::add_public_keys;
///
/// let secp = Secp256k1::new();
/// let pk1 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x01; 32]).unwrap());
/// let pk2 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x02; 32]).unwrap());
/// let result = add_public_keys(&pk1, &pk2).unwrap();
/// ```
pub fn add_public_keys(pk1: &PublicKey, pk2: &PublicKey) -> Result<PublicKey, Secp256k1Error> {
    pk1.combine(pk2)
}

/// Subtracts the rhs public key from the lhs public key (pk1 - pk2)
///
/// Input keys must be 33-byte compressed secp256k1 public keys
///
/// # Arguments
///
/// * `pk1` - The first public key
/// * `pk2` - The second public key
///
/// # Returns
/// The result of subtracting the second public key from the first
///
/// # Errors
/// - [`Secp256k1Error`] if the keys are not valid.
///
/// # Examples
/// ```
/// use bitcoin::secp256k1::{PublicKey, SecretKey, Secp256k1};
/// use spark_crypto::secp::subtract_public_keys_b_from_a;
///
/// let secp = Secp256k1::new();
/// let pk1 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x01; 32]).unwrap());
/// let pk2 = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x02; 32]).unwrap());
/// let result = subtract_public_keys_b_from_a(&pk1, &pk2).unwrap();
/// ```
pub fn subtract_public_keys_b_from_a(
    pk1: &PublicKey,
    pk2: &PublicKey,
) -> Result<PublicKey, Secp256k1Error> {
    let secp = Secp256k1::new();
    // Negate the second key and add
    let negated = pk2.negate(&secp);
    pk1.combine(&negated)
}

/// Adds two secret keys together (sk1 + sk2)
///
/// Input keys must be 32 bytes
///
/// # Arguments
///
/// * `sk1` - The first secret key
/// * `sk2` - The second secret key
///
/// # Returns
/// The result of adding the two secret keys
///
/// # Errors
/// - [`Secp256k1Error`] if the keys are not valid.
///
/// # Examples
/// ```
/// use bitcoin::secp256k1::SecretKey;
/// use spark_crypto::secp::add_secret_keys;
///
/// let sk1 = SecretKey::from_slice(&[0x01; 32]).unwrap();
/// let sk2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
/// let result = add_secret_keys(&sk1, &sk2).unwrap();
/// ```
pub fn add_secret_keys(sk1: &SecretKey, sk2: &SecretKey) -> Result<SecretKey, Secp256k1Error> {
    sk1.add_tweak(&Scalar::from(*sk2))
}

/// Subtracts the rhs secret key from the lhs secret key (sk1 - sk2)
///
/// Input keys must be 32 bytes
///
/// # Arguments
///
/// * `sk1` - The first secret key
/// * `sk2` - The second secret key
///
/// # Returns
/// The result of subtracting the second secret key from the first
///
/// # Errors
/// - [`Secp256k1Error`] if the keys are not valid.
///
/// # Examples
/// ```
/// use bitcoin::secp256k1::SecretKey;
/// use spark_crypto::secp::subtract_secret_keys_b_from_a;
///
/// let sk1 = SecretKey::from_slice(&[0x01; 32]).unwrap();
/// let sk2 = SecretKey::from_slice(&[0x02; 32]).unwrap();
/// let result = subtract_secret_keys_b_from_a(&sk1, &sk2).unwrap();
/// ```
pub fn subtract_secret_keys_b_from_a(
    sk1: &SecretKey,
    sk2: &SecretKey,
) -> Result<SecretKey, Secp256k1Error> {
    // Negate the second key and add
    let negated = sk2.negate();
    sk1.add_tweak(&negated.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn test_keypair(bytes: &[u8; 32]) -> (SecretKey, PublicKey) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(bytes).expect("valid test key");
        let pk = PublicKey::from_secret_key(&secp, &sk);
        (sk, pk)
    }

    #[test]
    fn test_secret_key_addition_and_subtraction() {
        let (sk1, _) = test_keypair(&[0x11; 32]);
        let (sk2, _) = test_keypair(&[0x22; 32]);

        let added = add_secret_keys(&sk1, &sk2).unwrap();
        let subtracted = subtract_secret_keys_b_from_a(&added, &sk2).unwrap();

        assert_eq!(sk1, subtracted);

        // (sk1 + sk2) - sk1 = sk2
        let subtracted2 = subtract_secret_keys_b_from_a(&added, &sk1).unwrap();
        assert_eq!(sk2, subtracted2);
    }

    #[test]
    fn test_public_key_addition_and_subtraction() {
        let (_, pk1) = test_keypair(&[0x11; 32]);
        let (_, pk2) = test_keypair(&[0x22; 32]);

        let added = add_public_keys(&pk1, &pk2).unwrap();
        let subtracted = subtract_public_keys_b_from_a(&added, &pk2).unwrap();

        assert_eq!(pk1, subtracted);

        // (pk1 + pk2) - pk1 = pk2
        let subtracted2 = subtract_public_keys_b_from_a(&added, &pk1).unwrap();
        assert_eq!(pk2, subtracted2);
    }
}
