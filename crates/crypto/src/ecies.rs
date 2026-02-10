//! Elliptic Curve Integrated Encryption Scheme (ECIES) for secp256k1.
//!
//! Wire-format compatible with the [`ecies`](https://docs.rs/ecies) crate's default
//! configuration (uncompressed keys, 16-byte nonce AES-256-GCM, HKDF-SHA256).
//!
//! Built entirely from existing workspace dependencies plus `aes-gcm`:
//! - **ECDH**: `bitcoin::secp256k1` (already in tree)
//! - **HKDF-SHA256**: `bitcoin::hashes::hmac` (already in tree)
//! - **AES-256-GCM**: `aes-gcm` (sole addition)
//!
//! The caller supplies a [`Secp256k1`] context so the ~1 MB precomputed tables
//! are allocated once and amortized across many operations.
//!
//! # Example
//!
//! ```
//! use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
//! use spark_crypto::ecies;
//!
//! let secp = Secp256k1::new();
//! let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
//! let pk = PublicKey::from_secret_key(&secp, &sk);
//!
//! let mut rng = rand::thread_rng();
//! let ciphertext = ecies::encrypt(
//!     &secp,
//!     &pk.serialize_uncompressed(),
//!     b"hello world",
//!     &mut rng,
//! ).unwrap();
//!
//! let plaintext = ecies::decrypt(&secp, &sk[..], &ciphertext).unwrap();
//! assert_eq!(plaintext, b"hello world");
//! ```

use std::fmt;

use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::typenum::U16;
use aes_gcm::aes::Aes256;
use aes_gcm::{AesGcm, KeyInit};
use bitcoin::hashes::{Hash, HashEngine, hmac, sha256};
use bitcoin::secp256k1::rand::RngCore;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// AES-256-GCM with 16-byte nonce (ecies crate default).
type Aes256Gcm16 = AesGcm<Aes256, U16>;

const NONCE_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const NONCE_TAG_SIZE: usize = NONCE_SIZE + TAG_SIZE;
const UNCOMPRESSED_KEY_SIZE: usize = 65;
const COMPRESSED_KEY_SIZE: usize = 33;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by ECIES operations.
#[derive(Debug, PartialEq, Eq)]
pub enum EciesError {
    /// The provided secret key bytes are not a valid secp256k1 scalar.
    InvalidSecretKey,
    /// The provided public key bytes are not a valid secp256k1 point.
    InvalidPublicKey,
    /// The ciphertext is too short or structurally invalid.
    InvalidMessage,
    /// AES-256-GCM encryption failed.
    EncryptionFailed,
    /// AES-256-GCM decryption failed (wrong key or tampered ciphertext).
    DecryptionFailed,
}

impl fmt::Display for EciesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidMessage => write!(f, "invalid message"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::DecryptionFailed => write!(f, "decryption failed"),
        }
    }
}

impl std::error::Error for EciesError {}

// ---------------------------------------------------------------------------
// HKDF-SHA256 (via bitcoin::hashes::hmac)
// ---------------------------------------------------------------------------

/// HKDF-SHA256 extract-then-expand with zero salt and empty info.
///
/// Matches the `ecies` crate's derivation: `Hkdf::<Sha256>::new(None, ikm)`
/// expanded to 32 bytes with empty info.
fn hkdf_sha256(ikm: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt=zeros, IKM)
    let salt = [0u8; 32];
    let mut extract = hmac::HmacEngine::<sha256::Hash>::new(&salt);
    extract.input(ikm);
    let prk = hmac::Hmac::from_engine(extract);

    // Expand: T(1) = HMAC-SHA256(PRK, 0x01) — one iteration for 32 bytes
    let mut expand = hmac::HmacEngine::<sha256::Hash>::new(prk.as_byte_array());
    expand.input(&[1u8]);
    let okm = hmac::Hmac::from_engine(expand);

    *okm.as_byte_array()
}

// ---------------------------------------------------------------------------
// Helpers (zero heap allocations)
// ---------------------------------------------------------------------------

/// Generates a random secp256k1 secret key.
fn generate_secret_key(rng: &mut impl RngCore) -> SecretKey {
    let mut bytes = [0u8; 32];
    loop {
        rng.fill_bytes(&mut bytes);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

/// HKDF key derivation from sender public key and shared ECDH point.
fn derive_shared_key(
    sender_pk: &PublicKey,
    shared_point: &PublicKey,
    compressed: bool,
) -> [u8; 32] {
    if compressed {
        let mut ikm = [0u8; COMPRESSED_KEY_SIZE * 2];
        ikm[..COMPRESSED_KEY_SIZE].copy_from_slice(&sender_pk.serialize());
        ikm[COMPRESSED_KEY_SIZE..].copy_from_slice(&shared_point.serialize());
        hkdf_sha256(&ikm)
    } else {
        let mut ikm = [0u8; UNCOMPRESSED_KEY_SIZE * 2];
        ikm[..UNCOMPRESSED_KEY_SIZE].copy_from_slice(&sender_pk.serialize_uncompressed());
        ikm[UNCOMPRESSED_KEY_SIZE..].copy_from_slice(&shared_point.serialize_uncompressed());
        hkdf_sha256(&ikm)
    }
}

// ---------------------------------------------------------------------------
// ECDH key agreement
// ---------------------------------------------------------------------------

/// Sender-side ECDH: derives the ephemeral public key and shared symmetric key.
fn encapsulate<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    ephemeral_sk: &SecretKey,
    receiver_pk: &PublicKey,
    compressed: bool,
) -> Result<(PublicKey, [u8; 32]), EciesError> {
    let scalar = Scalar::from(*ephemeral_sk);
    let shared_point = receiver_pk
        .mul_tweak(secp, &scalar)
        .map_err(|_| EciesError::InvalidPublicKey)?;
    let ephemeral_pk = PublicKey::from_secret_key(secp, ephemeral_sk);
    let key = derive_shared_key(&ephemeral_pk, &shared_point, compressed);
    Ok((ephemeral_pk, key))
}

/// Receiver-side ECDH: derives the shared symmetric key from the ephemeral public key.
fn decapsulate<C: Verification>(
    secp: &Secp256k1<C>,
    ephemeral_pk: &PublicKey,
    receiver_sk: &SecretKey,
    compressed: bool,
) -> Result<[u8; 32], EciesError> {
    let scalar = Scalar::from(*receiver_sk);
    let shared_point = ephemeral_pk
        .mul_tweak(secp, &scalar)
        .map_err(|_| EciesError::InvalidPublicKey)?;
    Ok(derive_shared_key(ephemeral_pk, &shared_point, compressed))
}

// ---------------------------------------------------------------------------
// AES-256-GCM primitives
//
// GenericArray 0.14 deprecation warnings are unavoidable with aes-gcm 0.10.
// Contained here so the rest of the module stays clean.
// ---------------------------------------------------------------------------

/// AES-256-GCM encrypt in-place, returning the authentication tag.
#[allow(deprecated)]
fn aes_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    data: &mut [u8],
) -> Result<[u8; TAG_SIZE], EciesError> {
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm16::new_from_slice(key).expect("32-byte key is valid");
    let nonce = GenericArray::from_slice(nonce);
    let tag = cipher
        .encrypt_in_place_detached(nonce, &[], data)
        .map_err(|_| EciesError::EncryptionFailed)?;
    let mut out = [0u8; TAG_SIZE];
    out.copy_from_slice(tag.as_slice());
    Ok(out)
}

/// AES-256-GCM decrypt in-place, verifying the authentication tag.
#[allow(deprecated)]
fn aes_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    tag: &[u8; TAG_SIZE],
    data: &mut [u8],
) -> Result<(), EciesError> {
    use aes_gcm::aead::generic_array::GenericArray;
    let cipher = Aes256Gcm16::new_from_slice(key).expect("32-byte key is valid");
    let nonce = GenericArray::from_slice(nonce);
    let tag = GenericArray::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, &[], data, tag)
        .map_err(|_| EciesError::DecryptionFailed)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// ECIES configuration controlling key serialization format.
///
/// Both fields default to `false`, matching the `ecies` crate's default
/// configuration for cross-compatibility.
#[derive(Debug, Default, Clone, Copy)]
pub struct Config {
    /// If true, the ephemeral public key in the ciphertext is 33 bytes
    /// (compressed) instead of 65 bytes (uncompressed).
    pub ephemeral_key_compressed: bool,
    /// If true, HKDF key derivation uses compressed public keys (33 bytes
    /// each) instead of uncompressed (65 bytes each).
    pub hkdf_key_compressed: bool,
}

impl Config {
    fn ephemeral_key_size(&self) -> usize {
        if self.ephemeral_key_compressed {
            COMPRESSED_KEY_SIZE
        } else {
            UNCOMPRESSED_KEY_SIZE
        }
    }
}

/// Encrypts a message for `receiver_pub` using the default configuration.
///
/// Output format: `ephemeral_pk(65) || nonce(16) || tag(16) || ciphertext`
///
/// **Heap allocations:** one `Vec` for the returned ciphertext.
///
/// # Errors
///
/// Returns [`EciesError::InvalidPublicKey`] if the receiver key is invalid.
pub fn encrypt<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    receiver_pub: &[u8],
    msg: &[u8],
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, EciesError> {
    encrypt_with_config(secp, receiver_pub, msg, &Config::default(), rng)
}

/// Decrypts a message using `receiver_sec` with the default configuration.
///
/// **Heap allocations:** one `Vec` for the returned plaintext.
///
/// # Errors
///
/// Returns [`EciesError::InvalidSecretKey`] if the key is invalid,
/// [`EciesError::InvalidMessage`] if the ciphertext is malformed, or
/// [`EciesError::DecryptionFailed`] if authentication fails.
pub fn decrypt<C: Verification>(
    secp: &Secp256k1<C>,
    receiver_sec: &[u8],
    msg: &[u8],
) -> Result<Vec<u8>, EciesError> {
    decrypt_with_config(secp, receiver_sec, msg, &Config::default())
}

/// Encrypts a message with explicit configuration.
///
/// **Heap allocations:** one `Vec` for the returned ciphertext.
pub fn encrypt_with_config<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    receiver_pub: &[u8],
    msg: &[u8],
    config: &Config,
    rng: &mut impl RngCore,
) -> Result<Vec<u8>, EciesError> {
    let receiver_pk =
        PublicKey::from_slice(receiver_pub).map_err(|_| EciesError::InvalidPublicKey)?;
    let ephemeral_sk = generate_secret_key(rng);
    let (ephemeral_pk, sym_key) = encapsulate(
        secp,
        &ephemeral_sk,
        &receiver_pk,
        config.hkdf_key_compressed,
    )?;

    // Single allocation: ephemeral_pk || nonce || tag || ciphertext
    let key_size = config.ephemeral_key_size();
    let mut out = Vec::with_capacity(key_size + NONCE_TAG_SIZE + msg.len());
    if config.ephemeral_key_compressed {
        out.extend_from_slice(&ephemeral_pk.serialize());
    } else {
        out.extend_from_slice(&ephemeral_pk.serialize_uncompressed());
    }

    let mut nonce = [0u8; NONCE_SIZE];
    rng.fill_bytes(&mut nonce);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&[0u8; TAG_SIZE]); // tag placeholder
    out.extend_from_slice(msg);

    let ct_start = key_size + NONCE_TAG_SIZE;
    let tag = aes_gcm_encrypt(&sym_key, &nonce, &mut out[ct_start..])?;
    out[key_size + NONCE_SIZE..ct_start].copy_from_slice(&tag);

    Ok(out)
}

/// Decrypts a message with explicit configuration.
///
/// **Heap allocations:** one `Vec` for the returned plaintext.
pub fn decrypt_with_config<C: Verification>(
    secp: &Secp256k1<C>,
    receiver_sec: &[u8],
    msg: &[u8],
    config: &Config,
) -> Result<Vec<u8>, EciesError> {
    let receiver_sk =
        SecretKey::from_slice(receiver_sec).map_err(|_| EciesError::InvalidSecretKey)?;
    let key_size = config.ephemeral_key_size();

    if msg.len() < key_size + NONCE_TAG_SIZE {
        return Err(EciesError::InvalidMessage);
    }

    let ephemeral_pk =
        PublicKey::from_slice(&msg[..key_size]).map_err(|_| EciesError::InvalidPublicKey)?;
    let sym_key = decapsulate(
        secp,
        &ephemeral_pk,
        &receiver_sk,
        config.hkdf_key_compressed,
    )?;

    let nonce: &[u8; NONCE_SIZE] = msg[key_size..key_size + NONCE_SIZE]
        .try_into()
        .expect("length verified");
    let tag: &[u8; TAG_SIZE] = msg[key_size + NONCE_SIZE..key_size + NONCE_TAG_SIZE]
        .try_into()
        .expect("length verified");

    // Single allocation: plaintext buffer decrypted in-place
    let mut plaintext = msg[key_size + NONCE_TAG_SIZE..].to_vec();
    aes_gcm_decrypt(&sym_key, nonce, tag, &mut plaintext)?;
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn decode_hex(s: &str) -> Vec<u8> {
        let s = s
            .strip_prefix("0x")
            .or_else(|| s.strip_prefix("0X"))
            .unwrap_or(s);
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn test_sk(i: u8) -> SecretKey {
        let mut bytes = [0u8; 32];
        bytes[31] = i;
        SecretKey::from_slice(&bytes).unwrap()
    }

    // -- HKDF known vector --

    #[test]
    fn hkdf_known_vector() {
        let result = hkdf_sha256(b"secret");
        assert_eq!(
            result.to_vec(),
            decode_hex("2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf")
        );
    }

    // -- ECDH known vectors (from ecies crate) --

    #[test]
    fn encapsulate_uncompressed_known_vector() {
        let secp = Secp256k1::new();
        let sk2 = test_sk(2);
        let sk3 = test_sk(3);
        let pk3 = PublicKey::from_secret_key(&secp, &sk3);

        let (_, shared) = encapsulate(&secp, &sk2, &pk3, false).unwrap();
        assert_eq!(
            shared.to_vec(),
            decode_hex("6f982d63e8590c9d9b5b4c1959ff80315d772edd8f60287c9361d548d5200f82")
        );
    }

    #[test]
    fn encapsulate_compressed_known_vector() {
        let secp = Secp256k1::new();
        let sk2 = test_sk(2);
        let sk3 = test_sk(3);
        let pk3 = PublicKey::from_secret_key(&secp, &sk3);

        let (_, shared) = encapsulate(&secp, &sk2, &pk3, true).unwrap();
        assert_eq!(
            shared.to_vec(),
            decode_hex("b192b226edb3f02da11ef9c6ce4afe1c7e40be304e05ae3b988f4834b1cb6c69")
        );
    }

    // -- ecies crate cross-compatibility: decrypt known ciphertext --

    #[test]
    fn decrypt_ecies_crate_known_ciphertext() {
        let secp = Secp256k1::new();
        let sk = decode_hex("e520872701d9ec44dbac2eab85512ad14ad0c42e01de56d7b528abd8524fcb47");
        let encrypted = decode_hex(
            "047be1885aeb48d4d4db0c992996725d3264784fef88c5b60782f8d0f940c213\
             227fc3f904f846d5ec3d0fba6653754501e8ebadc421aa3892a20fef33cff020\
             6047058a4cfb4efbeae96b2d019b4ab2edce33328748a0d008a69c8f5816b72d\
             45bd9b5a41bb6ea0127ab23057ec6fcd",
        );
        let plaintext = decrypt(&secp, &sk, &encrypted).unwrap();
        assert_eq!(plaintext, "hello world\u{1f30d}".as_bytes());
    }

    // -- Round-trip tests --

    #[test]
    fn round_trip_uncompressed() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let msg = b"hello world";
        let ct = encrypt(&secp, &pk.serialize_uncompressed(), msg, &mut rng).unwrap();
        let pt = decrypt(&secp, &sk[..], &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn round_trip_compressed_receiver_key() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xab; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let msg = b"compressed receiver key test";
        let ct = encrypt(&secp, &pk.serialize(), msg, &mut rng).unwrap();
        let pt = decrypt(&secp, &sk[..], &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn round_trip_compressed_config() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xef; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();
        let config = Config {
            ephemeral_key_compressed: true,
            hkdf_key_compressed: true,
        };

        let msg = b"compressed config test";
        let ct = encrypt_with_config(&secp, &pk.serialize(), msg, &config, &mut rng).unwrap();
        assert!(ct.len() < UNCOMPRESSED_KEY_SIZE + NONCE_TAG_SIZE + msg.len());
        let pt = decrypt_with_config(&secp, &sk[..], &ct, &config).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn round_trip_empty_message() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let ct = encrypt(&secp, &pk.serialize_uncompressed(), b"", &mut rng).unwrap();
        let pt = decrypt(&secp, &sk[..], &ct).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn round_trip_large_message() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let msg = vec![0xFFu8; 64 * 1024];
        let ct = encrypt(&secp, &pk.serialize_uncompressed(), &msg, &mut rng).unwrap();
        let pt = decrypt(&secp, &sk[..], &ct).unwrap();
        assert_eq!(pt, msg);
    }

    // -- Error paths --

    #[test]
    fn encrypt_invalid_public_key() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        assert_eq!(
            encrypt(&secp, &[0u8; 33], b"msg", &mut rng),
            Err(EciesError::InvalidPublicKey)
        );
    }

    #[test]
    fn decrypt_invalid_secret_key() {
        let secp = Secp256k1::new();
        assert_eq!(
            decrypt(&secp, &[0u8; 32], &[]),
            Err(EciesError::InvalidSecretKey)
        );
    }

    #[test]
    fn decrypt_message_too_short() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        assert_eq!(
            decrypt(&secp, &sk[..], &[]),
            Err(EciesError::InvalidMessage)
        );
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[0xaa; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let sk2 = SecretKey::from_slice(&[0xbb; 32]).unwrap();
        let mut rng = rand::thread_rng();

        let ct = encrypt(&secp, &pk1.serialize_uncompressed(), b"secret", &mut rng).unwrap();
        assert_eq!(
            decrypt(&secp, &sk2[..], &ct),
            Err(EciesError::DecryptionFailed)
        );
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcc; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let mut ct = encrypt(
            &secp,
            &pk.serialize_uncompressed(),
            b"tamper test",
            &mut rng,
        )
        .unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0xFF;
        assert_eq!(
            decrypt(&secp, &sk[..], &ct),
            Err(EciesError::DecryptionFailed)
        );
    }

    // -- Live cross-compatibility with the `ecies` crate --

    #[test]
    fn our_encrypt_ecies_crate_decrypt() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);
        let mut rng = rand::thread_rng();

        let msg = b"our encrypt, ecies crate decrypt";
        let ct = encrypt(&secp, &pk.serialize_uncompressed(), msg, &mut rng).unwrap();
        let pt = ecies_ext::decrypt(&sk[..], &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn ecies_crate_encrypt_our_decrypt() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0xcd; 32]).unwrap();
        let pk = PublicKey::from_secret_key(&secp, &sk);

        let msg = b"ecies crate encrypt, our decrypt";
        let ct = ecies_ext::encrypt(&pk.serialize_uncompressed(), msg).unwrap();
        let pt = decrypt(&secp, &sk[..], &ct).unwrap();
        assert_eq!(pt, msg);
    }
}
