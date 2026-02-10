//! Spark Address Encoding and Decoding
//!
//! Spark addresses are human-readable identifiers that encode a wallet's identity
//! public key using Bech32m encoding with a protobuf-style wrapper.
//!
//! # Format
//!
//! A Spark address consists of:
//! - A human-readable part (HRP) that identifies the network
//! - A separator (`1`)
//! - The Bech32m-encoded payload containing:
//!   - A protobuf tag byte (`0x0a` = field 1, wire type 2)
//!   - A length byte (`0x21` = 33)
//!   - The 33-byte compressed secp256k1 public key
//! - A 6-character checksum
//!
//! # Network Prefixes
//!
//! | Network  | HRP       | Example |
//! |----------|-----------|---------|
//! | Mainnet  | `spark`   | `spark1pgss...` |
//! | Regtest  | `sparkrt` | `sparkrt1pgss...` |
//!
//! # Heap Allocations
//!
//! | Operation | Allocations |
//! |-----------|-------------|
//! | `Display::fmt()` | 0 |
//! | `encode()` | 1 (String via `to_string()`) |
//! | `parse()` (lowercase input) | 0 |
//! | `parse()` (mixed-case input) | 1 (`to_lowercase()`) |
//! | `pubkey_hex()` | 1 (String) |
//!
//! # Example
//!
//! ```rust
//! use sdk_core::{SparkAddress, Network};
//!
//! // Create an address from a public key
//! let pubkey = [0x02u8; 33]; // Example compressed public key
//! let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);
//! println!("Spark address: {}", address);
//!
//! // Parse an address string (roundtrip test)
//! let encoded = address.encode();
//! let parsed = SparkAddress::parse(&encoded).unwrap();
//! assert_eq!(parsed.network(), Network::Mainnet);
//! assert_eq!(parsed.pubkey(), &pubkey);
//! ```

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

use crate::Network;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Protobuf tag byte: field 1, wire type 2 (length-delimited).
/// Calculated as: (1 << 3) | 2 = 0x0a
const PROTO_TAG: u8 = 0x0a;

/// Length of a compressed secp256k1 public key.
const PUBKEY_LEN: u8 = 33;

/// Total size of the protobuf envelope: tag + length + pubkey.
const PROTO_ENVELOPE_SIZE: usize = 2 + PUBKEY_LEN as usize;

/// Human-readable part for Spark mainnet addresses.
pub const HRP_MAINNET: &str = "spark";

/// Human-readable part for Spark regtest addresses.
pub const HRP_REGTEST: &str = "sparkrt";

// ---------------------------------------------------------------------------
// SparkAddress
// ---------------------------------------------------------------------------

/// A Spark address containing a network and identity public key.
///
/// Spark addresses are Bech32m-encoded representations of identity public keys,
/// similar to how Bitcoin Taproot addresses encode public keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SparkAddress {
    /// The network this address belongs to.
    network: Network,
    /// The 33-byte compressed identity public key.
    pubkey: [u8; 33],
}

impl SparkAddress {
    /// Creates a new Spark address from a network and identity public key.
    ///
    /// # Arguments
    ///
    /// * `network` -- The Spark network (Mainnet, Regtest)
    /// * `pubkey` -- The 33-byte compressed secp256k1 public key
    pub fn from_pubkey(network: Network, pubkey: [u8; 33]) -> Self {
        Self { network, pubkey }
    }

    /// Returns the network this address belongs to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Returns the identity public key as a 33-byte array.
    pub fn pubkey(&self) -> &[u8; 33] {
        &self.pubkey
    }

    /// Returns the identity public key as a lowercase hex string.
    ///
    /// Allocates a 66-character `String`.
    pub fn pubkey_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(66);
        for &b in &self.pubkey {
            s.push(HEX[(b >> 4) as usize] as char);
            s.push(HEX[(b & 0x0f) as usize] as char);
        }
        s
    }

    /// Returns the human-readable part (HRP) for this address's network.
    pub fn hrp(&self) -> &'static str {
        match self.network {
            Network::Mainnet => HRP_MAINNET,
            Network::Regtest => HRP_REGTEST,
        }
    }

    /// Encodes this address as a Bech32m string.
    ///
    /// Allocates a `String`. For zero-alloc writing, use the [`Display`] impl
    /// directly (e.g. `write!(buf, "{address}")`).
    pub fn encode(&self) -> String {
        self.to_string()
    }

    /// Parses a Spark address from a Bech32m string.
    ///
    /// Zero heap allocations when the input is already lowercase (the common
    /// case -- our own encoder produces lowercase). Mixed-case input triggers
    /// one allocation for case normalization.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The string is not valid Bech32m
    /// - The HRP doesn't match a known network
    /// - The protobuf envelope is invalid (wrong tag, length, or size)
    /// - The public key has an invalid prefix (must be `0x02` or `0x03`)
    pub fn parse(s: &str) -> Result<Self, SparkAddressError> {
        // Bech32m is case-insensitive. Avoid heap allocation when already
        // lowercase (the common path -- our encoder always produces lowercase).
        let normalized: Cow<'_, str> = if s.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(s.to_lowercase())
        } else {
            Cow::Borrowed(s)
        };

        // Zero-alloc Bech32m decoding via CheckedHrpstring.
        let checked = CheckedHrpstring::new::<Bech32m>(&normalized)
            .map_err(|e| SparkAddressError::Bech32(e.to_string()))?;

        // Determine network from HRP.
        let network = match checked.hrp().as_str() {
            HRP_MAINNET => Network::Mainnet,
            HRP_REGTEST => Network::Regtest,
            other => return Err(SparkAddressError::UnknownNetwork(other.to_string())),
        };

        // Decode proto envelope into a stack buffer -- zero alloc.
        let mut buf = [0u8; PROTO_ENVELOPE_SIZE];
        let mut len = 0;
        for byte in checked.byte_iter() {
            if len >= PROTO_ENVELOPE_SIZE {
                return Err(SparkAddressError::BadProto);
            }
            buf[len] = byte;
            len += 1;
        }

        // Validate proto envelope: exact size, correct tag and length.
        if len != PROTO_ENVELOPE_SIZE || buf[0] != PROTO_TAG || buf[1] != PUBKEY_LEN {
            return Err(SparkAddressError::BadProto);
        }

        // Extract pubkey.
        let mut pubkey = [0u8; 33];
        pubkey.copy_from_slice(&buf[2..]);

        // Compressed public key must start with 0x02 or 0x03.
        if pubkey[0] != 0x02 && pubkey[0] != 0x03 {
            return Err(SparkAddressError::InvalidPublicKey(
                "compressed public key must start with 0x02 or 0x03",
            ));
        }

        Ok(Self { network, pubkey })
    }

    /// Returns the protobuf-encoded payload as a stack-allocated array.
    ///
    /// Format: `[PROTO_TAG, PUBKEY_LEN, ...33 bytes of pubkey]` = 35 bytes.
    fn proto_bytes(&self) -> [u8; PROTO_ENVELOPE_SIZE] {
        let mut buf = [0u8; PROTO_ENVELOPE_SIZE];
        buf[0] = PROTO_TAG;
        buf[1] = PUBKEY_LEN;
        buf[2..].copy_from_slice(&self.pubkey);
        buf
    }
}

/// Zero-alloc: writes the Bech32m encoding directly to the formatter.
impl fmt::Display for SparkAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hrp = Hrp::parse(self.hrp()).expect("HRP constant is valid");
        let data = self.proto_bytes();
        bech32::encode_lower_to_fmt::<Bech32m, _>(f, hrp, &data).map_err(|_| fmt::Error)
    }
}

impl FromStr for SparkAddress {
    type Err = SparkAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing Spark addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparkAddressError {
    /// Bech32m decoding failed.
    Bech32(String),

    /// The HRP does not match any known Spark network.
    UnknownNetwork(String),

    /// The protobuf envelope is missing, malformed, or has wrong size.
    BadProto,

    /// The public key has an invalid prefix byte.
    InvalidPublicKey(&'static str),
}

impl fmt::Display for SparkAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bech32(e) => write!(f, "bech32 error: {e}"),
            Self::UnknownNetwork(hrp) => write!(f, "unknown network prefix: {hrp}"),
            Self::BadProto => write!(f, "invalid protobuf envelope"),
            Self::InvalidPublicKey(reason) => write!(f, "invalid public key: {reason}"),
        }
    }
}

impl std::error::Error for SparkAddressError {}

// ---------------------------------------------------------------------------
// Convenience functions
// ---------------------------------------------------------------------------

/// Encodes an identity public key as a Spark address string.
pub fn encode_spark_address(network: Network, pubkey: &[u8; 33]) -> String {
    SparkAddress::from_pubkey(network, *pubkey).encode()
}

/// Decodes a Spark address string into its components.
pub fn decode_spark_address(address: &str) -> Result<(Network, [u8; 33]), SparkAddressError> {
    let addr = SparkAddress::parse(address)?;
    Ok((addr.network, addr.pubkey))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into bytes. Test-only helper to avoid a `hex` dependency.
    fn from_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn encode_mainnet_address() {
        // Generator point compressed public key.
        let pubkey = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);
        let encoded = address.encode();

        assert!(encoded.starts_with("spark1"));
        assert!(!encoded.contains(char::is_uppercase));

        // Roundtrip.
        let parsed = SparkAddress::parse(&encoded).unwrap();
        assert_eq!(parsed.network(), Network::Mainnet);
        assert_eq!(parsed.pubkey(), &pubkey);
    }

    #[test]
    fn encode_regtest_address() {
        let pubkey = [0x02u8; 33];
        let address = SparkAddress::from_pubkey(Network::Regtest, pubkey);
        let encoded = address.encode();

        assert!(encoded.starts_with("sparkrt1"));

        let parsed = SparkAddress::parse(&encoded).unwrap();
        assert_eq!(parsed.network(), Network::Regtest);
    }

    #[test]
    fn case_insensitive_parsing() {
        let pubkey = [0x02u8; 33];
        let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);
        let encoded = address.encode();

        // Parse uppercase version.
        let upper = encoded.to_uppercase();
        let parsed = SparkAddress::parse(&upper).unwrap();
        assert_eq!(parsed.pubkey(), &pubkey);

        // Parse mixed case version.
        let mixed: String = encoded
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_uppercase().next().unwrap()
                } else {
                    c
                }
            })
            .collect();
        let parsed = SparkAddress::parse(&mixed).unwrap();
        assert_eq!(parsed.pubkey(), &pubkey);
    }

    #[test]
    fn non_spark_bech32m_rejected() {
        // Taproot address (valid Bech32m, but wrong HRP).
        let result =
            SparkAddress::parse("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
        assert!(matches!(result, Err(SparkAddressError::UnknownNetwork(_))));
    }

    #[test]
    fn bech32_v0_rejected() {
        // Segwit v0 address (Bech32, not Bech32m) -- fails checksum validation.
        let result = SparkAddress::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
        assert!(matches!(result, Err(SparkAddressError::Bech32(_))));
    }

    #[test]
    fn invalid_public_key_prefix() {
        let mut pubkey = [0x04u8; 33];
        pubkey[0] = 0x04;

        let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);
        let encoded = address.encode();

        let result = SparkAddress::parse(&encoded);
        assert!(matches!(
            result,
            Err(SparkAddressError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn display_trait() {
        let pubkey = [0x02u8; 33];
        let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);

        let display = format!("{address}");
        let encoded = address.encode();

        assert_eq!(display, encoded);
    }

    #[test]
    fn from_str_trait() {
        let pubkey = [0x02u8; 33];
        let address = SparkAddress::from_pubkey(Network::Mainnet, pubkey);
        let encoded = address.encode();

        let parsed: SparkAddress = encoded.parse().unwrap();
        assert_eq!(parsed, address);
    }

    #[test]
    fn convenience_functions() {
        let pubkey = [0x02u8; 33];

        let encoded = encode_spark_address(Network::Regtest, &pubkey);
        assert!(encoded.starts_with("sparkrt1"));

        let (network, decoded_pubkey) = decode_spark_address(&encoded).unwrap();
        assert_eq!(network, Network::Regtest);
        assert_eq!(decoded_pubkey, pubkey);
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let pubkey_hex_str = "0341a00a9a26c4c5ba25246c36ba8b527ac4001131d307b51cc5400285b673ecdc";
        let pubkey_bytes = from_hex(pubkey_hex_str);
        let pubkey: [u8; 33] = pubkey_bytes.try_into().unwrap();

        let address = SparkAddress::from_pubkey(Network::Regtest, pubkey);
        assert_eq!(address.pubkey_hex(), pubkey_hex_str);
    }

    #[test]
    fn real_sparkscan_address() {
        let pubkey_hex_str = "0341a00a9a26c4c5ba25246c36ba8b527ac4001131d307b51cc5400285b673ecdc";
        let expected_addr =
            "sparkrt1pgssxsdqp2dzd3x9hgjjgmpkh294y7kyqqgnr5c8k5wv2sqzskm88mxu93h6m9";

        let pubkey_bytes = from_hex(pubkey_hex_str);
        let pubkey: [u8; 33] = pubkey_bytes.try_into().unwrap();

        let addr = SparkAddress::from_pubkey(Network::Regtest, pubkey);
        let encoded = addr.encode();

        assert_eq!(encoded, expected_addr, "address encoding mismatch");
    }

    #[test]
    fn parse_official_sparkscan_address() {
        let official_addr =
            "sparkrt1pgssxsdqp2dzd3x9hgjjgmpkh294y7kyqqgnr5c8k5wv2sqzskm88mxu93h6m9";

        let parsed = SparkAddress::parse(official_addr).expect("should parse official address");

        assert_eq!(parsed.network(), Network::Regtest);
        assert_eq!(
            parsed.pubkey_hex(),
            "0341a00a9a26c4c5ba25246c36ba8b527ac4001131d307b51cc5400285b673ecdc"
        );

        // Re-encoding produces identical address.
        assert_eq!(parsed.encode(), official_addr);
    }

    #[test]
    fn error_display() {
        let err = SparkAddressError::BadProto;
        assert_eq!(err.to_string(), "invalid protobuf envelope");

        let err = SparkAddressError::UnknownNetwork("btc".into());
        assert_eq!(err.to_string(), "unknown network prefix: btc");

        let err = SparkAddressError::InvalidPublicKey("bad prefix");
        assert_eq!(err.to_string(), "invalid public key: bad prefix");
    }
}
