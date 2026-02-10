//! Bitcoin transaction utilities for Spark leaf operations.
//!
//! Provides refund transaction construction, Taproot sighash computation,
//! and timelock sequence helpers used by both send and claim flows.

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from transaction utilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxError {
    /// Failed to deserialize a raw transaction.
    DeserializeFailed,
    /// Failed to compute sighash.
    SighashFailed,
    /// The transaction is missing required data (e.g. outputs).
    MissingData,
}

impl core::fmt::Display for TxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DeserializeFailed => write!(f, "transaction deserialization failed"),
            Self::SighashFailed => write!(f, "sighash computation failed"),
            Self::MissingData => write!(f, "transaction missing required data"),
        }
    }
}

impl std::error::Error for TxError {}

// ---------------------------------------------------------------------------
// Parse / Serialize
// ---------------------------------------------------------------------------

/// Deserialize a Bitcoin transaction from consensus-encoded bytes.
///
/// # Errors
///
/// Returns [`TxError::DeserializeFailed`] if the bytes are not a valid transaction.
pub fn parse_tx(raw: &[u8]) -> Result<Transaction, TxError> {
    deserialize(raw).map_err(|_| TxError::DeserializeFailed)
}

/// Serialize a Bitcoin transaction to consensus-encoded bytes.
pub fn serialize_tx(tx: &Transaction) -> Vec<u8> {
    serialize(tx)
}

// ---------------------------------------------------------------------------
// Refund Transaction Construction
// ---------------------------------------------------------------------------

/// Create a **CPFP** refund transaction (2 outputs: P2TR + P2A anchor).
///
/// The CPFP variant has:
///   - `output[0]`: P2TR to receiver's new signing key
///   - `output[1]`: P2A ephemeral anchor (`OP_1 <0x4e73>`)
pub fn create_cpfp_refund_tx(
    prev_txid: Txid,
    prev_vout: u32,
    value: Amount,
    sequence: Sequence,
    receiver_xonly: &XOnlyPublicKey,
    network: Network,
) -> Transaction {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let address = Address::p2tr(&secp, *receiver_xonly, None, network);

    // BIP-431 ephemeral anchor: OP_1 OP_PUSHBYTES_2 0x4e73
    let anchor_script = ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]);

    Transaction {
        version: bitcoin::transaction::Version::non_standard(3),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value,
                script_pubkey: address.script_pubkey(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: anchor_script,
            },
        ],
    }
}

/// Estimated transaction vbyte size for fee calculation (matches Spark operators).
const ESTIMATED_TX_SIZE: u64 = 191;

/// Default fee rate in sat/vbyte.
const DEFAULT_FEE_RATE: u64 = 5;

/// Default fee in satoshis: 191 * 5 = 955 sats.
const DEFAULT_FEE_SATS: u64 = ESTIMATED_TX_SIZE * DEFAULT_FEE_RATE;

/// Create a **direct** refund transaction (1 output: P2TR only, no anchor).
///
/// Direct refund txs embed the relay fee in the output value since they lack
/// an anchor for CPFP fee-bumping. The output value is `max(value - 955, 0)`.
pub fn create_direct_refund_tx(
    prev_txid: Txid,
    prev_vout: u32,
    value: Amount,
    sequence: Sequence,
    receiver_xonly: &XOnlyPublicKey,
    network: Network,
) -> Transaction {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let address = Address::p2tr(&secp, *receiver_xonly, None, network);

    // Deduct default fee from the output value (no anchor for CPFP).
    // Only deduct if the value exceeds the fee; otherwise use value as-is.
    let raw = value.to_sat();
    let output_sats = if raw > DEFAULT_FEE_SATS {
        raw - DEFAULT_FEE_SATS
    } else {
        raw
    };

    Transaction {
        version: bitcoin::transaction::Version::non_standard(3),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(prev_txid, prev_vout),
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_sats),
            script_pubkey: address.script_pubkey(),
        }],
    }
}

// ---------------------------------------------------------------------------
// Taproot Sighash
// ---------------------------------------------------------------------------

/// Compute the BIP341 Taproot key-spend sighash for a transaction input.
///
/// Uses `SIGHASH_DEFAULT` (equivalent to `SIGHASH_ALL` for Taproot).
///
/// # Arguments
///
/// * `tx` -- The transaction being signed
/// * `input_idx` -- The input index to compute the sighash for
/// * `prev_outs` -- ALL previous outputs being spent (BIP341 requires all)
///
/// # Errors
///
/// Returns [`TxError::SighashFailed`] if sighash computation fails.
pub fn taproot_sighash(
    tx: &Transaction,
    input_idx: usize,
    prev_outs: &[TxOut],
) -> Result<[u8; 32], TxError> {
    let mut cache = SighashCache::new(tx);
    let hash = cache
        .taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(prev_outs),
            TapSighashType::Default,
        )
        .map_err(|_| TxError::SighashFailed)?;
    Ok(hash.to_byte_array())
}

// ---------------------------------------------------------------------------
// Timelock Sequences
// ---------------------------------------------------------------------------

/// Compute the claim timelock sequences (same as current, not decremented).
///
/// For claiming, we keep the **exact** same sequence as the intermediate refund
/// transaction. The nSequence value may include flags (e.g. CSV type flag at
/// bit 22) that must be preserved.
///
/// Returns `(cpfp_sequence, direct_sequence)`.
pub fn current_claim_sequences(old_sequence: Sequence) -> (Sequence, Sequence) {
    // For claiming, both CPFP and direct use the same sequence.
    (old_sequence, old_sequence)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the x-only public key from a P2TR output's script_pubkey.
///
/// Returns `None` if the output is not a valid P2TR script.
pub fn xonly_from_p2tr_script(script: &ScriptBuf) -> Option<XOnlyPublicKey> {
    if script.is_p2tr() {
        // P2TR script: OP_1 OP_PUSH32 <32-byte x-only key>
        let bytes = script.as_bytes();
        if bytes.len() == 34 {
            XOnlyPublicKey::from_slice(&bytes[2..]).ok()
        } else {
            None
        }
    } else {
        None
    }
}

/// Convert a compressed public key (33 bytes) to an x-only public key.
///
/// Drops the parity byte prefix and returns the 32-byte x coordinate.
pub fn compressed_to_xonly(compressed: &[u8; 33]) -> Option<XOnlyPublicKey> {
    XOnlyPublicKey::from_slice(&compressed[1..]).ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_claim_sequences_preserves_original() {
        // Simple value.
        let (cpfp, direct) = current_claim_sequences(Sequence::from_consensus(1800));
        assert_eq!(cpfp.to_consensus_u32(), 1800);
        assert_eq!(direct.to_consensus_u32(), 1800);

        // CSV with type flag (bit 22) -- must be preserved as-is.
        let csv_seq = Sequence::from_consensus(0x40000708); // type_flag | 1800
        let (cpfp, direct) = current_claim_sequences(csv_seq);
        assert_eq!(cpfp.to_consensus_u32(), 0x40000708);
        assert_eq!(direct.to_consensus_u32(), 0x40000708);
    }

    #[test]
    fn compressed_to_xonly_works() {
        // Generator point compressed (02 prefix + x coordinate).
        let gen_compressed: [u8; 33] = [
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        let xonly = compressed_to_xonly(&gen_compressed).unwrap();
        assert_eq!(xonly.serialize(), gen_compressed[1..]);
    }

    #[test]
    fn create_cpfp_refund_tx_has_two_outputs() {
        let txid = Txid::from_byte_array([0xAA; 32]);
        let gen_compressed: [u8; 33] = [
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        let xonly = compressed_to_xonly(&gen_compressed).unwrap();

        let tx = create_cpfp_refund_tx(
            txid,
            0,
            Amount::from_sat(1000),
            Sequence::from_consensus(1800),
            &xonly,
            Network::Regtest,
        );

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 2);
        assert_eq!(tx.input[0].sequence.to_consensus_u32(), 1800);
        assert_eq!(tx.output[0].value, Amount::from_sat(1000));
        assert!(tx.output[0].script_pubkey.is_p2tr());
        // output[1] is P2A anchor
        assert_eq!(tx.output[1].value, Amount::ZERO);
        assert_eq!(
            tx.output[1].script_pubkey.as_bytes(),
            &[0x51, 0x02, 0x4e, 0x73]
        );

        let raw = serialize_tx(&tx);
        let recovered = parse_tx(&raw).unwrap();
        assert_eq!(recovered.compute_txid(), tx.compute_txid());
    }

    #[test]
    fn create_direct_refund_tx_has_one_output() {
        let txid = Txid::from_byte_array([0xBB; 32]);
        let gen_compressed: [u8; 33] = [
            0x02, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE,
            0x87, 0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81,
            0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        let xonly = compressed_to_xonly(&gen_compressed).unwrap();

        let tx = create_direct_refund_tx(
            txid,
            0,
            Amount::from_sat(500),
            Sequence::from_consensus(1800),
            &xonly,
            Network::Regtest,
        );

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert!(tx.output[0].script_pubkey.is_p2tr());

        let raw = serialize_tx(&tx);
        let recovered = parse_tx(&raw).unwrap();
        assert_eq!(recovered.compute_txid(), tx.compute_txid());
    }
}
