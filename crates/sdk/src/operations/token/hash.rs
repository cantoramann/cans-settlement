//! Deterministic protobuf hashing for token transactions (protoreflecthash).
//!
//! Implements the same algorithm as the Go/JS SDKs to produce identical
//! 32-byte SHA256 hashes for `PartialTokenTransaction` and its nested types.
//!
//! The algorithm walks proto fields by field number, hashes each value
//! with a type-tag prefix, and combines them with a map hash.  Default/zero
//! values are **skipped**.
//!
//! # Type Tags
//!
//! | Tag | Meaning  | Encoding                            |
//! |-----|----------|-------------------------------------|
//! | `b` | bool     | `"0"` / `"1"` (ASCII)              |
//! | `i` | integer  | 8-byte big-endian                   |
//! | `r` | bytes    | raw bytes                           |
//! | `u` | string   | UTF-8 bytes                         |
//! | `l` | list     | concat of element hashes            |
//! | `d` | map/msg  | concat of sorted `H(key)‖H(value)` |

use bitcoin::hashes::{Hash, sha256};
use transport::spark_token::{
    self, InvoiceAttachment, PartialTokenOutput, TokenCreateInput, TokenMintInput,
    TokenOutputToSpend, TokenTransactionMetadata, TokenTransferInput,
    partial_token_transaction::TokenInputs,
};

// ---------------------------------------------------------------------------
// Type-tag prefixes (ASCII)
// ---------------------------------------------------------------------------

const BOOL_TAG: &[u8] = b"b";
const INT_TAG: &[u8] = b"i";
const BYTES_TAG: &[u8] = b"r";
const UNICODE_TAG: &[u8] = b"u";
const LIST_TAG: &[u8] = b"l";
const MAP_TAG: &[u8] = b"d";

// ---------------------------------------------------------------------------
// Primitive hashers
// ---------------------------------------------------------------------------

/// `SHA256(tag || data)`.
fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32] {
    let mut engine = sha256::Hash::engine();
    bitcoin::hashes::HashEngine::input(&mut engine, tag);
    bitcoin::hashes::HashEngine::input(&mut engine, data);
    sha256::Hash::from_engine(engine).to_byte_array()
}

fn hash_bool(v: bool) -> [u8; 32] {
    tagged_hash(BOOL_TAG, if v { b"1" } else { b"0" })
}

fn hash_uint32(v: u32) -> [u8; 32] {
    tagged_hash(INT_TAG, &(v as u64).to_be_bytes())
}

fn hash_uint64(v: u64) -> [u8; 32] {
    tagged_hash(INT_TAG, &v.to_be_bytes())
}

fn hash_int64(v: i64) -> [u8; 32] {
    tagged_hash(INT_TAG, &v.to_be_bytes())
}

fn hash_int32(v: i32) -> [u8; 32] {
    // protoreflecthash encodes enums/int32 as int64
    hash_int64(v as i64)
}

fn hash_bytes(v: &[u8]) -> [u8; 32] {
    tagged_hash(BYTES_TAG, v)
}

fn hash_string(v: &str) -> [u8; 32] {
    tagged_hash(UNICODE_TAG, v.as_bytes())
}

/// Hash a proto field key (field number as uint64).
fn hash_field_key(field_number: u32) -> [u8; 32] {
    hash_int64(field_number as i64)
}

/// Combine `(key_hash, value_hash)` pairs into a map hash.
fn hash_map(pairs: &[([u8; 32], [u8; 32])]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(pairs.len() * 64);
    for (k, v) in pairs {
        buf.extend_from_slice(k);
        buf.extend_from_slice(v);
    }
    tagged_hash(MAP_TAG, &buf)
}

/// Hash a repeated field (list of pre-hashed elements).
fn hash_list(elements: &[[u8; 32]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(elements.len() * 32);
    for h in elements {
        buf.extend_from_slice(h);
    }
    tagged_hash(LIST_TAG, &buf)
}

// ---------------------------------------------------------------------------
// Default checks (proto3 semantics: zero/empty = default = skip)
// ---------------------------------------------------------------------------

fn is_default_u32(v: u32) -> bool {
    v == 0
}
fn is_default_u64(v: u64) -> bool {
    v == 0
}
fn is_default_i32(v: i32) -> bool {
    v == 0
}
fn is_default_bytes(v: &[u8]) -> bool {
    v.is_empty()
}
fn is_default_string(v: &str) -> bool {
    v.is_empty()
}

// ---------------------------------------------------------------------------
// Message hashers (one per proto message type)
// ---------------------------------------------------------------------------

/// Hash `prost_types::Timestamp`.
///
/// The JS SDK (ts-proto) converts Timestamp to a `Date` object, and the
/// ProtoHasher special-cases `Date` as a LIST of `[seconds, nanos]`.
/// We must match that encoding: `SHA256("l" || H(seconds) || H(nanos))`.
fn hash_timestamp(ts: &prost_types::Timestamp) -> [u8; 32] {
    let elements = [hash_int64(ts.seconds), hash_int64(ts.nanos as i64)];
    hash_list(&elements)
}

/// Hash `InvoiceAttachment` (field 1=spark_invoice:string).
fn hash_invoice_attachment(inv: &InvoiceAttachment) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(1);
    if !is_default_string(&inv.spark_invoice) {
        pairs.push((hash_field_key(1), hash_string(&inv.spark_invoice)));
    }
    hash_map(&pairs)
}

/// Hash `TokenOutputToSpend` (field 1=prev_hash:bytes, field 2=prev_vout:uint32).
fn hash_token_output_to_spend(o: &TokenOutputToSpend) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(2);
    if !is_default_bytes(&o.prev_token_transaction_hash) {
        pairs.push((
            hash_field_key(1),
            hash_bytes(&o.prev_token_transaction_hash),
        ));
    }
    if !is_default_u32(o.prev_token_transaction_vout) {
        pairs.push((
            hash_field_key(2),
            hash_uint32(o.prev_token_transaction_vout),
        ));
    }
    hash_map(&pairs)
}

/// Hash `TokenTransferInput` (field 1=outputs_to_spend:repeated message).
fn hash_transfer_input(ti: &TokenTransferInput) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(1);
    if !ti.outputs_to_spend.is_empty() {
        let elements: Vec<[u8; 32]> = ti
            .outputs_to_spend
            .iter()
            .map(hash_token_output_to_spend)
            .collect();
        pairs.push((hash_field_key(1), hash_list(&elements)));
    }
    hash_map(&pairs)
}

/// Hash `TokenMintInput` (field 1=issuer_public_key:bytes, field 2=token_identifier:optional bytes).
fn hash_mint_input(mi: &TokenMintInput) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(2);
    if !is_default_bytes(&mi.issuer_public_key) {
        pairs.push((hash_field_key(1), hash_bytes(&mi.issuer_public_key)));
    }
    if let Some(ref tid) = mi.token_identifier {
        if !is_default_bytes(tid) {
            pairs.push((hash_field_key(2), hash_bytes(tid)));
        }
    }
    hash_map(&pairs)
}

/// Hash `TokenCreateInput`.
fn hash_create_input(ci: &TokenCreateInput) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(8);
    // field 1: issuer_public_key (bytes)
    if !is_default_bytes(&ci.issuer_public_key) {
        pairs.push((hash_field_key(1), hash_bytes(&ci.issuer_public_key)));
    }
    // field 2: token_name (string)
    if !is_default_string(&ci.token_name) {
        pairs.push((hash_field_key(2), hash_string(&ci.token_name)));
    }
    // field 3: token_ticker (string)
    if !is_default_string(&ci.token_ticker) {
        pairs.push((hash_field_key(3), hash_string(&ci.token_ticker)));
    }
    // field 4: decimals (uint32)
    if !is_default_u32(ci.decimals) {
        pairs.push((hash_field_key(4), hash_uint32(ci.decimals)));
    }
    // field 5: max_supply (bytes)
    if !is_default_bytes(&ci.max_supply) {
        pairs.push((hash_field_key(5), hash_bytes(&ci.max_supply)));
    }
    // field 6: is_freezable (bool)
    if ci.is_freezable {
        pairs.push((hash_field_key(6), hash_bool(ci.is_freezable)));
    }
    // field 7: creation_entity_public_key (optional bytes)
    if let Some(ref cepk) = ci.creation_entity_public_key {
        if !is_default_bytes(cepk) {
            pairs.push((hash_field_key(7), hash_bytes(cepk)));
        }
    }
    // field 8: extra_metadata (optional bytes)
    if let Some(ref em) = ci.extra_metadata {
        if !is_default_bytes(em) {
            pairs.push((hash_field_key(8), hash_bytes(em)));
        }
    }
    hash_map(&pairs)
}

/// Hash `PartialTokenOutput`.
fn hash_partial_token_output(o: &PartialTokenOutput) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(5);
    // field 1: owner_public_key (bytes)
    if !is_default_bytes(&o.owner_public_key) {
        pairs.push((hash_field_key(1), hash_bytes(&o.owner_public_key)));
    }
    // field 2: withdraw_bond_sats (uint64)
    if !is_default_u64(o.withdraw_bond_sats) {
        pairs.push((hash_field_key(2), hash_uint64(o.withdraw_bond_sats)));
    }
    // field 3: withdraw_relative_block_locktime (uint64)
    if !is_default_u64(o.withdraw_relative_block_locktime) {
        pairs.push((
            hash_field_key(3),
            hash_uint64(o.withdraw_relative_block_locktime),
        ));
    }
    // field 4: token_identifier (bytes)
    if !is_default_bytes(&o.token_identifier) {
        pairs.push((hash_field_key(4), hash_bytes(&o.token_identifier)));
    }
    // field 5: token_amount (bytes)
    if !is_default_bytes(&o.token_amount) {
        pairs.push((hash_field_key(5), hash_bytes(&o.token_amount)));
    }
    hash_map(&pairs)
}

/// Hash `TokenTransactionMetadata`.
fn hash_token_transaction_metadata(m: &TokenTransactionMetadata) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(5);
    // field 2: spark_operator_identity_public_keys (repeated bytes)
    if !m.spark_operator_identity_public_keys.is_empty() {
        let elements: Vec<[u8; 32]> = m
            .spark_operator_identity_public_keys
            .iter()
            .map(|k| hash_bytes(k))
            .collect();
        pairs.push((hash_field_key(2), hash_list(&elements)));
    }
    // field 3: network (enum -> int32)
    if !is_default_i32(m.network) {
        pairs.push((hash_field_key(3), hash_int32(m.network)));
    }
    // field 4: client_created_timestamp (optional message)
    if let Some(ref ts) = m.client_created_timestamp {
        pairs.push((hash_field_key(4), hash_timestamp(ts)));
    }
    // field 5: validity_duration_seconds (uint64)
    if !is_default_u64(m.validity_duration_seconds) {
        pairs.push((hash_field_key(5), hash_uint64(m.validity_duration_seconds)));
    }
    // field 6: invoice_attachments (repeated message)
    if !m.invoice_attachments.is_empty() {
        let elements: Vec<[u8; 32]> = m
            .invoice_attachments
            .iter()
            .map(hash_invoice_attachment)
            .collect();
        pairs.push((hash_field_key(6), hash_list(&elements)));
    }
    hash_map(&pairs)
}

/// Hash a `PartialTokenTransaction` using the protoreflecthash algorithm.
///
/// This produces a deterministic 32-byte digest used to sign token
/// transactions.  The hash is identical to the one produced by the
/// Go and JS SDKs.
pub(crate) fn hash_partial_token_transaction(
    tx: &spark_token::PartialTokenTransaction,
) -> [u8; 32] {
    let mut pairs = Vec::with_capacity(4);

    // field 1: version (uint32)
    if !is_default_u32(tx.version) {
        pairs.push((hash_field_key(1), hash_uint32(tx.version)));
    }

    // field 2: token_transaction_metadata (optional message)
    if let Some(ref meta) = tx.token_transaction_metadata {
        pairs.push((hash_field_key(2), hash_token_transaction_metadata(meta)));
    }

    // Oneof token_inputs (fields 3, 4, 5)
    if let Some(ref inputs) = tx.token_inputs {
        match inputs {
            TokenInputs::MintInput(mi) => {
                pairs.push((hash_field_key(3), hash_mint_input(mi)));
            }
            TokenInputs::TransferInput(ti) => {
                pairs.push((hash_field_key(4), hash_transfer_input(ti)));
            }
            TokenInputs::CreateInput(ci) => {
                pairs.push((hash_field_key(5), hash_create_input(ci)));
            }
        }
    }

    // field 6: partial_token_outputs (repeated message)
    if !tx.partial_token_outputs.is_empty() {
        let elements: Vec<[u8; 32]> = tx
            .partial_token_outputs
            .iter()
            .map(hash_partial_token_output)
            .collect();
        pairs.push((hash_field_key(6), hash_list(&elements)));
    }

    hash_map(&pairs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn tagged_hash_deterministic() {
        let h1 = tagged_hash(b"i", &42u64.to_be_bytes());
        let h2 = tagged_hash(b"i", &42u64.to_be_bytes());
        assert_eq!(h1, h2);
    }

    #[test]
    fn default_values_skipped() {
        // A completely default PartialTokenTransaction should hash to
        // an empty map hash: SHA256("d" || "").
        let tx = spark_token::PartialTokenTransaction::default();
        let h = hash_partial_token_transaction(&tx);
        let expected = tagged_hash(MAP_TAG, &[]);
        assert_eq!(h, expected);
    }

    #[test]
    fn transfer_hash_is_stable() {
        let tx = spark_token::PartialTokenTransaction {
            version: 3,
            token_transaction_metadata: Some(TokenTransactionMetadata {
                spark_operator_identity_public_keys: vec![Bytes::from_static(&[0x02; 33])],
                network: 1,
                client_created_timestamp: Some(prost_types::Timestamp {
                    seconds: 1700000000,
                    nanos: 0,
                }),
                validity_duration_seconds: 60,
                invoice_attachments: vec![],
            }),
            token_inputs: Some(TokenInputs::TransferInput(TokenTransferInput {
                outputs_to_spend: vec![TokenOutputToSpend {
                    prev_token_transaction_hash: Bytes::from_static(&[0xAB; 32]),
                    prev_token_transaction_vout: 0,
                }],
            })),
            partial_token_outputs: vec![PartialTokenOutput {
                owner_public_key: Bytes::from_static(&[0x03; 33]),
                withdraw_bond_sats: 10_000,
                withdraw_relative_block_locktime: 1_000,
                token_identifier: Bytes::from_static(&[0xCC; 32]),
                token_amount: Bytes::from_static(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100,
                ]),
            }],
        };

        let h1 = hash_partial_token_transaction(&tx);
        let h2 = hash_partial_token_transaction(&tx);
        assert_eq!(h1, h2, "hash must be deterministic");
        assert_ne!(h1, [0u8; 32], "hash must not be zero");
    }

    #[test]
    fn different_inputs_different_hashes() {
        let base = spark_token::PartialTokenTransaction {
            version: 3,
            token_transaction_metadata: None,
            token_inputs: Some(TokenInputs::MintInput(TokenMintInput {
                issuer_public_key: Bytes::from_static(&[0x02; 33]),
                token_identifier: Some(Bytes::from_static(&[0xAA; 32])),
            })),
            partial_token_outputs: vec![],
        };

        let mut different = base.clone();
        if let Some(TokenInputs::MintInput(ref mut mi)) = different.token_inputs {
            mi.issuer_public_key = Bytes::from_static(&[0x03; 33]);
        }

        assert_ne!(
            hash_partial_token_transaction(&base),
            hash_partial_token_transaction(&different),
        );
    }
}
