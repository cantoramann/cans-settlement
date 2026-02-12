//! Token operations: send, create, mint, freeze, query, and sync.
//!
//! Token operations use ECDSA identity key signatures (not FROST).
//! V3 protocol: build `PartialTokenTransaction`, hash via protoreflecthash,
//! ECDSA-sign the hash, and broadcast via `SparkTokenService`.

pub(crate) mod hash;
pub(crate) mod helpers;
pub mod ops;
pub mod sync;

// Re-export public types for consumer convenience.
pub use ops::{
    CreateTokenParams, CreateTokenResult, FreezeTokensResult, MintTokenResult, SendTokenResult,
    TokenBalance,
};
pub use sync::SyncTokensResult;
