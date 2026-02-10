//! SDK error types.
//!
//! [`SdkError`] is the unified error type for all SDK operations. Variants
//! are zero-size discriminants -- no string payloads.

use std::fmt;

// ---------------------------------------------------------------------------
// SdkError
// ---------------------------------------------------------------------------

/// Errors from SDK operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkError {
    /// The SDK has been shut down (cancellation token fired).
    Cancelled,

    /// The wallet public key could not be resolved to a wallet entry.
    WalletNotFound,

    /// The wallet store operation failed.
    StoreFailed,

    /// A signing operation failed (FROST, ECDSA, ECIES, or VSS).
    SigningFailed,

    /// Authentication with an operator failed (challenge/verify handshake).
    AuthFailed,

    /// A gRPC transport call failed.
    TransportFailed,

    /// An operator returned an unexpected or invalid response.
    InvalidOperatorResponse,

    /// Not enough available leaves to satisfy the requested amount.
    InsufficientBalance,

    /// Not enough token outputs to satisfy the requested amount.
    InsufficientTokenBalance,

    /// The leaf reservation was not found or already finalized.
    ReservationNotFound,

    /// The token output lock was not found or already released.
    LockNotFound,

    /// A duplicate key or ID was detected.
    DuplicateEntry,

    /// The request parameters are invalid.
    InvalidRequest,

    /// The operation failed after exhausting retries.
    OperationFailed,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::WalletNotFound => write!(f, "wallet not found"),
            Self::StoreFailed => write!(f, "store operation failed"),
            Self::SigningFailed => write!(f, "signing operation failed"),
            Self::AuthFailed => write!(f, "authentication failed"),
            Self::TransportFailed => write!(f, "transport call failed"),
            Self::InvalidOperatorResponse => write!(f, "invalid operator response"),
            Self::InsufficientBalance => write!(f, "insufficient balance"),
            Self::InsufficientTokenBalance => write!(f, "insufficient token balance"),
            Self::ReservationNotFound => write!(f, "reservation not found"),
            Self::LockNotFound => write!(f, "lock not found"),
            Self::DuplicateEntry => write!(f, "duplicate entry"),
            Self::InvalidRequest => write!(f, "invalid request"),
            Self::OperationFailed => write!(f, "operation failed"),
        }
    }
}

impl std::error::Error for SdkError {}
