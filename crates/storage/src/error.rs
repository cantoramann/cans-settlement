//! Storage error types shared across all repository implementations.

use std::fmt;

/// Errors that can occur when interacting with a storage backend.
///
/// This enum covers failures from any backend (PostgreSQL, Redis, etc.).
/// Input-validation errors (bad parameters, malformed IDs) should be handled
/// at the call site before reaching the storage layer.
#[derive(Debug)]
pub enum StorageError {
    /// The backend is unreachable or the connection was lost.
    ConnectionFailed(String),

    /// An optimistic concurrency check failed: the row was modified between
    /// read and write. The caller should re-read and retry.
    TransactionConflict,

    /// The requested entity does not exist.
    NotFound,

    /// A uniqueness or foreign-key constraint was violated.
    ConstraintViolation(String),

    /// Encoding or decoding a value failed (e.g. serde, protobuf).
    Serialization(String),

    /// The operation exceeded its deadline.
    Timeout,

    /// An unclassified backend error. Inspect the inner error for details.
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(reason) => write!(f, "connection failed: {reason}"),
            Self::TransactionConflict => write!(f, "transaction conflict (optimistic lock)"),
            Self::NotFound => write!(f, "entity not found"),
            Self::ConstraintViolation(detail) => write!(f, "constraint violation: {detail}"),
            Self::Serialization(detail) => write!(f, "serialization error: {detail}"),
            Self::Timeout => write!(f, "operation timed out"),
            Self::Internal(e) => write!(f, "internal storage error: {e}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Internal(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
