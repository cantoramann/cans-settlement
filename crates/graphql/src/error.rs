//! SSP transport error type.

use std::fmt;

/// Errors from SSP GraphQL communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SspError {
    /// Invalid SSP configuration (bad URL, bad public key hex, etc.).
    InvalidConfig(&'static str),

    /// TLS setup failed.
    TlsFailed,

    /// The HTTP request to the SSP failed (network, timeout, non-2xx status).
    RequestFailed,

    /// The SSP returned an unparseable or unexpected response.
    InvalidResponse,

    /// A signing operation failed during the auth challenge.
    SigningFailed,
}

impl fmt::Display for SspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "invalid SSP config: {msg}"),
            Self::TlsFailed => write!(f, "TLS setup failed"),
            Self::RequestFailed => write!(f, "SSP request failed"),
            Self::InvalidResponse => write!(f, "invalid SSP response"),
            Self::SigningFailed => write!(f, "signing failed"),
        }
    }
}

impl std::error::Error for SspError {}
