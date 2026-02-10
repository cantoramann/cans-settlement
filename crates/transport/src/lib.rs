//! Transport layer for Spark SDK.
//!
//! Provides gRPC client stubs for the Spark protocol services, generated from
//! protocol buffer definitions.
//!
//! # Feature flags
//!
//! - **`grpc`** (default): Enables gRPC client generation via tonic/prost.
//! - **`mock`**: Reserved for mock transport implementations (testing).
//!
//! # Proto modules
//!
//! When the `grpc` feature is enabled, the following modules are available:
//!
//! | Module | Service client | Description |
//! |--------|----------------|-------------|
//! | [`spark`] | `SparkServiceClient` | Core Spark operations (deposits, transfers, signing) |
//! | [`spark_authn`] | `SparkAuthnServiceClient` | Authentication (challenge/verify) |
//! | [`spark_token`] | `SparkTokenServiceClient` | Token operations (mint, transfer, query) |
//! | [`common`] | -- | Shared message types used across services |

// ---------------------------------------------------------------------------
// gRPC transport implementation
// ---------------------------------------------------------------------------

#[cfg(feature = "grpc")]
pub mod grpc;

#[cfg(feature = "grpc")]
pub mod session;

// ---------------------------------------------------------------------------
// gRPC modules (generated from proto definitions)
// ---------------------------------------------------------------------------

#[cfg(feature = "grpc")]
pub mod common {
    include!(concat!(env!("OUT_DIR"), "/common.rs"));
}

#[cfg(feature = "grpc")]
pub mod spark {
    include!(concat!(env!("OUT_DIR"), "/spark.rs"));
}

#[cfg(feature = "grpc")]
pub mod spark_authn {
    include!(concat!(env!("OUT_DIR"), "/spark_authn.rs"));
}

#[cfg(feature = "grpc")]
pub mod spark_token {
    include!(concat!(env!("OUT_DIR"), "/spark_token.rs"));
}

/// Validation rule types from `validate.proto`.
///
/// These are generated from the envoyproxy protoc-gen-validate schema and
/// exist only because other protos import them for field annotations.
/// Application code should not need to use these types directly.
#[cfg(feature = "grpc")]
#[allow(clippy::len_without_is_empty)]
pub mod validate {
    include!(concat!(env!("OUT_DIR"), "/validate.rs"));
}
