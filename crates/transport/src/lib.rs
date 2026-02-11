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
// gRPC modules (pre-generated from proto definitions)
//
// These files live in src/gen/ and are checked in to version control.
// To regenerate after proto changes:
//
//   cargo run -p transport --features grpc --bin generate-protos
//
// Or manually with tonic-prost-build (see proto/README.md).
// ---------------------------------------------------------------------------

#[cfg(feature = "grpc")]
pub mod common {
    include!("gen/common.rs");
}

#[cfg(feature = "grpc")]
pub mod spark {
    include!("gen/spark.rs");
}

#[cfg(feature = "grpc")]
pub mod spark_authn {
    include!("gen/spark_authn.rs");
}

#[cfg(feature = "grpc")]
pub mod spark_token {
    include!("gen/spark_token.rs");
}

/// Validation rule types from `validate.proto`.
///
/// These are generated from the envoyproxy protoc-gen-validate schema and
/// exist only because other protos import them for field annotations.
/// Application code should not need to use these types directly.
#[cfg(feature = "grpc")]
#[allow(clippy::len_without_is_empty)]
pub mod validate {
    include!("gen/validate.rs");
}
