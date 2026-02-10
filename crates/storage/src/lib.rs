//! Shared storage primitives for Flashnet.
//!
//! This crate provides the common [`StorageError`] type used by domain-specific
//! repository traits throughout the workspace. Repository traits themselves live
//! in the crates that own the domain types (e.g. `exchange-processor` owns
//! `PoolRepository`, `wallet-module` owns `LeafRepository`) to avoid coupling
//! this crate to every domain model.
//!
//! # Design Principles
//!
//! - **No generic key-value trait.** Storage access is expressed through
//!   domain-specific repository traits with typed, meaningful methods.
//! - **Error type covers real failures.** Connection loss, transaction conflicts,
//!   constraint violations -- not input validation.
//! - **Repository traits are added incrementally.** Each trait is introduced
//!   when the first consumer needs it.

mod error;

pub use error::StorageError;
