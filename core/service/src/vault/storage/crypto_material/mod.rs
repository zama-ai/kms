//! Cryptographic material storage implementation for the KMS.
//!
//! This module provides a comprehensive storage solution for cryptographic material used in the KMS,
//! with a specialized implementation for threshold cryptography. It handles the secure storage,
//! retrieval, and management of cryptographic keys and related material.
//!
//! # Module Organization
//!
//! - `traits`: Defines core interfaces including the `CryptoMaterialReader` trait and storage traits
//! - `readers`: Contains implementations of the `CryptoMaterialReader` trait for various types
//! - `base`: Provides the base implementation of the `CryptoMaterialStorage` abstraction
//! - `cached`: Implements storage for threshold KMS cryptographic operations
//! - `utils`: Contains utility functions for cryptographic material management
//! - `tests`: Contains test suites for validating the storage implementations
//!
//! # Features
//!
//! - **Secure Storage**: Safe handling of sensitive cryptographic material
//! - **Type Safety**: Strongly-typed interfaces for cryptographic operations
//! - **Asynchronous**: Built with async/await for non-blocking operations
//!
//! # Examples
//!
//! ```rust,ignore
//! use kms_core::vault::storage::crypto_material::{
//!     CryptoMaterialStorage,
//!     CachedCryptoMaterialStorage,
//!     CryptoMaterialReader
//! };
//! // ...
//! ```

mod base;
mod cached;
mod readers;
mod traits;
mod utils;

// Tests
#[cfg(test)]
mod tests;

// Re-export the public API for external consumption
pub use base::CryptoMaterialStorage;
pub use base::PublicKeySet;
pub(crate) use base::StorageError;
pub use cached::CachedCryptoMaterialStorage;
pub use traits::CryptoMaterialReader;
pub use traits::PrivateCryptoMaterialReader;
pub use utils::*;
