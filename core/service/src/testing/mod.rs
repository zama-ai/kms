//! Consolidated testing infrastructure for KMS
//!
//! This module provides a unified API for writing isolated tests in the KMS codebase.
//!
//! # Module Organization
//!
//! - **`material`**: Test material management (`TestMaterialManager`, `TestMaterialSpec`)
//! - **`setup`**: Test environment setup (centralized & threshold)
//! - **`helpers`**: Common test utilities and helper functions
//! - **`types`**: Test-specific types and configurations
//! - **`prelude`**: Convenient re-exports for test files
//!
//! # Architecture
//!
//! The testing infrastructure is organized around two main concepts:
//!
//! 1. **Test Material**: Pre-generated cryptographic keys managed by `TestMaterialManager`
//! 2. **Test Environments**: Isolated KMS server setups for centralized and threshold modes
//!
//! ## Test Material
//!
//! Test material is pre-generated using the `generate-test-material` tool and stored
//! in the workspace `test-material/` directory. Tests copy only the required material
//! into isolated temporary directories.
//!
//! ## Test Environments
//!
//! Test environments provide fully configured KMS servers with clients:
//! - `CentralizedTestEnv`: Single-party KMS setup
//! - `ThresholdTestEnv`: Multi-party threshold KMS setup
//!
//! Both environments use RAII for automatic cleanup.
pub mod helpers;
pub mod material;
pub mod setup;
pub mod types;
pub mod utils;

/// Convenient re-exports for test files
pub mod prelude {
    // Material management
    pub use super::material::{
        KeyType, MaterialType, TestMaterialHandle, TestMaterialManager, TestMaterialSpec,
    };

    // Setup utilities
    pub use super::setup::{
        centralized::{
            CentralizedTestEnv, CentralizedTestEnvBuilder, CentralizedTestMaterialGuard,
        },
        threshold::{
            TestMaterialGuard, ThresholdTestConfig, ThresholdTestEnv, ThresholdTestEnvBuilder,
        },
    };

    // Helper functions
    pub use super::helpers::{
        create_test_material_manager, domain_to_msg, regenerate_central_keys,
    };

    // Test utilities
    pub use super::utils::{
        EncryptionConfig, TestingPlaintext, compute_cipher, compute_cipher_from_stored_key,
    };

    // Common types
    pub use super::types::{ServerHandle, TestResult};

    // Re-exports from anyhow for convenience
    pub use anyhow::{Context, Result};

    pub use crate::vault::storage::{Storage, StorageType, file::FileStorage};
    pub use tempfile::TempDir;
    pub use threshold_types::role::Role;
}
