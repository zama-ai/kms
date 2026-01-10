//! Test material management
//!
//! This module provides utilities for managing pre-generated cryptographic test material.
//! Material is generated once using `make generate-test-material-testing` and then copied
//! into isolated temporary directories for each test.
//!
//! # Key Types
//!
//! - **`TestMaterialSpec`**: Declares what cryptographic material a test needs
//! - **`TestMaterialManager`**: Copies pre-generated material into isolated directories
//! - **`MaterialType`**: Testing (fast) vs Default (production-like) parameters
//! - **`KeyType`**: Types of cryptographic keys (FHE, CRS, signing, etc.)
mod manager;
mod spec;

pub use manager::{TestMaterialHandle, TestMaterialManager};
pub use spec::{KeyType, MaterialType, TestMaterialSpec};
