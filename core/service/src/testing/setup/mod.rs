//! Test environment setup utilities
//!
//! This module provides high-level test environment builders for threshold KMS
//! configurations.
//!
//! # Examples
//!
//! ## Threshold Test
//!
//! ```no_run
//! use kms_lib::testing::prelude::*;
//!
//! #[tokio::test]
//! async fn test_threshold() -> Result<()> {
//!     let env = ThresholdTestEnv::builder()
//!         .with_test_name("my_test")
//!         .with_party_count(4)
//!         .with_threshold(1) // For 4 parties: nodes = 3*threshold + 1
//!         .build()
//!         .await?;
//!
//!     // Use env.servers, env.clients
//!     Ok(())
//! }
//! ```
pub mod environment;

// Re-export for convenience
pub use environment::{
    TestMaterialGuard, ThresholdTestConfig, ThresholdTestEnv, ThresholdTestEnvBuilder,
};
