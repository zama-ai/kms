//! Test environment setup utilities
//!
//! This module provides high-level test environment builders for both
//! centralized and threshold KMS configurations.
//!
//! # Examples
//!
//! ## Centralized Test
//!
//! ```no_run
//! use kms_lib::testing::prelude::*;
//!
//! #[tokio::test]
//! async fn test_centralized() -> Result<()> {
//!     let env = CentralizedTestEnv::builder()
//!         .with_test_name("my_test")
//!         .build()
//!         .await?;
//!     
//!     // Use env.server, env.client
//!     Ok(())
//! }
//! ```
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
//!         .with_threshold(2)
//!         .build()
//!         .await?;
//!     
//!     // Use env.servers, env.clients
//!     Ok(())
//! }
//! ```

pub mod centralized;
pub mod threshold;

// Re-export for convenience
pub use centralized::{CentralizedTestEnv, CentralizedTestEnvBuilder};
pub use threshold::{ThresholdTestConfig, ThresholdTestEnv, ThresholdTestEnvBuilder};
