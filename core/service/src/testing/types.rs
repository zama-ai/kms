//! Test-specific types and configurations
//!
//! This module provides common types used across the testing infrastructure.

use anyhow::Result;

/// Type alias for test results
pub type TestResult<T = ()> = Result<T>;

/// Re-export ServerHandle from client::test_tools
/// This will be moved here in a future refactor
pub use crate::client::test_tools::ServerHandle;

/// Re-export ThresholdTestConfig from client::test_tools
/// This is the actual config used by setup functions
pub use crate::client::test_tools::ThresholdTestConfig;
