//! Data generation utilities for backward compatibility tests.
//!
//! This crate is separate from `backward-compatibility` to isolate version-specific
//! dependencies (like old KMS versions) from the test loading and execution logic.

pub mod data_0_15;
pub mod generate;
