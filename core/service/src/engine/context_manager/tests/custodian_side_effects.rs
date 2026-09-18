//! Failure tests for destructive custodian-context storage operations.
//!
//! The fixture creates two valid custodian contexts through the threshold service.
//! Tests inject storage failures, check lifecycle state, and verify cleanup and locking.

mod cases;
mod support;
