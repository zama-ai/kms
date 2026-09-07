//! Failure tests for destructive custodian-context storage operations.
//!
//! The fixture creates two valid custodian contexts through the threshold service.
//! Tests fail one exact delete, inspect persistent lifecycle state, and retry the operation.

mod cases;
mod support;
