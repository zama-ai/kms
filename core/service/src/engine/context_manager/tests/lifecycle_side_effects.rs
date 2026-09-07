//! Tests MPC context lifecycle side effects in persistent and in-memory state.
//!
//! Cases cover storage failures, backup failures, session rollback, duplicate creation and
//! serialized updates. The fixture also stores a keeper context to detect broad cleanup.

mod cases;
mod support;
