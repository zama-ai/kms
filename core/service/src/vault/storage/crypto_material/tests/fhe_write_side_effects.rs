//! Tests cleanup after the second step of an FHE key write fails.
//!
//! The tests cover the compressed and uncompressed write paths using centralized key material. A
//! failed write must remove every new entry while leaving unrelated storage and the private-key
//! cache unchanged.

mod cases;
mod support;
