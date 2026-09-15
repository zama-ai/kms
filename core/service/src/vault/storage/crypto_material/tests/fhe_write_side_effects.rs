//! Tests rejection of existing FHE material and cleanup after a partial write.
//!
//! The tests cover the compressed and uncompressed write paths using centralized key material. A
//! failed write must remove every new entry while leaving unrelated storage and the private-key
//! cache unchanged.
//! A complete key write rejects an existing pair half before touching storage or the cache.

mod cases;
mod support;
