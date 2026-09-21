//! Tests storage effects from [`CryptoMaterialStorage::write_all`].
//!
//! Threshold calls to `write_all` use two public/private pairs: `PublicKey`/`FheKeyInfo` and
//! `CRS`/`CrsInfo`.
//! Pair tests start with empty or mixed state and fail either write before or after mutation.
//! A separate case covers a request-scoped `ContextInfo` write. All cases compare state and events
//! and use unrelated entries to detect broad cleanup. Backup updates are not covered here.

mod cases;
mod support;
