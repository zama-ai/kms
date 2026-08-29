//! Tests cleanup after the second step of an FHE key write fails.
//!
//! FHE key storage first writes a `ServerKey` or `CompressedXofKeySet`, then writes the paired
//! `PublicKey` and private key material. A failure in the pair must remove every entry created by
//! the call, preserve unrelated storage and leave the private-key cache empty.

mod cases;
mod support;
