//! Standalone benchmark crate for the KMS — see `benches/`.
//!
//! Kept separate from `kms` so `cargo bench -p kms-benches` builds `kms` as a dependency
//! (skipping `kms`'s dev-dependencies) for faster bench iteration. The crate itself is empty.
