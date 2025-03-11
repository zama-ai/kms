pub mod common;
#[cfg(feature = "extension_degree_7")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf128;
#[cfg(feature = "extension_degree_4")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf16;
#[cfg(feature = "extension_degree_8")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf256;
#[cfg(feature = "extension_degree_5")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf32;
#[cfg(feature = "extension_degree_6")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf64;
#[cfg(feature = "extension_degree_3")]
#[expect(clippy::derived_hash_with_manual_eq)]
pub mod gf8;
