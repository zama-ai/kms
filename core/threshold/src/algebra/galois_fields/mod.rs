pub mod common;
#[cfg(feature = "extension_degree_4")]
pub mod gf16;
#[cfg(feature = "extension_degree_8")]
pub mod gf256;
#[cfg(feature = "extension_degree_3")]
pub mod gf8;
