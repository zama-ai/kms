/// Map from (index, degree) to precomputed exceptional set powers.
#[cfg(any(
    feature = "extension_degree_3",
    feature = "extension_degree_4",
    feature = "extension_degree_5",
    feature = "extension_degree_6",
    feature = "extension_degree_7",
    feature = "extension_degree_8",
))]
pub(crate) type ExceptionalSetMap<T> = std::collections::HashMap<(usize, usize), Vec<T>>;

pub mod common;
#[cfg(feature = "extension_degree_3")]
pub mod degree_3;
#[cfg(feature = "extension_degree_4")]
pub mod degree_4;
#[cfg(feature = "extension_degree_5")]
pub mod degree_5;
#[cfg(feature = "extension_degree_6")]
pub mod degree_6;
#[cfg(feature = "extension_degree_7")]
pub mod degree_7;
#[cfg(feature = "extension_degree_8")]
pub mod degree_8;
pub mod utils;
