/// Map from (index, degree) to precomputed exceptional set powers.
pub(crate) type ExceptionalSetMap<T> = std::collections::HashMap<(usize, usize), Vec<T>>;

pub mod common;
pub mod degree_3;
pub mod degree_4;
pub mod degree_5;
pub mod degree_6;
pub mod degree_7;
pub mod degree_8;
pub mod utils;
