use crate::poly::Poly;
use std::collections::HashMap;

/// Map from evaluation points to their precomputed Lagrange polynomials.
pub(crate) type LagrangeMap<F> = HashMap<Vec<F>, Vec<Poly<F>>>;

pub mod common;
#[cfg(feature = "extension_degree_7")]
pub mod gf128;
#[cfg(feature = "extension_degree_4")]
pub mod gf16;
#[cfg(feature = "extension_degree_8")]
pub mod gf256;
#[cfg(feature = "extension_degree_5")]
pub mod gf32;
#[cfg(feature = "extension_degree_6")]
pub mod gf64;
#[cfg(feature = "extension_degree_3")]
pub mod gf8;
