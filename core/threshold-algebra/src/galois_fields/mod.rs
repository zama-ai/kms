/// Map from evaluation points to their precomputed Lagrange polynomials.
#[cfg(any(
    feature = "extension_degree_3",
    feature = "extension_degree_4",
    feature = "extension_degree_5",
    feature = "extension_degree_6",
    feature = "extension_degree_7",
    feature = "extension_degree_8",
))]
pub(crate) type LagrangeMap<F> = std::collections::HashMap<Vec<F>, Vec<crate::poly::Poly<F>>>;

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
#[cfg(any(
    feature = "extension_degree_3",
    feature = "extension_degree_4",
    feature = "extension_degree_5",
    feature = "extension_degree_6",
    feature = "extension_degree_7",
    feature = "extension_degree_8",
))]
pub mod lagrange;
