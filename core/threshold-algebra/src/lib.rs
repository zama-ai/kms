pub mod base_ring;
pub mod bivariate;
pub mod error_correction;
pub mod galois_fields;
pub mod galois_rings;
pub mod poly;
pub mod role;
pub mod sharing;
pub mod structure_traits;
pub mod syndrome;

// TODO(dp): Shamir stuff from execution:
// shamir::{ShamirSharings, InputOp, RevealOp, ShamirFieldPoly}
// share::Share

// TODO(dp): from execution, but used in algebra tests
/// Trait required for PRSS executions
pub trait PRSSConversions {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self;
    fn from_i128(value: i128) -> Self;
}
