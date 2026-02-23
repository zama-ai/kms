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

// TODO(dp): Temporarily move this here so we have a local version before extraction.
/// Domain separator for hashing elements.
/// This is used to ensure that the hash is unique to the context in which it is used.
pub(crate) type DomainSep = [u8; DSEP_LEN];
pub(crate) const DSEP_LEN: usize = 8;

// TODO(dp): Shamir stuff from execution:
// shamir::{ShamirSharings, InputOp, RevealOp, ShamirFieldPoly}
// share::Share

// TODO(dp): from execution, but used in algebra tests
/// Trait required for PRSS executions
pub trait PRSSConversions {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self;
    fn from_i128(value: i128) -> Self;
}
