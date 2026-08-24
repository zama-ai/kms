pub mod base_ring;
pub mod bivariate;
pub mod commitment;
pub mod error_correction;
pub mod galois_fields;
pub mod galois_rings;
pub mod matrix;
pub mod poly;
pub mod randomness_check;
pub mod sharing;
pub mod structure_traits;
pub mod syndrome;

/// Trait required for PRSS executions
pub trait PRSSConversions {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self;
    fn from_i128(value: i128) -> Self;

    /// Multiply `self` by the ring element `from_i128(scalar)`.
    ///
    /// The default does a full ring multiply; `ResiduePoly` overrides it with a cheaper
    /// coefficient-wise scale. It always goes through `from_i128`, so it stays correct for rings
    /// whose modulus does not divide 2^128 (e.g. a prime modulus), unlike scaling by
    /// `from_u128(scalar as u128)` which mis-reduces negative scalars on such rings.
    fn mul_by_i128(self, scalar: i128) -> Self
    where
        Self: Sized + core::ops::Mul<Self, Output = Self>,
    {
        self * Self::from_i128(scalar)
    }
}
