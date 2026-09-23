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

    /// Converts PRF chunks in their original order, with the same encoding as `from_u128_chunks`.
    /// The default collects a vector; fixed-size rings override this to fill their coefficients directly.
    ///
    /// # Panics
    /// Fixed-size rings panic if the iterator length differs from their extension degree.
    fn from_u128_iter(coefs: impl ExactSizeIterator<Item = u128>) -> Self
    where
        Self: Sized,
    {
        Self::from_u128_chunks(coefs.collect())
    }

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

#[cfg(test)]
mod prss_conversion_tests {
    use super::PRSSConversions;
    use crate::base_ring::{Z64, Z128};
    use crate::galois_rings::common::ResiduePoly;
    use std::num::Wrapping;

    #[test]
    fn prss_iterator_conversion_preserves_encoding() {
        fn check<const N: usize>() {
            let values = [
                0,
                1,
                u64::MAX as u128,
                1_u128 << 64,
                u128::MAX,
                42,
                1_u128 << 127,
                7,
            ];
            let chunks: [u128; N] = std::array::from_fn(|i| values[i]);
            let z64 = ResiduePoly::<Z64, N>::from_u128_iter(chunks.into_iter());
            let z128 = ResiduePoly::<Z128, N>::from_u128_iter(chunks.into_iter());
            assert_eq!(z64.coefs, chunks.map(|v| Wrapping(v as u64)));
            assert_eq!(z128.coefs, chunks.map(Wrapping));
            assert_eq!(
                z64,
                ResiduePoly::<Z64, N>::from_u128_chunks(chunks.to_vec())
            );
            assert_eq!(
                z128,
                ResiduePoly::<Z128, N>::from_u128_chunks(chunks.to_vec())
            );
        }
        check::<4>();
        check::<8>();
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn prss_iterator_conversion_rejects_short_input() {
        ResiduePoly::<Z64, 4>::from_u128_iter([0; 3].into_iter());
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn prss_iterator_conversion_rejects_long_input() {
        ResiduePoly::<Z128, 4>::from_u128_iter([0; 5].into_iter());
    }
}
