use crate::gf256::GF256;
use crate::{One, Sample, ZConsts, Zero, Z128, Z64};
use anyhow::anyhow;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    iter::Sum,
    num::Wrapping,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

/// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8).
/// This is also the 'value' of a single ShamirShare.
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct ResiduePoly<Z> {
    pub coefs: [Z; F_DEG], // TODO(Daniel) can this be a slice instead of an array?
}

impl<Z> ResiduePoly<Z> {
    pub fn from_scalar(x: Z) -> Self
    where
        Z: Zero,
    {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = x;
        ResiduePoly { coefs }
    }

    pub fn to_scalar(self) -> anyhow::Result<Z>
    where
        Z: Zero + PartialEq + Display + Copy,
    {
        for i in 1..F_DEG {
            if self.coefs[i] != Z::ZERO {
                return Err(anyhow!(
                    "Higher coefficient must be zero but was {}",
                    self.coefs[i]
                ));
            }
        }
        Ok(self.coefs[0])
    }

    pub fn from_slice(coefs: [Z; F_DEG]) -> Self {
        ResiduePoly { coefs }
    }

    /// multiplies a ResiduePoly by x using the irreducible poly F = x8 + x4 + x3 + x + 1
    pub fn mul_by_x(&mut self)
    where
        Z: Neg<Output = Z> + SubAssign + Copy,
    {
        let last = self.coefs[F_DEG - 1];
        for i in (1..F_DEG).rev() {
            self.coefs[i] = self.coefs[i - 1]
        }

        self.coefs[0] = -last;
        self.coefs[1] -= last;
        self.coefs[3] -= last;
        self.coefs[4] -= last;
    }

    pub fn from_vec(coefs: Vec<Z>) -> anyhow::Result<Self> {
        if coefs.len() != F_DEG {
            return Err(anyhow!(
                "Error: required {F_DEG} coefficients, but got {}",
                coefs.len()
            ));
        }
        Ok(ResiduePoly {
            coefs: coefs
                .try_into()
                .map_err(|_| anyhow!("Error converting coefficient vector into Z64Poly"))?,
        })
    }

    /// return coefficient at index
    pub fn at(&self, index: usize) -> &Z {
        &self.coefs[index]
    }

    // check that all coefficients are zero
    pub fn is_zero(&self) -> bool
    where
        Z: Zero + PartialEq,
    {
        for c in self.coefs.iter() {
            if c != &Z::ZERO {
                return false;
            }
        }
        true
    }
}

impl<Z: Zero + Sample + Copy> Sample for ResiduePoly<Z> {
    fn sample<R: RngCore>(rng: &mut R) -> Self {
        let mut coefs = [Z::ZERO; F_DEG];
        for coef in coefs.iter_mut() {
            *coef = Z::sample(rng);
        }
        ResiduePoly { coefs }
    }
}

impl<Z: Zero> Zero for ResiduePoly<Z> {
    const ZERO: Self = ResiduePoly {
        coefs: [Z::ZERO; F_DEG],
    };
}

impl<Z: One + Zero + Copy> One for ResiduePoly<Z> {
    const ONE: Self = {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = Z::ONE;
        ResiduePoly { coefs }
    };
}

impl<Z: Zero + Copy + AddAssign> Sum<ResiduePoly<Z>> for ResiduePoly<Z> {
    fn sum<I: Iterator<Item = ResiduePoly<Z>>>(iter: I) -> Self {
        let mut coefs = [Z::ZERO; F_DEG];
        for poly in iter {
            for (i, coef) in coefs.iter_mut().enumerate() {
                *coef += poly.coefs[i];
            }
        }
        // implicit mod reduction on `coefs`
        ResiduePoly::<Z> { coefs }
    }
}

impl<Z> Add<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn add(mut self, other: ResiduePoly<Z>) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] += other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z> Sub<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Copy,
    Z: SubAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn sub(mut self, other: ResiduePoly<Z>) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] -= other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z> Add<&ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn add(mut self, other: &ResiduePoly<Z>) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] += other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z> Sub<&ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Copy,
    Z: SubAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn sub(mut self, other: &ResiduePoly<Z>) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] -= other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z> Add<Z> for ResiduePoly<Z>
where
    Z: AddAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn add(mut self, other: Z) -> Self::Output {
        // add const only to free term:
        self.coefs[0] += other;
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z> Mul<Z> for ResiduePoly<Z>
where
    Z: Copy,
    Z: Mul<Z, Output = Z>,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: Z) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl<Z> Mul<Z> for &ResiduePoly<Z>
where
    Z: Copy,
    Z: Mul<Z, Output = Z>,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: Z) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl<Z> Add<Z> for &ResiduePoly<Z>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = ResiduePoly<Z>;
    fn add(self, other: Z) -> Self::Output {
        // add const only to free term:
        let mut coefs = self.coefs;
        coefs[0] += other;
        ResiduePoly { coefs }
    }
}

impl<Z> Mul<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,

    // TODO(Morten) clean up below; move into trait?
    ResiduePoly<Z>: ReductionTable<Z>,
    Z: ZConsts + One + Zero,
    Z: Copy,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    for<'l> [Z; 8]: TryFrom<&'l [Z]>,
    for<'l> <[Z; 8] as TryFrom<&'l [Z]>>::Error: std::fmt::Debug,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_with_tables(extended_coefs)
    }
}

impl<Z> Mul<&ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,

    // TODO(Morten) clean up below; move into trait?
    ResiduePoly<Z>: ReductionTable<Z>,
    Z: ZConsts + One + Zero,
    Z: Copy,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    for<'l> [Z; 8]: TryFrom<&'l [Z]>,
    for<'l> <[Z; 8] as TryFrom<&'l [Z]>>::Error: std::fmt::Debug,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: &ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_with_tables(extended_coefs)
    }
}

impl<Z> Mul<&ResiduePoly<Z>> for &ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,

    // TODO(Morten) clean up below; move into trait?
    ResiduePoly<Z>: ReductionTable<Z>,
    Z: ZConsts + One + Zero,
    Z: Copy,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    for<'l> [Z; 8]: TryFrom<&'l [Z]>,
    for<'l> <[Z; 8] as TryFrom<&'l [Z]>>::Error: std::fmt::Debug,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: &ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_with_tables(extended_coefs)
    }
}

impl<Z> ResiduePoly<Z>
where
    ResiduePoly<Z>: ReductionTable<Z>,
    Z: ZConsts + One + Zero,
    Z: Copy,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    for<'l> [Z; 8]: TryFrom<&'l [Z]>,
    for<'l> <[Z; 8] as TryFrom<&'l [Z]>>::Error: std::fmt::Debug,
{
    fn reduce_with_tables(coefs: [Z; 2 * (F_DEG - 1) + 1]) -> ResiduePoly<Z> {
        let mut res = ResiduePoly::<Z>::from_slice(coefs[0..F_DEG].try_into().unwrap());
        for (i, coef) in coefs.iter().enumerate().skip(F_DEG) {
            for j in 0..F_DEG {
                res.coefs[j] += *ResiduePoly::REDUCTION_TABLES.entry(i, j) * *coef;
            }
        }
        res
    }
}

pub trait ReductionTable<Z> {
    const REDUCTION_TABLES: ReductionTablesGF256<Z>;
}

/// Precomputes reductions of x^8, x^9, ...x^14 to help us in reducing polynomials faster
pub struct ReductionTablesGF256<Z> {
    pub reduced: [ResiduePoly<Z>; 8],
}

impl<Z> Default for ReductionTablesGF256<Z>
where
    Z: ZConsts + One + Zero,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Z> ReductionTablesGF256<Z>
where
    Z: ZConsts + One + Zero,
{
    pub const fn new() -> Self {
        Self {
            reduced: [
                ResiduePoly {
                    coefs: [
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::ZERO,
                        Z::ZERO,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::ZERO,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ZERO,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ZERO,
                        Z::ZERO,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ONE,
                        Z::ONE,
                        Z::ZERO,
                        Z::ONE,
                        Z::ZERO,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ONE,
                        Z::TWO,
                        Z::ONE,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                        Z::MAX,
                        Z::ZERO,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ZERO,
                        Z::ONE,
                        Z::TWO,
                        Z::ONE,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                        Z::MAX,
                    ],
                },
                ResiduePoly {
                    coefs: [
                        Z::ONE,
                        Z::ONE,
                        Z::ONE,
                        Z::THREE,
                        Z::TWO,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                    ],
                },
            ],
        }
    }

    #[inline(always)]
    pub fn entry(&self, deg: usize, idx_coef: usize) -> &Z {
        &self.reduced[deg - F_DEG].coefs[idx_coef]
    }
}

impl<Z> ResiduePoly<Z>
where
    Z: Zero + One,
{
    /// embed party index to ResiduePoly
    /// This is done by taking the bitwise representation of the index and map each bit to each coefficient
    /// For eg, suppose x = sum(2^i * x_i); Then ResiduePoly = (x_0, ..., x_7) where x_i \in Z
    pub fn embed(x: usize) -> anyhow::Result<ResiduePoly<Z>> {
        if x >= (1 << F_DEG) {
            return Err(anyhow!("Value {x} is too large to be embedded!"));
        }

        let mut coefs: [Z; F_DEG] = [Z::ZERO; F_DEG];

        for (i, val) in coefs.iter_mut().enumerate().take(F_DEG) {
            let b = (x >> i) & 1;
            if b > 0 {
                *val = Z::ONE;
            }
        }

        Ok(ResiduePoly { coefs })
    }
}

macro_rules! impl_share_type {
    ($z:ty, $u:ty) => {
        /// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
        ///
        /// Comes with fixed evaluation points lifted from GF(2^8).
        /// This is also the 'value' of a single ShamirShare.
        impl ResiduePoly<$z> {
            pub fn bit_compose(&self, idx_bit: usize) -> GF256 {
                let x: u8 = self
                    .coefs
                    .iter()
                    .enumerate()
                    .fold(0_u8, |acc, (i, element)| {
                        let shifted_entry = ((element.0 >> idx_bit & 1) as u8) << i;
                        acc + shifted_entry
                    });
                GF256::from(x)
            }

            pub fn multiple_pow2(&self, exp: usize) -> bool {
                use crate::Ring;
                assert!(exp <= <$z>::RING_SIZE);
                if exp == <$z>::RING_SIZE {
                    return self.is_zero();
                }
                let bit_checks: Vec<_> = self
                    .coefs
                    .iter()
                    .filter_map(|c| {
                        let bit = c & ((<$z>::ONE << exp) - <$z>::ONE);
                        match bit {
                            Wrapping(0) => None,
                            _ => Some(bit),
                        }
                    })
                    .collect();

                bit_checks.len() == 0
            }
        }

        impl ResiduePoly<$z> {
            pub fn bit_lift(x: GF256, pos: usize) -> anyhow::Result<ResiduePoly<$z>> {
                let c8: u8 = x.into();
                let shifted_coefs: Vec<_> = (0..F_DEG)
                    .map(|i| Wrapping(((c8 >> i) & 1) as $u) << pos)
                    .collect();
                ResiduePoly::<$z>::from_vec(shifted_coefs)
            }
        }

        impl ReductionTable<$z> for ResiduePoly<$z> {
            const REDUCTION_TABLES: ReductionTablesGF256<$z> = ReductionTablesGF256::<$z>::new();
        }
    };
}

impl_share_type!(Z128, u128);
impl_share_type!(Z64, u64);

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use std::num::Wrapping;

    #[test]
    fn test_is_zero() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let mut z128poly: ResiduePoly<Z128> = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z128poly.is_zero());
        z128poly = ResiduePoly::<Z128>::sample(&mut rng);
        assert!(!z128poly.is_zero());

        let mut z64poly: ResiduePoly<Z64> = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z64poly.is_zero());
        z64poly.coefs[1] = Z64::ONE;
        assert!(!z64poly.is_zero());
    }

    macro_rules! tests_poly_shamir {
        ($z:ty, $u:ty) => {
            paste! {
            #[test]
            fn [<test_bitwise_slice_ $z:lower>]() {
                let s: ResiduePoly<$z> = ResiduePoly {
                    coefs: [
                        Wrapping(310),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                    ],
                };
                let b = s.bit_compose(1);
                assert_eq!(b, GF256::from(255));
            }

            #[test]
            fn [<test_multiple_pow2_ $z:lower>]() {
                let mut s: ResiduePoly<$z> = ResiduePoly {
                    coefs: [
                        Wrapping(310),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                    ],
                };

                assert!(s.multiple_pow2(0));
                assert!(s.multiple_pow2(1));
                assert!(!s.multiple_pow2(5));

                s.coefs[0] = Wrapping(7);
                assert!(s.multiple_pow2(0));
                assert!(!s.multiple_pow2(1));
                assert!(!s.multiple_pow2(5));

                s.coefs = [Wrapping(64); F_DEG];
                assert!(s.multiple_pow2(0));
                assert!(s.multiple_pow2(1));
                assert!(s.multiple_pow2(5));
                assert!(s.multiple_pow2(6));
                assert!(!s.multiple_pow2(7));
                assert!(!s.multiple_pow2(23));
            }

            #[test]
            fn [<test_arithmetic_ $z:lower>]() {
                let p1 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };
                let p2 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                    ],
                };
                let mut p3 = p2;
                p3.mul_by_x();

                assert_eq!(&p1 * &p2, p3);

                // mul by x twice
                let p1 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };

                let p2 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                    ],
                };
                let mut p3 = p2;
                p3.mul_by_x();
                p3.mul_by_x();

                assert_eq!(&p1 * &p2, p3);


                // 1 x 1 = 1
                let p1 = ResiduePoly::<$z>::ONE;
                let p2 = ResiduePoly::<$z>::ONE;
                let p3 = ResiduePoly::<$z>::ONE;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);


                // 0 x 1 = 0
                let p1 = ResiduePoly::<$z>::ZERO;
                let p2 = ResiduePoly::<$z>::ONE;
                let p3 = ResiduePoly::<$z>::ZERO;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);

                // rnd multiplication
                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let p0 = ResiduePoly::<$z>::ZERO;
                let prnd = ResiduePoly::<$z>::sample(& mut rng);
                let p1 = ResiduePoly::<$z>::ONE;

                assert_eq!(&p0 * &prnd, p0);
                assert_eq!(&p1 * &prnd, prnd);

                // all-1 mul by 1
                let p1 = ResiduePoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ResiduePoly {
                    coefs: [
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };
                assert_eq!(&p1 * &p2, p1);

                // mul by zero = all-zero
                let p1 = ResiduePoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ResiduePoly::ZERO;
                assert_eq!(&p1 * &p2, p2);

                let p1 = ResiduePoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ResiduePoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p3 = ResiduePoly {
                    coefs: [
                        Wrapping($u::MAX),
                        Wrapping($u::MAX - 2),
                        Wrapping($u::MAX - 3),
                        Wrapping($u::MAX - 5),
                        Wrapping($u::MAX - 6),
                        Wrapping($u::MAX - 5),
                        Wrapping($u::MAX - 3),
                        $z::ZERO,
                    ],
                };
                assert_eq!(&p1 * &p2, p3);
            }

            }
        };
    }
    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);
}
