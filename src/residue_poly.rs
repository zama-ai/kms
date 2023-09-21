use crate::gf256::GF256;
use crate::poly::Ring;
use crate::{One, Sample, ZConsts, Zero, Z128, Z64};
use anyhow::anyhow;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::ops::MulAssign;
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
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Hash, Eq, Debug)]
pub struct ResiduePoly<Z> {
    pub coefs: [Z; F_DEG], // TODO(Daniel) can this be a slice instead of an array?
}

impl<Z> Ring for ResiduePoly<Z>
where
    Z: Ring + ZConsts,
    ResiduePoly<Z>: ReductionTable<Z>,
{
    const EL_BIT_LENGTH: usize = Z::EL_BIT_LENGTH;
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

impl<Z: One + Zero + ZConsts + Copy> ZConsts for ResiduePoly<Z> {
    const TWO: Self = {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = Z::TWO;
        ResiduePoly { coefs }
    };

    const THREE: Self = {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = Z::THREE;
        ResiduePoly { coefs }
    };

    const MAX: Self = {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = Z::MAX;
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

impl<Z> AddAssign<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: AddAssign + Copy,
{
    fn add_assign(&mut self, other: ResiduePoly<Z>) {
        for i in 0..F_DEG {
            self.coefs[i] += other.coefs[i];
        }
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

impl<Z> SubAssign<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: SubAssign + Copy,
{
    fn sub_assign(&mut self, other: ResiduePoly<Z>) {
        for i in 0..F_DEG {
            self.coefs[i] -= other.coefs[i];
        }
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
    Z: Copy,
    ResiduePoly<Z>: LutMulReduction<Z>,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_mul(extended_coefs)
    }
}

impl<Z> Mul<&ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    Z: Copy,
    ResiduePoly<Z>: LutMulReduction<Z>,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: &ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_mul(extended_coefs)
    }
}

impl<Z> Mul<&ResiduePoly<Z>> for &ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    Z: Copy,
    ResiduePoly<Z>: LutMulReduction<Z>,
{
    type Output = ResiduePoly<Z>;
    fn mul(self, other: &ResiduePoly<Z>) -> Self::Output {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        ResiduePoly::reduce_mul(extended_coefs)
    }
}

impl<Z> MulAssign<ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: Zero,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    Z: Copy,
    ResiduePoly<Z>: LutMulReduction<Z>,
{
    fn mul_assign(&mut self, other: ResiduePoly<Z>) {
        let mut extended_coefs = [Z::ZERO; 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        self.coefs = ResiduePoly::reduce_mul(extended_coefs).coefs;
    }
}
pub trait LutMulReduction<Z> {
    fn reduce_mul(coefs: [Z; 2 * (F_DEG - 1) + 1]) -> Self;
}

impl<Z> LutMulReduction<Z> for ResiduePoly<Z>
where
    ResiduePoly<Z>: ReductionTable<Z>,
    Z: ZConsts + One + Zero,
    Z: Copy,
    Z: Mul<Z, Output = Z>,
    Z: AddAssign<Z>,
    for<'l> [Z; 8]: TryFrom<&'l [Z]>,
    for<'l> <[Z; 8] as TryFrom<&'l [Z]>>::Error: std::fmt::Debug,
{
    fn reduce_mul(coefs: [Z; 2 * (F_DEG - 1) + 1]) -> ResiduePoly<Z> {
        let mut res = ResiduePoly::<Z>::from_slice(coefs[0..F_DEG].try_into().unwrap());
        for (i, coef) in coefs.iter().enumerate().skip(F_DEG) {
            for j in 0..F_DEG {
                res.coefs[j] += *ResiduePoly::<Z>::REDUCTION_TABLES.entry(i, j) * *coef;
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

            /// invert and lift an Integer to the large Ring
            pub fn lift_and_invert(p: usize) -> anyhow::Result<ResiduePoly<$z>> {
                if p == 0 {
                    return Err(anyhow!("Party ID must be at least 1"));
                }

                let gamma = ResiduePoly::<$z>::ZERO - ResiduePoly::embed(p)?;
                let alpha_k = gamma.bit_compose(0);
                let ainv = GF256::from(1) / alpha_k;
                let mut x0 = ResiduePoly::embed(ainv.0 as usize)?;

                // compute Newton-Raphson iterations
                for _ in 0..<$z>::EL_BIT_LENGTH.ilog2() {
                    x0 *= ResiduePoly::TWO - gamma * x0;
                }

                debug_assert_eq!(x0 * gamma, ResiduePoly::ONE);

                Ok(x0)
            }

            pub fn multiple_pow2(&self, exp: usize) -> bool {
                assert!(exp <= <$z>::EL_BIT_LENGTH);
                if exp == <$z>::EL_BIT_LENGTH {
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
            fn [<test_bit_compose_ $z:lower>]() {
                let mut input: ResiduePoly<$z> = ResiduePoly::ZERO;
                // Set the constant term to 3
                input.coefs[0] = Wrapping(3);
                let mut res = ResiduePoly::<$z>::bit_compose(&input, 0);
                // 3 mod 2 = 1, since it is the constant term, it will be the least significant bit
                // i.e. 1 = 0b00000001
                assert_eq!(1, res.0);

                input = ResiduePoly::ZERO;
                // Set degree 1 term to 100
                input.coefs[1] = Wrapping(100);
                res = ResiduePoly::<$z>::bit_compose(&input, 0);
                // 100 mod 2 = 0
                assert_eq!(0, res.0);

                input = ResiduePoly::ZERO;
                // Set degree 2 term to 1000000009
                input.coefs[2] = Wrapping(1000000009);
                res = ResiduePoly::<$z>::bit_compose(&input, 0);
                // 1000000009 mod 2 = 1, since it is the degree 2 term, it will be the third bit that gets set to 1, and hence the result is 2^2=2^(3-1) because of 0-indexing
                // i.e. x^2 = 0b00000100
                assert_eq!(4, res.0);
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

                // check assign operations
                let mut p4 = ResiduePoly::<$z>::ONE;
                p4 *= p1;
                assert_eq!(&p1, &p4);

                let mut p5 = ResiduePoly::<$z>::ONE;
                p5 += p5;
                assert_eq!(p5, ResiduePoly::TWO);

                p5 -= p5;
                assert_eq!(p5, ResiduePoly::ZERO);
            }

            }
        };
    }
    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);

    #[test]
    fn embed_sunshine() {
        let mut input: usize;
        let mut reference = ResiduePoly::ZERO;
        let mut res: ResiduePoly<Z128>;

        // Set the polynomial to 1+x, i.e. 0b00000011 = 3
        input = 3;
        reference.coefs[0] = Wrapping(1);
        reference.coefs[1] = Wrapping(1);
        res = ResiduePoly::embed(input).unwrap();
        assert_eq!(reference, res);

        // Set the polynomial to x^2+x^5+x^6, i.e. 0b01100100 = 100
        input = 100;
        reference = ResiduePoly::ZERO;
        reference.coefs[0] = Wrapping(0);
        reference.coefs[1] = Wrapping(0);
        reference.coefs[2] = Wrapping(1);
        reference.coefs[3] = Wrapping(0);
        reference.coefs[4] = Wrapping(0);
        reference.coefs[5] = Wrapping(1);
        reference.coefs[6] = Wrapping(1);
        reference.coefs[7] = Wrapping(0);
        res = ResiduePoly::embed(input).unwrap();
        assert_eq!(reference, res);

        // Set the polynomial to x^7, i.e. 0b10000000 = 128
        input = 128;
        reference = ResiduePoly::ZERO;
        reference.coefs[7] = Wrapping(1);
        res = ResiduePoly::embed(input).unwrap();
        assert_eq!(reference, res);
    }
}
