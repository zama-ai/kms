use super::{
    bivariate::compute_powers_list,
    gf256::{ShamirZ2Poly, GF256},
    poly::Poly,
    structure_traits::{BaseRing, FromU128, One, Ring, Sample, ZConsts, Zero},
    syndrome::lagrange_numerators,
};
use crate::algebra::structure_traits::Field;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        gf256::syndrome_decoding_z2,
    },
    execution::{
        large_execution::local_single_share::Derive,
        runtime::party::Role,
        sharing::{
            shamir::{HenselLiftInverse, RingEmbed, ShamirSharings, Syndrome},
            share::Share,
        },
        small_execution::prf::PRSSConversions,
    },
};
use crate::{error::error_handler::anyhow_error_and_log, execution::online::gen_bits::Solve};
use itertools::Itertools;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Shl, Sub, SubAssign},
};
use std::{num::Wrapping, ops::MulAssign};
use zeroize::Zeroize;

pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

/// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8).
/// This is also the 'value' of a single ShamirShare.
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Hash, Eq, Debug, Zeroize)]
pub struct ResiduePoly<Z> {
    pub coefs: [Z; F_DEG], // TODO(Daniel) can this be a slice instead of an array?
}

impl<Z: BaseRing> Ring for ResiduePoly<Z>
where
    ResiduePoly<Z>: ReductionTable<Z>,
{
    const BIT_LENGTH: usize = Z::BIT_LENGTH * F_DEG;
    const CHAR_LOG2: usize = Z::CHAR_LOG2;

    fn to_byte_vec(&self) -> Vec<u8> {
        let size = Self::BIT_LENGTH >> 3;
        let mut res = Vec::with_capacity(size);
        for coef in self.coefs {
            coef.to_byte_vec()
                .into_iter()
                .for_each(|byte| res.push(byte));
        }
        res
    }
}

impl<Z: BaseRing> FromU128 for ResiduePoly<Z> {
    fn from_u128(value: u128) -> Self {
        Self::from_scalar(Z::from_u128(value))
    }
}

//Cant do TryInto with generics, see https://github.com/rust-lang/rust/issues/50133#issuecomment-646908391
pub struct TryFromWrapper<Z>(pub Z);
impl<Z: Ring + std::fmt::Display> TryFrom<ResiduePoly<Z>> for TryFromWrapper<Z> {
    type Error = anyhow::Error;
    fn try_from(poly: ResiduePoly<Z>) -> Result<TryFromWrapper<Z>, Self::Error> {
        Ok(TryFromWrapper(poly.to_scalar()?))
    }
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
                return Err(anyhow_error_and_log(format!(
                    "Higher coefficient must be zero but was {}",
                    self.coefs[i]
                )));
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
            return Err(anyhow_error_and_log(format!(
                "Error: required {F_DEG} coefficients, but got {}",
                coefs.len()
            )));
        }
        Ok(ResiduePoly {
            coefs: coefs.try_into().map_err(|_| {
                anyhow_error_and_log("Error converting coefficient vector into Z64Poly".to_string())
            })?,
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
    fn sample<R: Rng>(rng: &mut R) -> Self {
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

impl<Z> AddAssign<&ResiduePoly<Z>> for ResiduePoly<Z>
where
    Z: AddAssign + Copy,
{
    fn add_assign(&mut self, other: &ResiduePoly<Z>) {
        for i in 0..F_DEG {
            self.coefs[i] += other.coefs[i];
        }
    }
}

impl<Z: Neg<Output = Z>> Neg for ResiduePoly<Z> {
    type Output = Self;
    fn neg(self) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| -x),
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

/// Compute R << i which translates to left shifting by i each coefficient of the ResiduePoly
/// If i >= Z::CHAR_LOG2 then it computes R << (i % Z::CHAR_LOG2)
impl<Z> Shl<usize> for ResiduePoly<Z>
where
    Z: Ring + ZConsts,
    Z: std::ops::Shl<usize, Output = Z>,
{
    type Output = ResiduePoly<Z>;

    fn shl(self, rhs: usize) -> Self {
        let mut coefs = self.coefs;
        for coef in &mut coefs {
            *coef = *coef << rhs;
        }
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

/// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8).
/// This is also the 'value' of a single ShamirShare.
impl<Z: BaseRing> ResiduePoly<Z> {
    pub fn bit_compose(&self, idx_bit: usize) -> GF256 {
        let x: u8 = self
            .coefs
            .iter()
            .enumerate()
            .fold(0_u8, |acc, (i, element)| {
                let shifted_entry = (*element).extract_bit(idx_bit) << i;
                acc + shifted_entry
            });
        GF256::from(x)
    }

    pub fn multiple_pow2(&self, exp: usize) -> bool {
        assert!(exp <= Z::BIT_LENGTH);
        if exp == Z::BIT_LENGTH {
            return self.is_zero();
        }
        let bit_checks: Vec<_> = self
            .coefs
            .iter()
            .filter_map(|c| {
                let bit = (*c) & ((Z::ONE << exp) - Z::ONE);
                if bit == Z::ZERO {
                    None
                } else {
                    Some(bit)
                }
            })
            .collect();

        bit_checks.is_empty()
    }
}

impl<Z: BaseRing> ResiduePoly<Z> {
    pub fn bit_lift(x: GF256, pos: usize) -> anyhow::Result<ResiduePoly<Z>> {
        let c8: u8 = x.into();
        let shifted_coefs: Vec<_> = (0..F_DEG)
            .map(|i| Z::from_u128(((c8 >> i) & 1) as u128) << pos)
            .collect();
        ResiduePoly::<Z>::from_vec(shifted_coefs)
    }
}

impl<Z: BaseRing> ReductionTable<Z> for ResiduePoly<Z> {
    const REDUCTION_TABLES: ReductionTablesGF256<Z> = ReductionTablesGF256::<Z>::new();
}

impl<Z: Ring> RingEmbed for ResiduePoly<Z> {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self> {
        if idx >= (1 << F_DEG) {
            return Err(anyhow_error_and_log(format!(
                "Value {idx} is too large to be embedded!"
            )));
        }

        let mut coefs: [Z; F_DEG] = [Z::ZERO; F_DEG];

        for (i, val) in coefs.iter_mut().enumerate().take(F_DEG) {
            let b = (idx >> i) & 1;
            if b > 0 {
                *val = Z::ONE;
            }
        }

        Ok(ResiduePoly { coefs })
    }
}

impl<Z: BaseRing> Syndrome for ResiduePoly<Z> {
    // decode a ring syndrome into an error vector, containing the error magnitudes at the respective indices
    fn syndrome_decode(
        mut syndrome_poly: Poly<ResiduePoly<Z>>,
        parties: &[Role],
        threshold: usize,
    ) -> anyhow::Result<Vec<ResiduePoly<Z>>> {
        let parties = parties.iter().map(|r| r.one_based()).collect_vec();
        // sum up the error vectors here
        let mut e_res: Vec<ResiduePoly<Z>> = vec![ResiduePoly::<Z>::ZERO; parties.len()];

        let ring_size: usize = Z::BIT_LENGTH;
        //  compute s_e^(j)/p mod p and decode
        for bit_idx in 0..ring_size {
            let sliced_syndrome_coefs: Vec<_> = syndrome_poly
                .coefs
                .iter()
                .map(|c| c.bit_compose(bit_idx))
                .collect();

            let sliced_syndrome = ShamirZ2Poly {
                coefs: sliced_syndrome_coefs,
            };

            // bit error in this for this bit-idx
            let ej = syndrome_decoding_z2(&parties, &sliced_syndrome, threshold);

            // lift bit error into the ring
            let lifted_e: Vec<ResiduePoly<Z>> = ej
                .iter()
                .map(|e| Self::bit_lift(*e, bit_idx))
                .collect::<anyhow::Result<Vec<_>>>()?;

            // add the lifted e^(j) to e
            for (e_res_e, lifted_e_e) in e_res.iter_mut().zip(lifted_e.iter()) {
                *e_res_e += *lifted_e_e;
            }
            // correction term in the ring (inside parenthesis in syndrome update)
            let correction_shares = lifted_e
                .iter()
                .enumerate()
                .map(|(idx, val)| Share::new(Role::indexed_by_zero(idx), *val))
                .collect_vec();
            let corrected_shamir = ShamirSharings {
                shares: correction_shares,
            };
            let syndrome_correction = Self::syndrome_compute(&corrected_shamir, threshold)?;

            // update syndrome with correction value
            syndrome_poly = syndrome_poly - syndrome_correction;
        }

        Ok(e_res)
    }

    // compute the syndrome in the GR from a given sharing and threshold
    fn syndrome_compute(
        sharing: &ShamirSharings<ResiduePoly<Z>>,
        threshold: usize,
    ) -> anyhow::Result<Poly<ResiduePoly<Z>>> {
        let n = sharing.shares.len();
        let r = n - (threshold + 1);

        let ys: Vec<_> = sharing.shares.iter().map(|share| share.value()).collect();

        // embed party IDs into the ring
        let parties: Vec<_> = sharing
            .shares
            .iter()
            .map(|share| ResiduePoly::<Z>::embed_exceptional_set(share.owner().one_based()))
            .collect::<Result<Vec<_>, _>>()?;

        // lagrange numerators from Eq.15
        let lagrange_polys = lagrange_numerators(&parties);

        let alpha_powers = compute_powers_list(&parties, r);
        let mut res = Poly::zeros(r);

        // compute syndrome coefficients
        for j in 0..r {
            let mut coef = Self::ZERO;

            for i in 0..n {
                let numerator = ys[i] * alpha_powers[i][j];
                let denom = lagrange_polys[i].eval(&parties[i]);
                coef += numerator * denom.invert()?;
            }

            res.coefs[j] = coef;
        }

        Ok(res)
    }
}

impl<Z> HenselLiftInverse for ResiduePoly<Z>
where
    Z: BaseRing,
{
    /// invert and lift an Integer to the large Ring
    fn invert(self) -> anyhow::Result<Self> {
        if self == Self::ZERO {
            return Err(anyhow_error_and_log("Cannot invert 0".to_string()));
        }

        let alpha_k = self.bit_compose(0);
        let ainv = alpha_k.invert();
        let mut x0 = Self::embed_exceptional_set(ainv.0 as usize)?;

        // compute Newton-Raphson iterations
        for _ in 0..Z::BIT_LENGTH.ilog2() {
            x0 *= Self::TWO - self * x0;
        }

        debug_assert_eq!(x0 * self, ResiduePoly::ONE);

        Ok(x0)
    }
}

impl<Z: BaseRing> ResiduePoly<Z> {
    pub fn shamir_bit_lift(x: &ShamirZ2Poly, pos: usize) -> anyhow::Result<Poly<ResiduePoly<Z>>> {
        let coefs: Vec<ResiduePoly<Z>> = x
            .coefs
            .iter()
            .map(|coef_2| Self::bit_lift(*coef_2, pos))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Poly::from_coefs(coefs))
    }

    fn solve_1(v: &Self) -> anyhow::Result<Self> {
        let mut res = GF256::from(0);
        let v = Self::bit_compose(v, 0);
        let v_powers = two_powers(v, F_DEG - 1);
        for i in 0..(F_DEG - 1) {
            res += INNER_LOOP[i] * v_powers[i];
        }
        Self::embed_exceptional_set(res.0 as usize)
    }
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
fn two_powers(input: GF256, max_power: usize) -> Vec<GF256> {
    let mut res = Vec::with_capacity(max_power);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

// Expansion of inner loop needed for computing the initial value of x for Newton-Raphson.
// Computed using the following code:
// const TRACE_ONE: GF256 = GF256(42); // ... which is an element with trace 1
// fn compute_inner_loop() -> [GF256; 7] {
//     let delta_powers = two_powers(TRACE_ONE, D);
//     let mut inner_loop: [GF256; (D - 1) as usize] = [GF256(0); (D - 1) as usize];
//     for i in 0..(D - 1) {
//         let mut inner_temp = GF256::from(0);
//         for j in i + 1..D {
//             inner_temp += delta_powers[j as usize];
//         }
//         inner_loop[i as usize] = inner_temp;
//     }
//     inner_loop
// }
static INNER_LOOP: [GF256; 7] = [
    GF256(43),
    GF256(3),
    GF256(47),
    GF256(19),
    GF256(52),
    GF256(77),
    GF256(208),
];

impl<Z: BaseRing> Solve for ResiduePoly<Z> {
    ///***NOTE: CAREFUL WHEN NOT USING Z64 OR Z128 AS BASE RING***
    fn solve(v: &Self) -> anyhow::Result<Self> {
        //Check to help detect if we forgot about the note above
        debug_assert_eq!(1 << Z::BIT_LENGTH.ilog2(), Z::BIT_LENGTH);
        debug_assert!(
            Z::MAX.to_byte_vec() == <Z64 as ZConsts>::MAX.to_byte_vec()
                || Z::MAX.to_byte_vec() == <Z128 as ZConsts>::MAX.to_byte_vec()
        );

        let one: ResiduePoly<Z> = ResiduePoly::ONE;
        let two: ResiduePoly<Z> = ResiduePoly::TWO;
        let mut x = Self::solve_1(v)?;
        let mut y = one;
        // Do outer Newton Raphson
        for _i in 1..=Z::BIT_LENGTH.ilog2() {
            // Do inner Newton Raphson to compute inverse of 1+2*x
            // Observe that because we use modulo 2^64 and 2^128, which are 2^2^i values
            // Hence there is no need to do the modulo operation of m as described in the NIST document.
            let z = one + two * x;
            y = y * (two - z * y);
            y = y * (two - z * y);
            x = (x * x + *v) * y;
        }
        // Validate the result, i.e. x+x^2 = input
        if v != &(x + x * x) {
            return Err(anyhow_error_and_log(
                "The outer Newton Raphson inversion computation in solve() failed".to_string(),
            ));
        }
        Ok(x)
    }
}

pub type ResiduePoly128 = ResiduePoly<Z128>;

impl ResiduePoly128 {
    pub fn from_bytes(bytes: &[u8; Self::BIT_LENGTH >> 3]) -> Self {
        let mut coefs = [Z128::default(); F_DEG];
        const Z128_SIZE_BYTE: usize = Z128::BIT_LENGTH >> 3;
        for (i, coef) in coefs.iter_mut().enumerate() {
            let curr_index = Z128_SIZE_BYTE * i;
            let mut coef_byte = [0_u8; Z128_SIZE_BYTE];
            coef_byte[..].copy_from_slice(&bytes[curr_index..curr_index + Z128_SIZE_BYTE]);
            *coef = Wrapping(u128::from_le_bytes(coef_byte));
        }
        ResiduePoly { coefs }
    }
}

impl Derive for ResiduePoly128 {
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: usize,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>> {
        let mut hasher = blake3::Hasher::new();
        //Update hasher with x
        for x_coef in x.coefs {
            hasher.update(&x_coef.0.to_le_bytes());
        }
        hasher.update(&g.to_le_bytes());

        roles
            .iter()
            .map(|role| {
                let mut hasher_cloned = hasher.clone();
                hasher_cloned.update(&role.one_based().to_le_bytes());
                let mut output_reader = hasher_cloned.finalize_xof();
                let mut challenges = vec![Self::ZERO; l];
                for challenge in challenges.iter_mut() {
                    let mut bytes_res_poly = [0u8; Self::BIT_LENGTH >> 3];
                    output_reader.fill(&mut bytes_res_poly);
                    *challenge = Self::from_bytes(&bytes_res_poly);
                }
                (*role, challenges)
            })
            .collect()
    }
}

impl PRSSConversions for ResiduePoly128 {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert_eq!(coefs.len(), F_DEG);
        let mut poly_coefs = [Z128::ZERO; F_DEG];
        for (idx, coef) in coefs.into_iter().enumerate() {
            poly_coefs[idx] = Wrapping(coef);
        }
        Self { coefs: poly_coefs }
    }
    fn from_i128(value: i128) -> Self {
        Self::from_scalar(Wrapping(value as u128))
    }
}

pub type ResiduePoly64 = ResiduePoly<Z64>;

impl ResiduePoly64 {
    pub fn from_bytes(bytes: &[u8; Self::BIT_LENGTH >> 3]) -> Self {
        let mut coefs = [Z64::default(); F_DEG];
        const Z64_SIZE_BYTE: usize = Z64::BIT_LENGTH >> 3;
        for (i, coef) in coefs.iter_mut().enumerate() {
            let curr_index = Z64_SIZE_BYTE * i;
            let mut coef_byte = [0_u8; Z64_SIZE_BYTE];
            coef_byte[..].copy_from_slice(&bytes[curr_index..curr_index + Z64_SIZE_BYTE]);
            *coef = Wrapping(u64::from_le_bytes(coef_byte));
        }
        ResiduePoly { coefs }
    }
}

impl Derive for ResiduePoly64 {
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: usize,
        l: usize,
        roles: &[Role],
    ) -> std::collections::HashMap<Role, Vec<Self>> {
        let mut hasher = blake3::Hasher::new();
        //Update hasher with x
        for x_coef in x.coefs {
            hasher.update(&x_coef.0.to_le_bytes());
        }
        hasher.update(&g.to_le_bytes());

        roles
            .iter()
            .map(|role| {
                let mut hasher_cloned = hasher.clone();
                hasher_cloned.update(&role.one_based().to_le_bytes());
                let mut output_reader = hasher_cloned.finalize_xof();
                let mut challenges = vec![Self::ZERO; l];
                for challenge in challenges.iter_mut() {
                    let mut bytes_res_poly = [0u8; Self::BIT_LENGTH >> 3];
                    output_reader.fill(&mut bytes_res_poly);
                    *challenge = Self::from_bytes(&bytes_res_poly);
                }
                (*role, challenges)
            })
            .collect()
    }
}

impl PRSSConversions for ResiduePoly64 {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert_eq!(coefs.len(), F_DEG / 2);
        let mut poly_coefs = [Z64::ZERO; F_DEG];
        for (idx, coef) in coefs.into_iter().enumerate() {
            poly_coefs[2 * idx] = Wrapping(coef as u64);
            poly_coefs[2 * idx + 1] = Wrapping((coef >> 64) as u64);
        }
        Self { coefs: poly_coefs }
    }

    fn from_i128(value: i128) -> Self {
        Self::from_scalar(Wrapping(value as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::base_ring::{Z128, Z64};
    use crate::execution::sharing::shamir::ErrorCorrect;
    use crate::execution::sharing::shamir::{InputOp, RevealOp};
    use aes_prng::AesRng;
    use itertools::Itertools;
    use paste::paste;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::num::Wrapping;

    #[test]
    fn test_is_zero() {
        let mut rng = AesRng::seed_from_u64(0);

        let mut z128poly: ResiduePoly128 = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z128poly.is_zero());
        z128poly = ResiduePoly128::sample(&mut rng);
        assert!(!z128poly.is_zero());

        let mut z64poly: ResiduePoly64 = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z64poly.is_zero());
        z64poly.coefs[1] = Z64::ONE;
        assert!(!z64poly.is_zero());
    }

    macro_rules! tests_residue_poly {
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
            fn [<test_ring_max_error_correction_ $z:lower>]() {
                let t: usize = 4;
                let max_err: usize = 3;
                let n = (t + 1) + 4 * max_err;

                let secret: ResiduePoly<$z> = ResiduePoly::<$z>::from_scalar
                (Wrapping(1000));
                let mut rng = AesRng::seed_from_u64(0);

                let mut shares = ShamirSharings::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct
                shares.shares[0] = Share::new(Role::indexed_by_zero(0),ResiduePoly::sample(&mut rng));
                shares.shares[1] = Share::new(Role::indexed_by_zero(1),ResiduePoly::sample(&mut rng));

                let recon = ResiduePoly::<$z>::error_correct(&shares,t, 1);
                let _ =
                    recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
            }

            #[rstest]
            #[case(Wrapping(0))]
            #[case(Wrapping(1))]
            #[case(Wrapping(10))]
            #[case(Wrapping(3213214))]
            #[case(Wrapping($u::MAX - 23) )]
            #[case(Wrapping($u::MAX - 1) )]
            #[case(Wrapping($u::MAX))]
            #[case(Wrapping(rand::Rng::gen::<$u>(&mut rand::thread_rng())))]
            fn [<test_share_reconstruct_ $z:lower>](#[case] secret: $z) {
                let threshold: usize = 5;
                let num_parties = 9;

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let sharings = ShamirSharings::<ResiduePoly<$z>>::share(&mut rng, residue_secret, num_parties, threshold).unwrap();
                let recon = TryFromWrapper::<$z>::try_from(sharings.reconstruct(threshold).unwrap()).unwrap();
                assert_eq!(recon.0, secret);
            }

            #[rstest]
            #[case(Wrapping(0))]
            #[case(Wrapping(1))]
            #[case(Wrapping(10))]
            #[case(Wrapping(3213214))]
            #[case(Wrapping($u::MAX - 23 ))]
            #[case(Wrapping($u::MAX - 1 ))]
            #[case(Wrapping($u::MAX))]
            #[case(Wrapping(rand::Rng::gen::<$u>(&mut rand::thread_rng())))]
            fn [<test_share_reconstruct_randomseed_ $z:lower>](#[case] secret: $z) {
                let threshold: usize = 5;
                let num_parties = 9;

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::from_entropy();
                let sharings = ShamirSharings::<ResiduePoly<$z>>::share(&mut rng, residue_secret, num_parties, threshold).unwrap();
                let recon = TryFromWrapper::<$z>::try_from(sharings.reconstruct(threshold).unwrap()).unwrap();
                assert_eq!(recon.0, secret);
            }

            #[rstest]
            #[case(1, 1, Wrapping(100))]
            #[case(2, 0, Wrapping(100))]
            #[case(4, 1, Wrapping(100))]
            #[case(8, 10, Wrapping(100))]
            #[case(10, 8, Wrapping(100))]
            fn [<test_ring_error_correction_ $z:lower>](#[case] t: usize, #[case] max_err: usize, #[case] secret: $z) {
                let n = (t + 1) + 2 * max_err;

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let mut sharings = ShamirSharings::<ResiduePoly<$z>>::share(&mut rng, residue_secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct

                for item in sharings.shares.iter_mut().take(max_err) {
                    *item = Share::new(item.owner(),ResiduePoly::sample(&mut rng));
                }

                let recon = ResiduePoly::<$z>::error_correct(&sharings,t, max_err);
                let f_zero = recon
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
            }

            #[cfg(feature = "slow_tests")]
            #[test]
            fn [<test_syndrome_decoding_large_ $z:lower>]() {
                let n = 10;
                let t = 3;
                let secret = Wrapping(123);
                let num_errs = 2;

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(2342);
                let sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();
                let party_ids = &sharings.shares.iter().map(|s| s.owner()).collect_vec();

                // verify that decoding with Gao works as a sanity check
                let decoded = ResiduePoly::<$z>::error_correct(&sharings, t, num_errs);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // try syndrome decoding without errors
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&sharings, t).unwrap();
                let errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                assert_eq!(errors, vec![ResiduePoly::ZERO; n]); // should be all-zero

                // add 1 error now
                let erridx = 3;
                let mut expected_errors = vec![ResiduePoly::ZERO; n];
                let mut bad_shares = sharings.clone();

                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePoly::sample(&mut rng);
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 1 error
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);

                // add 2nd error now
                let erridx = 6;
                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePoly::sample(&mut rng);
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 2 errors
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);
            }

            #[test]
            fn [<test_syndrome_decoding_even_odd_ $z:lower>]() {
                let n = 7;
                let t = 2;
                let secret = Wrapping(42);
                let num_errs = 2;

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(678);
                let sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();

                // verify that decoding with Gao works as a sanity check
                let decoded = ResiduePoly::<$z>::error_correct(&sharings, t, num_errs);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // try syndrome decoding without errors
                let parties = sharings.shares.iter().map(|s| s.owner()).collect_vec();
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&sharings, t).unwrap();
                let errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                assert_eq!(errors, vec![ResiduePoly::ZERO; n]); // should be all-zero

                // add 1 error now
                let erridx = 3;
                let mut expected_errors = vec![ResiduePoly::ZERO; n];
                let mut bad_shares = sharings.clone();

                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePoly::from_scalar(Wrapping(53));
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 1 error where the error term is 53
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);

                // add 2nd error now
                let erridx = 5;
                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePoly::from_scalar(Wrapping(54));
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 2 errors where the error terms are 53 and 54
                let syndrome_poly = ResiduePoly::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePoly::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);
            }

            #[test]
            fn [<test_syndrome_computation_ $z:lower>]() {
                let n = 10;
                let t = 2;
                let secret = Wrapping(123);

                let residue_secret = ResiduePoly::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let mut sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();

                // syndrome computation without errors
                let recon = ResiduePoly::<$z>::syndrome_compute(&sharings, t).unwrap();
                tracing::debug!("Syndrome Output = {:?}", recon);
                assert_eq!(recon, Poly::<ResiduePoly<$z>>::zero()); // should be zero without errors

                // add errors
                for item in sharings.shares.iter_mut().take(2) {
                    *item = Share::new(item.owner(), ResiduePoly::sample(&mut rng));
                }

                // verify that decoding still works
                let decoded = ResiduePoly::<$z>::error_correct(&sharings, t, 2);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // syndrome computation with errors
                let recon = ResiduePoly::<$z>::syndrome_compute(&sharings, t).unwrap();
                tracing::debug!("Syndrome Output = {:?}", recon);
                assert_ne!(recon, Poly::<ResiduePoly<$z>>::zero()); // should not be zero with errors
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
                let mut rng = AesRng::seed_from_u64(0);
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
            #[test]
            fn [<test_shift_ $z:lower>]() {
                assert_eq!(
                    ResiduePoly::<$z>::embed_exceptional_set(42).unwrap(),
                    ResiduePoly::<$z>::embed_exceptional_set(42).unwrap() << 0
                );
                assert_eq!(
                    ResiduePoly::<$z>::from_scalar(Wrapping(152)),
                    ResiduePoly::<$z>::from_scalar(Wrapping(19)) << 3
                );
                assert_eq!(
                    ResiduePoly::<$z>::from_scalar(Wrapping(2)),
                    ResiduePoly::<$z>::from_scalar(Wrapping(1)) << 1
                );
                // Observe the embedding of 2 is 0, 1, 0, 0, 0, 0, 0, 0
                assert_eq!(
                    ResiduePoly::<$z>::from_vec(vec![
                        $z::ZERO,
                        Wrapping(2),
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO
                    ])
                    .unwrap(),
                    ResiduePoly::<$z>::embed_exceptional_set(2).unwrap() << 1
                );
            }
            }
        };
    }
    tests_residue_poly!(Z64, u64);
    tests_residue_poly!(Z128, u128);

    #[test]
    fn embed_sunshine() {
        let mut input: usize;
        let mut reference = ResiduePoly::ZERO;
        let mut res: ResiduePoly128;

        // Set the polynomial to 1+x, i.e. 0b00000011 = 3
        input = 3;
        reference.coefs[0] = Wrapping(1);
        reference.coefs[1] = Wrapping(1);
        res = ResiduePoly::embed_exceptional_set(input).unwrap();
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
        res = ResiduePoly::embed_exceptional_set(input).unwrap();
        assert_eq!(reference, res);

        // Set the polynomial to x^7, i.e. 0b10000000 = 128
        input = 128;
        reference = ResiduePoly::ZERO;
        reference.coefs[7] = Wrapping(1);
        res = ResiduePoly::embed_exceptional_set(input).unwrap();
        assert_eq!(reference, res);
    }

    #[test]
    fn two_power_sunshine() {
        let input = GF256::from(42);
        let powers = two_powers(input, 8);
        assert_eq!(8, powers.len());
        assert_eq!(42, powers[0].0);
        assert_eq!(input * input, powers[1]);
        assert_eq!(input * input * input * input, powers[2]);
        assert_eq!(
            input * input * input * input * input * input * input * input,
            powers[3]
        );
    }

    #[test]
    fn test_from_u128_chunks_z128() {
        let rpoly = ResiduePoly128::sample(&mut AesRng::seed_from_u64(0));
        let coefs = rpoly.coefs.into_iter().map(|x| x.0).collect_vec();
        let rpoly_test = ResiduePoly128::from_u128_chunks(coefs);

        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_to_from_bytes_z128() {
        let rpoly = ResiduePoly128::sample(&mut AesRng::seed_from_u64(0));
        let byte_vec: [u8; ResiduePoly128::BIT_LENGTH >> 3] =
            rpoly.to_byte_vec().try_into().unwrap();
        let rpoly_test = ResiduePoly128::from_bytes(&byte_vec);
        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_from_u128_chunks_z64() {
        let rpoly = ResiduePoly64::sample(&mut AesRng::seed_from_u64(0));
        let coefs = rpoly.coefs.into_iter().map(|x| x.0).collect_vec();
        let mut new_coefs = Vec::new();
        for coef in coefs.chunks(2) {
            new_coefs.push((coef[0] as u128) + ((coef[1] as u128) << 64));
        }
        let rpoly_test = ResiduePoly64::from_u128_chunks(new_coefs);

        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_to_from_bytes_z64() {
        let rpoly = ResiduePoly64::sample(&mut AesRng::seed_from_u64(0));
        let byte_vec: [u8; ResiduePoly64::BIT_LENGTH >> 3] =
            rpoly.to_byte_vec().try_into().unwrap();
        let rpoly_test = ResiduePoly64::from_bytes(&byte_vec);
        assert_eq!(rpoly, rpoly_test);
    }
}
