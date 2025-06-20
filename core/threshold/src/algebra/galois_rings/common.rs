use super::utils::ArrayVisitor;
use crate::algebra::{
    base_ring::ToZ64,
    bivariate::compute_powers_list,
    poly::Poly,
    structure_traits::{
        BaseRing, Derive, FromU128, Invert, One, QuotientMaximalIdeal, Ring, RingEmbed, Sample,
        Solve, Solve1, Syndrome, ZConsts, Zero,
    },
    syndrome::lagrange_numerators,
};
use crate::error::error_handler::anyhow_error_and_log;
#[cfg(feature = "non-wasm")]
use crate::execution::small_execution::prf::PRSSConversions;
use crate::{algebra::structure_traits::Field, execution::sharing::shamir::ShamirFieldPoly};
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_fields::common::syndrome_decoding_z2,
    },
    execution::{
        runtime::party::Role,
        sharing::{shamir::ShamirSharings, share::Share},
    },
};
#[cfg(feature = "non-wasm")]
use ::std::num::Wrapping;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{ser::SerializeTuple, Deserialize, Serialize};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use std::marker::PhantomData;
use std::{
    collections::HashMap,
    fmt::Display,
    iter::Sum,
    ops::{Add, AddAssign, Mul, Neg, Shl, Sub, SubAssign},
};
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use zeroize::Zeroize;

/// Represents an element Z_{2^bitlen}[X]/F[X]
/// for F[X] of given EXTENSION_DEGREE.
/// Corresponding irreducible polynomial are defined in `galois_fields`
///
/// This is also the 'value' of a single ShamirShare.
#[derive(Clone, Copy, PartialEq, Hash, Eq, Debug, Zeroize, Versionize)]
#[versionize(ResiduePolyVersioned)]
pub struct ResiduePoly<Z, const EXTENSION_DEGREE: usize> {
    pub coefs: [Z; EXTENSION_DEGREE],
}

impl<Z: Default + Copy, const EXTENSION_DEGREE: usize> Default
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    fn default() -> Self {
        Self {
            coefs: [Z::default(); EXTENSION_DEGREE],
        }
    }
}

impl<Z: Serialize, const EXTENSION_DEGREE: usize> Serialize for ResiduePoly<Z, EXTENSION_DEGREE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = serializer.serialize_tuple(EXTENSION_DEGREE)?;
        for coef in self.coefs.iter() {
            s.serialize_element(coef)?;
        }
        s.end()
    }
}

impl<'a, Z: Deserialize<'a>, const EXTENSION_DEGREE: usize> Deserialize<'a>
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        let coefs = deserializer.deserialize_tuple(
            EXTENSION_DEGREE,
            ArrayVisitor::<Z, EXTENSION_DEGREE>(PhantomData),
        )?;
        Ok(Self { coefs })
    }
}

#[derive(Serialize, Deserialize, Clone, VersionsDispatch)]
pub enum ResiduePolyVersioned<Z, const EXTENSION_DEGREE: usize> {
    V0(ResiduePoly<Z, EXTENSION_DEGREE>),
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> FromU128 for ResiduePoly<Z, EXTENSION_DEGREE> {
    fn from_u128(value: u128) -> Self {
        Self::from_scalar(Z::from_u128(value))
    }
}

//Cant do TryInto with generics, see https://github.com/rust-lang/rust/issues/50133#issuecomment-646908391
pub struct TryFromWrapper<Z>(pub Z);
impl<Z: Ring + std::fmt::Display, const EXTENSION_DEGREE: usize>
    TryFrom<ResiduePoly<Z, EXTENSION_DEGREE>> for TryFromWrapper<Z>
{
    type Error = anyhow::Error;
    fn try_from(poly: ResiduePoly<Z, EXTENSION_DEGREE>) -> Result<TryFromWrapper<Z>, Self::Error> {
        Ok(TryFromWrapper(poly.to_scalar()?))
    }
}

impl<Z: Clone, const EXTENSION_DEGREE: usize> ResiduePoly<Z, EXTENSION_DEGREE> {
    pub fn from_scalar(x: Z) -> Self
    where
        Z: Zero,
    {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        coefs[0] = x;
        ResiduePoly { coefs }
    }

    pub fn to_scalar(self) -> anyhow::Result<Z>
    where
        Z: Zero + PartialEq + Display + Copy,
    {
        for i in 1..EXTENSION_DEGREE {
            if self.coefs[i] != Z::ZERO {
                return Err(anyhow_error_and_log(format!(
                    "Higher coefficient must be zero but was {}",
                    self.coefs[i]
                )));
            }
        }
        Ok(self.coefs[0])
    }

    pub fn from_array(coefs: [Z; EXTENSION_DEGREE]) -> Self {
        ResiduePoly { coefs }
    }

    pub fn from_vec(coefs: Vec<Z>) -> anyhow::Result<Self> {
        if coefs.len() != EXTENSION_DEGREE {
            return Err(anyhow_error_and_log(format!(
                "Error: required {EXTENSION_DEGREE} coefficients, but got {}",
                coefs.len()
            )));
        }
        Ok(ResiduePoly {
            coefs: coefs.try_into().map_err(|_| {
                anyhow_error_and_log("Error converting coefficient vector into Z64Poly")
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

impl<Z: Zero + Sample + Copy, const EXTENSION_DEGREE: usize> Sample
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    fn sample<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        for coef in coefs.iter_mut() {
            *coef = Z::sample(rng);
        }
        ResiduePoly { coefs }
    }
}

impl<Z: Zero + Clone, const EXTENSION_DEGREE: usize> Zero for ResiduePoly<Z, EXTENSION_DEGREE> {
    const ZERO: Self = ResiduePoly {
        coefs: [Z::ZERO; EXTENSION_DEGREE],
    };
}

impl<Z: One + Zero + Copy, const EXTENSION_DEGREE: usize> One for ResiduePoly<Z, EXTENSION_DEGREE> {
    const ONE: Self = {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        coefs[0] = Z::ONE;
        ResiduePoly { coefs }
    };
}

impl<Z: One + Zero + ZConsts + Copy, const EXTENSION_DEGREE: usize> ZConsts
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    const TWO: Self = {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        coefs[0] = Z::TWO;
        ResiduePoly { coefs }
    };

    const THREE: Self = {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        coefs[0] = Z::THREE;
        ResiduePoly { coefs }
    };

    const MAX: Self = {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        coefs[0] = Z::MAX;
        ResiduePoly { coefs }
    };
}

impl<Z: Zero + Copy + AddAssign, const EXTENSION_DEGREE: usize> Sum<Self>
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut coefs = [Z::ZERO; EXTENSION_DEGREE];
        for poly in iter {
            for (i, coef) in coefs.iter_mut().enumerate() {
                *coef += poly.coefs[i];
            }
        }
        // implicit mod reduction on `coefs`
        Self { coefs }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Add<Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = Self;
    fn add(mut self, other: ResiduePoly<Z, EXTENSION_DEGREE>) -> Self::Output {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] += other.coefs[i];
        }
        self
    }
}

impl<Z, const EXTENSION_DEGREE: usize> AddAssign<Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: AddAssign + Copy,
{
    fn add_assign(&mut self, other: Self) {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] += other.coefs[i];
        }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> AddAssign<&Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: AddAssign + Copy,
{
    fn add_assign(&mut self, other: &ResiduePoly<Z, EXTENSION_DEGREE>) {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] += other.coefs[i];
        }
    }
}

impl<Z: Neg<Output = Z> + Clone, const EXTENSION_DEGREE: usize> Neg
    for ResiduePoly<Z, EXTENSION_DEGREE>
{
    type Output = Self;
    fn neg(self) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| -x),
        }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Sub<Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: SubAssign<Z>,
{
    type Output = Self;
    fn sub(mut self, other: ResiduePoly<Z, EXTENSION_DEGREE>) -> Self::Output {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] -= other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> SubAssign<Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: SubAssign + Copy,
{
    fn sub_assign(&mut self, other: ResiduePoly<Z, EXTENSION_DEGREE>) {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] -= other.coefs[i];
        }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Add<&Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = Self;
    fn add(mut self, other: &ResiduePoly<Z, EXTENSION_DEGREE>) -> Self::Output {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] += other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Sub<&Self> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: SubAssign<Z>,
{
    type Output = Self;
    fn sub(mut self, other: &ResiduePoly<Z, EXTENSION_DEGREE>) -> Self::Output {
        for i in 0..EXTENSION_DEGREE {
            self.coefs[i] -= other.coefs[i];
        }
        ResiduePoly { coefs: self.coefs }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Add<Z> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: AddAssign<Z> + Clone,
{
    type Output = Self;
    fn add(mut self, other: Z) -> Self::Output {
        // add const only to free term:
        self.coefs[0] += other;
        self
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Mul<Z> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: Mul<Z, Output = Z>,
{
    type Output = Self;
    fn mul(self, other: Z) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Mul<Z> for &ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: Mul<Z, Output = Z>,
{
    type Output = ResiduePoly<Z, EXTENSION_DEGREE>;
    fn mul(self, other: Z) -> Self::Output {
        ResiduePoly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl<Z, const EXTENSION_DEGREE: usize> Add<Z> for &ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Copy,
    Z: AddAssign<Z>,
{
    type Output = ResiduePoly<Z, EXTENSION_DEGREE>;
    fn add(self, other: Z) -> Self::Output {
        // add const only to free term:
        let mut coefs = self.coefs;
        coefs[0] += other;
        ResiduePoly { coefs }
    }
}

/// Compute R << i which translates to left shifting by i each coefficient of the ResiduePoly
/// If i >= Z::CHAR_LOG2 then it computes R << (i % Z::CHAR_LOG2)
impl<Z, const EXTENSION_DEGREE: usize> Shl<usize> for ResiduePoly<Z, EXTENSION_DEGREE>
where
    Z: Ring + ZConsts,
    Z: std::ops::Shl<usize, Output = Z>,
{
    type Output = Self;

    fn shl(self, rhs: usize) -> Self::Output {
        let mut coefs = self.coefs;
        for coef in &mut coefs {
            *coef = *coef << rhs;
        }
        ResiduePoly { coefs }
    }
}

pub trait LutMulReduction<Z> {
    fn reduce_mul(lower_coefs: &[Z]) -> Self;
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> LutMulReduction<Z>
    for ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: ReductionTable<Z, EXTENSION_DEGREE>,
{
    fn reduce_mul(coefs: &[Z]) -> Self {
        let mut res = Self::from_array(coefs[0..EXTENSION_DEGREE].try_into().unwrap());
        for (i, coef) in coefs.iter().enumerate().skip(EXTENSION_DEGREE) {
            for j in 0..EXTENSION_DEGREE {
                res.coefs[j] += *Self::REDUCTION_TABLES.entry(i, j) * *coef;
            }
        }
        res
    }
}

pub trait ReductionTable<Z: Clone, const EXTENSION_DEGREE: usize> {
    const REDUCTION_TABLES: ReductionTables<Z, EXTENSION_DEGREE>;
}

/// Precomputes reductions of monomials of higher degree to help us in reducing polynomials
/// after multiplication faster
pub struct ReductionTables<Z: Clone, const EXTENSION_DEGREE: usize> {
    /// NOTE: We only need up to EXTENSION_DEGREE - 1 but can't do `const` operations with generic
    pub reduced: [ResiduePoly<Z, EXTENSION_DEGREE>; EXTENSION_DEGREE],
}

impl<Z: Clone, const EXTENSION_DEGREE: usize> ReductionTables<Z, EXTENSION_DEGREE> {
    #[inline(always)]
    pub fn entry(&self, deg: usize, idx_coef: usize) -> &Z {
        &self.reduced[deg - EXTENSION_DEGREE].coefs[idx_coef]
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> ResiduePoly<Z, EXTENSION_DEGREE> {
    //Checks if each coefficient is a multiple of 2^exp
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

impl<const EXTENSION_DEGREE: usize> Derive for ResiduePoly<Z128, EXTENSION_DEGREE>
where
    Self: QuotientMaximalIdeal,
{
    /// Implements H_{LDS}, mapping to the exceptional sequence
    /// via the finite field generator
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: u8,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>> {
        // Observe that since the application of SHAKE256 is highly specific and needs to be optimized here,
        // we don't use on the wrapper in `hashing.rs`
        let mut hasher = Shake256::default();
        hasher.update(&Self::DSEP_LDS);
        //Update hasher with x
        for x_coef in x.coefs {
            //This line is the reason why it's not straightforward to implement Derive
            //for ResiduePoly<Z> in general
            hasher.update(&x_coef.0.to_le_bytes());
        }

        //Encode g on 1 byte
        hasher.update(&g.to_le_bytes());

        roles
            .iter()
            .map(|role| {
                let mut hasher_cloned = hasher.clone();
                //Encode role on two bytes
                hasher_cloned.update(&(role.one_based() as u16).to_le_bytes());
                let mut output_reader = hasher_cloned.finalize_xof();
                let mut challenges_idx = vec![0u8; l];
                output_reader.read(&mut challenges_idx);
                let challenges = challenges_idx
                    .iter()
                    .map(|idx| {
                        Self::bit_lift_from_idx((*idx as usize) % (1 << EXTENSION_DEGREE), 0)
                            .unwrap()
                    })
                    .collect_vec();
                (*role, challenges)
            })
            .collect()
    }

    const LOG_SIZE_EXCEPTIONAL_SET: usize = Self::QUOTIENT_OUTPUT_SIZE.ilog2() as usize;
}

impl<const EXTENSION_DEGREE: usize> Derive for ResiduePoly<Z64, EXTENSION_DEGREE>
where
    Self: QuotientMaximalIdeal,
{
    /// Implements H_{LDS}, mapping to the exceptional sequence
    /// via the finite field generator
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: u8,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>> {
        // Observe that since the application of SHAKE256 is highly specific and needs to be optimized here,
        // we don't use on the wrapper in `hashing.rs`
        let mut hasher = Shake256::default();
        hasher.update(&Self::DSEP_LDS);
        //Update hasher with x
        for x_coef in x.coefs {
            //This line is the reason why it's not straightforward to implement Derive
            //for ResiduePoly<Z> in general
            hasher.update(&x_coef.0.to_le_bytes());
        }

        //Encode g on 1 byte
        hasher.update(&g.to_le_bytes());

        roles
            .iter()
            .map(|role| {
                let mut hasher_cloned = hasher.clone();
                //Encode role on two bytes
                hasher_cloned.update(&(role.one_based() as u16).to_le_bytes());
                let mut output_reader = hasher_cloned.finalize_xof();
                let mut challenges_idx = vec![0u8; l];
                output_reader.read(&mut challenges_idx);
                let challenges = challenges_idx
                    .iter()
                    .map(|idx| {
                        Self::bit_lift_from_idx((*idx as usize) % (1 << EXTENSION_DEGREE), 0)
                            .unwrap()
                    })
                    .collect_vec();
                (*role, challenges)
            })
            .collect()
    }

    const LOG_SIZE_EXCEPTIONAL_SET: usize = Self::QUOTIENT_OUTPUT_SIZE.ilog2() as usize;
}

impl<Z: Ring, const EXTENSION_DEGREE: usize> RingEmbed for ResiduePoly<Z, EXTENSION_DEGREE> {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self> {
        if idx >= (1 << EXTENSION_DEGREE) {
            return Err(anyhow_error_and_log(format!(
                "Value {idx} is too large to be embedded!"
            )));
        }

        let mut coefs: [Z; EXTENSION_DEGREE] = [Z::ZERO; EXTENSION_DEGREE];

        for (i, val) in coefs.iter_mut().enumerate().take(EXTENSION_DEGREE) {
            let b = (idx >> i) & 1;
            if b > 0 {
                *val = Z::ONE;
            }
        }

        Ok(ResiduePoly { coefs })
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> Syndrome for ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
{
    //NIST: Level Zero Operation (SynDecode + last step of correction)
    // decode a ring syndrome into an error vector, containing the error magnitudes at the respective indices
    fn syndrome_decode(
        mut syndrome_poly: Poly<Self>,
        parties: &[Role],
        threshold: usize,
    ) -> anyhow::Result<Vec<Self>> {
        let parties = parties.iter().map(|r| r.one_based()).collect_vec();
        // sum up the error vectors here
        let mut e_res: Vec<Self> = vec![Self::ZERO; parties.len()];

        let ring_size: usize = Z::BIT_LENGTH;
        //  compute s_e^(j)/p mod p and decode
        for bit_idx in 0..ring_size {
            let sliced_syndrome_coefs: Vec<_> = syndrome_poly
                .coefs()
                .iter()
                .map(|c| c.bit_compose(bit_idx))
                .collect();

            let sliced_syndrome =
                ShamirFieldPoly::<<Self as QuotientMaximalIdeal>::QuotientOutput>::from_coefs(
                    sliced_syndrome_coefs,
                );

            // bit error in this for this bit-idx
            let ej = syndrome_decoding_z2(&parties, &sliced_syndrome, threshold);

            // lift bit error into the ring
            let lifted_e: Vec<Self> = ej
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
                .map(|(idx, val)| Share::new(Role::indexed_from_zero(idx), *val))
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

    //NIST: Level Zero Operation (I believe this is is "Equation 19")
    // compute the syndrome in the GR from a given sharing and threshold
    fn syndrome_compute(
        sharing: &ShamirSharings<Self>,
        threshold: usize,
    ) -> anyhow::Result<Poly<Self>> {
        let n = sharing.shares.len();
        let r = n - (threshold + 1);

        let ys: Vec<_> = sharing.shares.iter().map(|share| share.value()).collect();

        // embed party IDs into the ring
        let parties: Vec<_> = sharing
            .shares
            .iter()
            .map(|share| Self::embed_exceptional_set(share.owner().one_based()))
            .collect::<Result<Vec<_>, _>>()?;

        // lagrange numerators from Eq.15
        let lagrange_polys = lagrange_numerators(&parties);

        let alpha_powers = compute_powers_list(&parties, r);
        let mut res = Poly::zero();

        // compute syndrome coefficients
        for j in 0..r {
            let mut coef = Self::ZERO;

            for i in 0..n {
                let numerator = ys[i] * alpha_powers[i][j];
                let denom = lagrange_polys[i].eval(&parties[i]);
                coef += numerator * denom.invert()?;
            }

            res.set_coef(j, coef);
        }

        Ok(res)
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> Invert for ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
{
    /// invert and lift an Integer to the large Ring
    fn invert(self) -> anyhow::Result<Self> {
        if self == Self::ZERO {
            return Err(anyhow_error_and_log("Cannot invert 0"));
        }

        let alpha_k = self.bit_compose(0);
        let ainv = alpha_k.invert();
        let mut x0 = Self::embed_quotient_exceptional_set(ainv)?;

        // compute Newton-Raphson iterations
        for _ in 0..Z::BIT_LENGTH.ilog2() {
            x0 *= Self::TWO - self * x0;
        }

        debug_assert_eq!(x0 * self, Self::ONE);

        Ok(x0)
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
{
    pub fn shamir_bit_lift(
        x: &ShamirFieldPoly<<Self as QuotientMaximalIdeal>::QuotientOutput>,
        pos: usize,
    ) -> anyhow::Result<Poly<Self>> {
        let coefs: Vec<Self> = x
            .coefs()
            .iter()
            .map(|coef_2| Self::bit_lift(*coef_2, pos))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Poly::from_coefs(coefs))
    }
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> Solve for ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Solve1,
    Self: Mul<Self, Output = Self>,
{
    //NIST: Level Zero Operation
    ///***NOTE: CAREFUL WHEN NOT USING Z64 OR Z128 AS BASE RING***
    fn solve(v: &Self) -> anyhow::Result<Self> {
        //Check to help detect if we forgot about the note above
        debug_assert_eq!(1 << Z::BIT_LENGTH.ilog2(), Z::BIT_LENGTH);
        debug_assert!(
            Z::MAX.to_byte_vec() == <Z64 as ZConsts>::MAX.to_byte_vec()
                || Z::MAX.to_byte_vec() == <Z128 as ZConsts>::MAX.to_byte_vec()
        );

        let one = Self::ONE;
        let two = Self::TWO;
        let mut x = Self::solve_1(v)?;
        let mut y = one;
        // Do outer Newton Raphson
        //NOTE: If the base ring isn't a power of 2, ilog2 is floor whereas we want ceil
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
        //Note: This is a sanity check, we don't explicitly need it
        if v != &(x + x * x) {
            return Err(anyhow_error_and_log(
                "The outer Newton Raphson inversion computation in solve() failed",
            ));
        }
        Ok(x)
    }
}

#[cfg(feature = "non-wasm")]
impl<const EXTENSION_DEGREE: usize> PRSSConversions for ResiduePoly<Z128, EXTENSION_DEGREE> {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert_eq!(coefs.len(), EXTENSION_DEGREE);
        let mut poly_coefs = [Z128::ZERO; EXTENSION_DEGREE];
        for (idx, coef) in coefs.into_iter().enumerate() {
            poly_coefs[idx] = Wrapping(coef);
        }
        Self { coefs: poly_coefs }
    }
    fn from_i128(value: i128) -> Self {
        Self::from_scalar(Wrapping(value as u128))
    }
}

#[cfg(feature = "non-wasm")]
impl<const EXTENSION_DEGREE: usize> PRSSConversions for ResiduePoly<Z64, EXTENSION_DEGREE> {
    fn from_u128_chunks(coefs: Vec<u128>) -> Self {
        assert_eq!(coefs.len(), EXTENSION_DEGREE);
        let mut poly_coefs = [Z64::ZERO; EXTENSION_DEGREE];
        for (idx, coef) in coefs.into_iter().enumerate() {
            poly_coefs[idx] = Wrapping(coef as u64);
        }
        Self { coefs: poly_coefs }
    }

    /// Calling this means we are trying to produce
    /// a Mask for post-SnS decryption using extesion of Z64
    /// which is wrong
    fn from_i128(_value: i128) -> Self {
        panic!("Trying to call from_i128 for a Galois extension of Z64. This should only happen for extensions of Z128.")
    }
}

impl<const EXTENSION_DEGREE: usize> ResiduePoly<Z128, EXTENSION_DEGREE> {
    pub fn to_residuepoly64(self) -> ResiduePoly<Z64, EXTENSION_DEGREE> {
        let coefs = self.coefs;
        let output_coefs = coefs.map(|coef| coef.to_z64());
        ResiduePoly::<Z64, EXTENSION_DEGREE> {
            coefs: output_coefs,
        }
    }
}

pub trait Monomials
where
    Self: Clone,
{
    fn monomials() -> Vec<Self>;
}

/// Given an array of residue polys p_0, p_1, ..., p_{n-1},
/// convert them into chunks of size [F_DEG]
/// (p_0, ..., p_{F_DEG-1}), (p_{F_DEG}, ..., p_{2F_DEG - 1}), ...
/// then pack every [F_DEG] polynomial into one polynomial
/// by multiplying every one by a different monomial.
/// For example:
/// q_0 = p_0 + p_1 * X + p_2 * X^2 + ... + p_{F_DEG-1} * X^{F_DEG-1},
/// q_1 = p_{F_DEG} + p_{F_DEG + 1} * X + ... + p_{2 * F_DEG-1} * X^{F_DEG-1},
/// q_2 = ...
pub fn pack_residue_poly<const EXTENSION_DEGREE: usize, Z: BaseRing>(
    polys: &[ResiduePoly<Z, EXTENSION_DEGREE>],
) -> Vec<ResiduePoly<Z, EXTENSION_DEGREE>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: Monomials,
    ResiduePoly<Z, EXTENSION_DEGREE>: Ring,
{
    let monomials = ResiduePoly::<Z, EXTENSION_DEGREE>::monomials();

    polys
        .chunks(EXTENSION_DEGREE)
        .map(|chunk| {
            let mut out = ResiduePoly::ZERO;
            for (p, monomial) in chunk.iter().zip(monomials.iter()) {
                out += (*p) * (*monomial);
            }
            out
        })
        .collect()
}
