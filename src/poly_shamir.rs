use crate::gf256::{error_correction, ShamirZ2Poly, ShamirZ2Sharing, GF256};
use crate::ring_constants::ReductionTablesGF256;
use anyhow::anyhow;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Display,
    iter::Sum,
    num::Wrapping,
    ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign},
};

pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

pub type Z64 = Wrapping<u64>;
pub type Z128 = Wrapping<u128>;

/// a collection of shares
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum Value {
    Share64(ZPoly<Z64>),
    Ring64(Wrapping<u64>),
}

/// this trait is currently used only for 64 bit circuit execution
pub trait Sharing {
    fn share<R: RngCore>(rng: &mut R, secret: u64, num_parties: usize, threshold: usize) -> Self;

    fn reveal(&self, threshold: usize) -> u64;
}

/// Sample random element(s)
pub trait Sample {
    fn sample<R: RngCore>(rng: &mut R) -> Self;
}

pub trait Zero {
    const ZERO: Self;
}

pub trait One {
    const ONE: Self;
}

/// The current ShamirPolynomial uses a vector for coefficients, so there is no constant ZERO poly. We need a zero function.
pub trait ZeroVec {
    fn zero() -> Self;
}

pub trait ZConsts {
    const TWO: Self;
    const THREE: Self;
    const MAX: Self;
}

pub trait Ring {
    const RING_SIZE: usize;
}

pub trait ReductionTable<Z> {
    const REDUCTION_TABLES: ReductionTablesGF256<Z>;
}

/// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8).
/// This is also the 'value' of a single ShamirShare.
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct ZPoly<Z> {
    pub coefs: [Z; F_DEG], // TODO(Daniel) can this be a slice instead of an array?
}

impl<Z> ZPoly<Z> {
    pub fn from_scalar(x: Z) -> Self
    where
        Z: Zero,
    {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = x;
        ZPoly { coefs }
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
        ZPoly { coefs }
    }

    /// multiplies a ZPoly by x using the irreducible poly F = x8 + x4 + x3 + x + 1
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
        Ok(ZPoly {
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

impl<Z: Zero + Sample + Copy> Sample for ZPoly<Z> {
    fn sample<R: RngCore>(rng: &mut R) -> Self {
        let mut coefs = [Z::ZERO; F_DEG];
        for coef in coefs.iter_mut() {
            *coef = Z::sample(rng);
        }
        ZPoly { coefs }
    }
}

impl<Z: Zero> Zero for ZPoly<Z> {
    const ZERO: Self = ZPoly {
        coefs: [Z::ZERO; F_DEG],
    };
}

impl<Z: One + Zero + Copy> One for ZPoly<Z> {
    const ONE: Self = {
        let mut coefs = [Z::ZERO; F_DEG];
        coefs[0] = Z::ONE;
        ZPoly { coefs }
    };
}

impl Sharing for ShamirGSharings<Z64> {
    fn share<R: RngCore>(
        rng: &mut R,
        secret: u64,
        num_parties: usize,
        threshold: usize,
    ) -> ShamirGSharings<Z64> {
        ZPoly::<Z64>::share(rng, Wrapping(secret), num_parties, threshold).unwrap()
    }

    fn reveal(&self, threshold: usize) -> u64 {
        ZPoly::<Z64>::reconstruct(self, threshold).unwrap().0
    }
}

impl Add<u64> for ZPoly<Z64> {
    type Output = ZPoly<Z64>;
    fn add(mut self, other: u64) -> Self::Output {
        // add const only to free term:
        self.coefs[0] += Wrapping(other);
        ZPoly { coefs: self.coefs }
    }
}

impl Add<u64> for &ZPoly<Z64> {
    type Output = ZPoly<Z64>;
    fn add(self, other: u64) -> Self::Output {
        // add const only to free term:
        let mut coefs = self.coefs;
        coefs[0] += Wrapping(other);
        ZPoly { coefs }
    }
}

impl Mul<u64> for ZPoly<Z64> {
    type Output = ZPoly<Z64>;
    fn mul(self, other: u64) -> Self::Output {
        ZPoly {
            coefs: self.coefs.map(|x| x * Wrapping(other)),
        }
    }
}

impl Mul<u64> for &ZPoly<Z64> {
    type Output = ZPoly<Z64>;
    fn mul(self, other: u64) -> Self::Output {
        ZPoly {
            coefs: self.coefs.map(|x| x * Wrapping(other)),
        }
    }
}

impl Sharing for ShamirGSharings<Z128> {
    fn share<R: RngCore>(
        rng: &mut R,
        secret: u64,
        num_parties: usize,
        threshold: usize,
    ) -> ShamirGSharings<Z128> {
        ZPoly::<Z128>::share(rng, Wrapping(secret.into()), num_parties, threshold).unwrap()
    }

    fn reveal(&self, threshold: usize) -> u64 {
        ZPoly::<Z128>::reconstruct(self, threshold).unwrap().0 as u64
    }
}

impl Add<u64> for ZPoly<Z128> {
    type Output = ZPoly<Z128>;
    fn add(mut self, other: u64) -> Self::Output {
        // add const only to free term:
        self.coefs[0] += Wrapping(other as u128);
        ZPoly { coefs: self.coefs }
    }
}

impl Add<u64> for &ZPoly<Z128> {
    type Output = ZPoly<Z128>;
    fn add(self, other: u64) -> Self::Output {
        // add const only to free term:
        let mut coefs = self.coefs;
        coefs[0] += Wrapping(other as u128);
        ZPoly { coefs }
    }
}

impl Mul<u64> for ZPoly<Z128> {
    type Output = ZPoly<Z128>;
    fn mul(self, other: u64) -> Self::Output {
        ZPoly {
            coefs: self.coefs.map(|x| x * Wrapping(other as u128)),
        }
    }
}

impl Mul<u64> for &ZPoly<Z128> {
    type Output = ZPoly<Z128>;
    fn mul(self, other: u64) -> Self::Output {
        ZPoly {
            coefs: self.coefs.map(|x| x * Wrapping(other as u128)),
        }
    }
}

impl<R> Add<ShamirPolynomial<R>> for ShamirPolynomial<R>
where
    R: Add<R, Output = R>,
    R: Zero,
    R: Copy,
{
    type Output = ShamirPolynomial<R>;
    fn add(self, other: ShamirPolynomial<R>) -> Self::Output {
        let max_len = usize::max(self.coefs.len(), other.coefs.len());

        let mut coefs: Vec<R> = Vec::with_capacity(max_len);
        for _i in 0..max_len {
            coefs.push(R::ZERO);
        }
        for (i, item) in coefs.iter_mut().enumerate() {
            if i < self.coefs.len() {
                *item = *item + self.coefs[i];
            }
            if i < other.coefs.len() {
                *item = *item + other.coefs[i];
            }
        }
        ShamirPolynomial { coefs }
    }
}

impl<Z: Zero + Copy + AddAssign> Sum<ZPoly<Z>> for ZPoly<Z> {
    fn sum<I: Iterator<Item = ZPoly<Z>>>(iter: I) -> Self {
        let mut coefs = [Z::ZERO; F_DEG];
        for poly in iter {
            for (i, coef) in coefs.iter_mut().enumerate() {
                *coef += poly.coefs[i];
            }
        }
        // implicit mod reduction on `coefs`
        ZPoly::<Z> { coefs }
    }
}

#[derive(Clone, Default, PartialEq, Debug)]
pub struct ShamirPolynomial<R> {
    pub coefs: Vec<R>,
}

impl<R> ShamirPolynomial<R> {
    pub fn from_vec_poly(coefs: Vec<R>) -> Self {
        ShamirPolynomial { coefs }
    }
}

impl<R> ShamirPolynomial<R>
where
    R: Zero + std::cmp::PartialEq,
{
    pub fn degree(&self) -> usize {
        for (d, coefs) in self.coefs.iter().enumerate().rev() {
            if coefs != &R::ZERO {
                return d;
            }
        }
        0
    }
}

impl<R> ShamirPolynomial<R>
where
    R: Zero,
{
    pub fn zeros(n: usize) -> Self {
        let mut coefs: Vec<R> = Vec::with_capacity(n);
        for _i in 0..n {
            coefs.push(R::ZERO);
        }
        ShamirPolynomial { coefs }
    }
}

impl<R> ZeroVec for ShamirPolynomial<R>
where
    R: Zero,
{
    fn zero() -> Self {
        let coefs = vec![R::ZERO];
        ShamirPolynomial { coefs }
    }
}

impl<R> ShamirPolynomial<R>
where
    R: Sample,
    R: Zero,
    R: One,
{
    pub fn sample_random<U: RngCore>(rng: &mut U, zero_coef: R, degree: usize) -> Self {
        let mut coefs: Vec<_> = (0..degree).map(|_| R::sample(rng)).collect();
        coefs.insert(0, zero_coef);
        ShamirPolynomial { coefs }
    }
}

impl<R> ShamirPolynomial<R>
where
    R: Zero,
    for<'r> R: Mul<&'r R, Output = R>,
    for<'r> R: Add<&'r R, Output = R>,
{
    pub fn eval(&self, point: &R) -> R {
        let mut res = R::ZERO;
        for coef in self.coefs.iter().rev() {
            res = res * point + coef;
        }
        res
    }
}

/// This data structure holds a collection of party_ids and their corresponding Shamir shares (each a ZPoly<Z>)
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ShamirGSharings<Z> {
    pub shares: Vec<(usize, ZPoly<Z>)>,
}

macro_rules! impl_share_type {
    ($z:ty, $u:ty, $l:expr) => {
        impl Add<ShamirGSharings<$z>> for ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn add(self, rhs: ShamirGSharings<$z>) -> Self::Output {
                ShamirGSharings {
                    shares: self
                        .shares
                        .iter()
                        .zip(&rhs.shares)
                        .map(|(a, b)| {
                            assert_eq!(a.0, b.0);
                            (a.0, a.1 + b.1)
                        })
                        .collect(),
                }
            }
        }

        impl<'l> Add<&'l ShamirGSharings<$z>> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn add(self, rhs: &'l ShamirGSharings<$z>) -> Self::Output {
                ShamirGSharings {
                    shares: self
                        .shares
                        .iter()
                        .zip(&rhs.shares)
                        .map(|(a, b)| {
                            assert_eq!(a.0, b.0);
                            (a.0, a.1 + b.1)
                        })
                        .collect(),
                }
            }
        }

        impl<'l> Sub<&'l ShamirGSharings<$z>> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn sub(self, rhs: &'l ShamirGSharings<$z>) -> Self::Output {
                ShamirGSharings {
                    shares: self
                        .shares
                        .iter()
                        .zip(&rhs.shares)
                        .map(|(a, b)| {
                            assert_eq!(a.0, b.0);
                            (a.0, a.1 - b.1)
                        })
                        .collect(),
                }
            }
        }

        impl<'l> Mul<&'l ShamirGSharings<$z>> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn mul(self, _rhs: &'l ShamirGSharings<$z>) -> Self::Output {
                // interactive secret-secret multiplication protocol needs to be implemented
                todo!();
            }
        }

        impl<'l> Mul<$z> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn mul(self, rhs: $z) -> Self::Output {
                ShamirGSharings {
                    shares: self.shares.iter().map(|s| (s.0, s.1 * rhs)).collect(),
                }
            }
        }

        impl<'l> Add<$z> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn add(self, rhs: $z) -> Self::Output {
                ShamirGSharings {
                    shares: self.shares.iter().map(|s| (s.0, s.1 + rhs)).collect(),
                }
            }
        }

        impl<'l> Mul<u64> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn mul(self, rhs: u64) -> Self::Output {
                ShamirGSharings {
                    shares: self.shares.iter().map(|s| (s.0, s.1 * rhs)).collect(),
                }
            }
        }

        impl<'l> Add<u64> for &'l ShamirGSharings<$z> {
            type Output = ShamirGSharings<$z>;
            fn add(self, rhs: u64) -> Self::Output {
                ShamirGSharings {
                    shares: self.shares.iter().map(|s| (s.0, s.1 + rhs)).collect(),
                }
            }
        }

        impl Add<ZPoly<$z>> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn add(mut self, other: ZPoly<$z>) -> Self::Output {
                for i in 0..F_DEG {
                    self.coefs[i] += other.coefs[i];
                }
                ZPoly { coefs: self.coefs }
            }
        }

        impl Sub<ZPoly<$z>> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn sub(mut self, other: ZPoly<$z>) -> Self::Output {
                for i in 0..F_DEG {
                    self.coefs[i] -= other.coefs[i];
                }
                ZPoly { coefs: self.coefs }
            }
        }

        impl Add<&ZPoly<$z>> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn add(mut self, other: &ZPoly<$z>) -> Self::Output {
                for i in 0..F_DEG {
                    self.coefs[i] += other.coefs[i];
                }
                ZPoly { coefs: self.coefs }
            }
        }

        impl Sub<&ZPoly<$z>> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn sub(mut self, other: &ZPoly<$z>) -> Self::Output {
                for i in 0..F_DEG {
                    self.coefs[i] -= other.coefs[i];
                }
                ZPoly { coefs: self.coefs }
            }
        }

        impl Mul<$z> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn mul(self, other: $z) -> Self::Output {
                ZPoly {
                    coefs: self.coefs.map(|x| x * other),
                }
            }
        }

        impl Mul<$z> for &ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn mul(self, other: $z) -> Self::Output {
                ZPoly {
                    coefs: self.coefs.map(|x| x * other),
                }
            }
        }

        impl Add<$z> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn add(mut self, other: $z) -> Self::Output {
                // add const only to free term:
                self.coefs[0] += other;
                ZPoly { coefs: self.coefs }
            }
        }

        impl Add<$z> for &ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn add(self, other: $z) -> Self::Output {
                // add const only to free term:
                let mut coefs = self.coefs;
                coefs[0] += other;
                ZPoly { coefs }
            }
        }

        impl Mul<&ZPoly<$z>> for ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn mul(self, other: &ZPoly<$z>) -> Self::Output {
                let mut extended_coefs = [<$z>::ZERO; 2 * (F_DEG - 1) + 1];
                for i in 0..F_DEG {
                    for j in 0..F_DEG {
                        extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
                    }
                }
                ZPoly::<$z>::reduce_with_tables(extended_coefs)
            }
        }

        impl Mul<&ZPoly<$z>> for &ZPoly<$z> {
            type Output = ZPoly<$z>;
            fn mul(self, other: &ZPoly<$z>) -> Self::Output {
                let mut extended_coefs = [<$z>::ZERO; 2 * (F_DEG - 1) + 1];
                for i in 0..F_DEG {
                    for j in 0..F_DEG {
                        extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
                    }
                }
                ZPoly::<$z>::reduce_with_tables(extended_coefs)
            }
        }

        /// Represents an element Z_{2^bitlen}[X]/F with implicit F = x8 + x4 + x3 + x + 1
        ///
        /// Comes with fixed evaluation points lifted from GF(2^8).
        /// This is also the 'value' of a single ShamirShare.
        impl ZPoly<$z> {
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

                matches!(bit_checks.len(), 0)
            }

            fn reduce_with_tables(coefs: [$z; 2 * (F_DEG - 1) + 1]) -> ZPoly<$z> {
                let mut res = ZPoly::<$z>::from_slice(coefs[0..F_DEG].try_into().unwrap());
                for (i, coef) in coefs.iter().enumerate().skip(F_DEG) {
                    for j in 0..F_DEG {
                        res.coefs[j] += ZPoly::REDUCTION_TABLES.entry(i, j) * coef;
                    }
                }
                res
            }
        }

        impl ZPoly<$z> {
            /// a share for party i is G(encode(i)) where
            /// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
            /// a_i \in Z_{2^64}/F(X) = G; deg(F) = 8
            pub fn share<R: RngCore>(
                rng: &mut R,
                secret: $z,
                num_parties: usize,
                threshold: usize,
            ) -> anyhow::Result<ShamirGSharings<$z>> {
                let embedded_secret = ZPoly::from_scalar(secret);
                let poly = ShamirPolynomial::sample_random(rng, embedded_secret, threshold);
                let shares: Vec<_> = (1..num_parties + 1)
                    .map(|xi| {
                        let embedded_xi = embed(xi)?;
                        Ok((xi, poly.eval(&embedded_xi)))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;

                Ok(ShamirGSharings { shares })
            }

            pub fn bit_lift(x: GF256, pos: usize) -> anyhow::Result<ZPoly<$z>> {
                let c8: u8 = x.into();
                let shifted_coefs: Vec<_> = (0..F_DEG)
                    .map(|i| Wrapping(((c8 >> i) & 1) as $u) << pos)
                    .collect();
                ZPoly::<$z>::from_vec(shifted_coefs)
            }

            pub fn shamir_bit_lift(
                x: &ShamirZ2Poly,
                pos: usize,
            ) -> anyhow::Result<ShamirPolynomial<ZPoly<$z>>> {
                let coefs: Vec<ZPoly<$z>> = x
                    .coefs
                    .iter()
                    .map(|coef_2| Self::bit_lift(*coef_2, pos))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok(ShamirPolynomial { coefs })
            }

            pub fn decode(
                shares: &ShamirGSharings<$z>,
                threshold: usize,
                max_error_count: usize,
            ) -> anyhow::Result<ShamirPolynomial<ZPoly<$z>>> {
                // threshold is the degree of the shamir polynomial

                let ring_size: usize = <$z>::RING_SIZE;

                let mut y: Vec<_> = shares.shares.iter().map(|x| x.1).collect();
                let parties: Vec<_> = shares.shares.iter().map(|x| x.0).collect();
                let mut ring_polys = Vec::new();

                for bit_idx in 0..ring_size {
                    let z: Vec<ShamirZ2Sharing> = parties
                        .iter()
                        .zip(y.iter())
                        .map(|(party_id, sh)| ShamirZ2Sharing {
                            share: sh.bit_compose(bit_idx),
                            party_id: *party_id as u8,
                        })
                        .collect();

                    // apply error correction on z
                    // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
                    let fi_mod2 = error_correction(&z, threshold, max_error_count)?;
                    let fi = Self::shamir_bit_lift(&fi_mod2, bit_idx)?;

                    // compute fi(\gamma_1) ..., fi(\gamma_n) \in GF(256)
                    let ring_eval: Vec<ZPoly<$z>> = parties
                        .iter()
                        .map(|party_id| {
                            let embedded_xi: ZPoly<$z> = embed(*party_id)?;
                            Ok(fi.eval(&embedded_xi))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;

                    ring_polys.push(fi);

                    // remove LSBs computed from error correction in GF(256)
                    for (j, item) in y.iter_mut().enumerate() {
                        *item = *item - ring_eval[j];
                    }

                    // check that LSBs were removed correctly
                    let _errs: Vec<_> = y
                        .iter()
                        .map(|yj| {
                            // see if yj is divisible by 2^{i+1}
                            // different (and more expensive) check if we want to check divisibility by 2^{128} due to overflow
                            // bitwise operation to check that 2^{i+1} | yj
                            yj.multiple_pow2(bit_idx + 1)
                        })
                        .collect();
                }

                let result = ring_polys
                    .into_iter()
                    .fold(ShamirPolynomial::<ZPoly<$z>>::zero(), |acc, x| acc + x);
                Ok(result)
            }

            pub fn reconstruct(
                shares: &ShamirGSharings<$z>,
                threshold: usize,
            ) -> anyhow::Result<$z> {
                let recon = ZPoly::<$z>::decode(shares, threshold, 0)?;
                let f_zero = recon.eval(&ZPoly::ZERO);
                f_zero.to_scalar()
            }
        }

        impl Sample for $z {
            fn sample<R: RngCore>(rng: &mut R) -> Self {
                rng.gen::<$z>()
            }
        }

        impl Zero for $z {
            const ZERO: $z = Wrapping(0);
        }

        impl One for $z {
            const ONE: $z = Wrapping(1);
        }

        impl ZConsts for $z {
            const TWO: $z = Wrapping(2);
            const THREE: $z = Wrapping(3);
            const MAX: $z = Wrapping(<$u>::MAX);
        }

        impl Ring for $z {
            const RING_SIZE: usize = $l;
        }

        impl ReductionTable<$z> for ZPoly<$z> {
            const REDUCTION_TABLES: crate::ring_constants::ReductionTablesGF256<$z> =
                ReductionTablesGF256::<$z>::new();
        }
    };
}

impl_share_type!(Z128, u128, 128);
impl_share_type!(Z64, u64, 64);

/// embed party index to ZPoly
/// This is done by taking the bitwise representation of the index and map each bit to each coefficient
/// For eg, suppose x = sum(2^i * x_i); Then ZPoly = (x_0, ..., x_7) where x_i \in Z
pub fn embed<Z>(x: usize) -> anyhow::Result<ZPoly<Z>>
where
    Z: Zero + One,
{
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

    Ok(ZPoly { coefs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rstest::rstest;
    use std::num::Wrapping;

    #[test]
    fn test_is_zero() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let mut z128poly: ZPoly<Z128> = ZPoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z128poly.is_zero());
        z128poly = ZPoly::<Z128>::sample(&mut rng);
        assert!(!z128poly.is_zero());

        let mut z64poly: ZPoly<Z64> = ZPoly {
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
                let s: ZPoly<$z> = ZPoly {
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
                let mut s: ZPoly<$z> = ZPoly {
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
                let p1 = ZPoly {
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
                let p2 = ZPoly {
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
                let p1 = ZPoly {
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

                let p2 = ZPoly {
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
                let p1 = ZPoly::<$z>::ONE;
                let p2 = ZPoly::<$z>::ONE;
                let p3 = ZPoly::<$z>::ONE;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);


                // 0 x 1 = 0
                let p1 = ZPoly::<$z>::ZERO;
                let p2 = ZPoly::<$z>::ONE;
                let p3 = ZPoly::<$z>::ZERO;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);

                // rnd multiplication
                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let p0 = ZPoly::<$z>::ZERO;
                let prnd = ZPoly::<$z>::sample(& mut rng);
                let p1 = ZPoly::<$z>::ONE;

                assert_eq!(&p0 * &prnd, p0);
                assert_eq!(&p1 * &prnd, prnd);

                // all-1 mul by 1
                let p1 = ZPoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ZPoly {
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
                let p1 = ZPoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ZPoly::ZERO;
                assert_eq!(&p1 * &p2, p2);

                let p1 = ZPoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p2 = ZPoly {
                    coefs: [$z::ONE; F_DEG],
                };

                let p3 = ZPoly {
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

            #[test]
            fn [<test_ring_max_error_correction_ $z:lower>]() {
                let t: usize = 4;
                let max_err: usize = 3;
                let n = (t + 1) + 4 * max_err;

                let secret: $z = Wrapping(1000);
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let mut shares = ZPoly::<$z>::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct
                shares.shares[0].1 = ZPoly::sample(&mut rng);
                shares.shares[1].1 = ZPoly::sample(&mut rng);

                let recon = ZPoly::<$z>::decode(&shares, t, 1);
                let _ =
                    recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
            }

            #[test]
            fn [<test_arith_const_add2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let sharings = ZPoly::<$z>::share(&mut rng, Wrapping(23), 9, 5).unwrap();

                let sumsharing = &sharings + Wrapping(2);

                let recon = ZPoly::<$z>::reconstruct(&sumsharing, 5).unwrap();
                assert_eq!(recon, Wrapping(25));
            }

            #[test]
            fn [<test_arith_const_mul2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let sharings = ZPoly::<$z>::share(&mut rng, Wrapping(23), 9, 5).unwrap();

                let sumsharing = &sharings * Wrapping(2);

                let recon = ZPoly::<$z>::reconstruct(&sumsharing, 5).unwrap();
                assert_eq!(recon, Wrapping(46));
            }

            #[test]
            fn [<test_shamir_arithmetic_2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a: $z = Wrapping(23);
                let secret_b: $z = Wrapping(42);
                let secret_c: $z = Wrapping(29);

                let mut sharings_a = ZPoly::<$z>::share(&mut rng, secret_a, 9, 5).unwrap();
                let mut sharings_b = ZPoly::<$z>::share(&mut rng, secret_b, 9, 5).unwrap();
                let sharings_c = ZPoly::<$z>::share(&mut rng, secret_c, 9, 5).unwrap();

                sharings_a = &sharings_a + Wrapping(3);
                sharings_b = &sharings_b * Wrapping(3);

                // add the shares before reconstructing
                let mut sumsharing = sharings_a + sharings_b;

                sumsharing = &sumsharing - &sharings_c;

                let recon = ZPoly::<$z>::reconstruct(&sumsharing, 5).unwrap();
                assert_eq!(recon, Wrapping(123));
            }

            #[test]
            fn [<test_shamir_g_arithmetic_add_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a: $z = Wrapping(23);
                let secret_b: $z = Wrapping(42);

                let sharings_a = ZPoly::<$z>::share(&mut rng, secret_a, 9, 5).unwrap();
                let sharings_b = ZPoly::<$z>::share(&mut rng, secret_b, 9, 5).unwrap();

                let sumsharing = &sharings_a + &sharings_b;

                let recon = ZPoly::<$z>::reconstruct(&sumsharing, 5).unwrap();
                assert_eq!(recon, Wrapping(23 + 42));
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

                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let sharings = ZPoly::<$z>::share(&mut rng, secret, num_parties, threshold).unwrap();
                let recon = ZPoly::<$z>::reconstruct(&sharings, threshold).unwrap();
                assert_eq!(recon, secret);
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

                let mut rng = ChaCha12Rng::from_entropy();
                let sharings = ZPoly::<$z>::share(&mut rng, secret, num_parties, threshold).unwrap();
                let recon = ZPoly::<$z>::reconstruct(&sharings, threshold).unwrap();
                assert_eq!(recon, secret);
            }

            #[rstest]
            #[case(1, 1, Wrapping(100))]
            #[case(2, 0, Wrapping(100))]
            #[case(4, 1, Wrapping(100))]
            #[case(8, 10, Wrapping(100))]
            #[case(10, 8, Wrapping(100))]
            fn [<test_ring_error_correction_ $z:lower>](#[case] t: usize, #[case] max_err: usize, #[case] secret: $z) {
                let n = (t + 1) + 2 * max_err;

                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let mut sharings = ZPoly::<$z>::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct

                for item in sharings.shares.iter_mut().take(max_err) {
                    item.1 = ZPoly::sample(&mut rng);
                }

                let recon = ZPoly::<$z>::decode(&sharings, t, max_err);
                let f_zero = recon
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ZPoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
            }
            }
        };
    }
    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);
}
