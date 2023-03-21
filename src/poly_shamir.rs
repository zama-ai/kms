use crate::gf256::{error_correction, ShamirZ2Poly, ShamirZ2Sharing, GF256};
use crate::ring_constants::REDUCTION_TABLES;
use anyhow::anyhow;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::iter::Sum;
use std::num::Wrapping;
use std::ops::{Add, Mul, Sub};

pub type Z64 = Wrapping<u64>;
pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

/// a collection of shares
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum Value {
    Share64(Z64Poly),
    Ring64(Wrapping<u64>),
}

/// This data structure holds a collection of party_ids and their corresponding ShamirShares
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ShamirGSharings {
    pub shares: Vec<(usize, Z64Poly)>,
}

impl Add<ShamirGSharings> for ShamirGSharings {
    type Output = ShamirGSharings;
    fn add(self, rhs: ShamirGSharings) -> Self::Output {
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

impl<'l> Add<&'l ShamirGSharings> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn add(self, rhs: &'l ShamirGSharings) -> Self::Output {
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

impl<'l> Sub<&'l ShamirGSharings> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn sub(self, rhs: &'l ShamirGSharings) -> Self::Output {
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

impl<'l> Mul<&'l ShamirGSharings> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn mul(self, _rhs: &'l ShamirGSharings) -> Self::Output {
        // interactive secret-secret protocol needs to be implemented
        todo!();
    }
}

impl<'l> Mul<Z64> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn mul(self, rhs: Z64) -> Self::Output {
        ShamirGSharings {
            shares: self.shares.iter().map(|s| (s.0, s.1 * rhs)).collect(),
        }
    }
}

impl<'l> Add<Z64> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn add(self, rhs: Z64) -> Self::Output {
        ShamirGSharings {
            shares: self.shares.iter().map(|s| (s.0, s.1 + rhs)).collect(),
        }
    }
}

impl<'l> Mul<u64> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn mul(self, rhs: u64) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .map(|s| (s.0, s.1 * Wrapping(rhs)))
                .collect(),
        }
    }
}

impl<'l> Add<u64> for &'l ShamirGSharings {
    type Output = ShamirGSharings;
    fn add(self, rhs: u64) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .map(|s| (s.0, s.1 + Wrapping(rhs)))
                .collect(),
        }
    }
}

pub trait Sharing {
    fn share_from_z64<R: RngCore>(
        rng: &mut R,
        secret: Z64,
        num_parties: usize,
        threshold: usize,
    ) -> Self;

    fn reveal(&self, threshold: usize) -> Z64;
}

impl Sharing for ShamirGSharings {
    fn share_from_z64<R: RngCore>(
        rng: &mut R,
        secret: Z64,
        num_parties: usize,
        threshold: usize,
    ) -> ShamirGSharings {
        share(rng, secret, num_parties, threshold).unwrap()
    }

    fn reveal(&self, threshold: usize) -> Z64 {
        reconstruct(&self.clone(), threshold).unwrap()
    }
}

/// Represents an element Z_{2^64}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8).
/// This is also the 'value' of a single ShamirShare.
#[derive(Serialize, Deserialize, Clone, Copy, Default, PartialEq, Debug)]
pub struct Z64Poly {
    pub coefs: [Z64; F_DEG],
}

impl Z64Poly {
    pub fn mul_by_x(&mut self) {
        let last = self.coefs[F_DEG - 1];
        for i in (1..F_DEG).rev() {
            self.coefs[i] = self.coefs[i - 1]
        }

        self.coefs[0] = -last;
        self.coefs[1] -= last;
        self.coefs[3] -= last;
        self.coefs[4] -= last;
    }

    pub fn from_slice(coefs: [Wrapping<u64>; F_DEG]) -> Self {
        Z64Poly { coefs }
    }

    pub fn from_vec(coefs: Vec<Wrapping<u64>>) -> anyhow::Result<Self> {
        if coefs.len() != F_DEG {
            return Err(anyhow!(
                "Error: required {F_DEG} coefficients, but got {}",
                coefs.len()
            ));
        }
        Ok(Z64Poly {
            coefs: coefs
                .try_into()
                .map_err(|_| anyhow!("Error converting coefficient vector into Z64Poly"))?,
        })
    }

    pub fn at(&self, index: usize) -> &Z64 {
        &self.coefs[index]
    }

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
        assert!(exp <= 64);
        if exp == 64 {
            return self.is_zero();
        }
        let bit_checks: Vec<_> = self
            .coefs
            .iter()
            .filter_map(|c| {
                let bit = c & ((Z64::one() << exp) - Z64::one());
                match bit {
                    Wrapping(0_u64) => None,
                    _ => Some(bit),
                }
            })
            .collect();

        matches!(bit_checks.len(), 0)
    }

    pub fn is_zero(&self) -> bool {
        for c in self.coefs.iter() {
            if c != &Wrapping(0_u64) {
                return false;
            }
        }
        true
    }
}

/// Sample random element(s)
pub trait Sample {
    fn sample<R: RngCore>(rng: &mut R) -> Self;
}

impl Sample for Z64 {
    fn sample<R: RngCore>(rng: &mut R) -> Self {
        Wrapping(rng.next_u64())
    }
}

impl Sample for Z64Poly {
    fn sample<R: RngCore>(rng: &mut R) -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        for coef in coefs.iter_mut() {
            *coef = Z64::sample(rng);
        }
        Z64Poly { coefs }
    }
}

pub trait Zero {
    fn zero() -> Self;
}

impl Zero for Z64 {
    fn zero() -> Self {
        Wrapping(0)
    }
}

pub trait One {
    fn one() -> Self;
}

impl One for Z64 {
    fn one() -> Self {
        Wrapping(1)
    }
}

impl Zero for Z64Poly {
    fn zero() -> Self {
        let coefs = [Z64::zero(); F_DEG];
        Z64Poly { coefs }
    }
}

impl One for Z64Poly {
    fn one() -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        coefs[0] = Z64::one();
        Z64Poly { coefs }
    }
}

impl Add<Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn add(mut self, other: Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] += other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Sub<Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn sub(mut self, other: Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] -= other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Add<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn add(mut self, other: &Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] += &other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Sub<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn sub(mut self, other: &Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] -= &other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

fn reduce_with_tables(coefs: [Wrapping<u64>; 2 * (F_DEG - 1) + 1]) -> Z64Poly {
    let mut res = Z64Poly::from_slice(coefs[0..F_DEG].try_into().unwrap());
    for (i, coef) in coefs.iter().enumerate().skip(F_DEG) {
        for j in 0..F_DEG {
            res.coefs[j] += REDUCTION_TABLES.entry(i, j) * coef;
        }
    }
    res
}

impl Mul<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn mul(self, other: &Z64Poly) -> Self::Output {
        let mut extended_coefs = [Z64::zero(); 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        reduce_with_tables(extended_coefs)
    }
}

impl Mul<&Z64Poly> for &Z64Poly {
    type Output = Z64Poly;
    fn mul(self, other: &Z64Poly) -> Self::Output {
        let mut extended_coefs = [Z64::zero(); 2 * (F_DEG - 1) + 1];
        for i in 0..F_DEG {
            for j in 0..F_DEG {
                extended_coefs[i + j] += self.coefs[i] * other.coefs[j];
            }
        }
        reduce_with_tables(extended_coefs)
    }
}

impl Mul<Z64> for Z64Poly {
    type Output = Z64Poly;
    fn mul(self, other: Z64) -> Self::Output {
        Z64Poly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl Mul<Z64> for &Z64Poly {
    type Output = Z64Poly;
    fn mul(self, other: Z64) -> Self::Output {
        Z64Poly {
            coefs: self.coefs.map(|x| x * other),
        }
    }
}

impl Add<Z64> for Z64Poly {
    type Output = Z64Poly;
    fn add(mut self, other: Z64) -> Self::Output {
        // add const only to free term:
        self.coefs[0] += other;
        Z64Poly { coefs: self.coefs }
    }
}

impl Add<Z64> for &Z64Poly {
    type Output = Z64Poly;
    fn add(self, other: Z64) -> Self::Output {
        // add const only to free term:
        let mut coefs = self.coefs;
        coefs[0] += other;
        Z64Poly { coefs }
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
            if coefs != &R::zero() {
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
            coefs.push(R::zero());
        }
        ShamirPolynomial { coefs }
    }
}

impl<R> Zero for ShamirPolynomial<R>
where
    R: Zero,
{
    fn zero() -> Self {
        let coefs = vec![R::zero()];
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
        let mut res = R::zero();
        for coef in self.coefs.iter().rev() {
            res = res * point + coef;
        }
        res
    }
}

impl<'l, 'r> Mul<&'r Z64Poly> for &'l ShamirPolynomial<Z64Poly> {
    type Output = ShamirPolynomial<Z64Poly>;
    fn mul(self, other: &'r Z64Poly) -> ShamirPolynomial<Z64Poly> {
        let coefs: Vec<Z64Poly> = self.coefs.iter().map(|c| c * other).collect();
        ShamirPolynomial { coefs }
    }
}

impl<'l, 'r> Add<&'r ShamirPolynomial<Z64Poly>> for &'l ShamirPolynomial<Z64Poly>
where
    &'l Z64Poly: Add<&'r Z64Poly, Output = Z64Poly>,
{
    type Output = ShamirPolynomial<Z64Poly>;
    fn add(self, other: &'r ShamirPolynomial<Z64Poly>) -> Self::Output {
        assert_eq!(self.coefs.len(), other.coefs.len());
        let mut coefs = Vec::new();
        for i in 0..self.coefs.len() {
            coefs.push(self.coefs[i] + other.coefs[i]);
        }
        ShamirPolynomial { coefs }
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
            coefs.push(R::zero());
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

impl Z64Poly {
    pub fn from_scalar(x: Z64) -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        coefs[0] = x;
        Z64Poly { coefs }
    }

    pub fn to_scalar(self) -> anyhow::Result<Z64> {
        for i in 1..F_DEG {
            if self.coefs[i] != Z64::zero() {
                return Err(anyhow!(
                    "Higher coefficient must be zero but was {}",
                    self.coefs[i]
                ));
            }
        }
        Ok(self.coefs[0])
    }
}

/// embed party index to Z64Poly
/// This is done by taking the bitwise representation of the index and map each bit to each coefficient
/// For eg, suppose x = sum(2^i * x_i); Then Z64Poly = (x_0, ..., x_7) where x_i \in Z64
pub fn embed(x: usize) -> anyhow::Result<Z64Poly> {
    if x >= (1 << F_DEG) {
        return Err(anyhow!("Value {x} is too large to be embedded!"));
    }
    let bits: Vec<_> = (0..F_DEG)
        .map(|i| {
            let b = (x >> i) & 1;
            if b == 0 {
                Z64::zero()
            } else {
                Z64::one()
            }
        })
        .collect();

    let coefs: [Z64; F_DEG] = bits.as_slice().try_into()?;

    Ok(Z64Poly { coefs })
}

/// a share for party i is G(encode(i)) where
/// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
/// a_i \in Z_{2^64}/F(X) = G; deg(F) = 8
pub fn share<R: RngCore>(
    rng: &mut R,
    secret: Z64,
    num_parties: usize,
    threshold: usize,
) -> anyhow::Result<ShamirGSharings> {
    let embedded_secret = Z64Poly::from_scalar(secret);
    let poly = ShamirPolynomial::sample_random(rng, embedded_secret, threshold);
    let shares: Vec<_> = (1..num_parties + 1)
        .map(|xi| {
            let embedded_xi = embed(xi)?;
            Ok((xi, poly.eval(&embedded_xi)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(ShamirGSharings { shares })
}

impl Sum<Z64Poly> for Z64Poly {
    fn sum<I: Iterator<Item = Z64Poly>>(iter: I) -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        for poly in iter {
            for (i, coef) in coefs.iter_mut().enumerate() {
                *coef += poly.coefs[i];
            }
        }
        // implicit mod reduction on `coefs`
        Z64Poly { coefs }
    }
}

pub fn reconstruct(shares: &ShamirGSharings, threshold: usize) -> anyhow::Result<Z64> {
    let recon = decode(shares, threshold, 0)?;
    let f_zero = recon.eval(&Z64Poly::zero());
    f_zero.to_scalar()
}

fn bit_lift(x: GF256, pos: usize) -> anyhow::Result<Z64Poly> {
    let c8: u8 = x.into();
    let shifted_coefs: Vec<_> = (0..F_DEG)
        .map(|i| Wrapping(((c8 >> i) & 1) as u64) << pos)
        .collect();
    Z64Poly::from_vec(shifted_coefs)
}

fn shamir_bit_lift(x: &ShamirZ2Poly, pos: usize) -> anyhow::Result<ShamirPolynomial<Z64Poly>> {
    let coefs_64: Vec<Z64Poly> = x
        .coefs
        .iter()
        .map(|coef_2| bit_lift(*coef_2, pos))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(ShamirPolynomial { coefs: coefs_64 })
}

pub fn decode(
    shares: &ShamirGSharings,
    threshold: usize,
    max_error_count: usize,
) -> anyhow::Result<ShamirPolynomial<Z64Poly>> {
    // threshold is the degree of the shamir polynomial

    // TODO(Dragos) this should be a trait associated to ShamirSharing
    let ring_size: usize = 64;

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
        let fi = shamir_bit_lift(&fi_mod2, bit_idx)?;

        // compute fi(\gamma_1) ..., fi(\gamma_n) \in GF(256)
        let ring_eval: Vec<Z64Poly> = parties
            .iter()
            .map(|party_id| {
                let embedded_xi: Z64Poly = embed(*party_id)?;
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
                // different (and more expensive) check if we want to check divisibility by 2^{64} due to overflow
                // bitwise operation to check that 2^{i+1} | yj
                yj.multiple_pow2(bit_idx + 1)
            })
            .collect();
    }

    let result = ring_polys
        .into_iter()
        .fold(ShamirPolynomial::<Z64Poly>::zero(), |acc, x| acc + x);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rstest::rstest;
    use std::num::Wrapping;

    #[rstest]
    #[case(Wrapping(0))]
    #[case(Wrapping(1))]
    #[case(Wrapping(10))]
    #[case(Wrapping(3213214))]
    #[case(Wrapping(18446744073709551615))]
    #[case(Wrapping(18446744073702352342))]
    #[case(Wrapping(u64::MAX - 1))]
    #[case(Wrapping(u64::MAX))]
    #[case(Wrapping(rand::Rng::gen::<u64>(&mut rand::thread_rng())))]
    fn test_share_reconstruct(#[case] secret: Wrapping<u64>) {
        let threshold: usize = 5;
        let num_parties = 9;

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let sharings = share(&mut rng, secret, num_parties, threshold).unwrap();
        let recon = reconstruct(&sharings, threshold).unwrap();
        assert_eq!(recon, secret);
    }

    #[rstest]
    #[case(Wrapping(0))]
    #[case(Wrapping(1))]
    #[case(Wrapping(10))]
    #[case(Wrapping(3213214))]
    #[case(Wrapping(18446744073709551615))]
    #[case(Wrapping(18446744073702352342))]
    #[case(Wrapping(u64::MAX - 1))]
    #[case(Wrapping(u64::MAX))]
    #[case(Wrapping(rand::Rng::gen::<u64>(&mut rand::thread_rng())))]
    fn test_share_reconstruct_randomseed(#[case] secret: Wrapping<u64>) {
        let threshold: usize = 5;
        let num_parties = 9;

        let mut rng = ChaCha12Rng::from_entropy();
        let sharings = share(&mut rng, secret, num_parties, threshold).unwrap();
        let recon = reconstruct(&sharings, threshold).unwrap();
        assert_eq!(recon, secret);
    }

    #[rstest]
    #[case(1, 1, Wrapping(100))]
    #[case(2, 0, Wrapping(100))]
    #[case(4, 1, Wrapping(100))]
    #[case(8, 10, Wrapping(100))]
    #[case(13, 40, Wrapping(100))]
    fn test_ring_error_correction(
        #[case] t: usize,
        #[case] max_err: usize,
        #[case] secret: Wrapping<u64>,
    ) {
        let n = (t + 1) + 2 * max_err;

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let mut sharings = share(&mut rng, secret, n, t).unwrap();
        // t+1 to reconstruct a degree t polynomial
        // for each error we need to add in 2 honest shares to reconstruct

        for item in sharings.shares.iter_mut().take(max_err) {
            item.1 = Z64Poly::sample(&mut rng);
        }

        let recon = decode(&sharings, t, max_err);
        let f_zero = recon
            .expect("Unable to correct. Too many errors.")
            .eval(&Z64Poly::zero());
        assert_eq!(f_zero.to_scalar().unwrap(), secret);
    }

    #[test]
    fn test_ring_max_error_correction() {
        let t: usize = 4;
        let max_err: usize = 3;
        let n = (t + 1) + 4 * max_err;

        let secret: Wrapping<u64> = Wrapping(1000);
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let mut shares = share(&mut rng, secret, n, t).unwrap();
        // t+1 to reconstruct a degree t polynomial
        // for each error we need to add in 2 honest shares to reconstruct
        shares.shares[0].1 = Z64Poly::sample(&mut rng);
        shares.shares[1].1 = Z64Poly::sample(&mut rng);

        let recon = decode(&shares, t, 1);
        let _ =
            recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
    }

    #[test]
    fn test_bitwise_slice() {
        let s = Z64Poly {
            coefs: [
                Wrapping(310_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
            ],
        };
        let b = s.bit_compose(1);
        assert_eq!(b, GF256::from(255));
    }

    #[test]
    fn test_multiple_pow2() {
        let mut s = Z64Poly {
            coefs: [
                Wrapping(310_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
                Wrapping(210_u64),
            ],
        };

        assert!(s.multiple_pow2(0));
        assert!(s.multiple_pow2(1));
        assert!(!s.multiple_pow2(5));

        s.coefs[0] = Wrapping(7);
        assert!(s.multiple_pow2(0));
        assert!(!s.multiple_pow2(1));
        assert!(!s.multiple_pow2(5));

        s.coefs = [Wrapping(64_u64); F_DEG];
        assert!(s.multiple_pow2(0));
        assert!(s.multiple_pow2(1));
        assert!(s.multiple_pow2(5));
        assert!(s.multiple_pow2(6));
        assert!(!s.multiple_pow2(7));
        assert!(!s.multiple_pow2(23));
    }

    #[test]
    fn test_z64_arithmetic() {
        let p1: Z64Poly = Z64Poly {
            coefs: [
                Z64::zero(),
                Z64::one(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
            ],
        };
        let p2: Z64Poly = Z64Poly {
            coefs: [
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::one(),
            ],
        };
        let mut p3 = p2;
        p3.mul_by_x();

        assert_eq!(&p1 * &p2, p3);

        // mul by x twice
        let p1: Z64Poly = Z64Poly {
            coefs: [
                Z64::zero(),
                Z64::zero(),
                Z64::one(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
            ],
        };

        let p2: Z64Poly = Z64Poly {
            coefs: [
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::one(),
            ],
        };
        let mut p3 = p2;
        p3.mul_by_x();
        p3.mul_by_x();

        assert_eq!(&p1 * &p2, p3);

        // all-1 mul by 1
        let p1: Z64Poly = Z64Poly {
            coefs: [Z64::one(); F_DEG],
        };

        let p2: Z64Poly = Z64Poly {
            coefs: [
                Z64::one(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
                Z64::zero(),
            ],
        };
        assert_eq!(&p1 * &p2, p1);

        // mul by zero = all-zero
        let p1: Z64Poly = Z64Poly {
            coefs: [Z64::one(); F_DEG],
        };

        let p2: Z64Poly = Z64Poly::zero();
        assert_eq!(&p1 * &p2, p2);

        let p1: Z64Poly = Z64Poly {
            coefs: [Z64::one(); F_DEG],
        };

        let p2: Z64Poly = Z64Poly {
            coefs: [Z64::one(); F_DEG],
        };

        let p3: Z64Poly = Z64Poly {
            coefs: [
                Wrapping(18446744073709551615_u64),
                Wrapping(18446744073709551613),
                Wrapping(18446744073709551612),
                Wrapping(18446744073709551610),
                Wrapping(18446744073709551609),
                Wrapping(18446744073709551610),
                Wrapping(18446744073709551612),
                Z64::zero(),
            ],
        };
        assert_eq!(&p1 * &p2, p3);
    }

    #[test]
    fn test_arith_const_add2() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let sharings = share(&mut rng, Wrapping(23), 9, 5).unwrap();

        let sumsharing = &sharings + Wrapping(2);

        let recon = reconstruct(&sumsharing, 5).unwrap();
        assert_eq!(recon, Wrapping(25));
    }

    #[test]
    fn test_arith_const_mul2() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let sharings = share(&mut rng, Wrapping(23), 9, 5).unwrap();

        let sumsharing = &sharings * Wrapping(2);

        let recon = reconstruct(&sumsharing, 5).unwrap();
        assert_eq!(recon, Wrapping(46));
    }

    #[test]
    fn test_shamir_z64_arithmetic_2() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let secret_a: Z64 = Wrapping(23);
        let secret_b: Z64 = Wrapping(42);
        let secret_c: Z64 = Wrapping(29);

        let mut sharings_a = share(&mut rng, secret_a, 9, 5).unwrap();
        let mut sharings_b = share(&mut rng, secret_b, 9, 5).unwrap();
        let sharings_c = share(&mut rng, secret_c, 9, 5).unwrap();

        sharings_a = &sharings_a + Wrapping(3);
        sharings_b = &sharings_b * Wrapping(3);

        // add the shares before reconstructing
        let mut sumsharing = sharings_a + sharings_b;

        sumsharing = &sumsharing - &sharings_c;

        let recon = reconstruct(&sumsharing, 5).unwrap();
        assert_eq!(recon, Wrapping(123));
    }

    #[test]
    fn test_shamir_g_arithmetic_add() {
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let secret_a: Z64 = Wrapping(23);
        let secret_b: Z64 = Wrapping(42);

        let sharings_a = share(&mut rng, secret_a, 9, 5).unwrap();
        let sharings_b = share(&mut rng, secret_b, 9, 5).unwrap();

        let sumsharing = &sharings_a + &sharings_b;

        let recon = reconstruct(&sumsharing, 5).unwrap();
        assert_eq!(recon, Wrapping(23 + 42));
    }
}
