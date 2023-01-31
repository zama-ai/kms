use std::iter::Sum;
use std::num::Wrapping;
use std::ops::{Add, Mul};

pub type Z64 = Wrapping<u64>;

pub const T: usize = 5; // Shamir reconstruction threshold
pub const N: usize = 9; // Number of Shamir parties
pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

pub struct ShamirSharing {
    pub share: Z64Poly,
}

/// Represents Z_{2^64}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8)
pub struct Z64Poly {
    coefs: [Z64; F_DEG],
}

pub trait Sample {
    fn sample() -> Self;
}

impl Sample for Z64 {
    fn sample() -> Self {
        todo!(); // DRAGOS
                 // 42
        Wrapping(5)
    }
}

impl Sample for Z64Poly {
    fn sample() -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        for i in 0..F_DEG {
            coefs[i] = Z64::sample();
        }
        Z64Poly { coefs }
    }
}

pub trait Zero {
    fn zero() -> Self;
}

impl Zero for Z64 {
    fn zero() -> Self {
        Wrapping(0_u64)
    }
}

impl Zero for Z64Poly {
    fn zero() -> Self {
        let coefs = [Z64::zero(); F_DEG];
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

impl Add<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn add(mut self, other: &Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] += &other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Mul<Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn mul(mut self, other: Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] *= other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Mul<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn mul(mut self, other: &Z64Poly) -> Self::Output {
        for i in 0..F_DEG {
            self.coefs[i] *= &other.coefs[i];
        }
        Z64Poly { coefs: self.coefs }
    }
}

impl Mul<&Z64Poly> for &Z64Poly {
    type Output = Z64Poly;
    fn mul(self, other: &Z64Poly) -> Self::Output {
        let mut coefs = self.coefs.clone();
        for i in 0..F_DEG {
            coefs[i] *= &other.coefs[i];
        }
        Z64Poly { coefs }
    }
}

pub struct ShamirPolynomial<R> {
    coefs: Vec<R>,
}

impl<R> ShamirPolynomial<R>
where
    R: Sample,
{
    pub fn sample_random(zero_coef: R, degree: usize) -> Self {
        let mut coefs: Vec<_> = (0..degree).map(|_| R::sample()).collect();
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

impl Z64Poly {
    pub fn from_scalar(x: Z64) -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        coefs[0] = x;
        Z64Poly { coefs }
    }

    pub fn to_scalar(self) -> Z64 {
        // TODO check that all other coefs are zero?
        self.coefs[0]
    }
}

pub fn share(secret: Z64) -> Vec<Z64Poly> {
    let embedded_secret = Z64Poly::from_scalar(secret);
    let poly = ShamirPolynomial::sample_random(embedded_secret, T);
    let shares: Vec<_> = (0..N)
        .map(|xi| {
            let embedded_xi: Z64Poly = todo!(); // TODO lifted from xi
            poly.eval(&embedded_xi)
        })
        .collect();
    shares
}

impl Sum<Z64Poly> for Z64Poly {
    fn sum<I: Iterator<Item = Z64Poly>>(iter: I) -> Self {
        let mut coefs = [Z64::zero(); F_DEG];
        for poly in iter {
            for i in 0..F_DEG {
                coefs[i] += poly.coefs[i];
            }
        }
        // implicit mod reduction on `coefs`
        Z64Poly { coefs }
    }
}

pub fn reconstruct(shares: &[ShamirSharing]) -> Z64 {
    let lagrange_constants: Vec<Z64Poly> = todo!(); // TODO precompute these
    assert_eq!(shares.len(), lagrange_constants.len());

    let embedded_secret: Z64Poly = shares
        .iter()
        .zip(lagrange_constants.iter())
        .map(|(share, lagrange)| &share.share * lagrange)
        .sum();

    let secret = embedded_secret.to_scalar();
    secret
}
