use lazy_static::lazy_static;
use rand::Rng;
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
#[derive(Clone, Default, PartialEq, Debug)]
pub struct Z64Poly {
    coefs: [Z64; F_DEG],
}

impl Z64Poly {
    pub fn mul_by_x(&mut self) {
        let last = self.coefs[F_DEG - 1];
        for i in 1..F_DEG {
            self.coefs[i] = self.coefs[i - 1]
        }
        self.coefs[0] = Wrapping(0_u64);
        let x8 = Z64Poly {
            coefs: [
                -last,
                -last,
                Wrapping(0),
                -last,
                -last,
                Wrapping(0),
                Wrapping(0),
                Wrapping(0),
            ],
        };
        for i in 0..F_DEG {
            self.coefs[i] += x8.coefs[i];
        }
    }

    pub fn from_slice(coefs: [Wrapping<u64>; F_DEG]) -> Self {
        Z64Poly { coefs }
    }
}

/// Precomputes reductions of x^8, x^9, ...x^14 to help us in reducing polynomials faster
pub struct ReductionTablesGF256 {
    pub reduced: Vec<Z64Poly>,
}

lazy_static! {
    pub static ref REDUCTION_TABLES: ReductionTablesGF256 = ReductionTablesGF256::new();
}

impl ReductionTablesGF256 {
    pub fn new() -> Self {
        let mut tables = Vec::new();

        // x^8 = -1 - x - x^3 - x^4
        let x8 = {
            Z64Poly {
                coefs: [
                    -Wrapping(1_u64),
                    -Wrapping(1_u64),
                    Wrapping(0),
                    -Wrapping(1_u64),
                    -Wrapping(1_u64),
                    Wrapping(0),
                    Wrapping(0),
                    Wrapping(0),
                ],
            }
        };
        tables.push(x8);

        for i in 1..F_DEG {
            let mut last = tables[i - 1].clone();
            last.mul_by_x();
            tables.push(last);
        }
        Self { reduced: tables }
    }

    fn entry(&self, deg: usize, idx_coef: usize) -> &Wrapping<u64> {
        &self.reduced[deg - F_DEG].coefs[idx_coef]
    }
}

/// Represents an entry from F = x8 + x4 + x3 + x + 1
pub struct PolyPoint {
    point: u8,
}

pub trait Sample {
    fn sample() -> Self;
}

impl Sample for Z64 {
    fn sample() -> Self {
        // TODO(Dragos) we need to make this more efficient, grabbing rng from a mutable reference
        let mut rng = rand::thread_rng();
        Wrapping(rng.gen::<u64>())
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

fn reduce_with_tables(coefs: [Wrapping<u64>; 2 * (F_DEG - 1) + 1]) -> Z64Poly {
    let mut res = Z64Poly::from_slice(coefs[0..F_DEG].try_into().unwrap());
    for i in F_DEG..2 * (F_DEG - 1) + 1 {
        for j in 0..F_DEG {
            res.coefs[j] += REDUCTION_TABLES.entry(i, j) * &coefs[i];
        }
    }
    res
}

impl Mul<&Z64Poly> for Z64Poly {
    type Output = Z64Poly;
    fn mul(mut self, other: &Z64Poly) -> Self::Output {
        let mut extended_coefs = [Wrapping(0_u64); 2 * (F_DEG - 1) + 1];
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
        let mut extended_coefs = [Wrapping(0_u64); 2 * (F_DEG - 1) + 1];
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_share() {
        let secret: Z64 = std::num::Wrapping(42);
        let sharings = share(secret);
    }

    #[test]
    fn test_arithmetic() {
        let mut c1 = vec![Wrapping(0_u64); F_DEG];
        let mut c2 = vec![Wrapping(0_u64); F_DEG];

        c1[1] = Wrapping(1_u64);
        c2[F_DEG - 1] = Wrapping(1_u64);

        let p1: Z64Poly = Z64Poly::from_slice(c1[..].try_into().unwrap());
        let p2: Z64Poly = Z64Poly::from_slice(c2[..].try_into().unwrap());
        let mut p3 = p2.clone();
        p3.mul_by_x();

        assert_eq!(&p1 * &p2, p3);


        let mut c1 = vec![Wrapping(1_u64); F_DEG];
        let mut c2 = vec![Wrapping(1_u64); F_DEG];
        let p1: Z64Poly = Z64Poly::from_slice(c1[..].try_into().unwrap());
        let p2: Z64Poly = Z64Poly::from_slice(c2[..].try_into().unwrap());

        let c3 = [18446744073709551615_u64, 18446744073709551613, 18446744073709551612, 18446744073709551610, 18446744073709551609, 18446744073709551610, 18446744073709551612, 0];
        let c3 = c3.map(|x| Wrapping(x));
        let p3: Z64Poly = Z64Poly { coefs: c3 };
        assert_eq!(&p1 * &p2, p3);


    }
}
