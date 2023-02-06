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
}

/// Precomputes reductions of x^8, x^9, ...x^14 to help us in reducing polynomials faster
pub struct ReductionTablesGF256 {
    pub reduced: Vec<Z64Poly>,
}

lazy_static! {
    pub static ref REDUCTION_TABLES: ReductionTablesGF256 = ReductionTablesGF256::new();
}

impl Default for ReductionTablesGF256 {
    fn default() -> Self {
        Self::new()
    }
}
impl ReductionTablesGF256 {
    pub fn new() -> Self {
        let mut tables = Vec::new();

        // x^8 = -1 - x - x^3 - x^4
        let x8 = {
            Z64Poly {
                coefs: [
                    -Z64::one(),
                    -Z64::one(),
                    Z64::zero(),
                    -Z64::one(),
                    -Z64::one(),
                    Z64::zero(),
                    Z64::zero(),
                    Z64::zero(),
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

/// embed party index to Z64Poly
/// This is done by taking the bitwise representation of the index and map each bit to each coefficient
/// For eg, suppose x = sum(2^i * x_i); Then Z64Poly = (x_0, ..., x_7) where x_i \in Z64
pub fn embed(x: usize) -> Z64Poly {
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
    Z64Poly {
        coefs: bits.try_into().unwrap(),
    }
}

/// a share for party i is G(encode(i)) where
/// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
/// a_i \in Z_{2^64}/F(X) = G; F(X) = GF(2^8)
pub fn share(secret: Z64) -> Vec<Z64Poly> {
    let embedded_secret = Z64Poly::from_scalar(secret);
    let poly = ShamirPolynomial::sample_random(embedded_secret, T);

    let shares: Vec<_> = (0..N)
        .map(|xi| {
            let embedded_xi: Z64Poly = embed(xi);
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
        let _sharings = share(secret);
    }

    #[test]
    fn test_arithmetic() {
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
        let mut p3 = p2.clone();
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
        let mut p3 = p2.clone();
        p3.mul_by_x();
        p3.mul_by_x();

        assert_eq!(&p1 * &p2, p3);

        // all-1 mul by 1
        let p1: Z64Poly = Z64Poly {
            coefs: [
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
            ],
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
            coefs: [
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
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
                Z64::zero(),
            ],
        };
        assert_eq!(&p1 * &p2, p2);

        let p1: Z64Poly = Z64Poly {
            coefs: [
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
            ],
        };

        let p2: Z64Poly = Z64Poly {
            coefs: [
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
                Z64::one(),
            ],
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
}
