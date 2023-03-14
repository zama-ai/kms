use std::iter::Sum;
use std::num::Wrapping;
use std::ops::{Add, Mul, Sub};

use crate::gf256::{error_correction, GF256};
use crate::gf256::{ShamirZ2Poly, ShamirZ2Sharing};
use crate::ring_constants::REDUCTION_TABLES;

use rand::RngCore;

pub type Z64 = Wrapping<u64>;
pub const F_DEG: usize = 8; // degree of irreducible polynomial F = x8 + x4 + x3 + x + 1

#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct ShamirSharing {
    pub share: Z64Poly,
}

/// Represents Z_{2^64}[X]/F with implicit F = x8 + x4 + x3 + x + 1
///
/// Comes with fixed evaluation points lifted from GF(2^8)
#[derive(Clone, Copy, Default, PartialEq, Debug)]
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

    pub fn from_vec(coefs: Vec<Wrapping<u64>>) -> Self {
        assert_eq!(coefs.len(), 8);
        Z64Poly {
            coefs: coefs.try_into().unwrap(),
        }
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

impl Sub<ShamirSharing> for ShamirSharing {
    type Output = ShamirSharing;
    fn sub(self, other: ShamirSharing) -> Self::Output {
        ShamirSharing {
            share: self.share - other.share,
        }
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
pub fn embed(x: usize) -> Result<Z64Poly, anyhow::Error> {
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
) -> Result<Vec<Z64Poly>, anyhow::Error> {
    let embedded_secret = Z64Poly::from_scalar(secret);
    let poly = ShamirPolynomial::sample_random(rng, embedded_secret, threshold);
    let shares: Vec<Z64Poly> = (0..num_parties + 1)
        .map(|xi| {
            let embedded_xi = embed(xi)?;
            Ok(poly.eval(&embedded_xi))
        })
        .collect::<Result<Vec<_>, anyhow::Error>>()?;
    Ok(shares)
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

pub fn reconstruct(
    shares: &[(usize, ShamirSharing)],
    threshold: usize,
) -> Result<Z64, anyhow::Error> {
    let recon = decode(shares, threshold, 0)?;
    let f_zero = recon.eval(&Z64Poly::zero());
    Ok(f_zero.to_scalar())
}

fn bit_lift(x: GF256, pos: usize) -> Z64Poly {
    let c8: u8 = x.into();
    let shifted_coefs: Vec<_> = (0..F_DEG)
        .map(|i| Wrapping(((c8 >> i) & 1) as u64) << pos)
        .collect();
    Z64Poly::from_vec(shifted_coefs)
}

fn shamir_bit_lift(x: &ShamirZ2Poly, pos: usize) -> ShamirPolynomial<Z64Poly> {
    let coefs_64: Vec<Z64Poly> = x
        .coefs
        .iter()
        .map(|coef_2| bit_lift(*coef_2, pos))
        .collect();
    ShamirPolynomial { coefs: coefs_64 }
}

pub fn decode(
    shares: &[(usize, ShamirSharing)],
    threshold: usize,
    max_error_count: usize,
) -> Result<ShamirPolynomial<Z64Poly>, anyhow::Error> {
    // threshold is the degree of the shamir polynomial

    // TODO(Dragos) this should be a trait associated to ShamirSharing
    let ring_size: usize = 64;

    let mut y: Vec<_> = shares.iter().map(|(_, sharing)| *sharing).collect();
    let parties: Vec<_> = shares.iter().map(|(party_id, _)| *party_id).collect();

    let mut ring_polys = Vec::new();

    for bit_idx in 0..ring_size {
        let z: Vec<ShamirZ2Sharing> = parties
            .iter()
            .zip(y.iter())
            .map(|(party_id, sh)| ShamirZ2Sharing {
                share: sh.share.bit_compose(bit_idx),
                party_id: *party_id as u8,
            })
            .collect();

        // apply error correction on z
        // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
        let fi_mod2 = error_correction(&z, threshold, max_error_count)?;
        let fi = shamir_bit_lift(&fi_mod2, bit_idx);

        // compute fi(\gamma_1) ..., fi(\gamma_n) \in GF(256)
        let ring_eval: Vec<Z64Poly> = parties
            .iter()
            .map(|party_id| {
                let embedded_xi: Z64Poly = embed(*party_id)?;
                Ok(fi.eval(&embedded_xi))
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        ring_polys.push(fi);

        // remove LSBs computed from error correction in GF(256)
        for (j, item) in y.iter_mut().enumerate() {
            *item = *item
                - ShamirSharing {
                    share: ring_eval[j],
                }
        }

        // check that LSBs were removed correctly
        let _errs: Vec<_> = y
            .iter()
            .map(|yj| {
                // see if yj is divisible by 2^{i+1}
                // different (and more expensive) check if we want to check divisibility by 2^{64} due to overflow
                // bitwise operation to check that 2^{i+1} | yj
                yj.share.multiple_pow2(bit_idx + 1)
            })
            .collect();
        // println!("errs: {:?}", _errs);
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
    fn test_share(#[case] secret: Wrapping<u64>) {
        let threshold: usize = 5;
        let num_parties = 9;

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let sharings = share(&mut rng, secret, num_parties, threshold).unwrap();
        let recon_data: Vec<(usize, ShamirSharing)> = (1..num_parties + 1)
            .map(|party_id| {
                (
                    party_id,
                    ShamirSharing {
                        share: sharings[party_id],
                    },
                )
            })
            .collect();
        let recon = reconstruct(&recon_data, threshold).unwrap();
        assert_eq!(recon, secret);
    }

    #[rstest]
    #[case(1, 1, Wrapping(100))]
    #[case(2, 0, Wrapping(100))]
    #[case(8, 10, Wrapping(100))]
    fn test_ring_error_correction(
        #[case] t: usize,
        #[case] max_err: usize,
        #[case] secret: Wrapping<u64>,
    ) {
        let n = (t + 1) + 2 * max_err;

        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let sharings = share(&mut rng, secret, n, t).unwrap();
        // t+1 to reconstruct a degree t polynomial
        // for each error we need to add in 2 honest shares to reconstruct
        let mut shares: Vec<(usize, ShamirSharing)> = (1..n + 1)
            .map(|party_id| {
                (
                    party_id,
                    ShamirSharing {
                        share: sharings[party_id],
                    },
                )
            })
            .collect();

        for item in shares.iter_mut().take(max_err) {
            item.1.share = Z64Poly::sample(&mut rng);
        }

        let recon = decode(&shares, t, max_err);
        let f_zero = recon
            .expect("Unable to correct. Too many errors.")
            .eval(&Z64Poly::zero());
        assert_eq!(f_zero.to_scalar(), secret);
    }

    #[test]
    fn test_ring_max_error_correction() {
        let t: usize = 4;
        let max_err: usize = 3;
        let n = (t + 1) + 4 * max_err;

        let secret: Wrapping<u64> = Wrapping(1000);
        let mut rng = ChaCha12Rng::seed_from_u64(0);

        let sharings = share(&mut rng, secret, n, t).unwrap();
        // t+1 to reconstruct a degree t polynomial
        // for each error we need to add in 2 honest shares to reconstruct
        let mut shares: Vec<(usize, ShamirSharing)> = (1..n + 1)
            .map(|party_id| {
                (
                    party_id,
                    ShamirSharing {
                        share: sharings[party_id],
                    },
                )
            })
            .collect();

        shares[0].1.share = Z64Poly::sample(&mut rng);
        shares[1].1.share = Z64Poly::sample(&mut rng);

        let recon = decode(&shares, t, 1);
        let _ =
            recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
    }

    #[test]
    fn test_bitwise_slice() {
        let s = ShamirSharing {
            share: Z64Poly {
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
            },
        };
        let b = s.share.bit_compose(1);
        assert_eq!(b, GF256::from(255));
    }

    #[test]
    fn test_multiple_pow2() {
        let mut s = ShamirSharing {
            share: Z64Poly {
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
            },
        };

        assert!(s.share.multiple_pow2(0));
        assert!(s.share.multiple_pow2(1));
        assert!(!s.share.multiple_pow2(5));

        s.share.coefs[0] = Wrapping(7);
        assert!(s.share.multiple_pow2(0));
        assert!(!s.share.multiple_pow2(1));
        assert!(!s.share.multiple_pow2(5));

        s.share.coefs = [Wrapping(64_u64); F_DEG];
        assert!(s.share.multiple_pow2(0));
        assert!(s.share.multiple_pow2(1));
        assert!(s.share.multiple_pow2(5));
        assert!(s.share.multiple_pow2(6));
        assert!(!s.share.multiple_pow2(7));
        assert!(!s.share.multiple_pow2(23));
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
