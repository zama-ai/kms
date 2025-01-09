use super::{
    galois_fields::{gf16::GF16, gf256::GF256},
    galois_rings::common::{LutMulReduction, ResiduePoly},
    structure_traits::{Field, Invert, One, Ring, RingEmbed, Sample, Zero},
};
use crate::error::error_handler::anyhow_error_and_log;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

/// Generic polynomial struct
#[derive(Serialize, Deserialize, Hash, Clone, Default, Debug)]
pub struct Poly<F> {
    pub coefs: Vec<F>,
}

/// Polynomial struct where all coefficients are bit-strings.
/// We use this as a helper to optimize the reconstruction algorithms
/// where we need to lift binary polynomials into the full ring domain.
#[derive(Serialize, Deserialize, Hash, Clone, Default, Debug)]
pub struct BitwisePoly {
    pub coefs: Vec<u8>,
}

impl From<Poly<GF256>> for BitwisePoly {
    fn from(poly: Poly<GF256>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<GF16>> for BitwisePoly {
    fn from(poly: Poly<GF16>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

pub trait BitWiseEval<Z, const EXTENSION_DEGREE: usize>
where
    Z: Zero + for<'a> AddAssign<&'a Z> + Copy + Clone,
    ResiduePoly<Z, EXTENSION_DEGREE>: LutMulReduction<Z>,
{
    fn lazy_eval(
        &self,
        powers: &[ResiduePoly<Z, EXTENSION_DEGREE>],
    ) -> ResiduePoly<Z, EXTENSION_DEGREE>;
}

impl<Z> Poly<Z>
where
    Z: Ring,
    Z: RingEmbed,
    Z: Invert,
{
    ///Outputs a vector of the monomials (X - embed(party_id))/(party_id)
    /// for all party_id in \[num_parties\]
    /// as well as the vector of party's points
    ///
    /// **NOTE: THE VECTOR IS ZERO INDEXED**
    pub fn normalized_parties_root(num_parties: usize) -> anyhow::Result<(Vec<Self>, Vec<Z>)> {
        // compute lifted, negated and inverted gamma values once, i.e. Lagrange coefficients
        //TODO: This could be memoized
        let mut inv_coefs = (1..=num_parties)
            .map(|idx| {
                let gamma = Z::embed_exceptional_set(idx)?;
                Z::invert(Z::ZERO - gamma)
            })
            .collect::<Result<Vec<_>, _>>()?;
        inv_coefs.insert(0, Z::ZERO);

        // embed party IDs as invertible x-points on the polynomial
        //TODO: This could be memoized
        let x_coords: Vec<_> = (0..=num_parties)
            .map(Z::embed_exceptional_set)
            .collect::<Result<Vec<_>, _>>()?;

        // compute additive inverse of embedded party IDs
        //TODO: This could be memoized
        let neg_parties: Vec<_> = (0..=num_parties)
            .map(|p| Self::from_coefs(vec![Z::ZERO - x_coords[p]]))
            .collect::<Vec<_>>();

        // make a polynomial F(X)=X
        let x = Self::from_coefs(vec![Z::ZERO, Z::ONE]);
        let mut res = Vec::<Self>::with_capacity(num_parties);
        for p in 1..=num_parties {
            res.push((x.clone() + neg_parties[p].clone()) * Self::from_coefs(vec![inv_coefs[p]]))
        }
        Ok((res, x_coords))
    }
}

impl<R> Poly<R> {
    pub fn from_coefs(coefs: Vec<R>) -> Self {
        Poly { coefs }
    }
}

impl<R: PartialEq + Zero> PartialEq for Poly<R> {
    fn eq(&self, other: &Self) -> bool {
        let common_len = usize::min(self.coefs.len(), other.coefs.len());
        for i in 0..common_len {
            if self.coefs[i] != other.coefs[i] {
                return false;
            }
        }
        let longest = if self.coefs.len() >= other.coefs.len() {
            &self.coefs
        } else {
            &other.coefs
        };
        for coef in longest.iter().skip(common_len) {
            if coef != &R::ZERO {
                return false;
            }
        }
        true
    }
}

impl<R: Eq + Zero> Eq for Poly<R> {}

impl<F> Poly<F>
where
    F: Zero,
    F: Copy,
    F: Mul<F, Output = F>,
    F: Add<F, Output = F>,
{
    /// evaluate the polynomial at a given point
    pub fn eval(&self, point: &F) -> F {
        let mut res = F::ZERO;
        for coef in self.coefs.iter().rev() {
            res = res * *point + *coef;
        }
        res
    }
}

impl<F> Poly<F>
where
    F: Zero,
    F: PartialEq,
    F: Copy,
{
    /// the degree of the polynomial, i.e., the highest exponent of the variable whose coefficient is not zero.
    pub fn deg(&self) -> usize {
        for (i, item) in self.coefs.iter().enumerate().rev() {
            if item != &F::ZERO {
                return i;
            }
        }
        0
    }

    /// check if poly is all-zero
    pub fn is_zero(&self) -> bool {
        for c in self.coefs.iter() {
            if c != &F::ZERO {
                return false;
            }
        }
        true
    }

    /// return a poly that is constant zero
    pub fn zero() -> Self {
        Poly {
            coefs: vec![F::ZERO],
        }
    }

    /// return a poly that is constant zero and has n zero coefficients
    pub fn zeros(n: usize) -> Self {
        Poly {
            coefs: vec![F::ZERO; n],
        }
    }

    /// return the highest non-zero coefficient, or zero else
    fn highest_coefficient(&self) -> F {
        for c in self.coefs.iter().rev() {
            if c != &F::ZERO {
                return *c;
            }
        }
        F::ZERO
    }

    /// remove zero-coefficients from the highest degree variables
    fn compress(&mut self) {
        while let Some(c) = self.coefs.last() {
            if c == &F::ZERO {
                self.coefs.pop();
            } else {
                break;
            }
        }
    }
}

impl<F: Field> Poly<F> {
    pub fn formal_derivative(&self) -> Self {
        if self.deg() > 0 {
            let mut coefs = self.coefs[1..].to_vec();
            let mut mul = F::ONE;
            for c in &mut coefs {
                *c *= mul;
                mul += F::ONE;
            }
            return Poly { coefs };
        }
        Poly {
            coefs: vec![F::ZERO],
        }
    }
}

impl<F> Poly<F>
where
    F: One,
{
    pub fn one() -> Self {
        Poly {
            coefs: vec![F::ONE],
        }
    }
}

impl<F> Poly<F>
where
    F: Sample,
    F: Zero + One,
{
    /// sample a random poly of given degree with `zero_coef` as fixed value for the constant term
    pub fn sample_random_with_fixed_constant<U: Rng + CryptoRng>(
        rng: &mut U,
        zero_coef: F,
        degree: usize,
    ) -> Self {
        let mut coefs: Vec<_> = (0..degree).map(|_| F::sample(rng)).collect();
        coefs.insert(0, zero_coef);
        Poly { coefs }
    }
}

impl<R: Ring> Add<&Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn add(self, other: &Poly<R>) -> Self::Output {
        let max_len = usize::max(self.coefs.len(), other.coefs.len());
        let mut res = Poly::zeros(max_len);
        for i in 0..max_len {
            if i < self.coefs.len() {
                res.coefs[i] += self.coefs[i];
            }
            if i < other.coefs.len() {
                res.coefs[i] += other.coefs[i];
            }
        }
        res.compress();
        res
    }
}

impl<F> Add<Poly<F>> for Poly<F>
where
    F: Add<F, Output = F>,
    F: PartialEq,
    F: Copy,
    F: Zero,
{
    type Output = Poly<F>;
    fn add(self, other: Poly<F>) -> Self::Output {
        let (mut longest, shortest) = if self.coefs.len() >= other.coefs.len() {
            (self, other)
        } else {
            (other, self)
        };
        for i in 0..shortest.coefs.len() {
            longest.coefs[i] = longest.coefs[i] + shortest.coefs[i];
        }
        longest.compress();
        longest
    }
}

impl<F> Sub<Poly<F>> for Poly<F>
where
    F: Copy,
    F: Zero,
    F: SubAssign,
    F: PartialEq,
{
    type Output = Poly<F>;
    fn sub(self, other: Poly<F>) -> Self::Output {
        let mut res = Poly::<F>::zeros(std::cmp::max(self.coefs.len(), other.coefs.len()));
        for (idx, coef) in self.coefs.iter().enumerate() {
            res.coefs[idx] = *coef;
        }
        for (idx, coef) in other.coefs.iter().enumerate() {
            res.coefs[idx] -= *coef;
        }
        res.compress();
        res
    }
}

impl<R: Ring> Mul<Poly<R>> for Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: Poly<R>) -> Self::Output {
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<&Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: &Poly<R>) -> Self::Output {
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: Poly<R>) -> Self::Output {
        // TODO we could reuse other
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<&R> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: &R) -> Self::Output {
        let mut res = Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            res.coefs[i] = *xi * *other;
        }
        res.compress();
        res
    }
}

impl<R: Ring> Mul<&R> for Poly<R> {
    type Output = Poly<R>;
    fn mul(mut self, other: &R) -> Self::Output {
        for i in 0..self.coefs.len() {
            self.coefs[i] *= *other;
        }
        self
    }
}

impl<F: Field> Div<&F> for &Poly<F> {
    type Output = Poly<F>;
    fn div(self, other: &F) -> Self::Output {
        let mut res = Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            res.coefs[i] = *xi / *other;
        }
        res.compress();
        res
    }
}

impl<F: Field> Div<&F> for Poly<F> {
    type Output = Poly<F>;
    fn div(mut self, other: &F) -> Self::Output {
        for i in 0..self.coefs.len() {
            self.coefs[i] /= *other;
        }
        self
    }
}

impl<F: Field> Div<&Poly<F>> for &Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: &Poly<F>) -> Self::Output {
        quo_rem(self.clone(), other)
    }
}

impl<F: Field> Div<Poly<F>> for Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: Poly<F>) -> Self::Output {
        quo_rem(self, &other)
    }
}

impl<F: Field> Div<&Poly<F>> for Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: &Poly<F>) -> Self::Output {
        quo_rem(self, other)
    }
}

/// computes quotient `q` and remainder `r` for dividing `a / b`, s.t. `a = q*b + r`
fn quo_rem<F: Field>(a: Poly<F>, b: &Poly<F>) -> (Poly<F>, Poly<F>) {
    let a_len = a.coefs.len();
    let b_len = b.coefs.len();

    let t = b.highest_coefficient().invert();

    let mut q = Poly::zeros(a.coefs.len());
    let mut r = a;

    if a_len >= b_len {
        for i in (0..=(a_len - b_len)).rev() {
            q.coefs[i] = r.coefs[i + b_len - 1] * t;
            for j in 0..b_len {
                r.coefs[i + j] -= q.coefs[i] * b.coefs[j];
            }
        }
    }
    q.compress();
    r.compress();
    (q, r)
}

/// compute Lagrange polynomials for the given list of points
pub fn lagrange_polynomials<F: Field>(points: &[F]) -> Vec<Poly<F>> {
    let polys: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(i, xi)| {
            let mut numerator = Poly {
                coefs: vec![F::ONE, F::ZERO],
            };
            let mut denominator = F::ONE;
            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    numerator = numerator
                        * Poly {
                            coefs: vec![-*xj, F::ONE],
                        };
                    denominator *= *xi - *xj;
                }
            }
            numerator / &denominator
        })
        .collect();
    polys
}

/// interpolate a polynomial through coordinates where points holds the x-coordinates and values holds the y-coordinates
pub fn lagrange_interpolation<F: Field>(points: &[F], values: &[F]) -> anyhow::Result<Poly<F>> {
    let ls = F::memoize_lagrange(points)?;
    assert_eq!(ls.len(), values.len());
    let mut res = Poly::zero();
    for (li, vi) in ls.into_iter().zip(values.iter()) {
        let term = li * vi;
        res = res + term;
    }
    Ok(res)
}

/// computes the extended Euclidean algorithm for a and b and stops when r1 reaches the stop degree or higher
fn partial_xgcd<F: Field>(a: Poly<F>, b: Poly<F>, stop: usize) -> (Poly<F>, Poly<F>) {
    let (mut r0, mut r1) = (a, b);
    let (mut t0, mut t1) = (Poly::zero(), Poly::one());
    // r = gcd(a, b) = a * s + b * t
    // note that s is not computed here
    while r1.deg() >= stop {
        let (q, _) = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 - (&q * r1));
        (t0, t1) = (t1.clone(), t0 - (&q * t1));
    }
    // return r and t
    (r1, t1)
}

//NIST: Level Zero Operation
/// Runs Gao decoding algorithm.
///
/// - `points` holds the x-coordinates
/// - `values` holds the y-coordinates
/// - `k` such that we apply error correction to a polynomial of degree < k
///   (usually degree = threshold in our scheme, but it can be 2*threshold in some cases)
/// - `max_errs` is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is 2*threshold)
///
/// __NOTE__ : We assume values already identified as errors have been excluded by the caller (i.e. values denoted Bot in NIST doc)
pub fn gao_decoding<F: Field>(
    points: &[F],
    values: &[F],
    k: usize,
    max_errs: usize,
) -> anyhow::Result<Poly<F>> {
    // in the literature we find (n, k, d) codes
    // parameter k is called v in the NIST doc (the RS dimension)
    // this means that n is the number of points xi for which we have some values yi
    // yi ~= G(xi))
    // where deg(G) <= k-1
    let n = points.len();

    // d = n-k+1
    let d = (n + 1)
        .checked_sub(k)
        .ok_or_else(|| anyhow_error_and_log("Gao decoding failure: overflow computing d"))?;

    // sanity checks for parameter sizes
    if values.len() != points.len() {
        return Err(anyhow_error_and_log(
            "Gao decoding failure: mismatch between number of values and points".to_string(),
        ));
    }

    // We are expecting to correct more than what can be done
    // Gao can only correct up to (d-1)/2 errors
    if 2 * max_errs >= d {
        return Err(anyhow_error_and_log(
            "Gao decoding failure: expected max number of errors is too large for given code parameters".to_string(),
        ));
    }

    // R \in GF(256)[X] such that R(xi) = yi. Called g_1(x) in the Gao paper.
    let r = lagrange_interpolation(points, values)?;

    // G = prod(X - xi) where xi is party i's index. Called g_0(x) in the Gao paper.
    // note that deg(G) >= deg(R)
    let mut g = Poly::one();
    for xi in points.iter() {
        let fi = Poly {
            coefs: vec![-*xi, F::ONE],
        };
        g = g * fi;
    }

    // apply EEA to compute q0, q1 such that
    // q1 = gcd(g, r) = g * t + r * q0
    // q1 | g, q1 | r
    // q1 and q0 are called g(x) and v(x), respectively in the Gao paper.
    // q0 = v(x) is the error locator polynomial. Its roots are the error positions xi.
    let gcd_stop = (n + k) / 2;
    let (q1, q0) = partial_xgcd(g, r, gcd_stop);

    // abort early if we have too many errors
    if q0.deg() > max_errs {
        return Err(anyhow_error_and_log(
            format!("Gao decoding failure: Allowed at most {max_errs} errors but xgcd factor degree indicates {}.", q0.deg())
        ));
    }

    // h is called f_1(x) in the Gao paper.
    let (h, rem) = q1 / &q0;

    if !rem.is_zero() {
        Err(anyhow_error_and_log(format!(
            "Gao decoding failure: Division remainder is not zero but {:?}.",
            rem
        )))
    } else if h.deg() >= k {
        Err(anyhow_error_and_log(format!("Gao decoding failure: Division result is of too high degree {}, but should be at most {}.", h.deg(), k-1)))
    } else {
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::error_correction::MemoizedExceptionals;
    use crate::algebra::galois_fields::gf256::GF256;
    use crate::algebra::galois_rings::degree_8::ResiduePolyF8Z128;
    use proptest::prelude::*;
    use rstest::rstest;

    #[test]
    fn test_lagrange_mod2() {
        let poly = Poly {
            coefs: vec![
                GF256::from(11),
                GF256::from(2),
                GF256::from(3),
                GF256::from(22),
                GF256::from(9),
            ],
        };
        let xs = vec![
            GF256::from(0),
            GF256::from(21),
            GF256::from(30),
            GF256::from(40),
            GF256::from(42),
        ];

        // we need at least degree + 1 points to interpolate
        assert!(xs.len() > poly.deg());

        let ys: Vec<_> = xs.iter().map(|x| poly.eval(x)).collect();
        let interpolated = lagrange_interpolation(&xs, &ys);
        assert_eq!(poly, interpolated.unwrap());
    }

    #[rstest]
    #[case(vec![GF256::from(7),
                GF256::from(4),
                GF256::from(5),
                GF256::from(4)],
            vec![GF256::from(1), GF256::from(0), GF256::from(1)],
    )]
    #[case(vec![GF256::from(255), GF256::from(123)],
        vec![GF256::from(1)])]
    fn test_poly_divmod(#[case] coefs_a: Vec<GF256>, #[case] coefs_b: Vec<GF256>) {
        let a = Poly { coefs: coefs_a };
        let b = Poly { coefs: coefs_b };

        let (q, r) = a.clone() / b.clone();

        assert_eq!(q * b + r, a);
    }

    proptest! {
        #[test]
        fn test_fuzzy_divmod((coefs_a, coefs_b) in (
            proptest::collection::vec(any::<u8>().prop_map(GF256::from), 1..10),
            proptest::collection::vec(any::<u8>().prop_map(GF256::from), 1..10)
        )) {

            let a = Poly { coefs: coefs_a };
            let b = Poly { coefs: coefs_b };

            if !b.is_zero() {
                let (q, r) = a.clone() / b.clone();
                assert_eq!(q * b + r, a);
            }

        }
    }

    #[test]
    #[should_panic(expected = "Division by 0 in GF256")]
    fn test_specific_panic() {
        let a = Poly {
            coefs: vec![GF256::from(255), GF256::from(123)],
        };
        let b = Poly {
            coefs: vec![GF256::from(0)],
        };
        let (_q, _r) = a / b;
    }

    #[test]
    fn test_gao_decoding() {
        let f = Poly {
            coefs: vec![GF256::from(7), GF256::from(13), GF256::from(2)],
        };
        let xs = vec![
            GF256::from(20),
            GF256::from(30),
            GF256::from(40),
            GF256::from(50),
            GF256::from(60),
            GF256::from(70),
            GF256::from(80),
        ];
        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();

        tracing::debug!(
            "n={}, v={}, r=detect={}, correct={}",
            xs.len(),
            f.coefs.len(),
            xs.len() - f.coefs.len(),
            (xs.len() - f.coefs.len()) / 2
        );

        // add an error
        ys[0] += GF256::from(3);
        ys[1] += GF256::from(4);
        let polynomial = gao_decoding(&xs, &ys, f.coefs.len(), 2).unwrap();
        assert_eq!(polynomial.eval(&GF256::from(0)), GF256::from(7));
    }

    #[test]
    fn test_gao_decoding_failure() {
        let f = Poly {
            coefs: vec![GF256::from(7), GF256::from(23), GF256::from(8)],
        };
        let xs = vec![
            GF256::from(20),
            GF256::from(30),
            GF256::from(40),
            GF256::from(50),
            GF256::from(60),
            GF256::from(70),
        ];
        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();
        // adding two errors
        ys[0] += GF256::from(222);
        ys[1] += GF256::from(55);
        let r = gao_decoding(&xs, &ys, 3, 1).unwrap_err().to_string();
        assert!(r.contains(
            "Gao decoding failure: Allowed at most 1 errors but xgcd factor degree indicates 2."
        ));
    }

    #[test]
    fn test_formal_derivative() {
        // f(x) = 7 + 23x + 8x^2 + 2x^3
        let f = Poly {
            coefs: vec![
                GF256::from(7),
                GF256::from(23),
                GF256::from(8),
                GF256::from(2),
            ],
        };

        // f'(x) = 23 + 0x + 2x^2 (Note: addition in GF256 is XOR)
        let f1 = Poly {
            coefs: vec![GF256::from(23), GF256::from(0), GF256::from(2)],
        };

        // f''(x) = 0
        let f2 = Poly::zero();

        assert_eq!(f1, f.formal_derivative());
        assert_eq!(f2, f1.formal_derivative());
        assert_eq!(f2, f2.formal_derivative()); // derivative of zero is still zero
    }

    #[test]
    fn test_bitwise_poly() {
        let f = Poly {
            coefs: vec![GF256::from(7), GF256::from(23), GF256::from(8)],
        };
        let degree = f.coefs.len();

        let shifted_pos = 10;
        let lifted_f = ResiduePolyF8Z128::shamir_bit_lift(&f, shifted_pos).unwrap();

        let party_ids = [0, 1, 2, 3, 4, 5];
        let ring_evals: Vec<ResiduePolyF8Z128> = party_ids
            .iter()
            .map(|id| {
                let embedded_xi = ResiduePolyF8Z128::embed_exceptional_set(*id)?;
                Ok(lifted_f.eval(&embedded_xi))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();

        let bitwise = BitwisePoly::from(f);

        for party_id in party_ids {
            assert_eq!(
                ring_evals[party_id],
                bitwise.lazy_eval(&ResiduePolyF8Z128::exceptional_set(party_id, degree).unwrap())
                    << 10,
                "party with index {party_id} failed with wrong evaluation"
            );
        }
    }
}
