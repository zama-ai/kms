use std::ops::{Add, Div, Mul};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{error::error_handler::anyhow_error_and_log, execution::sharing::shamir::ShamirRing};

use super::structure_traits::{Field, One, Ring, Sample, Zero};

#[derive(Serialize, Deserialize, Hash, Clone, Default, Debug)]
pub struct Poly<F> {
    pub coefs: Vec<F>,
}

impl<Z: ShamirRing> Poly<Z> {
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

        // embed party IDs as invertable x-points on the polynomial
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
    pub fn deg(&self) -> usize {
        for (i, item) in self.coefs.iter().enumerate().rev() {
            if item != &F::ZERO {
                return i;
            }
        }
        0
    }

    pub fn is_zero(&self) -> bool {
        for c in self.coefs.iter() {
            if c != &F::ZERO {
                return false;
            }
        }
        true
    }

    pub fn zero() -> Self {
        Poly {
            coefs: vec![F::ZERO],
        }
    }

    fn zeros(n: usize) -> Self {
        Poly {
            coefs: vec![F::ZERO; n],
        }
    }

    fn highest_coefficient(&self) -> F {
        for c in self.coefs.iter().rev() {
            if c != &F::ZERO {
                return *c;
            }
        }
        F::ZERO
    }

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

impl<F> Poly<F>
where
    F: One,
    F: PartialEq,
    F: Copy,
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
    pub fn sample_random<U: RngCore>(rng: &mut U, zero_coef: F, degree: usize) -> Self {
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

fn quo_rem<F: Field>(a: Poly<F>, b: &Poly<F>) -> (Poly<F>, Poly<F>) {
    let a_len = a.coefs.len();
    let b_len = b.coefs.len();

    let t = F::ONE / b.highest_coefficient(); // TODO(Morten) replace with inv operation?
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

fn lagrange_polynomials<F: Field>(points: &[F]) -> Vec<Poly<F>> {
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
                            coefs: vec![*xj, F::ONE],
                        };
                    denominator *= *xi + *xj;
                }
            }
            numerator / &denominator
        })
        .collect();
    polys
}

pub fn lagrange_interpolation<F: Field>(points: &[F], values: &[F]) -> Poly<F> {
    let ls = lagrange_polynomials(points);
    assert_eq!(ls.len(), values.len());
    let mut res = Poly::zero();
    for (li, vi) in ls.into_iter().zip(values.iter()) {
        let term = li * vi;
        res = res + term;
    }
    res
}

fn partial_xgcd<F: Field>(a: Poly<F>, b: Poly<F>, stop: usize) -> (Poly<F>, Poly<F>) {
    let (mut r0, mut r1) = (a, b);
    let (mut t0, mut t1) = (Poly::zero(), Poly::one());

    while r1.deg() >= stop {
        let (q, _) = &r0 / &r1;
        (r0, r1) = (r1.clone(), r0 + (&q * r1));
        (t0, t1) = (t1.clone(), t0 + (&q * t1));
    }
    // r = gcd(a, b) = a * s + b * t
    (r1, t1)
}

pub fn gao_decoding<F: Field>(
    points: &Vec<F>,
    values: &Vec<F>,
    k: usize,
    max_error_count: usize,
) -> anyhow::Result<Poly<F>> {
    // in the literature we find (n, k, d) codes
    // this means that n is the number of points xi for which we have some values yi
    // yi ~= G(xi))
    // where deg(G) <= k-1
    let n = points.len();
    let d = (n + 1)
        .checked_sub(k)
        .ok_or_else(|| anyhow_error_and_log("overflow computing d".to_string()))?;

    //Note: Changed assert to error because we dont want to panic here
    //assert!(2 * max_error_count < d);
    //assert_eq!(values.len(), points.len());
    if 2 * max_error_count >= d || values.len() != points.len() {
        return Err(anyhow_error_and_log(
            "Gao decoding failure, too many errors or missmatch between values and points size "
                .to_string(),
        ));
    }

    // R \in GF(256)[X] such that R(xi) = yi
    let r = lagrange_interpolation(points, values);

    // G = prod(X - xi) where xi is party i's index
    // note that deg(G) >= deg(R)
    let mut g = Poly::one();
    for xi in points.iter() {
        let fi = Poly {
            coefs: vec![*xi, F::ONE],
        };
        g = g * fi;
    }

    // apply EEA to compute q0, q1 such that
    // q1 = gcd(g, r) = g * t + r * q0
    // q1 | g, q1 | r
    let gcd_stop = (n + k) / 2;
    let (q1, q0) = partial_xgcd(g, r, gcd_stop);

    // abort early if we have too many errors
    if q0.deg() > max_error_count {
        return Err(anyhow_error_and_log(
            format!("Gao decoding failure: Allowed at most {max_error_count} errors but xgcd factor degree indicates {}.", q0.deg())
        ));
    }

    let (h, rem) = q1 / &q0;

    if !rem.is_zero() {
        Err(anyhow_error_and_log(
            "Gao decoding failure: Division remainder is not zero but.".to_string(),
        ))
    } else if h.deg() >= k {
        Err(anyhow_error_and_log(format!("Gao decoding failure: Division result is of too high degree {}, but should be less than {}.", h.deg(), k-1)))
    } else {
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::gf256::GF256;
    use proptest::prelude::*;
    use rstest::rstest;

    #[test]
    fn test_lagrange_mod2() {
        let poly = Poly {
            coefs: vec![GF256::from(1), GF256::from(2), GF256::from(3)],
        };
        let xs = vec![
            GF256::from(0),
            GF256::from(20),
            GF256::from(30),
            GF256::from(40),
        ];
        let ys: Vec<_> = xs.iter().map(|x| poly.eval(x)).collect();
        let g = lagrange_interpolation(&xs, &ys);
        assert_eq!(poly, g);
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
        ];
        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();
        // add an error
        ys[0] += GF256::from(3);
        let polynomial = gao_decoding(&xs, &ys, 3, 1).unwrap();
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
}
