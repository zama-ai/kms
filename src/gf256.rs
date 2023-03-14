use anyhow::anyhow;
use std::ops::{Add, Div, Mul};

use g2p::{g2p, GaloisField};

g2p!(
    GF256,
    8,
    modulus: 0b_1_0001_1011,
);

#[derive(Clone, PartialEq, Debug)]
pub struct ShamirZ2Sharing {
    pub share: GF256,
    pub party_id: u8,
}

#[derive(Clone, Default, Debug)]
pub struct ShamirZ2Poly {
    pub coefs: Vec<GF256>,
}

impl PartialEq for ShamirZ2Poly {
    fn eq(&self, other: &Self) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        compress(&mut a);
        compress(&mut b);
        a.coefs == b.coefs
    }
}

impl ShamirZ2Poly {
    pub fn eval(&self, point: &GF256) -> GF256 {
        let mut res = GF256::ZERO;
        for coef in self.coefs.iter().rev() {
            res = res * *point + *coef;
        }
        res
    }

    pub fn deg(&self) -> usize {
        for (i, item) in self.coefs.iter().enumerate().rev() {
            if item != &GF256::ZERO {
                return i;
            }
        }
        0
    }

    pub fn is_zero(&self) -> bool {
        for c in self.coefs.iter() {
            if c != &GF256::ZERO {
                return false;
            }
        }
        true
    }
}

impl ShamirZ2Poly {
    pub fn zero() -> Self {
        ShamirZ2Poly {
            coefs: vec![GF256::ZERO],
        }
    }

    pub fn zeros(n: usize) -> Self {
        let mut coefs: Vec<GF256> = Vec::with_capacity(n);
        for _i in 0..n {
            coefs.push(GF256::ZERO);
        }
        ShamirZ2Poly { coefs }
    }

    pub fn one() -> Self {
        ShamirZ2Poly {
            coefs: vec![GF256::ONE],
        }
    }
}

fn compress(poly: &mut ShamirZ2Poly) {
    while let Some(c) = poly.coefs.last() {
        if c == &GF256::ZERO {
            poly.coefs.pop();
        } else {
            break;
        }
    }
}

fn highest_coefficient(coefs: &[GF256]) -> GF256 {
    for c in coefs.iter().rev() {
        if c != &GF256::ZERO {
            return *c;
        }
    }
    GF256::ZERO
}

impl Add<&ShamirZ2Poly> for &ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn add(self, other: &ShamirZ2Poly) -> Self::Output {
        let max_len = usize::max(self.coefs.len(), other.coefs.len());
        let mut res = ShamirZ2Poly::zeros(max_len);
        for i in 0..max_len {
            if i < self.coefs.len() {
                res.coefs[i] += self.coefs[i];
            }
            if i < other.coefs.len() {
                res.coefs[i] += other.coefs[i];
            }
        }
        compress(&mut res);
        res
    }
}

impl Add<ShamirZ2Poly> for ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn add(self, other: ShamirZ2Poly) -> Self::Output {
        let max_len = usize::max(self.coefs.len(), other.coefs.len());
        let mut res = ShamirZ2Poly::zeros(max_len);
        for i in 0..max_len {
            if i < self.coefs.len() {
                res.coefs[i] += self.coefs[i];
            }
            if i < other.coefs.len() {
                res.coefs[i] += other.coefs[i];
            }
        }
        compress(&mut res);
        res
    }
}

impl Mul<ShamirZ2Poly> for ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn mul(self, other: ShamirZ2Poly) -> Self::Output {
        let mut extended = ShamirZ2Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        compress(&mut extended);
        extended
    }
}

impl Mul<&ShamirZ2Poly> for &ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn mul(self, other: &ShamirZ2Poly) -> Self::Output {
        let mut extended = ShamirZ2Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        compress(&mut extended);
        extended
    }
}

impl Mul<&GF256> for &ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn mul(self, other: &GF256) -> Self::Output {
        let mut res = ShamirZ2Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            res.coefs[i] = *xi * *other;
        }
        compress(&mut res);
        res
    }
}

impl Div<&GF256> for &ShamirZ2Poly {
    type Output = ShamirZ2Poly;
    fn div(self, other: &GF256) -> Self::Output {
        let mut extended = ShamirZ2Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            extended.coefs[i] = *xi / *other;
        }
        compress(&mut extended);
        extended
    }
}

fn quo_rem(a: &ShamirZ2Poly, b: &ShamirZ2Poly) -> (ShamirZ2Poly, ShamirZ2Poly) {
    let a_len = a.coefs.len();
    let b_len = b.coefs.len();

    let t = GF256::ONE / highest_coefficient(&b.coefs);
    let mut q = ShamirZ2Poly::zeros(a.coefs.len());
    let mut r = a.clone();

    if a_len >= b_len {
        for i in (0..(a_len - b_len + 1)).rev() {
            // q[i] = r[i+len(b) - 1] * t^{-1}
            q.coefs[i] = r.coefs[i + b_len - 1] * t;
            for j in 0..b_len {
                // r[i+j] = r[i+j] - q[i] * b[j]
                r.coefs[i + j] -= q.coefs[i] * b.coefs[j];
            }
        }
    }
    compress(&mut q);
    compress(&mut r);
    (q, r)
}

impl Div<&ShamirZ2Poly> for &ShamirZ2Poly {
    type Output = (ShamirZ2Poly, ShamirZ2Poly);
    fn div(self, other: &ShamirZ2Poly) -> Self::Output {
        quo_rem(self, other)
    }
}

impl Div<ShamirZ2Poly> for ShamirZ2Poly {
    type Output = (ShamirZ2Poly, ShamirZ2Poly);
    fn div(self, other: ShamirZ2Poly) -> Self::Output {
        quo_rem(&self, &other)
    }
}

fn lagrange_polynomials(points: &[GF256]) -> Vec<ShamirZ2Poly> {
    let polys: Vec<_> = points
        .iter()
        .enumerate()
        .map(|(i, xi)| {
            let mut numerator = ShamirZ2Poly {
                coefs: vec![GF256::from(1), GF256::from(0)],
            };
            let mut denominator = GF256::from(1);
            for (j, xj) in points.iter().enumerate() {
                if i != j {
                    numerator = &numerator
                        * &ShamirZ2Poly {
                            coefs: vec![*xj, GF256::from(1)],
                        };
                    denominator *= *xi + *xj;
                }
            }
            &numerator / &denominator
        })
        .collect();
    polys
}

pub fn lagrange_interpolation(points: &[GF256], values: &[GF256]) -> ShamirZ2Poly {
    let ls = lagrange_polynomials(points);
    let mut res = ShamirZ2Poly::zero();
    for (i, yi) in values.iter().enumerate() {
        let term = &ls[i] * yi;
        res = &res + &term;
    }
    res
}

fn partial_xgcd(a: &ShamirZ2Poly, b: &ShamirZ2Poly, stop: usize) -> (ShamirZ2Poly, ShamirZ2Poly) {
    let (mut r0, mut r1) = (a.clone(), b.clone());
    let (mut t0, mut t1) = (ShamirZ2Poly::zero(), ShamirZ2Poly::one());

    while r1.deg() >= stop {
        let (q, _) = &r0 / &r1;
        (r0, r1) = (r1.clone(), &r0 + &(&q * &r1));
        (t0, t1) = (t1.clone(), &t0 + &(&q * &t1));
    }
    // r = gcd(a, b) = a * s + b * t
    (r1, t1)
}

pub fn gao_decoding(
    points: &Vec<GF256>,
    values: &Vec<GF256>,
    k: usize,
    max_error_count: usize,
) -> Option<ShamirZ2Poly> {
    // in the literature we find (n, k, d) codes
    // this means that n is the number of points xi for which we have some values yi
    // yi ~= G(xi))
    // where deg(G) <= k-1
    let n = points.len();
    let d = n - k + 1;
    assert!(2 * max_error_count < d);
    assert_eq!(values.len(), points.len());

    // R \in GF(256)[X] such that R(xi) = yi
    let r = lagrange_interpolation(points, values);

    // G = prod(X - xi) where xi is party i's index
    // note that deg(G) >= deg(R)
    let mut g = ShamirZ2Poly::one();
    for xi in points.iter() {
        let fi = ShamirZ2Poly {
            coefs: vec![*xi, GF256::ONE],
        };
        g = &g * &fi;
    }

    // apply EEA to compute q0, q1 such that
    // q1 = gcd(g, r) = g * t + r * q0
    // q1 | g, q1 | r
    let gcd_stop = (n + k) / 2;
    let (q1, q0) = partial_xgcd(&g, &r, gcd_stop);

    let (h, rem) = &q1 / &q0;
    if rem.is_zero() && h.deg() < k && q0.deg() <= max_error_count {
        Some(h)
    } else {
        None
    }
}

pub fn error_correction(
    shares: &[ShamirZ2Sharing],
    threshold: usize,
    max_error_count: usize,
) -> Result<ShamirZ2Poly, anyhow::Error> {
    let xs: Vec<GF256> = shares.iter().map(|s| GF256::from(s.party_id)).collect();
    let ys: Vec<GF256> = shares.iter().map(|s| s.share).collect();

    if let Some(polynomial) = gao_decoding(&xs, &ys, threshold + 1, max_error_count) {
        Ok(polynomial)
    } else {
        Err(anyhow!(format!(
            "Cannot recover polynomial in GF(256) with threshold {threshold} and max_error_count: {max_error_count}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

    #[test]
    fn test_lagrange_mod2() {
        let poly = ShamirZ2Poly {
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
        let a = ShamirZ2Poly { coefs: coefs_a };
        let b = ShamirZ2Poly { coefs: coefs_b };

        let (q, r) = a.clone() / b.clone();

        assert_eq!(q * b + r, a);
    }

    proptest! {
        #[test]
        fn test_fuzzy_divmod((coefs_a, coefs_b) in (
            proptest::collection::vec(any::<u8>().prop_map(GF256::from), 1..10),
            proptest::collection::vec(any::<u8>().prop_map(GF256::from), 1..10)
        )) {

            let a = ShamirZ2Poly { coefs: coefs_a };
            let b = ShamirZ2Poly { coefs: coefs_b };

            if !b.is_zero() {
                let (q, r) = a.clone() / b.clone();
                assert_eq!(q * b + r, a);
            }

        }
    }

    #[test]
    #[should_panic(expected = "Division by 0 in GF256")]
    fn test_specific_panic() {
        let a = ShamirZ2Poly {
            coefs: vec![GF256::from(255), GF256::from(123)],
        };
        let b = ShamirZ2Poly {
            coefs: vec![GF256::from(0)],
        };
        let (_q, _r) = a / b;
    }

    #[test]
    fn test_gao_decoding() {
        let f = ShamirZ2Poly {
            coefs: vec![GF256::from(1), GF256::from(1), GF256::from(1)],
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
        // adding an error
        ys[0] += GF256::from(2);
        let polynomial = gao_decoding(&xs, &ys, 3, 1).unwrap();
        assert_eq!(polynomial.eval(&GF256::ZERO), GF256::ONE);
    }

    #[test]
    fn test_error_correction() {
        let f = ShamirZ2Poly {
            coefs: vec![GF256::from(25), GF256::from(1), GF256::from(1)],
        };
        let party_ids = vec![1_u8, 2, 3, 4, 5, 6];

        let mut shares: Vec<_> = party_ids
            .iter()
            .map(|x| ShamirZ2Sharing {
                share: f.eval(&GF256::from(*x)),
                party_id: *x,
            })
            .collect();

        // modify share of party with index 1
        shares[1].share += GF256::ONE;

        let secret_poly = error_correction(&shares, 2, 1).unwrap();
        assert_eq!(secret_poly, f);
    }
}
