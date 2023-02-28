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

#[derive(Clone, Default, PartialEq, Debug)]
pub struct ShamirZ2Poly {
    pub coefs: Vec<GF256>,
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

    pub fn is_empty(&self) -> bool {
        self.coefs.len() == 0
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

fn highest_coefficient(poly: ShamirZ2Poly) -> GF256 {
    let mut p = poly.clone();
    compress(&mut p);
    if let Some(coef) = p.coefs.last() {
        *coef
    } else {
        GF256::ZERO
    }
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

impl Div<&ShamirZ2Poly> for &ShamirZ2Poly {
    type Output = (ShamirZ2Poly, ShamirZ2Poly);
    fn div(self, other: &ShamirZ2Poly) -> Self::Output {
        let a_len = self.coefs.len();
        let b_len = other.coefs.len();

        let t_inv = GF256::ONE / highest_coefficient(other.clone());
        let mut q = ShamirZ2Poly::zeros(self.coefs.len());
        let mut r = self.clone();

        for i in (0..(a_len - b_len + 1)).rev() {
            // q[i] = r[i+len(b) - 1] * t^{-1}
            q.coefs[i] = r.coefs[i + b_len - 1] * t_inv;
            for j in 0..b_len {
                // r[i+j] = r[i+j] - q[i] * b[j]
                r.coefs[i + j] += q.coefs[i] * other.coefs[j];
            }
        }
        compress(&mut q);
        compress(&mut r);
        (q, r)
    }
}

fn lagrange_polynomials(points: &Vec<GF256>) -> Vec<ShamirZ2Poly> {
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
            let li = &numerator / &denominator;
            li
        })
        .collect();
    polys
}

pub fn lagrange_interpolation(points: &Vec<GF256>, values: &Vec<GF256>) -> ShamirZ2Poly {
    let ls = lagrange_polynomials(points);
    let mut res = ShamirZ2Poly::zero();
    for (i, yi) in values.iter().enumerate() {
        let term = &ls[i] * yi;
        res = &res + &term;
    }
    res
}

pub fn gao_decoding(
    points: &Vec<GF256>,
    values: &Vec<GF256>,
    max_degree: usize,
    max_error_count: usize,
) -> Option<(ShamirZ2Poly, ShamirZ2Poly)> {
    assert_eq!(values.len(), points.len());
    assert!(points.len() >= 2 * max_error_count + max_degree);

    let h = lagrange_interpolation(&points, &values);

    let mut f = ShamirZ2Poly::one();
    for xi in points.iter() {
        let fi = ShamirZ2Poly {
            coefs: vec![*xi, GF256::ONE],
        };
        f = &f * &fi;
    }

    let (mut r0, mut r1) = (f, h);
    let (mut s0, mut s1) = (ShamirZ2Poly::one(), ShamirZ2Poly::zero());

    let (mut t0, mut t1) = (ShamirZ2Poly::zero(), ShamirZ2Poly::one());

    while 1 != 0 {
        let (q, r2) = &r0 / &r1;
        if r0.deg() < max_degree + max_error_count {
            let (g, leftover) = &r0 / &t0;
            if leftover.is_empty() {
                let decoded_polynomial = g;
                let error_locator = t0;
                return Some((decoded_polynomial, error_locator));
            } else {
                return None;
            }
        }

        (r0, s0, t0, r1, s1, t1) = (
            r1.clone(),
            s1.clone(),
            t1.clone(),
            r2,
            &s0 + &(&s1 * &q),
            &t0 + &(&t1 * &q),
        );
    }
    None
}

pub fn error_correction(
    shares: &Vec<ShamirZ2Sharing>,
    threshold: usize,
    max_error_count: usize,
) -> Option<ShamirZ2Poly> {
    let xs: Vec<GF256> = shares.iter().map(|s| GF256::from(s.party_id)).collect();
    let ys: Vec<GF256> = shares.iter().map(|s| s.share).collect();

    if let Some((polynomial, _error_locator)) =
        gao_decoding(&xs, &ys, threshold + 1 + max_error_count, max_error_count)
    {
        Some(polynomial)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_poly_divmod() {
        let a = ShamirZ2Poly {
            coefs: vec![
                GF256::from(7),
                GF256::from(4),
                GF256::from(5),
                GF256::from(4),
            ],
        };
        let b = ShamirZ2Poly {
            coefs: vec![GF256::from(1), GF256::from(0), GF256::from(1)],
        };

        let (q, r) = &a / &b;

        assert_eq!(&(&q * &b) + &r, a);
        assert_ne!(&(&q * &b) + &r, &a + &a);
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
        ys[0] += GF256::ONE;
        let (polynomial, _error_locator) = gao_decoding(&xs, &ys, 3, 1).unwrap();
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
