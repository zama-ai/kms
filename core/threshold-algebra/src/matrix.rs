use crate::structure_traits::{One, Ring, RingWithExceptionalSequence};

use anyhow::Result;
use error_utils::anyhow_error_and_log;
use std::ops::Mul;

/// Row-major Vandermonde matrix used for randomness extraction.
#[derive(Debug, Default)]
pub struct VdmMatrix<Z> {
    height: usize,
    width: usize,
    coefs: Vec<Z>,
}

impl<Z> VdmMatrix<Z> {
    /// Returns true if the matrix has no coefficients.
    pub fn is_empty(&self) -> bool {
        self.coefs.is_empty()
    }

    /// Returns the matrix height.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Returns the matrix width.
    pub fn width(&self) -> usize {
        self.width
    }
}

impl<Z: RingWithExceptionalSequence> VdmMatrix<Z> {
    /// Creates the VDM matrix where row `i` is `[1, alpha_i, ..., alpha_i^(width - 1)]`.
    ///
    /// `alpha_i` is the `i + 1` entry from the exceptional sequence.
    pub fn from_exceptional_sequence(height: usize, width: usize) -> Result<Self> {
        if width == 0 {
            return Ok(Self {
                height,
                width,
                coefs: Vec::new(),
            });
        }

        let mut coefs = Vec::with_capacity(height * width);
        for idx in 0..height {
            let point = Z::get_from_exceptional_sequence(idx + 1)?;
            let mut power = Z::ONE;
            coefs.push(power);
            for _ in 1..width {
                power *= point;
                coefs.push(power);
            }
        }

        debug_assert_eq!(coefs.len(), height * width);
        Ok(Self {
            height,
            width,
            coefs,
        })
    }
}

impl<Z: Ring> VdmMatrix<Z> {
    /// Multiplies a row vector by this VDM matrix.
    pub fn mul_vector(&self, lhs: &[Z]) -> Result<Vec<Z>> {
        if lhs.len() != self.height {
            return Err(anyhow_error_and_log(format!(
                "Cannot multiply vector of length {} by VDM matrix of shape ({}, {})",
                lhs.len(),
                self.height,
                self.width,
            )));
        }
        if self.width == 0 {
            return Ok(Vec::new());
        }

        let mut res = vec![Z::ZERO; self.width];
        for (lhs_coef, row) in lhs.iter().zip(self.coefs.chunks_exact(self.width)) {
            for (res_coef, matrix_coef) in res.iter_mut().zip(row) {
                *res_coef += *lhs_coef * *matrix_coef;
            }
        }
        Ok(res)
    }
}

/// Computes powers of a specific point up to degree: p^0, p^1,...,p^degree
pub(crate) fn compute_powers<Z: One + Mul<Output = Z> + Copy>(point: Z, degree: usize) -> Vec<Z> {
    let mut powers_of_point = Vec::with_capacity(degree + 1);
    powers_of_point.push(Z::ONE);
    for i in 1..=degree {
        powers_of_point.push(powers_of_point[i - 1] * point);
    }
    powers_of_point
}

/// Computes powers of a list of points in F up to a given maximal exponent.
pub fn compute_powers_list<F: One + Mul<Output = F> + Copy>(
    points: &[F],
    max_exponent: usize,
) -> Vec<Vec<F>> {
    let mut alpha_powers = Vec::with_capacity(points.len());
    for p in points {
        alpha_powers.push(compute_powers(*p, max_exponent));
    }
    alpha_powers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galois_rings::degree_4::ResiduePolyF4Z128;
    use crate::structure_traits::{One, Zero};

    fn rp(n: u8) -> ResiduePolyF4Z128 {
        let mut acc = ResiduePolyF4Z128::ZERO;
        for _ in 0..n {
            acc += ResiduePolyF4Z128::ONE;
        }
        acc
    }

    #[test]
    fn compute_powers_basic() {
        let powers = compute_powers(rp(2), 4);
        assert_eq!(powers, vec![rp(1), rp(2), rp(4), rp(8), rp(16)]);
    }

    #[test]
    fn compute_powers_zero_degree() {
        let powers = compute_powers(rp(7), 0);
        assert_eq!(powers, vec![rp(1)]);
    }

    #[test]
    fn compute_powers_list_basic() {
        let lists = compute_powers_list(&[rp(2), rp(3)], 2);
        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0], vec![rp(1), rp(2), rp(4)]);
        assert_eq!(lists[1], vec![rp(1), rp(3), rp(9)]);
    }

    #[test]
    fn vdm_matrix_mul_left_vector() {
        let vdm = VdmMatrix {
            height: 2,
            width: 3,
            coefs: vec![rp(1), rp(2), rp(3), rp(4), rp(5), rp(6)],
        };
        let res = vdm.mul_vector(&[rp(1), rp(2)]).unwrap();
        assert_eq!(res, vec![rp(9), rp(12), rp(15)]);
    }

    #[test]
    fn vdm_matrix_dim_mismatch_err() {
        let vdm = VdmMatrix {
            height: 2,
            width: 2,
            coefs: vec![rp(1); 4],
        };
        assert!(vdm.mul_vector(&[rp(1); 3]).is_err());
    }

    #[test]
    fn vdm_matrix_from_exceptional_sequence_zero_width() {
        let vdm = VdmMatrix::<ResiduePolyF4Z128>::from_exceptional_sequence(2, 0).unwrap();

        assert!(vdm.is_empty());
        assert_eq!(vdm.height(), 2);
        assert_eq!(vdm.width(), 0);
        assert_eq!(vdm.mul_vector(&[rp(1), rp(2)]).unwrap(), Vec::new());
    }

    #[test]
    fn vdm_matrix_from_exceptional_sequence() {
        let vdm = VdmMatrix::<ResiduePolyF4Z128>::from_exceptional_sequence(2, 3).unwrap();
        let alpha_1 = ResiduePolyF4Z128::get_from_exceptional_sequence(1).unwrap();
        let alpha_2 = ResiduePolyF4Z128::get_from_exceptional_sequence(2).unwrap();

        assert_eq!(
            vdm.mul_vector(&[ResiduePolyF4Z128::ONE, ResiduePolyF4Z128::ZERO])
                .unwrap(),
            vec![ResiduePolyF4Z128::ONE, alpha_1, alpha_1 * alpha_1]
        );
        assert_eq!(
            vdm.mul_vector(&[ResiduePolyF4Z128::ZERO, ResiduePolyF4Z128::ONE])
                .unwrap(),
            vec![ResiduePolyF4Z128::ONE, alpha_2, alpha_2 * alpha_2,]
        );
    }
}
