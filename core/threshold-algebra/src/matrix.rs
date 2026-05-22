use crate::structure_traits::{One, Ring};

use anyhow::Result;
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
use ndarray::{Array, ArrayD, IxDyn};
use std::ops::Mul;

pub trait MatrixMul<Rhs = Self>: Sized {
    type Output;
    fn matmul(&self, rhs: &Rhs) -> Result<Self::Output>;
}

/// Computes powers of a specific point up to degree: p^0, p^1,...,p^degree
pub fn compute_powers<Z: One + Mul<Output = Z> + Copy>(point: Z, degree: usize) -> Vec<Z> {
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

impl<Z: Ring> MatrixMul<ArrayD<Z>> for ArrayD<Z> {
    type Output = ArrayD<Z>;

    fn matmul(&self, rhs: &ArrayD<Z>) -> Result<Self::Output> {
        match (self.ndim(), rhs.ndim()) {
            (1, 1) => {
                if self.dim() != rhs.dim() {
                    return Err(anyhow_error_and_log(format!(
                        "Cannot compute multiplication between rank 1 tensor where dimension of lhs {:?} and rhs {:?}",
                        self.dim(),
                        rhs.dim()
                    )));
                }
                if self.len() != rhs.len() {
                    return Err(anyhow_error_and_log(format!(
                        "Cannot multiply lhs of {:?} elements and rhs of {:?} elements for rank 1 tensors",
                        self.len(),
                        rhs.len()
                    )));
                }
                let res = self
                    .iter()
                    .zip_eq(rhs)
                    .fold(Z::ZERO, |acc, (a, b)| acc + *a * *b);
                Ok(Array::from_elem(IxDyn(&[1]), res).into_dyn())
            }
            (1, 2) => {
                if self.dim()[0] != rhs.dim()[0] {
                    Err(anyhow_error_and_log(format!(
                        "Cannot compute multiplication between rank 1 tensor and rank 2 tensor where dimension of lhs {:?} and rhs {:?}",
                        self.dim(),
                        rhs.dim()
                    )))
                } else {
                    let mut res = Vec::with_capacity(rhs.shape()[1]);
                    for col in rhs.columns() {
                        if col.len() != self.len() {
                            return Err(anyhow_error_and_log(format!(
                                "Cannot multiply lhs of {:?} elements and rhs of {:?} elements for rank 1 tensors and rank 2 tensors",
                                self.len(),
                                rhs.len()
                            )));
                        }
                        let s = col
                            .iter()
                            .zip_eq(self)
                            .fold(Z::ZERO, |acc, (a, b)| acc + *b * *a);
                        res.push(s);
                    }
                    Ok(Array::from_vec(res).into_dyn())
                }
            }
            (2, 1) => {
                if self.dim()[1] != rhs.dim()[0] {
                    Err(anyhow_error_and_log(format!(
                        "Cannot compute multiplication between rank 2 tensor and rank 1 tensor where dimension of lhs {:?} and rhs {:?}",
                        self.dim(),
                        rhs.dim()
                    )))
                } else {
                    let mut res = Vec::with_capacity(self.shape()[0]);
                    for row in self.rows() {
                        if row.len() != rhs.len() {
                            return Err(anyhow_error_and_log(format!(
                                "Cannot multiply lhs of {:?} elements and rhs of {:?} elements for rank 2 tensors and rank 1 tensors",
                                self.len(),
                                rhs.len()
                            )));
                        }
                        let s = row
                            .iter()
                            .zip_eq(rhs)
                            .fold(Z::ZERO, |acc, (a, b)| acc + *b * *a);
                        res.push(s);
                    }
                    Ok(Array::from_vec(res).into_dyn())
                }
            }
            (l_rank, r_rank) => Err(anyhow_error_and_log(format!(
                "Matmul not implemented for tensors of rank {l_rank:?}, {r_rank:?}",
            ))),
        }
    }
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
    fn matmul_rank1_dot() {
        let a = ArrayD::from_shape_vec(IxDyn(&[3]), vec![rp(1), rp(2), rp(3)]).unwrap();
        let b = ArrayD::from_shape_vec(IxDyn(&[3]), vec![rp(4), rp(5), rp(6)]).unwrap();
        let res = a.matmul(&b).unwrap();
        // 1*4 + 2*5 + 3*6 = 32
        assert_eq!(res.into_raw_vec_and_offset().0, vec![rp(32)]);
    }

    #[test]
    fn matmul_vector_matrix() {
        // [1,2] * [[1,2,3],[4,5,6]] = [9, 12, 15]
        let v = ArrayD::from_shape_vec(IxDyn(&[2]), vec![rp(1), rp(2)]).unwrap();
        let m = ArrayD::from_shape_vec(
            IxDyn(&[2, 3]),
            vec![rp(1), rp(2), rp(3), rp(4), rp(5), rp(6)],
        )
        .unwrap();
        let res = v.matmul(&m).unwrap();
        assert_eq!(res.into_raw_vec_and_offset().0, vec![rp(9), rp(12), rp(15)]);
    }

    #[test]
    fn matmul_matrix_vector() {
        // [[1,2,3],[4,5,6]] * [7,8,9] = [50, 122]
        let m = ArrayD::from_shape_vec(
            IxDyn(&[2, 3]),
            vec![rp(1), rp(2), rp(3), rp(4), rp(5), rp(6)],
        )
        .unwrap();
        let v = ArrayD::from_shape_vec(IxDyn(&[3]), vec![rp(7), rp(8), rp(9)]).unwrap();
        let res = m.matmul(&v).unwrap();
        assert_eq!(res.into_raw_vec_and_offset().0, vec![rp(50), rp(122)]);
    }

    #[test]
    fn matmul_dim_mismatches_err() {
        let v3 = ArrayD::from_shape_vec(IxDyn(&[3]), vec![rp(1); 3]).unwrap();
        let v2 = ArrayD::from_shape_vec(IxDyn(&[2]), vec![rp(1); 2]).unwrap();
        // rank-1 length mismatch
        assert!(v3.matmul(&v2).is_err());
        // rank mismatch on rank-2 sides
        let m22 = ArrayD::from_shape_vec(IxDyn(&[2, 2]), vec![rp(1); 4]).unwrap();
        assert!(m22.matmul(&m22).is_err());
        // (1, 2) shape mismatch
        let m23 = ArrayD::from_shape_vec(IxDyn(&[2, 3]), vec![rp(1); 6]).unwrap();
        assert!(v3.matmul(&m23).is_err());
        // (2, 1) shape mismatch
        assert!(m23.matmul(&v2).is_err());
    }
}
