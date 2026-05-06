use crate::structure_traits::Ring;

use anyhow::Result;
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
use ndarray::{Array, ArrayD, IxDyn};

pub trait MatrixMul<Rhs = Self>: Sized {
    type Output;
    fn matmul(&self, rhs: &Rhs) -> Result<Self::Output>;
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
