use crate::poly_shamir::Z64Poly;
use crate::poly_shamir::F_DEG;
use std::num::Wrapping;

/// Precomputes reductions of x^8, x^9, ...x^14 to help us in reducing polynomials faster
pub struct ReductionTablesGF256 {
    pub reduced: [Z64Poly; 8],
}

pub const REDUCTION_TABLES: ReductionTablesGF256 = ReductionTablesGF256::new();

impl Default for ReductionTablesGF256 {
    fn default() -> Self {
        Self::new()
    }
}
impl ReductionTablesGF256 {
    pub const fn new() -> Self {
        Self {
            reduced: [
                Z64Poly {
                    coefs: [
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(0),
                        Wrapping(0),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(0),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(0),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(0),
                        Wrapping(0),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(18446744073709551615),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(1),
                        Wrapping(1),
                        Wrapping(0),
                        Wrapping(1),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(1),
                        Wrapping(2),
                        Wrapping(1),
                        Wrapping(1),
                        Wrapping(2),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                        Wrapping(0),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(0),
                        Wrapping(1),
                        Wrapping(2),
                        Wrapping(1),
                        Wrapping(1),
                        Wrapping(2),
                        Wrapping(0),
                        Wrapping(18446744073709551615),
                    ],
                },
                Z64Poly {
                    coefs: [
                        Wrapping(1),
                        Wrapping(1),
                        Wrapping(1),
                        Wrapping(3),
                        Wrapping(2),
                        Wrapping(1),
                        Wrapping(2),
                        Wrapping(0),
                    ],
                },
            ],
        }
    }

    pub fn entry(&self, deg: usize, idx_coef: usize) -> &Wrapping<u64> {
        &self.reduced[deg - F_DEG].coefs[idx_coef]
    }
}
