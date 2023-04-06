use crate::poly_shamir::{One, ZConsts, ZPoly, Zero, F_DEG};

/// Precomputes reductions of x^8, x^9, ...x^14 to help us in reducing polynomials faster
pub struct ReductionTablesGF256<Z> {
    pub reduced: [ZPoly<Z>; 8],
}

impl<Z> Default for ReductionTablesGF256<Z>
where
    Z: ZConsts + One + Zero,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Z> ReductionTablesGF256<Z>
where
    Z: ZConsts + One + Zero,
{
    pub const fn new() -> Self {
        Self {
            reduced: [
                ZPoly {
                    coefs: [
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::ZERO,
                        Z::ZERO,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::ZERO,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ZERO,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ZERO,
                        Z::ZERO,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                        Z::MAX,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ONE,
                        Z::ONE,
                        Z::ZERO,
                        Z::ONE,
                        Z::ZERO,
                        Z::MAX,
                        Z::ZERO,
                        Z::MAX,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ONE,
                        Z::TWO,
                        Z::ONE,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                        Z::MAX,
                        Z::ZERO,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ZERO,
                        Z::ONE,
                        Z::TWO,
                        Z::ONE,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                        Z::MAX,
                    ],
                },
                ZPoly {
                    coefs: [
                        Z::ONE,
                        Z::ONE,
                        Z::ONE,
                        Z::THREE,
                        Z::TWO,
                        Z::ONE,
                        Z::TWO,
                        Z::ZERO,
                    ],
                },
            ],
        }
    }

    #[inline(always)]
    pub fn entry(&self, deg: usize, idx_coef: usize) -> &Z {
        &self.reduced[deg - F_DEG].coefs[idx_coef]
    }
}
