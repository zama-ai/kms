use anyhow::anyhow;
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    num::Wrapping,
    ops::{AddAssign, Mul, MulAssign, Neg, SubAssign},
    sync::RwLock,
};

use crate::algebra::{
    base_ring::{Z128, Z64},
    bivariate::compute_powers,
    error_correction::MemoizedExceptionals,
    galois_fields::gf256::{two_powers, GF256, GF256_FROM_GENERATOR, GF256_NEWTON_INNER_LOOP},
    poly::{BitWiseEval, BitwisePoly},
    structure_traits::{
        BaseRing, One, QuotientMaximalIdeal, Ring, RingEmbed, Solve1, ZConsts, Zero,
    },
};

use super::{
    common::{LutMulReduction, Monomials, ReductionTable, ReductionTables, ResiduePoly},
    utils::karatsuba_8,
};

/// This defines a degree 8 extension based on the irreducible polynomial
/// F = X^8 + X^4 + X^3 + X + 1
pub type ResiduePolyF8<Z> = ResiduePoly<Z, 8>;
pub type ResiduePolyF8Z128 = ResiduePolyF8<Z128>;
pub type ResiduePolyF8Z64 = ResiduePolyF8<Z64>;

impl<Z: BaseRing> Ring for ResiduePolyF8<Z> {
    const BIT_LENGTH: usize = Z::BIT_LENGTH * 8;
    const CHAR_LOG2: usize = Z::CHAR_LOG2;
    const EXTENSION_DEGREE: usize = 8;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = Z::NUM_BITS_STAT_SEC_BASE_RING;

    fn to_byte_vec(&self) -> Vec<u8> {
        let size = Self::BIT_LENGTH >> 3;
        let mut res = Vec::with_capacity(size);
        for coef in self.coefs {
            coef.to_byte_vec()
                .into_iter()
                .for_each(|byte| res.push(byte));
        }
        res
    }
}

impl<Z: Clone> ResiduePolyF8<Z> {
    /// multiplies a ResiduePoly by x using the irreducible poly F = X^8 + X^4 + X^3 + X + 1
    /// i.e. X * (aX^7 + bX^6 + cX^5 + dX^4 + eX^3 + fX^2 + gX + h)
    ///      = aX^8 + bX^7 + cX^6 + dX^5 + eX^4 + fX^3 + gX^2 + hX
    ///      = -a(X^4 + X^3 + X + 1) + bX^7 + cX^6 + dX^5 + eX^4 + fX^3 + gX^2 + hX
    ///      = bX^7 + cX^6 + dX^5 + (e-a)X^4 + (f-a)X^3 + gX^2 + (h-a) X - a
    pub fn mul_by_x(&mut self)
    where
        Z: Neg<Output = Z> + SubAssign + Copy,
    {
        let last = self.coefs[7];
        for i in (1..8).rev() {
            self.coefs[i] = self.coefs[i - 1]
        }

        self.coefs[0] = -last;
        self.coefs[1] -= last;
        self.coefs[3] -= last;
        self.coefs[4] -= last;
    }
}

impl<Z> Mul<Self> for ResiduePolyF8<Z>
where
    Z: Ring,
    ResiduePolyF8<Z>: LutMulReduction<Z>,
{
    type Output = Self;
    fn mul(self, other: ResiduePolyF8<Z>) -> Self::Output {
        let extended_coefs = karatsuba_8(&self.coefs, &other.coefs);
        ResiduePolyF8::reduce_mul(&extended_coefs)
    }
}

impl<Z> Mul<&Self> for ResiduePolyF8<Z>
where
    Z: Ring,
    ResiduePolyF8<Z>: LutMulReduction<Z>,
{
    type Output = Self;
    fn mul(self, other: &ResiduePolyF8<Z>) -> Self::Output {
        let extended_coefs = karatsuba_8(&self.coefs, &other.coefs);
        ResiduePolyF8::reduce_mul(&extended_coefs)
    }
}

impl<Z> Mul<&ResiduePolyF8<Z>> for &ResiduePolyF8<Z>
where
    Z: Ring,
    ResiduePolyF8<Z>: LutMulReduction<Z>,
{
    type Output = ResiduePolyF8<Z>;
    fn mul(self, other: &ResiduePolyF8<Z>) -> Self::Output {
        let extended_coefs = karatsuba_8(&self.coefs, &other.coefs);
        ResiduePolyF8::reduce_mul(&extended_coefs)
    }
}

impl<Z> MulAssign<Self> for ResiduePolyF8<Z>
where
    Z: Ring,
    ResiduePolyF8<Z>: LutMulReduction<Z>,
{
    fn mul_assign(&mut self, other: ResiduePolyF8<Z>) {
        let extended_coefs = karatsuba_8(&self.coefs, &other.coefs);
        self.coefs = ResiduePolyF8::reduce_mul(&extended_coefs).coefs;
    }
}

impl<Z> Default for ReductionTables<Z, 8>
where
    Z: ZConsts + One + Zero + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Z> ReductionTables<Z, 8>
where
    Z: ZConsts + One + Zero + Clone,
{
    pub const fn new() -> Self {
        Self {
            //Taken mod X^8 + X^4 + X^3 + X + 1
            reduced: [
                //X^8 = -X^4 - X^3 - X - 1
                ResiduePoly {
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
                //X^9 = -X^5 - X^4 - X^2 - X
                ResiduePoly {
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
                //X^10 = -X^6 - X^5 - X^3 - X^2
                ResiduePoly {
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
                //X^11 = -X^7 - X^6 - X^4 - X^3
                ResiduePoly {
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
                //X^12 = -X^7 - X^5 + X^3 + X + 1
                ResiduePoly {
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
                //X^13 = -X^6 + 2X^4 + X^3 + X^2 + 2X + 1
                ResiduePoly {
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
                //X^14 = -X^7 + 2X^5 + X^4 + X^3 + 2X^2 + X
                ResiduePoly {
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
                // NEVER USED, only there because generic can't be used in const operation
                // X^15 = 2X^6 + X^5 + 2X^4 + 3X^3 + X^2 + X + 1
                ResiduePoly {
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
}

impl<Z: BaseRing> ReductionTable<Z, 8> for ResiduePolyF8<Z> {
    const REDUCTION_TABLES: ReductionTables<Z, 8> = ReductionTables::<Z, 8>::new();
}

impl<Z: BaseRing> QuotientMaximalIdeal for ResiduePolyF8<Z> {
    type QuotientOutput = GF256;
    const QUOTIENT_OUTPUT_SIZE: usize = 256;
    ///Computes the isomorphism GR(Z,F) -> GF(2,F)
    /// to input Self/2^i
    ///
    ///
    /// I.e. for each coefficient of Self, extract the ith bit and
    /// set it as coefficient of same degree of the GF256 polynomial
    fn bit_compose(&self, idx_bit: usize) -> GF256 {
        let x: u8 = self
            .coefs
            .iter()
            .enumerate()
            .fold(0_u8, |acc, (i, element)| {
                let shifted_entry = (*element).extract_bit(idx_bit) << i;
                acc + shifted_entry
            });
        GF256::from(x)
    }

    // Lift an element of GF256 to element of ResiduePolyF8
    fn bit_lift(x: GF256, pos: usize) -> anyhow::Result<Self> {
        let c8: u8 = x.into();
        let shifted_coefs: Vec<_> = (0..8)
            .map(|i| Z::from_u128(((c8 >> i) & 1) as u128) << pos)
            .collect();
        Self::from_vec(shifted_coefs)
    }

    fn bit_lift_from_idx(idx: usize, pos: usize) -> anyhow::Result<Self> {
        let x = GF256_FROM_GENERATOR
            .get(idx)
            .ok_or_else(|| anyhow!("Unexpected index {} for GF256", idx))?;
        Self::bit_lift(*x, pos)
    }
    fn embed_quotient_exceptional_set(x: GF256) -> anyhow::Result<Self> {
        Self::embed_exceptional_set(x.0 as usize)
    }
}

impl<Z: BaseRing> Solve1 for ResiduePolyF8<Z> {
    fn solve_1(v: &Self) -> anyhow::Result<Self> {
        let mut res = GF256::from(0);
        let v = Self::bit_compose(v, 0);
        let v_powers = two_powers(v, 7);
        for i in 0..7 {
            res += GF256_NEWTON_INNER_LOOP[i] * v_powers[i];
        }
        Self::embed_exceptional_set(res.0 as usize)
    }
}

impl ResiduePolyF8Z128 {
    pub fn from_bytes(bytes: &[u8; Self::BIT_LENGTH >> 3]) -> Self {
        let mut coefs = [Z128::default(); 8];
        const Z128_SIZE_BYTE: usize = Z128::BIT_LENGTH >> 3;
        for (i, coef) in coefs.iter_mut().enumerate() {
            let curr_index = Z128_SIZE_BYTE * i;
            let mut coef_byte = [0_u8; Z128_SIZE_BYTE];
            coef_byte[..].copy_from_slice(&bytes[curr_index..curr_index + Z128_SIZE_BYTE]);
            *coef = Wrapping(u128::from_le_bytes(coef_byte));
        }
        ResiduePoly { coefs }
    }
}

impl ResiduePolyF8Z64 {
    pub fn from_bytes(bytes: &[u8; Self::BIT_LENGTH >> 3]) -> Self {
        let mut coefs = [Z64::default(); 8];
        const Z64_SIZE_BYTE: usize = Z64::BIT_LENGTH >> 3;
        for (i, coef) in coefs.iter_mut().enumerate() {
            let curr_index = Z64_SIZE_BYTE * i;
            let mut coef_byte = [0_u8; Z64_SIZE_BYTE];
            coef_byte[..].copy_from_slice(&bytes[curr_index..curr_index + Z64_SIZE_BYTE]);
            *coef = Wrapping(u64::from_le_bytes(coef_byte));
        }
        ResiduePoly { coefs }
    }
}

lazy_static! {
    static ref EXCEPTIONAL_SET_STORE_8_128: RwLock<HashMap<(usize, usize), Vec<ResiduePolyF8Z128>>> =
        RwLock::new(HashMap::new());
    static ref EXCEPTIONAL_SET_STORE_8_64: RwLock<HashMap<(usize, usize), Vec<ResiduePolyF8Z64>>> =
        RwLock::new(HashMap::new());
}

impl MemoizedExceptionals for ResiduePolyF8Z64 {
    fn calculate_powers(index: usize, degree: usize) -> anyhow::Result<Vec<Self>> {
        let point = Self::embed_exceptional_set(index)?;
        Ok(compute_powers(point, degree))
    }
    fn storage() -> &'static RwLock<HashMap<(usize, usize), Vec<Self>>> {
        &EXCEPTIONAL_SET_STORE_8_64
    }
}

impl MemoizedExceptionals for ResiduePolyF8Z128 {
    fn calculate_powers(index: usize, degree: usize) -> anyhow::Result<Vec<Self>> {
        let point = Self::embed_exceptional_set(index)?;
        Ok(compute_powers(point, degree))
    }
    fn storage() -> &'static RwLock<HashMap<(usize, usize), Vec<Self>>> {
        &EXCEPTIONAL_SET_STORE_8_128
    }
}

impl<Z> BitWiseEval<Z, 8> for BitwisePoly
where
    Z: Zero + for<'a> AddAssign<&'a Z> + Copy + Clone,
    ResiduePoly<Z, 8>: LutMulReduction<Z>,
{
    fn lazy_eval(&self, powers: &[ResiduePolyF8<Z>]) -> ResiduePolyF8<Z> {
        let mut res_coefs = [Z::ZERO; 15];
        // now we go through each
        for (coef_2, coef_r) in self.coefs().iter().zip(powers) {
            for bit_idx in 0..8 {
                if ((coef_2 >> bit_idx) & 1) == 1 {
                    for (j, cr) in coef_r.coefs.iter().enumerate() {
                        res_coefs[j + bit_idx] += cr;
                    }
                }
            }
        }
        ResiduePolyF8::<Z>::reduce_mul(&res_coefs)
    }
}
lazy_static::lazy_static! {
    static ref MONOMIALS_F8_Z64: Vec<ResiduePoly<Z64,8>> = (0..8)
        .map(|i| {
            let mut coefs_i = [Z64::ZERO; 8];
            coefs_i[i] = Z64::ONE;
            ResiduePoly::from_array(coefs_i)
        })
        .collect();

    static ref MONOMIALS_F8_Z128: Vec<ResiduePoly<Z128,8>> = (0..8)
        .map(|i| {
            let mut coefs_i = [Z128::ZERO; 8];
            coefs_i[i] = Z128::ONE;
            ResiduePoly::from_array(coefs_i)
        })
        .collect();
}

impl Monomials for ResiduePoly<Z64, 8> {
    fn monomials() -> Vec<Self> {
        MONOMIALS_F8_Z64.to_vec()
    }
}

impl Monomials for ResiduePoly<Z128, 8> {
    fn monomials() -> Vec<Self> {
        MONOMIALS_F8_Z128.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::base_ring::{Z128, Z64};
    use crate::algebra::galois_rings::common::{pack_residue_poly, TryFromWrapper};
    use crate::algebra::poly::Poly;
    use crate::algebra::structure_traits::{ErrorCorrect, Sample, Syndrome};
    use crate::execution::sharing::{
        shamir::{InputOp, RevealOp, ShamirSharings},
        share::Share,
    };
    use crate::execution::{runtime::party::Role, small_execution::prf::PRSSConversions};
    use aes_prng::AesRng;
    use itertools::Itertools;
    use paste::paste;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::collections::HashSet;
    use std::num::Wrapping;

    #[test]
    fn test_is_zero() {
        let mut rng = AesRng::seed_from_u64(0);

        let mut z128poly: ResiduePolyF8Z128 = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z128poly.is_zero());
        z128poly = ResiduePolyF8Z128::sample(&mut rng);
        assert!(!z128poly.is_zero());

        let mut z64poly: ResiduePolyF8Z64 = ResiduePoly {
            coefs: [Wrapping(0); 8],
        };
        assert!(z64poly.is_zero());
        z64poly.coefs[1] = Z64::ONE;
        assert!(!z64poly.is_zero());
    }

    macro_rules! tests_residue_poly {
        ($z:ty, $u:ty) => {
            paste! {
            #[test]
            fn [<test_bitwise_slice_ $z:lower>]() {
                let s: ResiduePolyF8<$z> = ResiduePolyF8 {
                    coefs: [
                        Wrapping(310),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                    ],
                };
                let b = s.bit_compose(1);
                assert_eq!(b, GF256::from(255));
            }

            #[test]
            fn [<test_ring_max_error_correction_ $z:lower>]() {
                let t: usize = 4;
                let max_err: usize = 3;
                let n = (t + 1) + 4 * max_err;

                let secret: ResiduePolyF8<$z> = ResiduePolyF8::<$z>::from_scalar
                (Wrapping(1000));
                let mut rng = AesRng::seed_from_u64(0);

                let mut shares = ShamirSharings::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct
                shares.shares[0] = Share::new(Role::indexed_by_zero(0),ResiduePoly::sample(&mut rng));
                shares.shares[1] = Share::new(Role::indexed_by_zero(1),ResiduePoly::sample(&mut rng));

                let recon = ResiduePolyF8::<$z>::error_correct(&shares,t, 1);
                let _ =
                    recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
            }

            #[rstest]
            #[case(Wrapping(0))]
            #[case(Wrapping(1))]
            #[case(Wrapping(10))]
            #[case(Wrapping(3213214))]
            #[case(Wrapping($u::MAX - 23) )]
            #[case(Wrapping($u::MAX - 1) )]
            #[case(Wrapping($u::MAX))]
            #[case(Wrapping(rand::Rng::gen::<$u>(&mut rand::thread_rng())))]
            fn [<test_share_reconstruct_ $z:lower>](#[case] secret: $z) {
                let threshold: usize = 5;
                let num_parties = 9;

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let sharings = ShamirSharings::<ResiduePolyF8<$z>>::share(&mut rng, residue_secret, num_parties, threshold).unwrap();
                let recon = TryFromWrapper::<$z>::try_from(sharings.reconstruct(threshold).unwrap()).unwrap();
                assert_eq!(recon.0, secret);
            }

            #[rstest]
            #[case(Wrapping(0))]
            #[case(Wrapping(1))]
            #[case(Wrapping(10))]
            #[case(Wrapping(3213214))]
            #[case(Wrapping($u::MAX - 23 ))]
            #[case(Wrapping($u::MAX - 1 ))]
            #[case(Wrapping($u::MAX))]
            #[case(Wrapping(rand::Rng::gen::<$u>(&mut rand::thread_rng())))]
            fn [<test_share_reconstruct_randomseed_ $z:lower>](#[case] secret: $z) {
                let threshold: usize = 5;
                let num_parties = 9;

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::from_entropy();
                let sharings = ShamirSharings::<ResiduePolyF8<$z>>::share(&mut rng, residue_secret, num_parties, threshold).unwrap();
                let recon = TryFromWrapper::<$z>::try_from(sharings.reconstruct(threshold).unwrap()).unwrap();
                assert_eq!(recon.0, secret);
            }

            #[rstest]
            #[case(1, 1, Wrapping(100))]
            #[case(2, 0, Wrapping(100))]
            #[case(4, 1, Wrapping(100))]
            #[case(8, 10, Wrapping(100))]
            #[case(10, 8, Wrapping(100))]
            fn [<test_ring_error_correction_ $z:lower>](#[case] t: usize, #[case] max_err: usize, #[case] secret: $z) {
                let n = (t + 1) + 2 * max_err;

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let mut sharings = ShamirSharings::<ResiduePolyF8<$z>>::share(&mut rng, residue_secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct

                for item in sharings.shares.iter_mut().take(max_err) {
                    *item = Share::new(item.owner(),ResiduePolyF8::sample(&mut rng));
                }

                let recon = ResiduePolyF8::<$z>::error_correct(&sharings,t, max_err);
                let f_zero = recon
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
            }

            #[cfg(feature = "slow_tests")]
            #[test]
            fn [<test_syndrome_decoding_large_ $z:lower>]() {
                let n = 10;
                let t = 3;
                let secret = Wrapping(123);
                let num_errs = 2;

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(2342);
                let sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();
                let party_ids = &sharings.shares.iter().map(|s| s.owner()).collect_vec();

                // verify that decoding with Gao works as a sanity check
                let decoded = ResiduePolyF8::<$z>::error_correct(&sharings, t, num_errs);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePolyF8::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // try syndrome decoding without errors
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&sharings, t).unwrap();
                let errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                assert_eq!(errors, vec![ResiduePolyF8::ZERO; n]); // should be all-zero

                // add 1 error now
                let erridx = 3;
                let mut expected_errors = vec![ResiduePolyF8::ZERO; n];
                let mut bad_shares = sharings.clone();

                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePolyF8::sample(&mut rng);
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 1 error
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);

                // add 2nd error now
                let erridx = 6;
                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePolyF8::sample(&mut rng);
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 2 errors
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, party_ids, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);
            }

            #[test]
            fn [<test_syndrome_decoding_even_odd_ $z:lower>]() {
                let n = 7;
                let t = 2;
                let secret = Wrapping(42);
                let num_errs = 2;

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(678);
                let sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();

                // verify that decoding with Gao works as a sanity check
                let decoded = ResiduePolyF8::<$z>::error_correct(&sharings, t, num_errs);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePolyF8::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // try syndrome decoding without errors
                let parties = sharings.shares.iter().map(|s| s.owner()).collect_vec();
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&sharings, t).unwrap();
                let errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                assert_eq!(errors, vec![ResiduePolyF8::ZERO; n]); // should be all-zero

                // add 1 error now
                let erridx = 3;
                let mut expected_errors = vec![ResiduePolyF8::ZERO; n];
                let mut bad_shares = sharings.clone();

                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePolyF8::from_scalar(Wrapping(53));
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 1 error where the error term is 53
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);

                // add 2nd error now
                let erridx = 5;
                for (idx, item) in bad_shares.shares.iter_mut().enumerate() {
                    if idx == erridx {
                        let errval = ResiduePolyF8::from_scalar(Wrapping(54));
                        expected_errors[idx] = errval;
                        *item = Share::new(item.owner(), item.value() + errval);
                    }
                }

                // try syndrome decoding with 2 errors where the error terms are 53 and 54
                let syndrome_poly = ResiduePolyF8::<$z>::syndrome_compute(&bad_shares, t).unwrap();
                let decoded_errors = ResiduePolyF8::<$z>::syndrome_decode(syndrome_poly, &parties, t).unwrap();
                tracing::debug!("Errors= {:?} vs. {:?}", expected_errors, decoded_errors);
                assert_eq!(expected_errors, decoded_errors);
            }

            #[test]
            fn [<test_syndrome_computation_ $z:lower>]() {
                let n = 10;
                let t = 2;
                let secret = Wrapping(123);

                let residue_secret = ResiduePolyF8::<$z>::from_scalar(secret);

                let mut rng = AesRng::seed_from_u64(0);
                let mut sharings = ShamirSharings::share(&mut rng, residue_secret, n, t).unwrap();

                // syndrome computation without errors
                let recon = ResiduePolyF8::<$z>::syndrome_compute(&sharings, t).unwrap();
                tracing::debug!("Syndrome Output = {:?}", recon);
                assert_eq!(recon, Poly::<ResiduePolyF8<$z>>::zero()); // should be zero without errors

                // add errors
                for item in sharings.shares.iter_mut().take(2) {
                    *item = Share::new(item.owner(), ResiduePolyF8::sample(&mut rng));
                }

                // verify that decoding still works
                let decoded = ResiduePolyF8::<$z>::error_correct(&sharings, t, 2);
                let f_zero = decoded
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePolyF8::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);

                // syndrome computation with errors
                let recon = ResiduePolyF8::<$z>::syndrome_compute(&sharings, t).unwrap();
                tracing::debug!("Syndrome Output = {:?}", recon);
                assert_ne!(recon, Poly::<ResiduePolyF8<$z>>::zero()); // should not be zero with errors
            }

            #[test]
            fn [<test_bit_compose_ $z:lower>]() {
                let mut input: ResiduePolyF8<$z> = ResiduePolyF8::ZERO;
                // Set the constant term to 3
                input.coefs[0] = Wrapping(3);
                let mut res = ResiduePolyF8::<$z>::bit_compose(&input, 0);
                // 3 mod 2 = 1, since it is the constant term, it will be the least significant bit
                // i.e. 1 = 0b00000001
                assert_eq!(1, res.0);

                input = ResiduePolyF8::ZERO;
                // Set degree 1 term to 100
                input.coefs[1] = Wrapping(100);
                res = ResiduePolyF8::<$z>::bit_compose(&input, 0);
                // 100 mod 2 = 0
                assert_eq!(0, res.0);

                input = ResiduePolyF8::ZERO;
                // Set degree 2 term to 1000000009
                input.coefs[2] = Wrapping(1000000009);
                res = ResiduePolyF8::<$z>::bit_compose(&input, 0);
                // 1000000009 mod 2 = 1, since it is the degree 2 term, it will be the third bit that gets set to 1, and hence the result is 2^2=2^(3-1) because of 0-indexing
                // i.e. x^2 = 0b00000100
                assert_eq!(4, res.0);
            }

            #[test]
            fn [<test_multiple_pow2_ $z:lower>]() {
                let mut s: ResiduePolyF8<$z> = ResiduePoly {
                    coefs: [
                        Wrapping(310),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                        Wrapping(210),
                    ],
                };

                //All coefs are multiple of 1 and 2 but not 2^5
                assert!(s.multiple_pow2(0));
                assert!(s.multiple_pow2(1));
                assert!(!s.multiple_pow2(5));

                //All coefs are multiple of 1 but not 2 nor 2^5
                s.coefs[0] = Wrapping(7);
                assert!(s.multiple_pow2(0));
                assert!(!s.multiple_pow2(1));
                assert!(!s.multiple_pow2(5));

                //All coefs are multiple of 1, 2, 2^5, 2^6 but not 2^7 nor 2^23
                s.coefs = [Wrapping(64); 8];
                assert!(s.multiple_pow2(0));
                assert!(s.multiple_pow2(1));
                assert!(s.multiple_pow2(5));
                assert!(s.multiple_pow2(6));
                assert!(!s.multiple_pow2(7));
                assert!(!s.multiple_pow2(23));
            }

            #[test]
            fn [<test_arithmetic_ $z:lower>]() {
                let p1 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };
                let p2 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                    ],
                };
                let mut p3 = p2;
                p3.mul_by_x();

                assert_eq!(&p1 * &p2, p3);

                // mul by x twice
                let p1 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };

                let p2 = ResiduePoly {
                    coefs: [
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ONE,
                    ],
                };
                let mut p3 = p2;
                p3.mul_by_x();
                p3.mul_by_x();

                assert_eq!(&p1 * &p2, p3);


                // 1 x 1 = 1
                let p1 = ResiduePolyF8::<$z>::ONE;
                let p2 = ResiduePolyF8::<$z>::ONE;
                let p3 = ResiduePolyF8::<$z>::ONE;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);


                // 0 x 1 = 0
                let p1 = ResiduePolyF8::<$z>::ZERO;
                let p2 = ResiduePolyF8::<$z>::ONE;
                let p3 = ResiduePolyF8::<$z>::ZERO;

                assert_eq!(&p1 * &p2, p3);
                assert_eq!(&p2 * &p1, p3);

                // rnd multiplication
                let mut rng = AesRng::seed_from_u64(0);
                let p0 = ResiduePolyF8::<$z>::ZERO;
                let prnd = ResiduePolyF8::<$z>::sample(& mut rng);
                let p1 = ResiduePolyF8::<$z>::ONE;

                assert_eq!(&p0 * &prnd, p0);
                assert_eq!(&p1 * &prnd, prnd);

                // all-1 mul by 1
                let p1 = ResiduePoly {
                    coefs: [$z::ONE; 8],
                };

                let p2 = ResiduePoly {
                    coefs: [
                        $z::ONE,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                    ],
                };
                assert_eq!(&p1 * &p2, p1);

                // mul by zero = all-zero
                let p1 = ResiduePoly {
                    coefs: [$z::ONE; 8],
                };

                let p2 = ResiduePolyF8::ZERO;
                assert_eq!(&p1 * &p2, p2);

                let p1 = ResiduePoly {
                    coefs: [$z::ONE; 8],
                };

                let p2 = ResiduePoly {
                    coefs: [$z::ONE; 8],
                };

                let p3 = ResiduePoly {
                    coefs: [
                        Wrapping($u::MAX),
                        Wrapping($u::MAX - 2),
                        Wrapping($u::MAX - 3),
                        Wrapping($u::MAX - 5),
                        Wrapping($u::MAX - 6),
                        Wrapping($u::MAX - 5),
                        Wrapping($u::MAX - 3),
                        $z::ZERO,
                    ],
                };
                assert_eq!(&p1 * &p2, p3);

                // check assign operations
                let mut p4 = ResiduePolyF8::<$z>::ONE;
                p4 *= p1;
                assert_eq!(&p1, &p4);

                let mut p5 = ResiduePolyF8::<$z>::ONE;
                p5 += p5;
                assert_eq!(p5, ResiduePolyF8::TWO);

                p5 -= p5;
                assert_eq!(p5, ResiduePolyF8::ZERO);
            }
            #[test]
            fn [<test_shift_ $z:lower>]() {
                assert_eq!(
                    ResiduePolyF8::<$z>::embed_exceptional_set(42).unwrap(),
                    ResiduePolyF8::<$z>::embed_exceptional_set(42).unwrap() << 0
                );
                assert_eq!(
                    ResiduePolyF8::<$z>::from_scalar(Wrapping(152)),
                    ResiduePolyF8::<$z>::from_scalar(Wrapping(19)) << 3
                );
                assert_eq!(
                    ResiduePolyF8::<$z>::from_scalar(Wrapping(2)),
                    ResiduePolyF8::<$z>::from_scalar(Wrapping(1)) << 1
                );
                // Observe the embedding of 2 is 0, 1, 0, 0, 0, 0, 0, 0
                assert_eq!(
                    ResiduePolyF8::<$z>::from_vec(vec![
                        $z::ZERO,
                        Wrapping(2),
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO,
                        $z::ZERO
                    ])
                    .unwrap(),
                    ResiduePolyF8::<$z>::embed_exceptional_set(2).unwrap() << 1
                );
            }
            }
        };
    }
    tests_residue_poly!(Z64, u64);
    tests_residue_poly!(Z128, u128);

    #[test]
    fn embed_sunshine() {
        let mut input: usize;
        let mut reference = ResiduePolyF8::ZERO;
        let mut res: ResiduePolyF8Z128;

        // Set the polynomial to 1+x, i.e. 0b00000011 = 3
        input = 3;
        reference.coefs[0] = Wrapping(1);
        reference.coefs[1] = Wrapping(1);
        res = ResiduePolyF8::embed_exceptional_set(input).unwrap();
        assert_eq!(reference, res);

        // Set the polynomial to x^2+x^5+x^6, i.e. 0b01100100 = 100
        input = 100;
        reference = ResiduePolyF8::ZERO;
        reference.coefs[0] = Wrapping(0);
        reference.coefs[1] = Wrapping(0);
        reference.coefs[2] = Wrapping(1);
        reference.coefs[3] = Wrapping(0);
        reference.coefs[4] = Wrapping(0);
        reference.coefs[5] = Wrapping(1);
        reference.coefs[6] = Wrapping(1);
        reference.coefs[7] = Wrapping(0);
        res = ResiduePolyF8::embed_exceptional_set(input).unwrap();
        assert_eq!(reference, res);

        // Set the polynomial to x^7, i.e. 0b10000000 = 128
        input = 128;
        reference = ResiduePolyF8::ZERO;
        reference.coefs[7] = Wrapping(1);
        res = ResiduePolyF8::embed_exceptional_set(input).unwrap();
        assert_eq!(reference, res);
    }

    #[test]
    fn two_power_sunshine() {
        let input = GF256::from(42);
        let powers = two_powers(input, 8);
        assert_eq!(8, powers.len());
        assert_eq!(42, powers[0].0);
        assert_eq!(input * input, powers[1]);
        assert_eq!(input * input * input * input, powers[2]);
        assert_eq!(
            input * input * input * input * input * input * input * input,
            powers[3]
        );
    }

    #[test]
    fn test_from_u128_chunks_z128() {
        let rpoly = ResiduePolyF8Z128::sample(&mut AesRng::seed_from_u64(0));
        let coefs = rpoly.coefs.into_iter().map(|x| x.0).collect_vec();
        let rpoly_test = ResiduePolyF8Z128::from_u128_chunks(coefs);

        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_to_from_bytes_z128() {
        let rpoly = ResiduePolyF8Z128::sample(&mut AesRng::seed_from_u64(0));
        let byte_vec: [u8; ResiduePolyF8Z128::BIT_LENGTH >> 3] =
            rpoly.to_byte_vec().try_into().unwrap();
        let rpoly_test = ResiduePolyF8Z128::from_bytes(&byte_vec);
        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_from_u128_chunks_z64() {
        let rpoly = ResiduePolyF8Z64::sample(&mut AesRng::seed_from_u64(0));
        let coefs = rpoly.coefs.into_iter().map(|x| x.0).collect_vec();
        let mut new_coefs = Vec::new();
        for coef in coefs.into_iter() {
            new_coefs.push(coef as u128);
        }
        let rpoly_test = ResiduePolyF8Z64::from_u128_chunks(new_coefs);

        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_to_from_bytes_z64() {
        let rpoly = ResiduePolyF8Z64::sample(&mut AesRng::seed_from_u64(0));
        let byte_vec: [u8; ResiduePolyF8Z64::BIT_LENGTH >> 3] =
            rpoly.to_byte_vec().try_into().unwrap();
        let rpoly_test = ResiduePolyF8Z64::from_bytes(&byte_vec);
        assert_eq!(rpoly, rpoly_test);
    }

    #[test]
    fn test_gf256_from_generator() {
        let mut hashset = HashSet::new();
        for e in GF256_FROM_GENERATOR.iter() {
            hashset.insert(*e);
        }
        //Make sure we have all 256 elements
        assert_eq!(hashset.len(), 256);
        assert_eq!(GF256_FROM_GENERATOR[255], GF256::from(0));
    }

    #[test]
    fn test_packed_polys() {
        const LEN: usize = 10;
        let mut rng = AesRng::seed_from_u64(0);
        let const_rpolys: Vec<_> = (0..10)
            .map(|_| {
                let z = Z64::sample(&mut rng);
                ResiduePolyF8Z64::from_scalar(z)
            })
            .collect();

        let packed_rpoly = pack_residue_poly(&const_rpolys);

        assert_eq!(packed_rpoly.len(), LEN.div_ceil(8));
        for i in 0..LEN {
            assert_eq!(packed_rpoly[i / 8].at(i % 8), const_rpolys[i].at(0));
        }
    }
}
