use crate::gf256::{error_correction, ShamirZ2Poly, ShamirZ2Sharing};
use crate::poly::{Poly, Ring};
use crate::residue_poly::ResiduePoly;
use crate::{Zero, Z128, Z64};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::num::Wrapping;
use std::ops::{Add, Mul, Sub};

/// This data structure holds a collection of party_ids and their corresponding Shamir shares (each a ResiduePoly<Z>)
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Debug)]
pub struct ShamirGSharings<Z> {
    pub shares: Vec<(usize, ResiduePoly<Z>)>,
}

impl<Z> ShamirGSharings<Z> {
    pub fn new() -> Self {
        ShamirGSharings { shares: Vec::new() }
    }
}

impl<Z> Add<ShamirGSharings<Z>> for ShamirGSharings<Z>
where
    ResiduePoly<Z>: Copy,
    ResiduePoly<Z>: Add<ResiduePoly<Z>, Output = ResiduePoly<Z>>,
{
    type Output = ShamirGSharings<Z>;
    fn add(self, rhs: ShamirGSharings<Z>) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .zip(&rhs.shares)
                .map(|(a, b)| {
                    assert_eq!(a.0, b.0);
                    (a.0, a.1 + b.1)
                })
                .collect(),
        }
    }
}

impl<Z> Add<&ShamirGSharings<Z>> for &ShamirGSharings<Z>
where
    ResiduePoly<Z>: Copy,
    ResiduePoly<Z>: Add<ResiduePoly<Z>, Output = ResiduePoly<Z>>,
{
    type Output = ShamirGSharings<Z>;
    fn add(self, rhs: &ShamirGSharings<Z>) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .zip(&rhs.shares)
                .map(|(a, b)| {
                    assert_eq!(a.0, b.0);
                    (a.0, a.1 + b.1)
                })
                .collect(),
        }
    }
}

impl<Z> Sub<&ShamirGSharings<Z>> for &ShamirGSharings<Z>
where
    ResiduePoly<Z>: Copy,
    ResiduePoly<Z>: Sub<ResiduePoly<Z>, Output = ResiduePoly<Z>>,
{
    type Output = ShamirGSharings<Z>;
    fn sub(self, rhs: &ShamirGSharings<Z>) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .zip(&rhs.shares)
                .map(|(a, b)| {
                    assert_eq!(a.0, b.0);
                    (a.0, a.1 - b.1)
                })
                .collect(),
        }
    }
}

impl<Z> Add<Z> for &ShamirGSharings<Z>
where
    Z: Copy,
    ResiduePoly<Z>: Add<Z, Output = ResiduePoly<Z>>,
{
    type Output = ShamirGSharings<Z>;
    fn add(self, rhs: Z) -> Self::Output {
        ShamirGSharings {
            shares: self.shares.iter().map(|s| (s.0, s.1 + rhs)).collect(),
        }
    }
}

impl<Z> Mul<&ShamirGSharings<Z>> for &ShamirGSharings<Z> {
    type Output = ShamirGSharings<Z>;
    fn mul(self, _rhs: &ShamirGSharings<Z>) -> Self::Output {
        // interactive secret-secret multiplication protocol needs to be implemented
        todo!();
    }
}

impl<Z> Mul<Z> for &ShamirGSharings<Z>
where
    Z: Copy,
    for<'l> &'l ResiduePoly<Z>: Mul<Z, Output = ResiduePoly<Z>>,
{
    type Output = ShamirGSharings<Z>;
    fn mul(self, rhs: Z) -> Self::Output {
        ShamirGSharings {
            shares: self.shares.iter().map(|s| (s.0, &s.1 * rhs)).collect(),
        }
    }
}

impl Mul<Z64> for &ShamirGSharings<Z128> {
    type Output = ShamirGSharings<Z128>;
    fn mul(self, rhs: Z64) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .map(|s| (s.0, s.1 * Wrapping(rhs.0 as u128)))
                .collect(),
        }
    }
}

impl Add<Z64> for &ShamirGSharings<Z128> {
    type Output = ShamirGSharings<Z128>;
    fn add(self, rhs: Z64) -> Self::Output {
        ShamirGSharings {
            shares: self
                .shares
                .iter()
                .map(|s| (s.0, s.1 + Wrapping(rhs.0 as u128)))
                .collect(),
        }
    }
}

macro_rules! impl_share_type {
    ($z:ty, $u:ty) => {
        impl ShamirGSharings<$z> {
            /// a share for party i is G(encode(i)) where
            /// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
            /// a_i \in Z_{2^K}/F(X) = G; deg(F) = 8
            pub fn share<R: RngCore>(
                rng: &mut R,
                secret: $z,
                num_parties: usize,
                threshold: usize,
            ) -> anyhow::Result<ShamirGSharings<$z>> {
                let embedded_secret = ResiduePoly::from_scalar(secret);
                let poly = Poly::sample_random(rng, embedded_secret, threshold);
                let shares: Vec<_> = (1..=num_parties)
                    .map(|xi| {
                        let embedded_xi = ResiduePoly::embed(xi)?;
                        Ok((xi, poly.eval(&embedded_xi)))
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;

                Ok(ShamirGSharings { shares })
            }

            pub fn reconstruct(&self, threshold: usize) -> anyhow::Result<$z> {
                self.err_reconstruct(threshold, 0)
            }

            pub fn err_reconstruct(
                &self,
                threshold: usize,
                max_error_count: usize,
            ) -> anyhow::Result<$z> {
                let recon = self.decode(threshold, max_error_count)?;
                let f_zero = recon.eval(&ResiduePoly::ZERO);
                f_zero.to_scalar()
            }

            pub fn decode(
                &self,
                threshold: usize,
                max_error_count: usize,
            ) -> anyhow::Result<Poly<ResiduePoly<$z>>> {
                // threshold is the degree of the shamir polynomial
                let ring_size: usize = <$z>::EL_BIT_LENGTH;

                let mut y: Vec<_> = self.shares.iter().map(|x| x.1).collect();
                let parties: Vec<_> = self.shares.iter().map(|x| x.0).collect();
                let mut ring_polys = Vec::new();

                for bit_idx in 0..ring_size {
                    let z: Vec<ShamirZ2Sharing> = parties
                        .iter()
                        .zip(y.iter())
                        .map(|(party_id, sh)| ShamirZ2Sharing {
                            share: sh.bit_compose(bit_idx),
                            party_id: *party_id as u8,
                        })
                        .collect();

                    // apply error correction on z
                    // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
                    let fi_mod2 = error_correction(&z, threshold, max_error_count)?;
                    let fi = ResiduePoly::<$z>::shamir_bit_lift(&fi_mod2, bit_idx)?;

                    // compute fi(\gamma_1) ..., fi(\gamma_n) \in GF(256)
                    let ring_eval: Vec<ResiduePoly<$z>> = parties
                        .iter()
                        .map(|party_id| {
                            let embedded_xi = ResiduePoly::embed(*party_id)?;
                            Ok(fi.eval(&embedded_xi))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;

                    ring_polys.push(fi);

                    // remove LSBs computed from error correction in GF(256)
                    for (j, item) in y.iter_mut().enumerate() {
                        *item -= ring_eval[j];
                    }

                    // check that LSBs were removed correctly
                    let _errs: Vec<_> = y
                        .iter()
                        .map(|yj| {
                            // see if yj is divisible by 2^{i+1}
                            // different (and more expensive) check if we want to check divisibility by 2^{128} due to overflow
                            // bitwise operation to check that 2^{i+1} | yj
                            yj.multiple_pow2(bit_idx + 1)
                        })
                        .collect();
                }

                let result = ring_polys
                    .into_iter()
                    .fold(Poly::<ResiduePoly<$z>>::zero(), |acc, x| acc + x);
                Ok(result)
            }
        }

        impl ResiduePoly<$z> {
            pub fn shamir_bit_lift(
                x: &ShamirZ2Poly,
                pos: usize,
            ) -> anyhow::Result<Poly<ResiduePoly<$z>>> {
                let coefs: Vec<ResiduePoly<$z>> = x
                    .coefs
                    .iter()
                    .map(|coef_2| Self::bit_lift(*coef_2, pos))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok(Poly::from_coefs(coefs))
            }
        }
    };
}

impl_share_type!(Z128, u128);
impl_share_type!(Z64, u64);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sample;
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use rstest::rstest;
    use std::num::Wrapping;

    macro_rules! tests_poly_shamir {
        ($z:ty, $u:ty) => {
            paste! {
            #[test]
            fn [<test_ring_max_error_correction_ $z:lower>]() {
                let t: usize = 4;
                let max_err: usize = 3;
                let n = (t + 1) + 4 * max_err;

                let secret: $z = Wrapping(1000);
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let mut shares = ShamirGSharings::<$z>::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct
                shares.shares[0].1 = ResiduePoly::sample(&mut rng);
                shares.shares[1].1 = ResiduePoly::sample(&mut rng);

                let recon = shares.decode(t, 1);
                let _ =
                    recon.expect_err("Unable to correct. Too many errors given a smaller max_err_count");
            }

            #[test]
            fn [<test_arith_const_add2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let sharings = ShamirGSharings::<$z>::share(&mut rng, Wrapping(23), 9, 5).unwrap();

                let sumsharing = &sharings + Wrapping(2 as $u);

                let recon = sumsharing.reconstruct(5).unwrap();
                assert_eq!(recon, Wrapping(25));
            }

            #[test]
            fn [<test_arith_const_mul2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let sharings = ShamirGSharings::<$z>::share(&mut rng, Wrapping(23), 9, 5).unwrap();

                let sumsharing = &sharings * Wrapping(2 as $u);

                let recon = sumsharing.reconstruct(5).unwrap();
                assert_eq!(recon, Wrapping(46));
            }

            #[test]
            fn [<test_shamir_arithmetic_2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a: $z = Wrapping(23);
                let secret_b: $z = Wrapping(42);
                let secret_c: $z = Wrapping(29);

                let mut sharings_a = ShamirGSharings::<$z>::share(&mut rng, secret_a, 9, 5).unwrap();
                let mut sharings_b = ShamirGSharings::<$z>::share(&mut rng, secret_b, 9, 5).unwrap();
                let sharings_c = ShamirGSharings::<$z>::share(&mut rng, secret_c, 9, 5).unwrap();

                sharings_a = &sharings_a + Wrapping(3 as $u);
                sharings_b = &sharings_b * Wrapping(3 as $u);

                // add the shares before reconstructing
                let mut sumsharing = sharings_a + sharings_b;

                sumsharing = &sumsharing - &sharings_c;

                let recon = sumsharing.reconstruct(5).unwrap();
                assert_eq!(recon, Wrapping(123));
            }

            #[test]
            fn [<test_shamir_g_arithmetic_add_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a: $z = Wrapping(23);
                let secret_b: $z = Wrapping(42);

                let sharings_a = ShamirGSharings::<$z>::share(&mut rng, secret_a, 9, 5).unwrap();
                let sharings_b = ShamirGSharings::<$z>::share(&mut rng, secret_b, 9, 5).unwrap();

                let sumsharing = &sharings_a + &sharings_b;

                let recon = sumsharing.reconstruct(5).unwrap();
                assert_eq!(recon, Wrapping(23 + 42));
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

                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let sharings = ShamirGSharings::<$z>::share(&mut rng, secret, num_parties, threshold).unwrap();
                let recon = sharings.reconstruct(threshold).unwrap();
                assert_eq!(recon, secret);
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

                let mut rng = ChaCha12Rng::from_entropy();
                let sharings = ShamirGSharings::<$z>::share(&mut rng, secret, num_parties, threshold).unwrap();
                let recon = sharings.reconstruct(threshold).unwrap();
                assert_eq!(recon, secret);
            }

            #[rstest]
            #[case(1, 1, Wrapping(100))]
            #[case(2, 0, Wrapping(100))]
            #[case(4, 1, Wrapping(100))]
            #[case(8, 10, Wrapping(100))]
            #[case(10, 8, Wrapping(100))]
            fn [<test_ring_error_correction_ $z:lower>](#[case] t: usize, #[case] max_err: usize, #[case] secret: $z) {
                let n = (t + 1) + 2 * max_err;

                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let mut sharings = ShamirGSharings::<$z>::share(&mut rng, secret, n, t).unwrap();
                // t+1 to reconstruct a degree t polynomial
                // for each error we need to add in 2 honest shares to reconstruct

                for item in sharings.shares.iter_mut().take(max_err) {
                    item.1 = ResiduePoly::sample(&mut rng);
                }

                let recon = sharings.decode(t, max_err);
                let f_zero = recon
                    .expect("Unable to correct. Too many errors.")
                    .eval(&ResiduePoly::ZERO);
                assert_eq!(f_zero.to_scalar().unwrap(), secret);
            }
        }
    }
}

    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);
}
