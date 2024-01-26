use super::share::Share;
use crate::algebra::poly::Poly;
use crate::execution::runtime::party::Role;
use crate::{algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log};
use rand::RngCore;
use std::ops::{Add, Mul, Sub};

///Trait required to be able to reconstruct a shamir sharing
pub trait ShamirRing: Ring {
    fn decode(
        sharing: &ShamirSharing<Self>,
        threshold: usize,
        max_correctable_errs: usize,
    ) -> anyhow::Result<Poly<Self>>;
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self>;
    ///***Calling invert on a non-invertible element of the ring results in undefined behavior***
    fn invert(self) -> anyhow::Result<Self>;
    fn syndrome_decode(
        syndrome_poly: Poly<Self>,
        parties: &[Role],
        threshold: usize,
    ) -> anyhow::Result<Vec<Self>>;
    fn syndrome_compute(
        sharing: &ShamirSharing<Self>,
        threshold: usize,
    ) -> anyhow::Result<Poly<Self>>;
}
/// This data structure holds a collection of party_ids and their corresponding Shamir shares (each a ResiduePoly<Z>)
#[derive(Clone, Default, PartialEq, Debug)]
pub struct ShamirSharing<Z: Ring> {
    pub shares: Vec<Share<Z>>,
}

impl<Z: Ring> ShamirSharing<Z> {
    pub fn new() -> Self {
        ShamirSharing { shares: Vec::new() }
    }

    //Create from shares
    pub fn create(mut shares: Vec<Share<Z>>) -> Self {
        //Sort to aid memoization of lagrange polynomials
        shares.sort_by_cached_key(|share| share.owner());
        ShamirSharing { shares }
    }

    //Add a single share in the correct spot to keep ordering
    pub fn add_share(&mut self, share: Share<Z>) -> anyhow::Result<()> {
        match self
            .shares
            .binary_search_by_key(&share.owner(), |s| s.owner())
        {
            Ok(_pos) => Err(anyhow_error_and_log(
                "Trying to insert two shares for the same player".to_string(),
            )),
            Err(pos) => {
                self.shares.insert(pos, share);
                Ok(())
            }
        }
    }
}

impl<Z: Ring> Add<ShamirSharing<Z>> for ShamirSharing<Z> {
    type Output = ShamirSharing<Z>;
    fn add(self, rhs: ShamirSharing<Z>) -> Self::Output {
        ShamirSharing {
            shares: self
                .shares
                .into_iter()
                .zip(rhs.shares)
                .map(|(a, b)| a + b)
                .collect(),
        }
    }
}

impl<Z: Ring> Add<&ShamirSharing<Z>> for &ShamirSharing<Z> {
    type Output = ShamirSharing<Z>;
    fn add(self, rhs: &ShamirSharing<Z>) -> Self::Output {
        ShamirSharing {
            shares: self
                .shares
                .iter()
                .zip(rhs.shares.iter())
                .map(|(a, b)| {
                    assert_eq!(a.owner(), b.owner());
                    Share::new(a.owner(), a.value() + b.value())
                })
                .collect(),
        }
    }
}

impl<Z: Ring> Sub<&ShamirSharing<Z>> for &ShamirSharing<Z> {
    type Output = ShamirSharing<Z>;
    fn sub(self, rhs: &ShamirSharing<Z>) -> Self::Output {
        ShamirSharing {
            shares: self
                .shares
                .iter()
                .zip(rhs.shares.iter())
                .map(|(a, b)| {
                    assert_eq!(a.owner(), b.owner());
                    Share::new(a.owner(), a.value() - b.value())
                })
                .collect(),
        }
    }
}

impl<Z: Ring> Add<Z> for &ShamirSharing<Z> {
    type Output = ShamirSharing<Z>;
    fn add(self, rhs: Z) -> Self::Output {
        ShamirSharing {
            shares: self
                .shares
                .iter()
                .map(|s| Share::new(s.owner(), s.value() + rhs))
                .collect(),
        }
    }
}

impl<Z: Ring> Mul<Z> for &ShamirSharing<Z> {
    type Output = ShamirSharing<Z>;
    fn mul(self, rhs: Z) -> Self::Output {
        ShamirSharing {
            shares: self
                .shares
                .iter()
                .map(|s| Share::new(s.owner(), s.value() * rhs))
                .collect(),
        }
    }
}

impl<Z: ShamirRing> ShamirSharing<Z> {
    /// a share for party i is G(encode(i)) where
    /// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
    /// a_i \in Z_{2^K}/F(X) = G; deg(F) = 8
    pub fn share<R: RngCore>(
        rng: &mut R,
        secret: Z,
        num_parties: usize,
        threshold: usize,
    ) -> anyhow::Result<ShamirSharing<Z>> {
        let poly = Poly::sample_random_with_fixed_constant(rng, secret, threshold);
        let shares: Vec<_> = (1..=num_parties)
            .map(|xi| {
                let embedded_xi = Z::embed_exceptional_set(xi)?;
                Ok(Share::new(
                    Role::indexed_by_one(xi),
                    poly.eval(&embedded_xi),
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(ShamirSharing { shares })
    }
    pub fn reconstruct(&self, threshold: usize) -> anyhow::Result<Z> {
        self.err_reconstruct(threshold, 0)
    }

    pub fn err_reconstruct(
        &self,
        threshold: usize,
        max_correctable_errs: usize,
    ) -> anyhow::Result<Z> {
        let recon = Z::decode(self, threshold, max_correctable_errs)?;
        Ok(recon.eval(&Z::ZERO))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::residue_poly::{ResiduePoly, TryFromWrapper};
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;
    use std::num::Wrapping;

    macro_rules! tests_poly_shamir {
        ($z:ty, $u:ty) => {
            paste! {
            #[test]
            fn [<test_arith_const_add2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);
                let secret : ResiduePoly<$z> = ResiduePoly::<$z>::from_scalar(Wrapping(23));
                let sharings = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret, 9, 5).unwrap();

                let sumsharing = &sharings + ResiduePoly::<$z>::from_scalar(Wrapping(2 as $u));

                let recon : TryFromWrapper<$z> = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();

                assert_eq!(recon.0, Wrapping(25));

            }

            #[test]
            fn [<test_arith_const_mul2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret : ResiduePoly<$z> = ResiduePoly::<$z>::from_scalar(Wrapping(23));
                let sharings = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret, 9, 5).unwrap();

                let sumsharing = &sharings * ResiduePoly::<$z>::from_scalar(Wrapping(2 as $u));

                //let recon = $z::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                let recon : TryFromWrapper<$z> = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(46));
            }

            #[test]
            fn [<test_shamir_arithmetic_2_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a = ResiduePoly::<$z>::from_scalar(Wrapping(23));
                let secret_b = ResiduePoly::<$z>::from_scalar(Wrapping(42));
                let secret_c = ResiduePoly::<$z>::from_scalar(Wrapping(29));

                let mut sharings_a = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret_a, 9, 5).unwrap();
                let mut sharings_b = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret_b, 9, 5).unwrap();
                let sharings_c = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret_c, 9, 5).unwrap();

                sharings_a = &sharings_a + ResiduePoly::<$z>::from_scalar(Wrapping(3 as $u));
                sharings_b = &sharings_b * ResiduePoly::<$z>::from_scalar(Wrapping(3 as $u));

                // add the shares before reconstructing
                let mut sumsharing = sharings_a + sharings_b;

                sumsharing = &sumsharing - &sharings_c;

                let recon = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(123));
            }

            #[test]
            fn [<test_shamir_g_arithmetic_add_ $z:lower>]() {
                let mut rng = ChaCha12Rng::seed_from_u64(0);

                let secret_a = ResiduePoly::<$z>::from_scalar(Wrapping(23));
                let secret_b = ResiduePoly::<$z>::from_scalar(Wrapping(42));

                let sharings_a = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret_a, 9, 5).unwrap();
                let sharings_b = ShamirSharing::<ResiduePoly<$z>>::share(&mut rng, secret_b, 9, 5).unwrap();

                let sumsharing = &sharings_a + &sharings_b;

                let recon = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(23 + 42));
            }
        }
    }
}

    use crate::algebra::base_ring::{Z128, Z64};
    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);
}
