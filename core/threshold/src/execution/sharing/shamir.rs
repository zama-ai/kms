use super::share::Share;
use crate::algebra::poly::Poly;
use crate::algebra::structure_traits::{ErrorCorrect, Ring, RingWithExceptionalSequence};
use crate::error::error_handler::anyhow_error_and_warn_log;
use crate::execution::runtime::party::Role;
use itertools::EitherOrBoth::{Both, Left, Right};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::ops::{Add, Mul, Sub};

pub trait HenselLiftInverse: Sized {
    fn invert(self) -> anyhow::Result<Self>;
}

/// This data structure holds a collection of party_ids and their corresponding Shamir shares
#[derive(Clone, Default, PartialEq, Debug)]
pub struct ShamirSharings<Z: Ring> {
    pub shares: Vec<Share<Z>>,
}

pub type ShamirFieldPoly<F> = Poly<F>;

impl<Z: Ring> ShamirSharings<Z> {
    pub fn new() -> Self {
        ShamirSharings { shares: Vec::new() }
    }

    //Create from shares
    pub fn create(mut shares: Vec<Share<Z>>) -> Self {
        //Sort to aid memoization of lagrange polynomials
        shares.sort_by_cached_key(|share| share.owner());
        ShamirSharings { shares }
    }

    /// Add a single share in the correct spot to keep ordering
    /// If a share for the same party already exists, we replace it.
    /// WARNING: When calling this function, be sure that the Role is trusted!
    pub fn add_share(&mut self, share: Share<Z>) {
        match self
            .shares
            .binary_search_by_key(&share.owner(), |s| s.owner())
        {
            Ok(pos) => {
                tracing::warn!("Replacing a share for {}", share.owner());
                self.shares[pos] = share
            }
            Err(pos) => self.shares.insert(pos, share),
        }
    }
}

impl<Z: Ring> Add<ShamirSharings<Z>> for ShamirSharings<Z> {
    type Output = ShamirSharings<Z>;
    fn add(self, rhs: ShamirSharings<Z>) -> Self::Output {
        let pair = self.shares.into_iter().zip_longest(rhs.shares);
        ShamirSharings {
            shares: pair
                .map(|cur| {
                    match cur {
                        Both(a, b) => a + b,
                        // If only one side has a share, we interpret the other side as zero
                        Left(a) => a,
                        Right(b) => b,
                    }
                })
                .collect_vec(),
        }
    }
}

impl<Z: Ring> Add<&ShamirSharings<Z>> for &ShamirSharings<Z> {
    type Output = ShamirSharings<Z>;
    fn add(self, rhs: &ShamirSharings<Z>) -> Self::Output {
        let pair = self.shares.iter().zip_longest(rhs.shares.iter());
        ShamirSharings {
            shares: pair
                .map(|cur| {
                    match cur {
                        Both(a, b) => {
                            assert_eq!(a.owner(), b.owner());
                            Share::new(a.owner(), a.value() + b.value())
                        }
                        // If only one side has a share, we interpret the other side as zero
                        Left(a) => Share::new(a.owner(), a.value()),
                        Right(b) => Share::new(b.owner(), b.value()),
                    }
                })
                .collect_vec(),
        }
    }
}

impl<Z: Ring> Sub<&ShamirSharings<Z>> for &ShamirSharings<Z> {
    type Output = ShamirSharings<Z>;
    fn sub(self, rhs: &ShamirSharings<Z>) -> Self::Output {
        let pair = self.shares.iter().zip_longest(rhs.shares.iter());
        ShamirSharings {
            shares: pair
                .map(|cur| {
                    match cur {
                        Both(a, b) => {
                            assert_eq!(a.owner(), b.owner());
                            Share::new(a.owner(), a.value() - b.value())
                        }
                        // If only one side has a share, we interpret the other side as zero
                        Left(a) => Share::new(a.owner(), a.value()),
                        Right(b) => Share::new(b.owner(), b.value()),
                    }
                })
                .collect_vec(),
        }
    }
}

impl<Z: Ring> Add<Z> for &ShamirSharings<Z> {
    type Output = ShamirSharings<Z>;
    fn add(self, rhs: Z) -> Self::Output {
        ShamirSharings {
            shares: self
                .shares
                .iter()
                .map(|s| Share::new(s.owner(), s.value() + rhs))
                .collect(),
        }
    }
}

impl<Z: Ring> Mul<Z> for &ShamirSharings<Z> {
    type Output = ShamirSharings<Z>;
    fn mul(self, rhs: Z) -> Self::Output {
        ShamirSharings {
            shares: self
                .shares
                .iter()
                .map(|s| Share::new(s.owner(), s.value() * rhs))
                .collect(),
        }
    }
}

pub trait InputOp<T> {
    /// a share for party i is G(encode(i)) where
    /// G(X) = a_0 + a_1 * X + ... + a_{t-1} * X^{t-1}
    /// a_i \in Z_{2^K}/F(X) = G; deg(F) = 8
    fn share<R: Rng + CryptoRng>(
        rng: &mut R,
        secret: T,
        num_parties: usize,
        threshold: usize,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;
}

impl<Z> InputOp<Z> for ShamirSharings<Z>
where
    Z: RingWithExceptionalSequence,
{
    //NIST: Level Zero Operation
    fn share<R: Rng + CryptoRng>(
        rng: &mut R,
        secret: Z,
        num_parties: usize,
        threshold: usize,
    ) -> anyhow::Result<Self> {
        if threshold >= num_parties {
            anyhow::bail!(
                "number of parties {num_parties} must be strictly bigger than the threshold {threshold}"
            );
        }
        let role_with_embeddings = (1..=num_parties)
            .map(|party_id| {
                let party = Role::indexed_from_one(party_id);
                let embedding = Z::embed_role_to_exceptional_sequence(&party)?;
                Ok((party, embedding))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let poly = Poly::sample_random_with_fixed_constant(rng, secret, threshold);
        let shares: Vec<_> = role_with_embeddings
            .into_iter()
            .map(|(role, embedded_role)| Share::new(role, poly.eval(&embedded_role)))
            .collect::<Vec<_>>();

        Ok(ShamirSharings { shares })
    }
}

pub trait RevealOp<Z> {
    fn reconstruct(&self, degree: usize) -> anyhow::Result<Z> {
        self.err_reconstruct(degree, 0)
    }

    fn err_reconstruct(&self, degree: usize, max_errs: usize) -> anyhow::Result<Z>;
}

impl<Z> RevealOp<Z> for ShamirSharings<Z>
where
    Z: ErrorCorrect,
{
    fn err_reconstruct(&self, degree: usize, max_errs: usize) -> anyhow::Result<Z> {
        let recon = <Z as ErrorCorrect>::error_correct(self, degree, max_errs)?;
        Ok(recon.eval(&Z::ZERO))
    }
}

/// Maps `values` into [ShamirSharings]s by pairwise adding each of these to each of the `sharings`.
/// Furthermore, adds a zero-share for each share in `sharings` if there is not supplied enough `values`,
/// and discard extra shares if too many are given.
/// This in turn means that there will be `num_values` shares in `sharings`.
/// The function is useful to ensure that an indexable vector of Shamir shares exist.
pub fn fill_indexed_shares<Z: Ring>(
    sharings: &mut [ShamirSharings<Z>],
    mut values: Vec<Z>,
    num_values: usize,
    party_id: Role,
) {
    if values.len() < num_values {
        tracing::warn!(
            "Received {} values from party {} but expected {}. Filling with 0s",
            values.len(),
            party_id,
            num_values
        );
    } else if values.len() > num_values {
        tracing::warn!(
            "Received more values than expected from party {}. Ignoring extra values.",
            party_id
        );
    }

    values.resize(num_values, Z::ZERO);

    // Use zip_eq as we just resized the values received to the expected length
    let pair = values.into_iter().zip_eq(sharings.iter_mut());
    for (v, sharing) in pair {
        sharing.add_share(Share::new(party_id, v));
    }
}

/// Core algorithm for robust reconstructions which tries to reconstruct from a collection of shares
/// in a sync network
/// Takes as input:
/// - num_parties as number of parties
/// - degree as the degree of the sharing (usually either t or 2t)
/// - threshold as the threshold of maximum corruptions
/// - num_bots as the number of known Bot (known wrong/empty values) contributions
/// - indexed_shares as the indexed shares of the parties
///
/// Returns either the result or None if there are not enough shares to do reconstruction yet
/// This assumes that sharing contains all the shares the current party know of, including its own if relevant
/// thus we always perform the check "case B".
pub fn reconstruct_w_errors_sync<Z>(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    num_bots: usize,
    sharing: &ShamirSharings<Z>,
) -> anyhow::Result<Option<Z>>
where
    Z: Ring + ErrorCorrect,
    ShamirSharings<Z>: RevealOp<Z>,
{
    //We've heard from parties we have shares for + parties that contributed Bot shares
    let num_heard_from = sharing.shares.len() + num_bots;
    //Make sure we have enough shares already to try and reconstrcut
    if degree + 2 * threshold < num_parties && num_heard_from > degree + 2 * threshold {
        // the maximum number of errors we can correct is threshold minus the number of bots
        // max_errs = threshold - num_bots
        let max_errs = threshold.checked_sub(num_bots).ok_or_else(|| {
            anyhow_error_and_warn_log(format!(
                "Underflow in reconstruction computing max_errs:  num_bots ({num_bots}) > threshold ({threshold})"
            ))
        })?;

        let opened = sharing.err_reconstruct(degree, max_errs)?;
        return Ok(Some(opened));
    }

    //Make sure there's hope to ever have enough shares to try and reconstruct
    if degree + 2 * threshold >= num_parties {
        return Err(anyhow_error_and_warn_log(format!("Can NOT reconstruct with {} shares, degree {degree}, threshold {threshold} and num_parties {num_parties}", sharing.shares.len())));
    }

    // Not enough shares to reconstruct (yet)
    Ok(None)
}

/// Core algorithm for robust reconstructions which tries to reconstruct from a collection of shares
/// in an async network
/// Takes as input:
/// - num_parties as number of parties
/// - degree as the degree of the sharing (i.e. the corruption threshold)
/// - threshold as the threshold of maximum corruptions
/// - num_bots as the number of known Bot contributions
/// - indexed_shares as the indexed shares of the parties
///
///  Returns either the result or None if there are not enough shares to do reconstruction yet
/// This assumes that sharing contains all the shares the current party know of, including its own if relevant
/// thus we always perform the check "case B".
pub fn reconstruct_w_errors_async<Z>(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    num_bots: usize,
    sharing: &ShamirSharings<Z>,
) -> anyhow::Result<Option<Z>>
where
    Z: Ring + ErrorCorrect,
    ShamirSharings<Z>: RevealOp<Z>,
{
    //We've heard from parties we have shares for + parties that contributed Bot shares
    let num_heard_from = sharing.shares.len() + num_bots;
    if degree + 3 * threshold < num_parties {
        if num_heard_from > degree + 2 * threshold {
            // max_errs = threshold - num_bots
            let max_errs = threshold.checked_sub(num_bots).ok_or_else(|| {
                anyhow_error_and_warn_log(format!(
                "Underflow in reconstruction computing max_errs:  num_bots ({num_bots}) > threshold ({threshold})"
            ))
            })?;
            let opened = sharing.err_reconstruct(degree, max_errs)?;
            Ok(Some(opened))
        } else {
            //We do not have enough shares yet
            Ok(None)
        }
    } else if degree + 2 * threshold < num_parties {
        if num_heard_from > degree + threshold {
            let r: usize = num_heard_from - (degree + threshold + 1);
            let opened_poly = Z::error_correct(sharing, degree, r);
            if let Ok(opened_poly) = opened_poly {
                if opened_poly.deg() <= degree {
                    //Note: Not entirely certain we really need all this checking mechanism.
                    //If error_correct succeeded, why isnt it enough?

                    //Check how many shares lie on the polynomial
                    let mut num_shares_on_poly = 0;
                    for share in sharing.shares.iter() {
                        if share.value()
                            == opened_poly
                                .eval(&Z::embed_role_to_exceptional_sequence(&share.owner())?)
                        {
                            num_shares_on_poly += 1;
                        }

                        //If enough, return the result
                        if num_shares_on_poly > degree + threshold {
                            return Ok(Some(opened_poly.eval(&(Z::ZERO))));
                        }
                    }
                    //If we havent returned, we do not have enough shares yet
                    Ok(None)
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        } else {
            //We do not have enough shares yet
            Ok(None)
        }
    //Make sure there's hope to ever have enough shares to try and reconstruct
    } else {
        Err(anyhow_error_and_warn_log(format!("Can NOT reconstruct with degree {degree}, threshold {threshold} and num_parties {num_parties}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        algebra::galois_rings::{
            common::{pack_residue_poly, TryFromWrapper},
            degree_4::ResiduePolyF4,
        },
        tests::randomness_check::execute_all_randomness_tests_tight,
    };
    use aes_prng::AesRng;
    use num_traits::FromPrimitive;
    use paste::paste;
    use proptest::prelude::*;
    use rand::SeedableRng;
    use std::num::Wrapping;

    macro_rules! tests_poly_shamir {
        ($z:ty, $u:ty) => {
            paste! {
            #[test]
            fn [<test_arith_const_add2_ $z:lower>]() {
                let mut rng = AesRng::seed_from_u64(0);
                let secret : ResiduePolyF4<$z> = ResiduePolyF4::<$z>::from_scalar(Wrapping(23));
                let sharings = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret, 9, 5).unwrap();

                let sumsharing = &sharings + ResiduePolyF4::<$z>::from_scalar(Wrapping(2 as $u));

                let recon : TryFromWrapper<$z> = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();

                assert_eq!(recon.0, Wrapping(25));

            }

            #[test]
            fn [<test_arith_const_mul2_ $z:lower>]() {
                let mut rng = AesRng::seed_from_u64(0);

                let secret : ResiduePolyF4<$z> = ResiduePolyF4::<$z>::from_scalar(Wrapping(23));
                let sharings = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret, 9, 5).unwrap();

                let sumsharing = &sharings * ResiduePolyF4::<$z>::from_scalar(Wrapping(2 as $u));

                //let recon = $z::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                let recon : TryFromWrapper<$z> = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(46));
            }

            #[test]
            fn [<test_shamir_arithmetic_2_ $z:lower>]() {
                let mut rng = AesRng::seed_from_u64(0);

                let secret_a = ResiduePolyF4::<$z>::from_scalar(Wrapping(23));
                let secret_b = ResiduePolyF4::<$z>::from_scalar(Wrapping(42));
                let secret_c = ResiduePolyF4::<$z>::from_scalar(Wrapping(29));

                let mut sharings_a = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret_a, 9, 5).unwrap();
                let mut sharings_b = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret_b, 9, 5).unwrap();
                let sharings_c = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret_c, 9, 5).unwrap();

                sharings_a = &sharings_a + ResiduePolyF4::<$z>::from_scalar(Wrapping(3 as $u));
                sharings_b = &sharings_b * ResiduePolyF4::<$z>::from_scalar(Wrapping(3 as $u));

                // add the shares before reconstructing
                let mut sumsharing = sharings_a + sharings_b;

                sumsharing = &sumsharing - &sharings_c;

                let recon = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(123));
            }

            #[test]
            fn [<test_shamir_g_arithmetic_add_ $z:lower>]() {
                let mut rng = AesRng::seed_from_u64(0);

                let secret_a = ResiduePolyF4::<$z>::from_scalar(Wrapping(23));
                let secret_b = ResiduePolyF4::<$z>::from_scalar(Wrapping(42));

                let sharings_a = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret_a, 9, 5).unwrap();
                let sharings_b = ShamirSharings::<ResiduePolyF4<$z>>::share(&mut rng, secret_b, 9, 5).unwrap();

                let sumsharing = &sharings_a + &sharings_b;

                let recon = TryFromWrapper::<$z>::try_from(sumsharing.reconstruct(5).unwrap()).unwrap();
                assert_eq!(recon.0, Wrapping(23 + 42));
            }
        }}
    }

    use crate::algebra::base_ring::{Z128, Z64};
    tests_poly_shamir!(Z64, u64);
    tests_poly_shamir!(Z128, u128);

    #[test]
    fn test_async_reconstruct() {
        let mut rng = AesRng::seed_from_u64(0);
        let num_parties = 10;
        let threshold = 3;

        let secret = ResiduePolyF4::<Z128>::from_scalar(Wrapping(23));

        let sharings =
            ShamirSharings::<ResiduePolyF4<Z128>>::share(&mut rng, secret, num_parties, threshold)
                .unwrap();

        let opened = reconstruct_w_errors_async(num_parties, threshold, threshold, 0, &sharings)
            .unwrap()
            .unwrap();

        assert_eq!(opened, secret);
    }

    #[test]
    fn test_adversarial_async_reconstruct() {
        let mut rng = AesRng::seed_from_u64(0);
        let num_parties = 10;
        let threshold = 3;

        let secret = ResiduePolyF4::<Z128>::from_scalar(Wrapping(23));

        let sharings =
            ShamirSharings::<ResiduePolyF4<Z128>>::share(&mut rng, secret, num_parties, threshold)
                .unwrap();

        let adv_target = ResiduePolyF4::<Z128>::from_scalar(Wrapping(32));
        let adv_sharings = ShamirSharings::<ResiduePolyF4<Z128>>::share(
            &mut rng,
            adv_target,
            num_parties,
            threshold,
        )
        .unwrap();

        //Start with all adversary contributions
        let mut contribution = adv_sharings.shares[0..threshold].to_vec();

        //Gradually add honest contributions
        //We expect not to be able to decode without all the shares
        //as the adversary as contributed as much as it can
        for i in threshold..3 * threshold {
            contribution.push(sharings.shares[i]);
            let faulty_shares = ShamirSharings::create(contribution.clone());
            let opened =
                reconstruct_w_errors_async(num_parties, threshold, threshold, 0, &faulty_shares)
                    .unwrap();

            assert!(opened.is_none());
        }

        //With all shares we should be able to decode
        contribution.push(*sharings.shares.last().unwrap());
        let shares = ShamirSharings::create(contribution.clone());
        let opened = reconstruct_w_errors_async(num_parties, threshold, threshold, 0, &shares)
            .unwrap()
            .unwrap();

        assert_eq!(opened, secret);
    }

    proptest! {
        #[test]
        fn test_packed_sharing_reconstruct_sunshine_128(s1: u128, s2: u128) {
            test_packed_sharing_reconstruct(
                Z128::from_u128(s1).unwrap(), Z128::from_u128(s2).unwrap(), false
            );
        }

        #[test]
        fn test_packed_sharing_reconstruct_with_error_128(s1: u128, s2: u128) {
            test_packed_sharing_reconstruct(
                Z128::from_u128(s1).unwrap(), Z128::from_u128(s2).unwrap(), true
            );
        }

        #[test]
        fn test_packed_sharing_reconstruct_sunshine_64(s1: u64, s2: u64) {
            test_packed_sharing_reconstruct(
                Z64::from_u64(s1).unwrap(), Z64::from_u64(s2).unwrap(), false
            );
        }

        #[test]
        fn test_packed_sharing_reconstruct_with_error_64(s1: u64, s2: u64) {
            test_packed_sharing_reconstruct(
                Z64::from_u64(s1).unwrap(), Z64::from_u64(s2).unwrap(), true
            );
        }
    }

    fn test_packed_sharing_reconstruct<Z: crate::algebra::structure_traits::BaseRing>(
        s1: Z,
        s2: Z,
        add_error: bool,
    ) where
        ResiduePolyF4<Z>: crate::algebra::error_correction::MemoizedExceptionals,
        ResiduePolyF4<Z>: crate::algebra::galois_rings::common::Monomials,
    {
        let mut rng = AesRng::seed_from_u64(0);
        let num_parties = 4;
        let threshold = 1;

        // only secret share const polynomial
        let secret1 = ResiduePolyF4::<Z>::from_scalar(s1);
        let secret2 = ResiduePolyF4::<Z>::from_scalar(s2);

        let block1_shares =
            ShamirSharings::<ResiduePolyF4<Z>>::share(&mut rng, secret1, num_parties, threshold)
                .unwrap()
                .shares
                .into_iter()
                .map(|x| x.value())
                .collect::<Vec<_>>();

        let block2_shares =
            ShamirSharings::<ResiduePolyF4<Z>>::share(&mut rng, secret2, num_parties, threshold)
                .unwrap()
                .shares
                .into_iter()
                .map(|x| x.value())
                .collect::<Vec<_>>();

        // shares of party i
        let collected_shares = (0..num_parties)
            .map(|i| vec![block1_shares[i], block2_shares[i]])
            .collect::<Vec<_>>();

        // packed shares of party i
        let packed_shares = (0..num_parties)
            .map(|i| pack_residue_poly(&collected_shares[i]))
            .collect::<Vec<_>>();
        for s in packed_shares.iter() {
            // two polynomials should be packed into 1
            // note that we can pack up to F_DEG polynomials into one
            assert_eq!(s.len(), 1);
        }

        // we need to convert everything back into sharmir shares to do the reconstruction
        let mut packed_sharmir_shares = ShamirSharings::new();
        for (i, share) in packed_shares.into_iter().enumerate() {
            if add_error && i < threshold {
                packed_sharmir_shares
                    .add_share(Share::new(Role::indexed_from_zero(i), share[0] + Z::ONE));
            } else {
                packed_sharmir_shares.add_share(Share::new(Role::indexed_from_zero(i), share[0]));
            }
        }

        let opened =
            reconstruct_w_errors_sync(num_parties, threshold, threshold, 0, &packed_sharmir_shares)
                .unwrap()
                .unwrap();
        assert_eq!(opened.at(0), secret1.at(0));
        assert_eq!(opened.at(1), secret2.at(0));
    }

    #[test]
    fn test_share_randomness() {
        let mut rng = AesRng::seed_from_u64(0);
        const SHARE_COUNT: usize = 500usize;
        const BUF_LEN: usize = 16 * 4;
        const TRIES: usize = 10;

        for _ in 0..TRIES {
            for (num_parties, threshold) in [(4, 1), (10, 4)] {
                let mut all_shares: Vec<Vec<ResiduePolyF4<Z128>>> = vec![vec![]; num_parties];
                for _ in 0..SHARE_COUNT {
                    let secret = ResiduePolyF4::<Z128>::from_scalar(Wrapping(32));
                    let sharings = ShamirSharings::<ResiduePolyF4<Z128>>::share(
                        &mut rng,
                        secret,
                        num_parties,
                        threshold,
                    )
                    .unwrap();

                    for (share, all_share) in
                        sharings.shares.into_iter().zip_eq(all_shares.iter_mut())
                    {
                        let share_buf_bincode = bc2wrap::serialize(&share.value()).unwrap();
                        let share_buf = share.value().to_byte_vec();
                        assert_eq!(share_buf_bincode, share_buf);
                        assert_eq!(share_buf.len(), BUF_LEN);
                        all_share.push(share.value());
                    }
                }

                for share in all_shares {
                    assert_eq!(share.len(), SHARE_COUNT);
                    execute_all_randomness_tests_tight(&share).unwrap();
                }
            }
        }
    }
}
