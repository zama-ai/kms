use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed, ZConsts},
    execution::{
        constants::STATSEC,
        online::{
            preprocessing::BasePreprocessing,
            triple::{mult_list, open_list},
        },
        runtime::session::SmallSessionHandles,
        sharing::share::Share,
        small_execution::prf::PRSSConversions,
    },
};

///This trait defines methods required to generate bits in
///in the subfield defined by the largest prime factor of a ring.
pub trait LargestPrimeFactor: Sized + ZConsts {
    fn mod_largest_prime(v: &Self) -> Self;
    fn largest_prime_factor_non_zero(v: &Self) -> bool;
    fn largest_prime_factor_sqrt(v: &Self) -> Self;
}

#[async_trait]
pub trait BitGenOdd {
    //To generate bits with an odd modulus q = q_1*...*q_L we need to compute
    //a sqrt mod q_L cf ['SqrtLargestPrimeFactor']
    async fn gen_bits_odd<
        Z: Ring + RingEmbed + Invert + ErrorCorrect + LargestPrimeFactor + ZConsts + PRSSConversions,
        Rnd: Rng + CryptoRng,
        Ses: SmallSessionHandles<Z, Rnd>,
        P: BasePreprocessing<Z> + Send,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>>;
}

pub struct RealBitGenOdd {}

#[async_trait]
impl BitGenOdd for RealBitGenOdd {
    async fn gen_bits_odd<
        Z: Ring + RingEmbed + Invert + ErrorCorrect + LargestPrimeFactor + ZConsts + PRSSConversions,
        Rnd: Rng + CryptoRng,
        Ses: SmallSessionHandles<Z, Rnd>,
        P: BasePreprocessing<Z> + Send,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let two_inv = Z::TWO.invert()?;
        let own_role = session.my_role()?;

        let mut s_vec = Vec::with_capacity(amount);
        let mut a_vec = Vec::with_capacity(amount);

        while s_vec.len() != amount {
            let current_amount = amount - s_vec.len();
            let tmp_a_vec = preproc.next_random_vec(current_amount)?;
            let trips = preproc.next_triple_vec(current_amount)?;

            let tmp_s_vec = mult_list(&tmp_a_vec, &tmp_a_vec, trips, session).await?;
            let tmp_s_vec = open_list(&tmp_s_vec, session).await?;
            tmp_s_vec
                .into_iter()
                .zip(tmp_a_vec.into_iter())
                .filter(|(s, _)| Z::largest_prime_factor_non_zero(s))
                .for_each(|(s, a)| {
                    s_vec.push(s);
                    a_vec.push(a);
                });
        }

        let c_vec = s_vec.iter().map(Z::largest_prime_factor_sqrt).collect_vec();

        let v_vec: Vec<Share<Z>> = a_vec
            .iter()
            .zip(c_vec.iter())
            .map(|(a, c)| match c.invert() {
                Ok(c_inv) => Ok(a * c_inv),
                Err(e) => Err(e),
            })
            .try_collect()?;

        let b_vec = v_vec.iter().map(|v| (v + &Z::ONE) * two_inv).collect_vec();

        let dist_shift = Z::from_u128(
            num_integer::binomial(session.num_parties() as u128, session.threshold() as u128)
                * (1 << STATSEC),
        );
        let r_vec: Vec<Z> = {
            let prss_state = session.prss_as_mut();

            (0..amount)
                .map(|_| prss_state.mask_next(own_role.one_based(), STATSEC as u128))
                .try_collect::<_, Vec<Z>, _>()?
                .into_iter()
                .map(|x| x + dist_shift)
                .collect()
        };

        let c_vec = b_vec
            .iter()
            .zip(r_vec.iter())
            .map(|(b, r)| b + r)
            .collect_vec();

        let c_vec = open_list(&c_vec, session).await?;
        let t_vec = c_vec.iter().map(Z::mod_largest_prime).collect_vec();

        let result = t_vec
            .into_iter()
            .zip(r_vec)
            .map(|(t, r)| Share::new(own_role, t - r))
            .collect();

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;

    use crate::{
        algebra::structure_traits::{One, Zero},
        execution::{
            online::preprocessing::dummy::DummyPreprocessing,
            runtime::session::SmallSession,
            sharing::shamir::{RevealOp, ShamirSharings},
        },
        experimental::bgv_algebra::LevelKsw,
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    use super::{BitGenOdd, RealBitGenOdd};

    #[test]
    fn test_bitgen() {
        let parties = 5;
        let threshold = 1;
        let amount = 100;
        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let mut preproc = DummyPreprocessing::<LevelKsw, AesRng, SmallSession<LevelKsw>>::new(
                0,
                session.clone(),
            );

            RealBitGenOdd::gen_bits_odd(amount, &mut preproc, &mut session)
                .await
                .unwrap()
        };
        let results = execute_protocol_small(parties, threshold, None, &mut task);

        //Make sure all are bits
        let mut one_count = 0;
        for index in 0..amount {
            let mut vec_b = Vec::new();
            for result in results.iter() {
                let b = result[index];
                vec_b.push(b);
            }
            let ss_b = ShamirSharings::create(vec_b);
            let b = ss_b.reconstruct(threshold as usize).unwrap();
            assert!(b == LevelKsw::ZERO || b == LevelKsw::ONE);
            if b == LevelKsw::ONE {
                one_count += 1;
            }
        }
        //Sanity check the result, that at least 25% are ones
        assert!(one_count > amount / 4);
        //Sanity check the result, that at least 25% are zeros
        assert!(amount - one_count > amount / 4);
    }
}
