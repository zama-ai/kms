use super::{basics::PrivateBgvKeySet, dkg_preproc::BGVDkgPreprocessing};
use crate::experimental::{
    algebra::cyclotomic::RqElement,
    algebra::levels::{CryptoModulus, GenericModulus, LevelEll, LevelKsw, LevelOne, ScalingFactor},
    algebra::ntt::{hadamard_product, ntt_inv, ntt_iter2, Const, NTTConstants},
    bgv::basics::PublicKey,
};
use crate::{
    algebra::structure_traits::FromU128,
    execution::{
        online::triple::{mult_list, open_list},
        runtime::{party::Role, session::BaseSessionHandles},
        sharing::share::Share,
    },
};
use crypto_bigint::{NonZero, U1536};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::ops::Mul;
use tracing::instrument;

#[derive(Clone)]
pub struct BGVShareSecretKey {
    pub sk: Vec<Share<LevelOne>>,
}

pub type NttForm<T> = Vec<T>;

#[derive(Clone)]
pub struct OwnedNttForm<T> {
    pub owner: Role,
    pub data: NttForm<T>,
}

impl BGVShareSecretKey {
    pub fn as_ntt_repr(&self, n: usize, theta: LevelOne) -> NttForm<LevelOne> {
        let mut sk_ntt = self.sk.iter().map(|x| x.value()).collect_vec();
        ntt_iter2(&mut sk_ntt, n, theta);
        sk_ntt
    }
}

#[instrument(name="BGV.Threshold-KeyGen",skip_all, fields(session_id = ?session.session_id(), own_identity = ?session.own_identity()))]
pub async fn bgv_distributed_keygen<
    N,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: BGVDkgPreprocessing,
>(
    session: &mut S,
    preprocessing: &mut P,
    plaintext_mod: u64,
) -> anyhow::Result<(PublicKey<LevelEll, LevelKsw, N>, PrivateBgvKeySet)>
where
    N: NTTConstants<LevelKsw> + Clone + Const,
    RqElement<LevelKsw, N>: Mul<RqElement<LevelKsw, N>, Output = RqElement<LevelKsw, N>>,
    for<'r> RqElement<LevelKsw, N>: Mul<&'r LevelKsw, Output = RqElement<LevelKsw, N>>,
{
    let own_role = session.my_role()?;
    let p = LevelKsw::from_u128(plaintext_mod as u128);
    //Sample secret key share
    let sk_share = preprocessing.next_ternary_vec(N::VALUE)?;

    let mut sk_ntt = sk_share.iter().map(|x| x.value()).collect_vec();
    ntt_iter2(&mut sk_ntt, N::VALUE, N::THETA);

    //Sample and open pk_a and pk'_a
    let pk_as = preprocessing.next_random_vec(2 * N::VALUE)?;
    let mut pk_as = open_list(&pk_as, session).await?;

    let pk_a = pk_as.split_off(N::VALUE);
    let pk_a_prime = pk_as;
    let mut pk_a_prime_ntt = pk_a_prime.clone();
    ntt_iter2(&mut pk_a_prime_ntt, N::VALUE, N::THETA);

    //Start computing pk'_b
    let mut pk_b_prime = hadamard_product(&sk_ntt, pk_a_prime_ntt);

    //take pk_a mod Q
    let modulus_q: NonZero<U1536> = NonZero::new(LevelEll::MODULUS.as_ref().into()).unwrap();
    let pk_a_mod_q = pk_a
        .iter()
        .map(|val| LevelKsw {
            value: GenericModulus(val.value.0.rem(&modulus_q)),
        })
        .collect_vec();
    let mut pk_a_mod_q_ntt = pk_a_mod_q.clone();
    ntt_iter2(&mut pk_a_mod_q_ntt, N::VALUE, N::THETA);

    //Sample e_pk noise
    let e_pk = preprocessing.next_noise_vec(N::VALUE)?;
    let e_pk_times_p = RqElement::<_, N>::from(e_pk.iter().map(|x| x.value() * p).collect_vec());

    //compute pk_b, manually do ntt as we already have sk in ntt domain
    let mut pk_b = hadamard_product(&sk_ntt, pk_a_mod_q_ntt);
    ntt_inv::<_, N>(&mut pk_b, N::VALUE);

    let pk_b = RqElement::<_, N>::from(pk_b) + e_pk_times_p;

    //Sample e'_pk noise
    let e_pk_prime = preprocessing.next_noise_vec(N::VALUE)?;
    let e_pk_prime_times_p = e_pk_prime.iter().map(|x| x * p).collect_vec();

    //Compute sk odot sk in the polynomial ring via NTT
    let sk_share_ntt = sk_ntt
        .into_iter()
        .map(|val| Share::new(own_role, val))
        .collect_vec();

    let triples = preprocessing.next_triple_vec(N::VALUE)?;
    let sk_odot_sk_ntt_share = mult_list(&sk_share_ntt, &sk_share_ntt, triples, session).await?;
    let mut sk_odot_sk = sk_odot_sk_ntt_share
        .iter()
        .map(|share| share.value())
        .collect_vec();
    ntt_inv::<_, N>(&mut sk_odot_sk, N::VALUE);

    let sk_odot_sk_times_r = sk_odot_sk
        .iter()
        .map(|x| x * &LevelKsw::FACTOR)
        .collect_vec();

    //Continue computing pk_b_prime now that we have sk \odot sk
    ntt_inv::<_, N>(&mut pk_b_prime, N::VALUE);
    let pk_b_prime = pk_b_prime
        .into_iter()
        .zip(e_pk_prime_times_p)
        .zip(sk_odot_sk_times_r)
        .map(|((x, y), z)| y + x - z)
        .collect_vec();

    //Open pk_b and pk'_b (in a single round)
    let pk_b = pk_b
        .data
        .into_iter()
        .map(|x| Share::new(own_role, x))
        .collect_vec();
    let concat_open = [pk_b, pk_b_prime].concat();
    let mut concat_opened = open_list(&concat_open, session).await?;
    let pk_b_prime = concat_opened.split_off(N::VALUE);
    let pk_b = concat_opened;

    //Format for output
    let pk_a_mod_q = pk_a_mod_q
        .iter()
        .map(|x| LevelEll {
            value: GenericModulus((&x.value.0).into()),
        })
        .collect_vec();

    let pk_b_mod_q = pk_b
        .iter()
        .map(|x| LevelEll {
            value: GenericModulus((&x.value.0.rem(&modulus_q)).into()),
        })
        .collect_vec();

    let modulus_q1: NonZero<U1536> = NonZero::new(LevelOne::MODULUS.as_ref().into()).unwrap();
    let sk_ntt_mod_q1 = sk_share_ntt
        .iter()
        .map(|x| {
            let x_mod_q1 = LevelOne {
                value: GenericModulus((&x.value().value.0.rem(&modulus_q1)).into()),
            };
            Share::new(own_role, x_mod_q1)
        })
        .collect_vec();

    let pk = PublicKey {
        a: RqElement::<_, N>::from(pk_a_mod_q),
        b: RqElement::<_, N>::from(pk_b_mod_q),
        a_prime: RqElement::<_, N>::from(pk_a_prime),
        b_prime: RqElement::<_, N>::from(pk_b_prime),
    };

    Ok((pk, PrivateBgvKeySet::from_eval_domain(sk_ntt_mod_q1)))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    use super::{bgv_distributed_keygen, BGVDkgPreprocessing};
    use crate::{
        algebra::structure_traits::{One, ZConsts, Zero},
        execution::{
            online::{preprocessing::dummy::DummyPreprocessing, triple::open_list},
            runtime::session::{BaseSessionHandles, SmallSession},
        },
        experimental::{
            algebra::{
                cyclotomic::{TernaryElement, TernaryEntry},
                levels::{LevelEll, LevelKsw, LevelOne},
                ntt::{ntt_inv, Const, N65536},
            },
            bgv::{
                basics::{bgv_dec, bgv_enc, PublicKey, SecretKey},
                dkg_preproc::InMemoryBGVDkgPreprocessing,
            },
            constants::PLAINTEXT_MODULUS,
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    #[allow(clippy::type_complexity)]
    fn test_dkg(
        results: &mut Vec<(PublicKey<LevelEll, LevelKsw, N65536>, Vec<LevelOne>)>,
        plaintext_mod: u64,
    ) {
        //Turn sk into proper type
        let (pk, sk_ntt) = results.pop().unwrap();

        let mut sk = sk_ntt.clone();
        ntt_inv::<_, N65536>(&mut sk, N65536::VALUE);

        let mut vec_sk = Vec::new();
        for sk_elem in sk {
            let ternary_elem = if sk_elem == LevelOne::MAX {
                TernaryEntry::NegativeOne
            } else if sk_elem == LevelOne::ZERO {
                TernaryEntry::Zero
            } else if sk_elem == LevelOne::ONE {
                TernaryEntry::PositiveOne
            } else {
                panic!("UNEXPECTED TERNARY ENTRY FOR SK")
            };
            vec_sk.push(ternary_elem);
        }

        let sk_correct_type = SecretKey {
            sk: TernaryElement { data: vec_sk },
        };

        //Encrypt and decrypt
        let mut rng = AesRng::seed_from_u64(0);
        let plaintext_vec: Vec<u32> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % plaintext_mod) as u32)
            .collect();
        let ct = bgv_enc(&mut rng, &plaintext_vec, &pk.a, &pk.b, plaintext_mod);
        let plaintext = bgv_dec(&ct, sk_correct_type, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, plaintext_vec);
    }

    #[test]
    fn test_dkg_dummy_preproc() {
        let parties = 5;
        let threshold = 1;
        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let mut prep = DummyPreprocessing::<LevelKsw, AesRng, SmallSession<LevelKsw>>::new(
                0,
                session.clone(),
            );

            let (pk, sk) = bgv_distributed_keygen::<N65536, _, _, _>(
                &mut session,
                &mut prep,
                PLAINTEXT_MODULUS.get().0,
            )
            .await
            .unwrap();

            let sk_opened = open_list(sk.as_eval(), &session).await.unwrap();

            (pk, sk_opened)
        };

        //This is Async because preproc is completely dummy, so we only do the DKG
        //Delay P1 by 1s every round
        let delay_vec = vec![std::time::Duration::from_secs(1)];
        let mut results = execute_protocol_small(
            parties,
            threshold,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );
        test_dkg(&mut results, PLAINTEXT_MODULUS.get().0);
    }

    #[test]
    fn test_dkg_with_offline() {
        let parties = 5;
        let threshold = 1;
        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let mut dummy_preproc =
                DummyPreprocessing::<LevelKsw, AesRng, SmallSession<LevelKsw>>::new(
                    0,
                    session.clone(),
                );

            let mut bgv_preproc = InMemoryBGVDkgPreprocessing::default();
            bgv_preproc
                .fill_from_base_preproc(N65536::VALUE, &mut session, &mut dummy_preproc)
                .await
                .unwrap();

            session
                .network()
                .set_timeout_for_next_round(Duration::from_secs(600))
                .unwrap();
            let (pk, sk) = bgv_distributed_keygen::<N65536, _, _, _>(
                &mut session,
                &mut bgv_preproc,
                PLAINTEXT_MODULUS.get().0,
            )
            .await
            .unwrap();

            let sk_opened = open_list(sk.as_eval(), &session).await.unwrap();

            (pk, sk_opened)
        };

        //This is Sync because Sync of the preproc takes priority over Async of the actual DKG
        let mut results =
            execute_protocol_small(parties, threshold, None, NetworkMode::Sync, None, &mut task);

        test_dkg(&mut results, PLAINTEXT_MODULUS.get().0);
    }
}
