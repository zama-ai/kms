use std::ops::Mul;

use crypto_bigint::{NonZero, U1536};
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tonic::async_trait;

use crate::{
    algebra::structure_traits::FromU128,
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        online::{
            preprocessing::{
                memory::{InMemoryBasePreprocessing, InMemoryBitPreprocessing},
                BasePreprocessing, BitPreprocessing, RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::{mult_list, open_list, Triple},
        },
        runtime::{
            party::Role,
            session::{BaseSessionHandles, SmallSession},
        },
        sharing::share::Share,
    },
};

use crate::experimental::{
    algebra::cyclotomic::RqElement,
    algebra::levels::{CryptoModulus, GenericModulus, LevelEll, LevelKsw, LevelOne, ScalingFactor},
    algebra::ntt::{hadamard_product, ntt_inv, ntt_iter2, Const, NTTConstants},
    bgv::basics::PublicKey,
    gen_bits_odd::{BitGenOdd, RealBitGenOdd},
};

#[derive(Clone)]
pub struct BGVShareSecretKey {
    pub sk: Vec<Share<LevelOne>>,
}

pub type NttForm<T> = Vec<T>;

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

#[async_trait]
pub trait BGVDkgPreprocessing: BasePreprocessing<LevelKsw> {
    fn num_required_triples_randoms(poly_size: usize, new_hope_bound: usize) -> BatchParams {
        let num_bits = 2 * poly_size + 2 * 2 * poly_size * new_hope_bound;
        let triples = num_bits + poly_size;
        let randoms = num_bits + 2 * poly_size;
        BatchParams { triples, randoms }
    }

    async fn fill_from_base_preproc(
        &mut self,
        poly_size: usize,
        new_hope_bound: usize,
        session: &mut SmallSession<LevelKsw>,
        preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
    ) -> anyhow::Result<()>;
    fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>>;
    fn next_noise_vec(
        &mut self,
        amount: usize,
        new_hope_bound: usize,
    ) -> anyhow::Result<Vec<Share<LevelKsw>>>;
}

#[derive(Default)]
pub struct InMemoryBGVDkgPreprocessing {
    in_memory_base: InMemoryBasePreprocessing<LevelKsw>,
    available_ternary: Vec<Share<LevelKsw>>,
    available_noise: Vec<Share<LevelKsw>>,
    new_hope_bound: usize,
}

impl TriplePreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<LevelKsw>>> {
        self.in_memory_base.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<LevelKsw>>) {
        self.in_memory_base.append_triples(triples)
    }

    fn triples_len(&self) -> usize {
        self.in_memory_base.triples_len()
    }
}

impl RandomPreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        self.in_memory_base.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<LevelKsw>>) {
        self.in_memory_base.append_randoms(randoms)
    }

    fn randoms_len(&self) -> usize {
        self.in_memory_base.randoms_len()
    }
}

#[async_trait]
impl BGVDkgPreprocessing for InMemoryBGVDkgPreprocessing {
    async fn fill_from_base_preproc(
        &mut self,
        poly_size: usize,
        new_hope_bound: usize,
        session: &mut SmallSession<LevelKsw>,
        preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
    ) -> anyhow::Result<()> {
        //NewHope(N,B) takes 2 * N * B bits, and we have:
        // - Newhope(N,1) for the secret key
        // - 2*NewHope(N,B) for the noise
        let num_bits_needed = 2 * poly_size + 2 * 2 * poly_size * new_hope_bound;

        let mut bit_preproc = InMemoryBitPreprocessing::default();
        bit_preproc.append_bits(
            RealBitGenOdd::gen_bits_odd(num_bits_needed, preprocessing, session).await?,
        );

        let ternary_vec = RealSecretDistributions::newhope(poly_size, 1, &mut bit_preproc)?;
        self.available_ternary = ternary_vec;

        let noise_vec =
            RealSecretDistributions::newhope(2 * poly_size, new_hope_bound, &mut bit_preproc)?;
        self.new_hope_bound = new_hope_bound;
        self.available_noise = noise_vec;

        self.in_memory_base
            .append_triples(preprocessing.next_triple_vec(poly_size)?);

        self.in_memory_base
            .append_randoms(preprocessing.next_random_vec(2 * poly_size)?);

        Ok(())
    }

    fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        if self.available_ternary.len() >= amount {
            Ok(self.available_ternary.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough of ternary element to pop {amount}, only have {}",
                self.available_ternary.len()
            )))
        }
    }

    fn next_noise_vec(
        &mut self,
        amount: usize,
        new_hope_bound: usize,
    ) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        assert_eq!(
            new_hope_bound, self.new_hope_bound,
            "new_hope distribution available in preprocessing does not match the one in online"
        );
        if self.available_noise.len() >= amount {
            Ok(self.available_noise.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough of ternary element to pop {amount}, only have {}",
                self.available_noise.len()
            )))
        }
    }
}

impl BasePreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {}

pub async fn bgv_distributed_keygen<
    N,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    P: BGVDkgPreprocessing,
>(
    session: &mut S,
    preprocessing: &mut P,
    new_hope_bound: usize,
    plaintext_mod: u64,
) -> anyhow::Result<(PublicKey<LevelEll, LevelKsw, N>, BGVShareSecretKey)>
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
    let e_pk = preprocessing.next_noise_vec(N::VALUE, new_hope_bound)?;
    let e_pk_times_p = RqElement::<_, N>::from(e_pk.iter().map(|x| x.value() * p).collect_vec());

    //compute pk_b, manually do ntt as we already have sk in ntt domain
    let mut pk_b = hadamard_product(&sk_ntt, pk_a_mod_q_ntt);
    ntt_inv::<_, N>(&mut pk_b, N::VALUE);

    let pk_b = RqElement::<_, N>::from(pk_b) + e_pk_times_p;

    //Sample e'_pk noise
    let e_pk_prime = preprocessing.next_noise_vec(N::VALUE, new_hope_bound)?;
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

    //Open pk_b and pk'_b
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
    let sk_mod_q1 = sk_share
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

    Ok((pk, BGVShareSecretKey { sk: sk_mod_q1 }))
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};
    use tonic::async_trait;

    use crate::{
        algebra::structure_traits::{One, ZConsts, Zero},
        execution::{
            online::{
                preprocessing::{dummy::DummyPreprocessing, BasePreprocessing},
                secret_distributions::{RealSecretDistributions, SecretDistributions},
                triple::open_list,
            },
            runtime::session::SmallSession,
            sharing::share::Share,
        },
        experimental::{
            algebra::{
                cyclotomic::{RingElement, TernaryElement, TernaryEntry},
                levels::{LevelEll, LevelKsw, LevelOne},
                ntt::{Const, N65536},
            },
            bgv::{
                basics::{bgv_dec, bgv_enc, PublicKey, SecretKey},
                dkg::InMemoryBGVDkgPreprocessing,
            },
            constants::PLAINTEXT_MODULUS,
        },
        tests::helper::tests_and_benches::execute_protocol_small,
    };

    use super::{bgv_distributed_keygen, BGVDkgPreprocessing};

    #[async_trait]
    impl BGVDkgPreprocessing for DummyPreprocessing<LevelKsw, AesRng, SmallSession<LevelKsw>> {
        async fn fill_from_base_preproc(
            &mut self,
            _poly_size: usize,
            _new_hope_bound: usize,
            _session: &mut SmallSession<LevelKsw>,
            _preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
        ) -> anyhow::Result<()> {
            unimplemented!("We do not implement filling for DummyPreprocessing")
        }

        fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
            RealSecretDistributions::newhope(amount, 1, self)
        }

        fn next_noise_vec(
            &mut self,
            amount: usize,
            new_hope_bound: usize,
        ) -> anyhow::Result<Vec<Share<LevelKsw>>> {
            RealSecretDistributions::newhope(amount, new_hope_bound, self)
        }
    }

    #[allow(clippy::type_complexity)]
    fn test_dkg(
        results: &mut Vec<(PublicKey<LevelEll, LevelKsw, N65536>, Vec<LevelOne>)>,
        plaintext_mod: u64,
        new_hope_bound: usize,
    ) {
        //Turn sk into proper type
        let (pk, sk) = results.pop().unwrap();

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
        let m: Vec<u16> = (0..N65536::VALUE)
            .map(|_| (rng.next_u64() % plaintext_mod) as u16)
            .collect();
        let mr = RingElement::<u16>::from(m);
        let ct = bgv_enc(&mut rng, &mr, pk.a, pk.b, new_hope_bound, plaintext_mod);
        let plaintext = bgv_dec(&ct, sk_correct_type, &PLAINTEXT_MODULUS);
        assert_eq!(plaintext, mr);
    }

    #[test]
    fn test_dkg_dummy_preproc() {
        let parties = 5;
        let threshold = 1;
        let new_hope_bound = 1;

        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let mut prep = DummyPreprocessing::<LevelKsw, AesRng, SmallSession<LevelKsw>>::new(
                0,
                session.clone(),
            );

            let (pk, sk) = bgv_distributed_keygen::<N65536, _, _, _>(
                &mut session,
                &mut prep,
                new_hope_bound,
                PLAINTEXT_MODULUS.get().0,
            )
            .await
            .unwrap();

            let sk_opened = open_list(&sk.sk, &session).await.unwrap();

            (pk, sk_opened)
        };

        let mut results = execute_protocol_small(parties, threshold, None, &mut task);
        test_dkg(&mut results, PLAINTEXT_MODULUS.get().0, new_hope_bound);
    }

    #[test]
    fn test_dkg_with_offline() {
        let parties = 5;
        let threshold = 1;
        let new_hope_bound = 1;

        let mut task = |mut session: SmallSession<LevelKsw>| async move {
            let mut dummy_preproc =
                DummyPreprocessing::<LevelKsw, AesRng, SmallSession<LevelKsw>>::new(
                    0,
                    session.clone(),
                );

            let mut bgv_preproc = InMemoryBGVDkgPreprocessing::default();
            bgv_preproc
                .fill_from_base_preproc(
                    N65536::VALUE,
                    new_hope_bound,
                    &mut session,
                    &mut dummy_preproc,
                )
                .await
                .unwrap();

            let (pk, sk) = bgv_distributed_keygen::<N65536, _, _, _>(
                &mut session,
                &mut bgv_preproc,
                new_hope_bound,
                PLAINTEXT_MODULUS.get().0,
            )
            .await
            .unwrap();

            let sk_opened = open_list(&sk.sk, &session).await.unwrap();

            (pk, sk_opened)
        };

        let mut results = execute_protocol_small(parties, threshold, None, &mut task);

        test_dkg(&mut results, PLAINTEXT_MODULUS.get().0, new_hope_bound);
    }
}
