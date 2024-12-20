use super::{
    preprocessing::BasePreprocessing,
    triple::{mult_list, open_list},
};
use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed, Solve},
    execution::{runtime::session::BaseSessionHandles, sharing::share::Share},
};
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use tracing::instrument;

#[async_trait]
pub trait BitGenEven {
    async fn gen_bits_even<
        Z: Ring + RingEmbed + Solve + Invert + ErrorCorrect,
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: BasePreprocessing<Z> + Send + ?Sized,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>>;
}

pub struct RealBitGenEven {}

//NOTE: We could also do like we do with triples, i.e. have a generation function which is async and stores
//the resulting bits, and then a next function that just pops them.
//The benefit is that functions that require bits (i.e. tuniform) will not necessarily be async

/// BitGen for even modulus
#[async_trait]
impl BitGenEven for RealBitGenEven {
    /// Generates a vector of secret shared random bits using a preprocessing functionality and a session.
    /// The code only works when the modulo of the ring used is even.
    #[instrument(name="MPC.GenBits", skip(amount, preproc, session), fields(session_id = ?session.session_id(), own_identity = ?session.own_identity(),batch_size=?amount))]
    async fn gen_bits_even<
        Z: Ring + RingEmbed + Invert + Solve + ErrorCorrect,
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: BasePreprocessing<Z> + Send + ?Sized,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let a = preproc.next_random_vec(amount)?;
        let triples = preproc.next_triple_vec(amount)?;
        let s = mult_list(&a, &a, triples, session).await?;
        let v = a
            .iter()
            .zip(s)
            .map(|(cur_a, cur_s)| (*cur_a) + cur_s)
            .collect_vec();
        let opened_v_vec = open_list(&v, session).await?;

        opened_v_vec
            .iter()
            .zip(a)
            .map(|(cur_v, cur_a)| {
                let cur_r = Z::solve(cur_v)?;
                let cur_d = Z::ZERO - (Z::ONE + Z::TWO * cur_r);
                let cur_b = (cur_a - cur_r) * Z::invert(cur_d)?;
                Ok(cur_b)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::online::gen_bits::BitGenEven;
    use crate::execution::online::gen_bits::RealBitGenEven;
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::degree_8::ResiduePolyF8,
            structure_traits::{One, Sample, Zero},
        },
        execution::{
            online::{
                gen_bits::Solve,
                preprocessing::{
                    dummy::DummyPreprocessing, MockBasePreprocessing, TriplePreprocessing,
                },
                triple::open_list,
            },
            runtime::party::Role,
            runtime::session::{ParameterHandles, SmallSession},
            sharing::share::Share,
        },
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_small,
    };
    use aes_prng::AesRng;
    use itertools::Itertools;
    use paste::paste;
    use rand::SeedableRng;
    use std::num::Wrapping;

    macro_rules! test_bitgen {
        ($z:ty, $u:ty) => {
            paste! {
                #[test]
                fn [<even_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    const AMOUNT: usize = 10;
                    async fn task(mut session: SmallSession<ResiduePolyF8<$z>>) -> Vec<ResiduePolyF8<$z>> {
                        let mut preprocessing = DummyPreprocessing::<ResiduePolyF8<$z>, AesRng, SmallSession<ResiduePolyF8<$z>>>::new(42, session.clone());
                        let bits = RealBitGenEven::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                            .await
                            .unwrap();
                        open_list(&bits, &session).await.unwrap()
                    }

                    // expect 3 rounds: 2 for bit gen and 1 for opening
                    // Async because the triple gen is dummy
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small(parties, threshold, Some(3), NetworkMode::Async, Some(delay_vec), &mut task);
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                #[test]
                fn [<even_malicious_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_party: Role = Role::indexed_by_one(2);
                    const AMOUNT: usize = 10;
                    let mut task = |mut session: SmallSession<ResiduePolyF8<$z>>| async move {
                        let mut preprocessing = DummyPreprocessing::<ResiduePolyF8<$z>, AesRng, SmallSession<ResiduePolyF8<$z>>>::new(42, session.clone());
                        // Execute with dummy prepreocessing for honest parties and a mock for the bad one
                        let bits = if session.my_role().unwrap() == bad_party {
                            let mut mock =
                                MockBasePreprocessing::<ResiduePolyF8<$z>>::new();
                            // Mock the bad party's preprocessing by returning incorrect shares on calls to next_random_vec
                            mock.expect_next_random_vec()
                                .returning(move |amount| {
                                    Ok((0..amount)
                                        .map(|i| {
                                            Share::new(
                                                bad_party,
                                                ResiduePolyF8::<$z>::from_scalar(Wrapping(i as $u)),
                                            )
                                        })
                                        .collect_vec())
                                });
                            mock.expect_next_triple_vec()
                                .returning(move |amount| preprocessing.next_triple_vec(amount));
                            RealBitGenEven::gen_bits_even(AMOUNT, &mut mock, &mut session)
                                .await
                                .unwrap()
                        } else {
                            RealBitGenEven::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                                .await
                                .unwrap()
                        };
                        open_list(&bits, &session).await.unwrap()
                    };

                    // Async because the triple gen is dummy
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small(parties, threshold, None, NetworkMode::Async, Some(delay_vec), &mut task);
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                fn [<validate_res_ $z:lower>](results: Vec<Vec<ResiduePolyF8<$z>>>, amount: usize, parties: usize) {
                    assert_eq!(results.len(), parties);
                    let mut one_count = 0;
                    for cur_party_res in results.clone() {
                        assert_eq!(amount, cur_party_res.len());
                        // Check that all parties agree on the result
                        assert_eq!(*results.first().unwrap(), cur_party_res);
                        for cur_bit in cur_party_res {
                            assert!(cur_bit == ResiduePolyF8::ZERO || cur_bit == ResiduePolyF8::ONE);
                            if cur_bit == ResiduePolyF8::ONE {
                                one_count += 1;
                            }
                        }
                    }
                    // Sanity check the result, that at least 25 % are ones
                    assert!(one_count > parties * amount / 4);
                    // Sanity check the result, that at least 25 % are zeros
                    // LHS is amount of 0's, RHS is 25% of the total
                    assert!((parties * amount - one_count) > parties * amount/ 4);
                }

                #[test]
                fn [<test_sunshine_sample_ $z:lower>]() {
                    let mut rng = AesRng::seed_from_u64(0);
                    let a = ResiduePolyF8::<$z>::sample(&mut rng);
                    let t = a + a * a;
                    let x = match ResiduePolyF8::<$z>::solve(&t) {
                        Ok(x) => x,
                        Err(error) => panic!("Failed with error: {}", error),
                    };
                    assert_eq!(t, x + x * x);
                }

                #[test]
                fn [<negative_sample_ $z:lower>]() {
                    let mut rng = AesRng::seed_from_u64(1);
                    let a = ResiduePolyF8::<$z>::sample(&mut rng);
                    // The input not of the form a+a*a
                    let t = a + a * a - ResiduePolyF8::<$z>::ONE;
                    let x = ResiduePolyF8::<$z>::solve(&t).unwrap();
                    assert_ne!(a + a * a, x + x * x);
                }

                #[test]
                fn [<soak_sample_ $z:lower>]() {
                    let iterations = 1000;
                    let mut rng = rand::thread_rng();
                    let mut a: ResiduePolyF8<$z>;
                    let mut base_solutions = 0;
                    for _i in 1..iterations {
                        a = ResiduePolyF8::<$z>::sample(&mut rng);
                        let t = a + a * a;
                        let x = match ResiduePolyF8::<$z>::solve(&t) {
                            Ok(x) => x,
                            Err(error) => panic!("Failed with error: {}", error),
                        };
                        assert_eq!(t, x + x * x);
                        // Observe that the result will have two possible solutions, either x = a, or x = -a - 1
                        if x == a {
                            base_solutions += 1;
                        }
                    }
                    // Check the results are within the expected variance
                    assert!(base_solutions as f32 >= (iterations as f32) * 0.25);
                    assert!(base_solutions as f32 <= (iterations as f32) * 0.75);
                }
            }
        };
    }
    test_bitgen![Z64, u64];
    test_bitgen![Z128, u128];
}
