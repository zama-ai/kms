use super::{
    preprocessing::BasePreprocessing,
    triple::{mult_list, open_list},
};
use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Solve},
    execution::{runtime::session::BaseSessionHandles, sharing::share::Share},
    thread_handles::spawn_compute_bound,
};
use async_trait::async_trait;
use itertools::Itertools;
use tracing::instrument;

#[async_trait]
pub trait BitGenEven {
    async fn gen_bits_even<
        Z: Solve + Invert + ErrorCorrect,
        Ses: BaseSessionHandles,
        P: BasePreprocessing<Z> + Send + ?Sized,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>>;
}

pub struct SecureBitGenEven {}

//NOTE: We could also do like we do with triples, i.e. have a generation function which is async and stores
//the resulting bits, and then a next function that just pops them.
//The benefit is that functions that require bits (i.e. tuniform) will not necessarily be async

/// BitGen for even modulus
#[async_trait]
impl BitGenEven for SecureBitGenEven {
    /// Generates a vector of secret shared random bits using a preprocessing functionality and a session.
    /// The code only works when the modulo of the ring used is even.
    #[instrument(name="MPC.GenBits", skip(amount, preproc, session), fields(sid = ?session.session_id(), my_role = ?session.my_role(),batch_size=?amount))]
    async fn gen_bits_even<
        Z: Invert + Solve + ErrorCorrect,
        Ses: BaseSessionHandles,
        P: BasePreprocessing<Z> + Send + ?Sized,
    >(
        amount: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let a = preproc.next_random_vec(amount)?;
        let triples = preproc.next_triple_vec(amount)?;
        let s = mult_list(&a, &a, triples, session).await?;
        // Assumption that since we are just adding it's pretty computationally cheap
        // and can stay on tokio thread
        let a_ref = a.clone();
        let v = spawn_compute_bound(move || {
            a_ref
                .into_iter()
                .zip_eq(s) // May panic but would imply a bug in `mult_list`
                .map(|(cur_a, cur_s)| cur_a + cur_s)
                .collect_vec()
        })
        .await?;
        let opened_v_vec = open_list(&v, session).await?;

        spawn_compute_bound(move || {
            opened_v_vec
                .iter()
                .zip_eq(a) // May panic but would imply a bug in `open_list`
                .map(|(cur_v, cur_a)| {
                    let cur_r = Z::solve(cur_v)?;
                    let cur_d = Z::ZERO - (Z::ONE + cur_r.mul_by_u128(2));
                    let cur_b = (cur_a - cur_r) * Z::invert(cur_d)?;
                    Ok(cur_b)
                })
                .try_collect()
        })
        .await?
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "extension_degree_3")]
    use crate::algebra::galois_rings::degree_3::{ResiduePolyF3Z128, ResiduePolyF3Z64};
    use crate::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
    #[cfg(feature = "extension_degree_5")]
    use crate::algebra::galois_rings::degree_5::{ResiduePolyF5Z128, ResiduePolyF5Z64};
    #[cfg(feature = "extension_degree_6")]
    use crate::algebra::galois_rings::degree_6::{ResiduePolyF6Z128, ResiduePolyF6Z64};
    #[cfg(feature = "extension_degree_7")]
    use crate::algebra::galois_rings::degree_7::{ResiduePolyF7Z128, ResiduePolyF7Z64};
    #[cfg(feature = "extension_degree_8")]
    use crate::algebra::galois_rings::degree_8::{ResiduePolyF8Z128, ResiduePolyF8Z64};
    use crate::algebra::structure_traits::Ring;
    use crate::execution::online::gen_bits::BitGenEven;
    use crate::execution::online::gen_bits::SecureBitGenEven;
    use crate::{
        algebra::structure_traits::{One, Sample, ZConsts, Zero},
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
                #[tokio::test]
                async fn [<even_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    const AMOUNT: usize = 10;
                    async fn task(mut session: SmallSession<$z>, _bot: Option<String>) -> Vec<$z> {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
                        let bits = SecureBitGenEven::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                            .await
                            .unwrap();
                        open_list(&bits, &session).await.unwrap()
                    }

                    // expect 3 rounds: 2 for bit gen and 1 for opening
                    // Async because the triple gen is dummy
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z, {$z::EXTENSION_DEGREE}>(parties, threshold, Some(3), NetworkMode::Async, Some(delay_vec), &mut task, None).await;
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                #[tokio::test]
                async fn [<even_malicious_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_party: Role = Role::indexed_from_one(2);
                    const AMOUNT: usize = 10;
                    let mut task = |mut session: SmallSession<$z>, _bot: Option<String>| async move {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
                        // Execute with dummy prepreocessing for honest parties and a mock for the bad one
                        let bits = if session.my_role() == bad_party {
                            let mut mock =
                                MockBasePreprocessing::<$z>::new();
                            // Mock the bad party's preprocessing by returning incorrect shares on calls to next_random_vec
                            mock.expect_next_random_vec()
                                .returning(move |amount| {
                                    Ok((0..amount)
                                        .map(|i| {
                                            Share::new(
                                                bad_party,
                                                $z::from_scalar(Wrapping(i as $u)),
                                            )
                                        })
                                        .collect_vec())
                                });
                            mock.expect_next_triple_vec()
                                .returning(move |amount| preprocessing.next_triple_vec(amount));
                            SecureBitGenEven::gen_bits_even(AMOUNT, &mut mock, &mut session)
                                .await
                                .unwrap()
                        } else {
                            SecureBitGenEven::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                                .await
                                .unwrap()
                        };
                        open_list(&bits, &session).await.unwrap()
                    };

                    // Async because the triple gen is dummy
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z, {$z::EXTENSION_DEGREE}>(parties, threshold, None, NetworkMode::Async, Some(delay_vec), &mut task, None).await;
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                fn [<validate_res_ $z:lower>](results: Vec<Vec<$z>>, amount: usize, parties: usize) {
                    assert_eq!(results.len(), parties);
                    let mut one_count = 0;
                    for cur_party_res in results.clone() {
                        assert_eq!(amount, cur_party_res.len());
                        // Check that all parties agree on the result
                        assert_eq!(*results.first().unwrap(), cur_party_res);
                        for cur_bit in cur_party_res {
                            assert!(cur_bit == $z::ZERO || cur_bit == $z::ONE);
                            if cur_bit == $z::ONE {
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
                    let a = $z::sample(&mut rng);
                    let t = a + a * a;
                    let x = match $z::solve(&t) {
                        Ok(x) => x,
                        Err(error) => panic!("Failed with error: {}", error),
                    };
                    assert_eq!(t, x + x * x);
                }

                #[test]
                fn [<negative_sample_ $z:lower>]() {
                    let mut rng = AesRng::seed_from_u64(1);
                    let a = $z::sample(&mut rng);
                    // The input not of the form a+a*a
                    // but has a solution to X^2 + X = t
                    // i.e. Tr(t) = 0 (mod 2) (section 7.1.5 in NIST doc)
                    let t = if $z::EXTENSION_DEGREE % 2 == 0 {
                        a + a * a - $z::ONE
                    } else {
                        a + a * a - $z::TWO
                    };
                    let x = $z::solve(&t).unwrap();
                    assert_ne!(a + a * a, x + x * x);
                }

                #[test]
                fn [<soak_sample_ $z:lower>]() {
                    let iterations = 1000;
                    let mut rng = rand::thread_rng();
                    let mut a: $z;
                    let mut base_solutions = 0;
                    for _i in 1..iterations {
                        a = $z::sample(&mut rng);
                        let t = a + a * a;
                        let x = match $z::solve(&t) {
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

    test_bitgen![ResiduePolyF4Z64, u64];
    test_bitgen![ResiduePolyF4Z128, u128];

    #[cfg(feature = "extension_degree_3")]
    test_bitgen![ResiduePolyF3Z64, u64];
    #[cfg(feature = "extension_degree_3")]
    test_bitgen![ResiduePolyF3Z128, u128];

    #[cfg(feature = "extension_degree_5")]
    test_bitgen![ResiduePolyF5Z64, u64];
    #[cfg(feature = "extension_degree_5")]
    test_bitgen![ResiduePolyF5Z128, u128];

    #[cfg(feature = "extension_degree_6")]
    test_bitgen![ResiduePolyF6Z64, u64];
    #[cfg(feature = "extension_degree_6")]
    test_bitgen![ResiduePolyF6Z128, u128];

    #[cfg(feature = "extension_degree_7")]
    test_bitgen![ResiduePolyF7Z64, u64];
    #[cfg(feature = "extension_degree_7")]
    test_bitgen![ResiduePolyF7Z128, u128];

    #[cfg(feature = "extension_degree_8")]
    test_bitgen![ResiduePolyF8Z64, u64];
    #[cfg(feature = "extension_degree_8")]
    test_bitgen![ResiduePolyF8Z128, u128];
}
