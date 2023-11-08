use super::{
    preprocessing::Preprocessing,
    share::Share,
    triple::{mult_list, open_list},
};
use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::session::BaseSessionHandles,
    gf256::GF256,
    residue_poly::{ResiduePoly, F_DEG},
    value, One, ZConsts, Zero, Z128, Z64,
};
use itertools::Itertools;
use rand::RngCore;
use std::marker::PhantomData;

// Iterations needed for Newton Raphson inversion computation
// The upper bound is based on Z128 for which 2^7=128
const ITERATIONS: u32 = 7;
// Degree of polynomial we are working in
const D: u32 = F_DEG as u32;

// Expansion of inner loop needed for computing the initial value of x for Newton-Raphson.
// Computed using the following code:
// const TRACE_ONE: GF256 = GF256(42); // ... which is an element with trace 1
// fn compute_inner_loop() -> [GF256; 7] {
//     let delta_powers = two_powers(TRACE_ONE, D);
//     let mut inner_loop: [GF256; (D - 1) as usize] = [GF256(0); (D - 1) as usize];
//     for i in 0..(D - 1) {
//         let mut inner_temp = GF256::from(0);
//         for j in i + 1..D {
//             inner_temp += delta_powers[j as usize];
//         }
//         inner_loop[i as usize] = inner_temp;
//     }
//     inner_loop
// }
static INNER_LOOP: [GF256; 7] = [
    GF256(43),
    GF256(3),
    GF256(47),
    GF256(19),
    GF256(52),
    GF256(77),
    GF256(208),
];

// Dummy struct used to access the solve method on supported [Ring] types
pub struct Solve<Z> {
    _phantom: PhantomData<Z>,
}

macro_rules! impl_gen_bits {
    ($z:ty, $u:ty) => {
        impl Solve<$z> {
            /// Generates a vector of secret shared random bits using a preprocessing functionality and a session.
            /// The code only works when the modulo of the ring used is even.
            pub async fn gen_bits_even<
                Rnd: RngCore + Send + Sync + 'static,
                Ses: BaseSessionHandles<Rnd> + 'static,
                P: Preprocessing<Rnd, ResiduePoly<$z>, Ses> + 'static,
            >(
                amount: usize,
                preproc: &mut P,
                session: &mut Ses,
            ) -> anyhow::Result<Vec<Share<ResiduePoly<$z>>>>
            where
                value::Value: std::convert::From<ResiduePoly<$z>>,
            {
                let a = preproc.next_random_vec(amount, session)?;
                let trips = preproc.next_triple_vec(amount, session)?;
                let s = mult_list(&a, &a, trips, session).await?;
                let v = a
                    .iter()
                    .zip(s)
                    .map(|(cur_a, cur_s)| (*cur_a) + cur_s)
                    .collect_vec();
                let opened_v_vec = open_list(&v, session).await?;
                let mut b = Vec::new();
                for (cur_v, cur_a) in opened_v_vec.iter().zip(a) {
                    let cur_r = Solve::<$z>::solve(cur_v)?;
                    let cur_d = ResiduePoly::<$z>::ZERO
                        - (ResiduePoly::<$z>::ONE + ResiduePoly::<$z>::TWO * cur_r);
                    let cur_b = (cur_a - cur_r) * ResiduePoly::<$z>::invert(cur_d)?;
                    b.push(cur_b);
                }
                Ok(b)
            }

            /// Executes the `solve` algorithm of MPC-3, which is needed for random bit generation.
            /// Concretely it takes an element v from Z_{2^k}[X]/x^8+x^4+x^3+x+1 which can be expressed as v=a+a^2.
            /// The algorithm then returns x=a or x=a+1. That is, we observe that there are two possible solutions for x
            /// and this method finds one of them, which will be equally and randomly distributed.
            pub fn solve(v: &ResiduePoly<$z>) -> anyhow::Result<ResiduePoly<$z>> {
                let one: ResiduePoly<$z> = ResiduePoly::ONE;
                let two: ResiduePoly<$z> = ResiduePoly::TWO;
                let mut x = Self::solve_1(v)?;
                let mut y = one;
                // Do outer Newton Raphson
                for _i in 1..=ITERATIONS {
                    // Do inner Newton Raphson to compute inverse of 1+2*x
                    // Observe that because we use modulo 2^64 and 2^128, which are 2^2^i values
                    // Hence there is no need to do the modulo operation of m as described in the NIST document.
                    let z = one + two * x;
                    y = y * (two - z * y);
                    y = y * (two - z * y);
                    x = (x * x + v) * y;
                }
                // Validate the result, i.e. x+x^2 = input
                if v != &(x + x * x) {
                    return Err(anyhow_error_and_log(
                        "The outer Newton Raphson inversion computation in solve() failed"
                            .to_string(),
                    ));
                }
                Ok(x)
            }

            fn solve_1(v: &ResiduePoly<$z>) -> anyhow::Result<ResiduePoly<$z>> {
                let mut res = GF256::from(0);
                let v = ResiduePoly::<$z>::bit_compose(v, 0);
                let v_powers = two_powers(v, D - 1);
                for i in 0..(D - 1) {
                    res += INNER_LOOP[i as usize] * v_powers[i as usize];
                }
                ResiduePoly::embed(res.0 as usize)
            }
        }
    };
}
impl_gen_bits!(Z128, u128);
impl_gen_bits!(Z64, u64);

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
fn two_powers(input: GF256, max_power: u32) -> Vec<GF256> {
    let mut res = Vec::with_capacity(max_power as usize);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

#[cfg(test)]
mod tests {
    use crate::{
        execution::{
            online::{
                gen_bits::{two_powers, Solve},
                preprocessing::{DummyPreprocessing, MockPreprocessing, Preprocessing},
                share::Share,
                triple::open_list,
            },
            party::Role,
            session::{ParameterHandles, SmallSession},
        },
        gf256::GF256,
        residue_poly::ResiduePoly,
        tests::helper::tests::execute_protocol_small,
        One, Sample, Zero, Z128, Z64,
    };
    use itertools::Itertools;
    use paste::paste;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::num::Wrapping;

    macro_rules! test_bitgen {
        ($z:ty, $u:ty) => {
            paste! {
                #[test]
                fn [<even_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    const AMOUNT: usize = 100;
                    async fn task(mut session: SmallSession) -> Vec<ResiduePoly<Wrapping<$u>>> {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                        let bits = Solve::<$z>::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                            .await
                            .unwrap();
                        open_list(&bits, &session).await.unwrap()
                    }

                    let results = execute_protocol_small(parties, threshold, &mut task);
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                #[test]
                fn [<even_malicious_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_party: Role = Role::indexed_by_one(2);
                    const AMOUNT: usize = 100;
                    let mut task = |mut session: SmallSession| async move {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                        // Execute with dummy prepreocessing for honest parties and a mock for the bad one
                        let bits = if session.my_role().unwrap() == bad_party {
                            let mut mock =
                                MockPreprocessing::<ChaCha20Rng, ResiduePoly<$z>, SmallSession>::new();
                            // Mock the bad party's preprocessing by returning incorrect shares on calls to next_random_vec
                            mock.expect_next_random_vec()
                                .returning(move |amount, _ses| {
                                    Ok((0..amount)
                                        .map(|i| {
                                            Share::new(
                                                bad_party,
                                                ResiduePoly::<$z>::from_scalar(Wrapping(i as $u)),
                                            )
                                        })
                                        .collect_vec())
                                });
                            mock.expect_next_triple_vec()
                                .returning(move |amount, ses| preprocessing.next_triple_vec(amount, ses));
                            Solve::<$z>::gen_bits_even(AMOUNT, &mut mock, &mut session)
                                .await
                                .unwrap()
                        } else {
                            Solve::<$z>::gen_bits_even(AMOUNT, &mut preprocessing, &mut session)
                                .await
                                .unwrap()
                        };
                        open_list(&bits, &session).await.unwrap()
                    };

                    let results = execute_protocol_small(parties, threshold, &mut task);
                    [<validate_res_ $z:lower>](results, AMOUNT, parties);
                }

                fn [<validate_res_ $z:lower>](results: Vec<Vec<ResiduePoly<$z>>>, amount: usize, parties: usize) {
                    assert_eq!(results.len(), parties);
                    let mut one_count = 0;
                    for cur_party_res in results.clone() {
                        assert_eq!(amount, cur_party_res.len());
                        // Check that all parties agree on the result
                        assert_eq!(*results.first().unwrap(), cur_party_res);
                        for cur_bit in cur_party_res {
                            assert!(cur_bit == ResiduePoly::ZERO || cur_bit == ResiduePoly::ONE);
                            if cur_bit == ResiduePoly::ONE {
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
                    let mut rng = ChaCha20Rng::seed_from_u64(0);
                    let a = ResiduePoly::<$z>::sample(&mut rng);
                    let t = a + a * a;
                    let x = match Solve::<$z>::solve(&t) {
                        Ok(x) => x,
                        Err(error) => panic!("Failed with error: {}", error),
                    };
                    assert_eq!(t, x + x * x);
                }

                #[test]
                fn [<negative_sample_ $z:lower>]() {
                    let mut rng = ChaCha20Rng::seed_from_u64(1);
                    let a = ResiduePoly::<$z>::sample(&mut rng);
                    // The input not of the form a+a*a
                    let t = a + a * a - ResiduePoly::<$z>::ONE;
                    let x = Solve::<$z>::solve(&t).unwrap();
                    assert_ne!(a + a * a, x + x * x);
                }

                #[test]
                fn [<soak_sample_ $z:lower>]() {
                    let iterations = 1000;
                    let mut rng = rand::thread_rng();
                    let mut a: ResiduePoly<$z>;
                    let mut base_solutions = 0;
                    for _i in 1..iterations {
                        a = ResiduePoly::<$z>::sample(&mut rng);
                        let t = a + a * a;
                        let x = match Solve::<$z>::solve(&t) {
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
}
