use super::distributed::DistributedSession;
use crate::{
    computation::SessionId,
    execution::{agree_random::AgreeRandom, constants::LOG_BD1_NOM, constants::PRSS_SIZE_MAX},
    poly::{Poly, Ring},
    residue_poly::ResiduePoly,
    One, Zero, Z128,
};
use aes_prng::AesRng;
use anyhow::anyhow;
use blake3::Hasher;
use byteorder::{BigEndian, ReadBytesExt};
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::num::Wrapping;

pub(crate) fn create_sets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (1..=n).combinations(n - t).collect()
}

/// structure for holding values for each subset of n-t parties
#[derive(Debug, Clone)]
struct PrssSet {
    parties: Vec<usize>,
    random_agreed_key: PrfKey,
    f_a_points: Vec<ResiduePoly<Z128>>,
}

/// PRSS object that holds info in a certain epoch for a single party Pi
#[derive(Debug, Clone)]
pub struct PRSSSetup {
    /// the logarithm of n choose t (num_parties choose threshold)
    log_n_choose_t: u32,
    /// all possible subsets of n-t parties (A) that contain Pi and their shared PRG
    sets: Vec<PrssSet>,
}

/// PRSS state for use within a given session.
#[derive(Debug, Clone)]
pub struct PRSSState {
    /// session id, which is fixed
    session_id: u128,
    /// counter that increases on every call to .next()
    counter: u128,
    /// PRSSSetup
    prss_setup: PRSSSetup,
}

/// key for blake3
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct PrfKey(pub [u8; 16]);

/// Function Psi that generates bounded randomness
fn psi(psi_prf_key: &PrfKey, sid: u128, ctr: u128, log_n_choose_t: u32) -> anyhow::Result<Z128> {
    let keyvec = [psi_prf_key.0, sid.to_le_bytes()].concat();
    let key = <&[u8; blake3::KEY_LEN]>::try_from(keyvec.as_slice())?;

    let mut prf = Hasher::new_keyed(key);
    prf.update(&ctr.to_le_bytes());
    let mut psi_out = prf.finalize_xof();
    let mut res = [0_u128; 1];
    psi_out.read_u128_into::<BigEndian>(&mut res)?;

    let u = res[0] >> (Z128::EL_BIT_LENGTH as u32 - LOG_BD1_NOM + log_n_choose_t);

    Ok(Wrapping(u))
}

/// computes the points on the polys f_A for all parties in the given sets A
/// f_A is one at 0, and zero at the party indices not in set A
fn party_compute_f_a_points(
    partysets: &Vec<Vec<usize>>,
    num_parties: usize,
) -> anyhow::Result<Vec<Vec<ResiduePoly<Z128>>>> {
    // compute lifted and inverted gamma values once
    let mut inv_coefs = (1..=num_parties)
        .map(ResiduePoly::<Z128>::lift_and_invert)
        .collect::<Result<Vec<_>, _>>()?;
    inv_coefs.insert(0, ResiduePoly::<Z128>::ZERO);

    // embed party IDs once
    let parties: Vec<_> = (0..=num_parties)
        .map(ResiduePoly::<Z128>::embed)
        .collect::<Result<Vec<_>, _>>()?;

    // compute additive inverse of embedded party IDs
    let neg_parties: Vec<_> = (0..=num_parties)
        .map(|p| Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO - parties[p]]))
        .collect::<Vec<_>>();

    // polynomial f(x) = x
    let x: Poly<ResiduePoly<std::num::Wrapping<u128>>> =
        Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO, ResiduePoly::<Z128>::ONE]);

    let mut sets = Vec::new();

    // iterate through the A sets
    for s in partysets {
        // compute poly for this combination of parties
        // poly will be of degree T, zero at the points p not in s, and one at 0
        let mut poly = Poly::from_coefs(vec![ResiduePoly::<Z128>::ONE]);
        for p in 1..=num_parties {
            if !s.contains(&p) {
                poly = poly
                    * (x.clone() + neg_parties[p].clone())
                    * Poly::from_coefs(vec![inv_coefs[p]]);
            }
        }

        // check that poly is 1 at position 0
        debug_assert_eq!(ResiduePoly::<Z128>::ONE, poly.eval(&parties[0]));
        // check that poly is of degree t
        debug_assert_eq!(num_parties - s.len(), poly.deg());

        // evaluate the poly at the party indices gamma
        let points: Vec<_> = (1..=num_parties).map(|p| poly.eval(&parties[p])).collect();
        sets.push(points);
    }
    Ok(sets)
}

impl PRSSState {
    /// PRSS Next for a single party
    pub fn next(&mut self, party_id: usize) -> anyhow::Result<ResiduePoly<Z128>> {
        // party IDs start from 1
        debug_assert!(party_id > 0);

        let mut res = ResiduePoly::<Z128>::ZERO;

        for set in self.prss_setup.sets.iter_mut() {
            if set.parties.contains(&party_id) {
                let psi = psi(
                    &set.random_agreed_key,
                    self.session_id,
                    self.counter,
                    self.prss_setup.log_n_choose_t,
                )?;
                let f_a = set.f_a_points[party_id - 1];
                res += f_a * psi;
            } else {
                return Err(anyhow!("Called prss.next() with party ID {party_id} that is not in a precomputed set of parties!"));
            }
        }

        self.counter += 1;

        Ok(res)
    }
}

impl PRSSSetup {
    pub async fn party_epoch_init_sess<A: AgreeRandom + Send>(
        session: DistributedSession,
        seed: u64,
        party_id: usize,
    ) -> anyhow::Result<Self> {
        let num_parties = session.role_assignments.len();
        let binom_nt = num_integer::binomial(num_parties, session.threshold as usize);

        if binom_nt > PRSS_SIZE_MAX {
            return Err(anyhow!("PRSS set size is too large!"));
        }

        let log_n_choose_t = binom_nt.next_power_of_two().ilog2();

        // create all the subsets A that contain the party id
        let party_sets: Vec<Vec<usize>> = create_sets(num_parties, session.threshold as usize)
            .into_iter()
            .filter(|aset| aset.contains(&party_id))
            .collect();

        let mut all_prss_sets: Vec<PrssSet> = Vec::new();

        // TODO use RNG from Session, once PR #168 is merged
        let mut rng = AesRng::seed_from_u64(seed);

        let seed = rng.next_u64();
        let ars = A::agree_random(&session, seed)
            .await
            .expect("AgreeRandom failed!");

        let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;

        for (idx, set) in party_sets.iter().enumerate() {
            let pset = PrssSet {
                parties: set.to_vec(),
                random_agreed_key: ars[idx].clone(),
                f_a_points: f_a_points[idx].clone(),
            };
            all_prss_sets.push(pset);
        }

        Ok(PRSSSetup {
            log_n_choose_t,
            sets: all_prss_sets,
        })
    }

    pub fn new_prss_session_state(&self, sid: SessionId) -> PRSSState {
        PRSSState {
            session_id: sid.0,
            counter: 0_u128,
            prss_setup: self.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::{Circuit, Operation, Operator},
        execution::{
            agree_random::{DummyAgreeRandom, RealAgreeRandom},
            distributed::{setup_prss_sess, DecryptionMode, DistributedTestRuntime},
            party::Identity,
            prep::to_large_ciphertext,
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
        shamir::ShamirGSharings,
        tests::{helper::get_dummy_session_party_id, test_data_setup::tests::TEST_KEY_PATH},
        value::Value,
    };
    use aes_prng::{AesRng, SEED_SIZE};
    use rand::SeedableRng;
    use rstest::rstest;

    impl PRSSSetup {
        // initializes the epoch for a single party (without actual networking)
        pub fn testing_party_epoch_init<R: RngCore>(
            num_parties: usize,
            threshold: usize,
            rng: &mut R,
            party_id: usize,
        ) -> anyhow::Result<Self> {
            let binom_nt = num_integer::binomial(num_parties, threshold);

            if binom_nt > PRSS_SIZE_MAX {
                return Err(anyhow!("PRSS set size is too large!"));
            }

            let log_n_choose_t = binom_nt.next_power_of_two().ilog2();

            let party_sets = create_sets(num_parties, threshold)
                .into_iter()
                .filter(|aset| aset.contains(&party_id))
                .collect::<Vec<_>>();

            let sess = get_dummy_session_party_id(num_parties, threshold as u8, party_id);
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let random_agreed_keys = rt
                .block_on(async {
                    DummyAgreeRandom::agree_random(&sess.clone(), rng.next_u64()).await
                })
                .unwrap();

            let f_a_points = party_compute_f_a_points(&party_sets, num_parties)?;

            let sets: Vec<PrssSet> = party_sets
                .iter()
                .enumerate()
                .map(|(idx, s)| PrssSet {
                    parties: s.to_vec(),
                    random_agreed_key: random_agreed_keys[idx].clone(),
                    f_a_points: f_a_points[idx].clone(),
                })
                .collect();

            tracing::debug!("epoch init: {:?}", sets);

            Ok(PRSSSetup {
                log_n_choose_t,
                sets,
            })
        }
    }

    #[test]
    fn test_create_sets() {
        let c = create_sets(4, 1);
        assert_eq!(
            c,
            vec![vec![1, 2, 3], vec![1, 2, 4], vec![1, 3, 4], vec![2, 3, 4],]
        )
    }

    #[rstest]
    #[case([23_u8; SEED_SIZE])]
    #[case(AesRng::generate_random_seed())]
    fn test_prss_no_network_bound(#[case] seed: [u8; SEED_SIZE]) {
        let num_parties = 10;
        let threshold = 3;

        let sid = SessionId::from(23);

        let mut rng = AesRng::from_seed(seed);

        let shares = (1..=num_parties)
            .map(|p| {
                let prss_setup =
                    PRSSSetup::testing_party_epoch_init(num_parties, threshold, &mut rng, p)
                        .unwrap();

                let mut state = prss_setup.new_prss_session_state(sid);

                assert_eq!(state.counter, 0);
                assert_eq!(state.session_id, sid.0);

                let nextval = state.next(p).unwrap();

                // prss state counter must have increased after call to next
                assert_eq!(state.counter, 1);
                // prss state session ID must have stayed the same
                assert_eq!(state.session_id, sid.0);

                (p, nextval)
            })
            .collect();

        let e_shares = ShamirGSharings { shares };

        let recon = e_shares.reconstruct(threshold).unwrap();

        tracing::debug!("reconstructed prss value: {}", recon.0);
        tracing::debug!("bitsize of reconstructed value: {}", recon.0.ilog2());
        tracing::debug!("maximum allowed bitsize: {}", LOG_BD1_NOM);

        // check that reconstructed PRSS random output E has limited bit length
        // must be at most (2^pow-1) * Bd bits (which is the nominator of Bd1)
        assert!(recon.0.ilog2() < LOG_BD1_NOM);
    }

    #[test]
    fn test_prss_distributed_local_sess() {
        let threshold = 2;
        let num_parties = 7;
        let mut rng = AesRng::seed_from_u64(69);
        let msg: u8 = 3;
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::PrssPrep,
                    operands: vec![String::from("s0")], // Preprocess random value and store in register s0
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("3"),     // Ignored
                        String::from("false"), // Ignored
                        String::from("c0"),    // Register we store in
                        String::from("s0"),    // Register we read
                    ],
                },
                Operation {
                    operator: Operator::ShrCI, // Right shift
                    operands: vec![String::from("c1"), String::from("c0"), String::from("123")], // Stores the result in c1, reads from c0, and shifts it 123=127-2*2
                },
                Operation {
                    operator: Operator::PrintRegPlain, // Output the value
                    operands: vec![
                        String::from("c1"), // From index c1
                        keys.pk
                            .threshold_lwe_parameters
                            .input_cipher_parameters
                            .usable_message_modulus_log
                            .0
                            .to_string(), // Bits in message
                    ],
                },
            ],
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
            Identity("localhost:5006".to_string()),
        ];

        // generate keys
        let key_shares = keygen_all_party_shares(&keys, &mut rng, num_parties, threshold).unwrap();
        let ct = keys.pk.encrypt(&mut rng, msg);
        let large_ct = to_large_ciphertext(&keys.ck, &ct);

        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_keys(key_shares);

        // create sessions for each prss party
        let sessions: Vec<DistributedSession> = (0..num_parties)
            .map(|p| runtime.session_for_prss(p))
            .collect();

        // Test with real dummy AgreeRandom
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            setup_prss_sess::<RealAgreeRandom>(sessions.clone(), rng.next_u64()).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with circuit evaluation
        let results_circ = runtime
            .evaluate_circuit(&circuit, Some(large_ct.clone()))
            .unwrap();
        let out_circ = &results_circ[&Identity("localhost:5000".to_string())];

        // test PRSS with decryption endpoint
        let results_dec = runtime
            .threshold_decrypt(large_ct.clone(), DecryptionMode::PRSSDecrypt)
            .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_dec[0], Value::Ring128(std::num::Wrapping(msg as u128)));
        assert_eq!(out_circ[0], Value::Ring128(std::num::Wrapping(msg as u128)));

        // Test with real AgreeRandom
        let _guard = rt.enter();
        let prss_setups = rt.block_on(async {
            setup_prss_sess::<DummyAgreeRandom>(sessions, rng.next_u64()).await
        });

        runtime.setup_prss(prss_setups);

        // test PRSS with circuit evaluation
        let results_circ = runtime
            .evaluate_circuit(&circuit, Some(large_ct.clone()))
            .unwrap();
        let out_circ = &results_circ[&Identity("localhost:5000".to_string())];

        // test PRSS with decryption endpoint
        let results_dec = runtime
            .threshold_decrypt(large_ct, DecryptionMode::PRSSDecrypt)
            .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_dec[0], Value::Ring128(std::num::Wrapping(msg as u128)));
        assert_eq!(out_circ[0], Value::Ring128(std::num::Wrapping(msg as u128)));
    }

    #[rstest]
    #[case(0)]
    #[case(1)]
    #[case(2)]
    #[case(23)]
    fn test_prss_next_ctr(#[case] rounds: u128) {
        let num_parties = 4;
        let threshold = 1;

        let sid = SessionId::from(23425);

        let mut rng = AesRng::seed_from_u64(54321);
        let prss =
            PRSSSetup::testing_party_epoch_init(num_parties, threshold, &mut rng, 1).unwrap();

        let mut state = prss.new_prss_session_state(sid);

        assert_eq!(state.counter, 0);
        assert_eq!(state.session_id, sid.0);

        for _ in 0..rounds {
            let _ = state.next(1);
        }

        // prss state counter must have increased to n after n rounds
        assert_eq!(state.counter, rounds);

        // prss state session ID must have stayed the same
        assert_eq!(state.session_id, sid.0);
    }

    #[rstest]
    #[case(4, 1)]
    #[case(10, 3)]
    /// check that points computed on f_A are well-formed
    fn test_prss_fa_poly(#[case] num_parties: usize, #[case] threshold: usize) {
        let mut rng = AesRng::seed_from_u64(5);
        let prss =
            PRSSSetup::testing_party_epoch_init(num_parties, threshold, &mut rng, 1).unwrap();

        for set in prss.sets.iter() {
            for p in 1..=num_parties {
                let point = set.f_a_points[p - 1];
                if set.parties.contains(&p) {
                    assert_ne!(point, ResiduePoly::<Z128>::ZERO)
                } else {
                    assert_eq!(point, ResiduePoly::<Z128>::ZERO)
                }
            }
        }
    }

    #[test]
    #[should_panic(expected = "PRSS set size is too large!")]
    fn test_prss_too_large() {
        let mut rng = AesRng::seed_from_u64(1);
        let _prss = PRSSSetup::testing_party_epoch_init(22, 7, &mut rng, 1).unwrap();
    }

    #[test]
    // check that the combinations of party ID in A and not in A add up to all party IDs and that the indices match when reversing one list
    fn test_matching_combinations() {
        let num_parties = 10;
        let threshold = 3;

        // the combinations of party IDs *in* the sets A
        let sets = create_sets(num_parties, threshold);

        // the combinations of party IDs *not* in the sets A
        let mut combinations = (1..=num_parties)
            .combinations(threshold)
            .collect::<Vec<_>>();
        // reverse the list of party IDs, so the order matches with the combinations of parties *in* the sets A in create_sets()
        combinations.reverse();

        // the list of all party IDs 1..=N in order
        let all_parties = (1..=num_parties).collect_vec();

        for (idx, c) in combinations.iter().enumerate() {
            // merge both sets of party IDs
            let mut merge = [sets[idx].clone(), c.clone()].concat();

            // sort the list, so we can check for equality with all_parites
            merge.sort();

            assert_eq!(merge, all_parties);
        }
    }
}
