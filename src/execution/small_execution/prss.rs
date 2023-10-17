use crate::{
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        agree_random::AgreeRandom,
        broadcast::broadcast_with_corruption,
        constants::LOG_BD1_NOM,
        constants::PRSS_SIZE_MAX,
        party::Role,
        session::{ParameterHandles, SmallSession, SmallSessionHandles, ToBaseSession},
    },
    poly::{Poly, Ring},
    residue_poly::ResiduePoly,
    value::{BroadcastValue, Value},
    One, Zero, Z128,
};
use blake3::Hasher;
use byteorder::{BigEndian, ReadBytesExt};
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    num::Wrapping,
};

pub(crate) fn create_sets(n: usize, t: usize) -> Vec<Vec<usize>> {
    (1..=n).combinations(n - t).collect()
}

/// structure for holding values for each subset of n-t parties
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrssSet {
    parties: PsiSet,
    random_agreed_key: PrfKey,
    f_a_points: Vec<ResiduePoly<Z128>>,
}

/// Structure to hold a n-t sized structure of party IDs
/// Assumed to be stored in increasing order, with party IDs starting from 1
pub type PsiSet = Vec<usize>;

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
    partysets: &Vec<PsiSet>,
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
                return Err(anyhow_error_and_log(format!("Called prss.next() with party ID {party_id} that is not in a precomputed set of parties!")));
            }
        }

        self.counter += 1;

        Ok(res)
    }

    /// Compute the check method which returns the summed up psi value for each party based on the internal counter.
    /// If parties are behaving maliciously they get added to the corruption list in [Dispute]
    pub async fn check<R: RngCore, S: SmallSessionHandles<R>>(
        &mut self,
        session: &mut S,
    ) -> anyhow::Result<HashMap<Role, ResiduePoly<Z128>>> {
        let sets = &self.prss_setup.sets;
        let mut psi_values = Vec::with_capacity(sets.len());
        for cur_set in sets {
            psi_values.push((
                cur_set.clone(),
                psi(
                    &cur_set.random_agreed_key,
                    self.session_id,
                    self.counter,
                    self.prss_setup.log_n_choose_t,
                )?,
            ));
        }
        let broadcastable_psi = psi_values
            .iter()
            .map(|(prss_set, psi)| (prss_set.parties.clone(), Value::Ring128(*psi)))
            .collect_vec();
        let broadcast_result = broadcast_with_corruption::<R, S>(
            session,
            BroadcastValue::PRSSVotes(broadcastable_psi),
        )
        .await?;

        // Count the votes received from the broadcast
        let count = Self::count_votes(&broadcast_result, session);
        // Find which values have received most votes
        let true_psi_vals = Self::find_winning_psi_values(&count);
        // Find the parties who did not vote for the results and add them to the corrupt set
        Self::handle_non_voting_parties(&true_psi_vals, &count, session);
        // Compute result based on majority votes
        self.compute_result(&true_psi_vals, session)
    }

    /// Helper method for counting the votes. Takes the `broadcast_result` and counts which parties has voted/replied each of the different [Value]s for each given [PrssSet].
    /// The result is a map from each unique received [PrssSet] to another map which maps from all possible received [Value]s associated
    /// with the [PrssSet] to the set of [Role]s which has voted/replied to the specific [Value] for the specific [PrssSet].
    fn count_votes<R: RngCore, S: SmallSessionHandles<R>>(
        broadcast_result: &HashMap<Role, BroadcastValue>,
        session: &mut S,
    ) -> HashMap<PsiSet, HashMap<Value, HashSet<Role>>> {
        // We count through a set of voting roles in order to avoid one party voting for the same value multiple times
        let mut count: HashMap<PsiSet, HashMap<Value, HashSet<Role>>> = HashMap::new();
        for (role, broadcast_val) in broadcast_result {
            let vec_pairs = match broadcast_val {
                BroadcastValue::PRSSVotes(vec_values) => {
                    // Check the type of the values sent is Ring128 and add party to the set of corruptions if not
                    for (_cur_set, cur_val) in vec_values {
                        match cur_val {
                            Value::Ring128(_) => continue,
                            _ => {
                                session.add_corrupt(*role);
                                tracing::warn!("Party with role {:?} and identity {:?} sent a value of unexpected type",
                                     role.0, session.role_assignments().get(role));
                            }
                        }
                    }
                    vec_values
                }
                // If the party does not broadcast the type as expected they are considered malicious
                _ => {
                    session.add_corrupt(*role);
                    tracing::warn!("Party with role {:?} and identity {:?} sent values they shouldn't and is thus malicious",
                     role.0, session.role_assignments().get(role));
                    continue;
                }
            };
            // Count the votes received from `role` during broadcast for each [PrssSet]
            for prss_value_pair in vec_pairs {
                let (prss_set, psi) = prss_value_pair;
                match count.get_mut(prss_set) {
                    Some(value_votes) => Self::add_vote(value_votes, psi, *role, session),
                    None => {
                        count.insert(
                            prss_set.clone(),
                            HashMap::from([(psi.clone(), HashSet::from([*role]))]),
                        );
                    }
                };
            }
        }
        count
    }

    /// Helper method that uses a psi value, `cur_psi`, and counts it in `value_votes`, associated to `cur_role`.
    /// That is, if it is not present in `value_votes` it gets added and in either case `cur_role` gets counted as having
    /// voted for `cur_psi`.
    /// In case `cur_role` has already voted for `cur_psi` they get added to the list of corrupt parties.
    fn add_vote<R: RngCore, S: SmallSessionHandles<R>>(
        value_votes: &mut HashMap<Value, HashSet<Role>>,
        cur_psi: &Value,
        cur_role: Role,
        session: &mut S,
    ) {
        match value_votes.get_mut(cur_psi) {
            Some(existing_roles) => {
                // If it has been seen before, insert the current contributing role
                let role_inserted = existing_roles.insert(cur_role);
                if !role_inserted {
                    // If the role was not inserted then it was already present and hence the party is trying to vote multiple times
                    // and they should be marked as corrupt
                    session.add_corrupt(cur_role);
                    tracing::warn!("Party with role {:?} and identity {:?} is trying to vote for the same psi more than once and is thus malicious",
                         cur_role.0, session.role_assignments().get(&cur_role));
                }
            }
            None => {
                value_votes.insert(cur_psi.clone(), HashSet::from([cur_role]));
            }
        };
    }

    /// Helper method for finding which values have received most votes
    /// Takes as input the counts of the different psi values from each of the parties and finds the value received
    /// by most parties for each entry in the [PrssSet].
    /// Returns a [HashMap] mapping each of the sets in [PrssSet] to the [Value] received by most parties for this set.
    fn find_winning_psi_values(
        count: &HashMap<PsiSet, HashMap<Value, HashSet<Role>>>,
    ) -> HashMap<&PsiSet, &Value> {
        let mut true_psi_vals = HashMap::with_capacity(count.len());
        for (prss_set, value_votes) in count {
            let mut local_max = 0;
            let mut value_max = &Value::Ring128(Wrapping(0));
            // Go through all values and keep track of which one has received the most votes
            for (value, votes) in value_votes {
                if votes.len() > local_max {
                    local_max = votes.len();
                    value_max = value;
                }
            }
            true_psi_vals.insert(prss_set, value_max);
        }
        true_psi_vals
    }

    /// Helper method for finding the parties who did not vote for the results and add them to the corrupt set.
    /// Goes through `true_psi_vals` and find which parties did not vote for the psi values it contains.
    /// This is done by cross-referencing the votes in `count`
    fn handle_non_voting_parties<R: RngCore, S: SmallSessionHandles<R>>(
        true_psi_vals: &HashMap<&PsiSet, &Value>,
        count: &HashMap<PsiSet, HashMap<Value, HashSet<Role>>>,
        session: &mut S,
    ) {
        for (prss_set, value) in true_psi_vals {
            if let Some(roles_votes) = count
                .get(*prss_set)
                .and_then(|value_map| value_map.get(value))
            {
                if prss_set.len() > roles_votes.len() {
                    for cur_role in session.role_assignments().clone().keys() {
                        if !roles_votes.contains(cur_role) {
                            session.add_corrupt(*cur_role);
                            tracing::warn!("Party with role {:?} and identity {:?} did not vote for the correct psi value and is thus malicious",
                                 cur_role.0, session.role_assignments().get(cur_role));
                        }
                    }
                }
            }
        }
    }

    /// Helper method for computing the resultant psi value based on the winning value for each [PrssSet]
    fn compute_result<R: RngCore, S: SmallSessionHandles<R>>(
        &mut self,
        true_psi_vals: &HashMap<&PsiSet, &Value>,
        session: &S,
    ) -> anyhow::Result<HashMap<Role, ResiduePoly<Z128>>> {
        let sets = create_sets(session.amount_of_parties(), session.threshold() as usize);
        let points = party_compute_f_a_points(&sets, session.amount_of_parties())?;

        let mut s_values = HashMap::with_capacity(session.amount_of_parties());
        for cur_role in session.role_assignments().keys() {
            let mut cur_s = ResiduePoly::<Z128>::ZERO;
            for (idx, set) in sets.iter().enumerate() {
                if set.contains(&(cur_role.0 as usize)) {
                    let f_a = points[idx][(cur_role.0 - 1) as usize];
                    if let Some(Value::Ring128(cur_psi)) = true_psi_vals.get(set) {
                        cur_s += f_a * (*cur_psi);
                    } else {
                        return Err(anyhow_error_and_log(
                            "A PSI value which should exist does no longer exist".to_string(),
                        ));
                    }
                }
            }
            s_values.insert(*cur_role, cur_s);
        }
        Ok(s_values)
    }
}

impl PRSSSetup {
    pub async fn party_epoch_init_sess<A: AgreeRandom + Send>(
        session: &SmallSession,
        party_id: usize,
    ) -> anyhow::Result<Self> {
        let num_parties = session.amount_of_parties();
        let binom_nt = num_integer::binomial(num_parties, session.threshold() as usize);

        if binom_nt > PRSS_SIZE_MAX {
            return Err(anyhow_error_and_log(
                "PRSS set size is too large!".to_string(),
            ));
        }

        let log_n_choose_t = binom_nt.next_power_of_two().ilog2();

        // create all the subsets A that contain the party id
        let party_sets: Vec<Vec<usize>> = create_sets(num_parties, session.threshold() as usize)
            .into_iter()
            .filter(|aset| aset.contains(&party_id))
            .collect();

        let mut all_prss_sets: Vec<PrssSet> = Vec::new();

        let ars = A::agree_random(&mut session.to_base_session())
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
            distributed::{setup_prss_sess, DistributedTestRuntime},
            party::{Identity, Role},
            session::{BaseSessionHandles, DecryptionMode},
            small_execution::prep::to_large_ciphertext,
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
        shamir::ShamirGSharings,
        tests::{
            helper::tests::{generate_identities, get_small_session_for_parties},
            test_data_setup::tests::TEST_KEY_PATH,
        },
        value::Value,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    impl PRSSSetup {
        // initializes the epoch for a single party (without actual networking)
        pub fn testing_party_epoch_init(
            num_parties: usize,
            threshold: usize,
            party_id: usize,
        ) -> anyhow::Result<Self> {
            let binom_nt = num_integer::binomial(num_parties, threshold);

            if binom_nt > PRSS_SIZE_MAX {
                return Err(anyhow_error_and_log(
                    "PRSS set size is too large!".to_string(),
                ));
            }

            let log_n_choose_t = binom_nt.next_power_of_two().ilog2();

            let party_sets = create_sets(num_parties, threshold)
                .into_iter()
                .filter(|aset| aset.contains(&party_id))
                .collect::<Vec<_>>();

            let sess = get_small_session_for_parties(
                num_parties,
                threshold as u8,
                Role::from(party_id as u64),
            );
            let rt = tokio::runtime::Runtime::new().unwrap();
            let _guard = rt.enter();
            let random_agreed_keys = rt
                .block_on(async {
                    DummyAgreeRandom::agree_random(&mut sess.to_base_session()).await
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
    fn test_prss_no_network_bound() {
        let num_parties = 10;
        let threshold = 3;

        let sid = SessionId::from(23);

        let shares = (1..=num_parties)
            .map(|p| {
                let prss_setup =
                    PRSSSetup::testing_party_epoch_init(num_parties, threshold, p).unwrap();

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

        let recon = Z128::try_from(e_shares.reconstruct(threshold).unwrap()).unwrap();

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
        // RNG for keys
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
        let identities = generate_identities(num_parties);

        // generate keys
        let key_shares = keygen_all_party_shares(&keys, &mut rng, num_parties, threshold).unwrap();
        let ct = keys.pk.encrypt(&mut rng, msg);
        let large_ct = to_large_ciphertext(&keys.ck, &ct);

        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_keys(key_shares);

        let mut seed = [0_u8; 32];
        // create sessions for each prss party
        let sessions: Vec<SmallSession> = (0..num_parties)
            .map(|p| {
                seed[0] = p as u8;
                runtime
                    .small_session_for_player(
                        SessionId(u128::MAX),
                        p,
                        Some(ChaCha20Rng::from_seed(seed)),
                    )
                    .unwrap()
            })
            .collect();

        // Test with real dummy AgreeRandom
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setups =
            rt.block_on(async { setup_prss_sess::<RealAgreeRandom>(sessions.clone()).await });

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
        let prss_setups =
            rt.block_on(async { setup_prss_sess::<DummyAgreeRandom>(sessions).await });

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

        let prss = PRSSSetup::testing_party_epoch_init(num_parties, threshold, 1).unwrap();

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
        let prss = PRSSSetup::testing_party_epoch_init(num_parties, threshold, 1).unwrap();

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
        let _prss = PRSSSetup::testing_party_epoch_init(22, 7, 1).unwrap();
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

    #[test]
    fn sunshine_prss_check() {
        let parties = 5;
        let threshold = 1;
        let identities = generate_identities(parties);

        let runtime = DistributedTestRuntime::new(identities, threshold as u8);
        let session_id = SessionId(23);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        let mut reference_values = Vec::with_capacity(parties);
        for party_id in 1..=parties {
            let rng = ChaCha20Rng::seed_from_u64(party_id as u64);
            let mut session = runtime
                .small_session_for_player(session_id, party_id - 1, Some(rng))
                .unwrap();
            DistributedTestRuntime::add_prss::<DummyAgreeRandom>(&mut session);
            let mut state = session.prss().clone().unwrap();
            // Compute reference value based on check (we clone to ensure that they are evaluated for the same counter)
            reference_values.push(state.clone().next(party_id).unwrap());
            // Do the actual computation
            set.spawn(async move {
                let res = state.check(&mut session).await.unwrap();
                // Ensure no corruptions happened
                assert!(session.corrupt_roles().is_empty());
                res
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        // Check the result
        // First verify that we get the expected amount of results (i.e. no threads panicked)
        assert_eq!(results.len(), parties);
        for output in &results {
            // Validate that each party has the expected amount of outputs
            assert_eq!(parties, output.len());
            // Validate that all parties have the same view of output
            assert_eq!(results.get(0).unwrap(), output);
            for (received_role, received_poly) in output {
                // Validate against result of the "next" method
                assert_eq!(
                    reference_values
                        .get((received_role.0 - 1) as usize)
                        .unwrap(),
                    received_poly
                );
                // Perform sanity checks (i.e. that nothing is a trivial element and party IDs are in a valid range)
                assert!(received_role.0 <= parties as u64);
                assert!(received_role.0 > 0_u64);
                assert_ne!(&ResiduePoly::ZERO, received_poly);
                assert_ne!(&ResiduePoly::ONE, received_poly);
            }
        }
    }

    #[test]
    fn test_count_votes() {
        let parties = 3;
        let my_role = Role(3);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = Value::Ring128(Wrapping(42));
        let values = Vec::from([(set.clone(), value.clone())]);
        let broadcast_result = HashMap::from([
            (Role(1), BroadcastValue::PRSSVotes(values.clone())),
            (Role(2), BroadcastValue::PRSSVotes(values.clone())),
            (Role(3), BroadcastValue::PRSSVotes(values.clone())),
        ]);

        let res = PRSSState::count_votes(&broadcast_result, &mut session);
        let reference_votes =
            HashMap::from([(value.clone(), HashSet::from([Role(1), Role(2), Role(3)]))]);
        let reference = HashMap::from([(set.clone(), reference_votes)]);
        assert_eq!(reference, res);
        assert!(session.corrupt_roles().is_empty());
    }

    /// Test the if a party broadcasts a wrong type then they will get added to the corruption set
    #[traced_test]
    #[test]
    fn test_count_votes_bad_type() {
        let parties = 3;
        let my_role = Role(3);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let set = Vec::from([1, 2, 3]);
        let value = Value::U64(42);
        let values = Vec::from([(set.clone(), value.clone())]);
        let broadcast_result = HashMap::from([
            (Role(1), BroadcastValue::PRSSVotes(values.clone())),
            (
                Role(2),
                BroadcastValue::RingValue(Value::Ring128(Wrapping(42))),
            ), // Not the broadcast type
            (
                Role(3),
                BroadcastValue::PRSSVotes(Vec::from([(set.clone(), Value::U64(42))])),
            ), // Not the right Value typw
        ]);

        let res = PRSSState::count_votes(&broadcast_result, &mut session);
        let reference_votes = HashMap::from([(value.clone(), HashSet::from([Role(1), Role(3)]))]);
        let reference = HashMap::from([(set.clone(), reference_votes)]);
        assert_eq!(reference, res);
        assert!(session.corrupt_roles().contains(&Role(2)));
        assert!(session.corrupt_roles().contains(&Role(3)));
        assert!(logs_contain(
            "sent values they shouldn't and is thus malicious"
        ));
        assert!(logs_contain("sent a value of unexpected type"));
    }

    #[traced_test]
    #[test]
    fn test_add_votes() {
        let parties = 3;
        let my_role = Role(3);
        let mut session = get_small_session_for_parties(parties, 0, my_role);
        let value = Value::U64(42);
        let mut votes = HashMap::new();

        PRSSState::add_vote(&mut votes, &value, Role(3), &mut session);
        // Check that the vote of `my_role` was added
        assert!(votes.get(&value).unwrap().contains(&Role(3)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        PRSSState::add_vote(&mut votes, &value, Role(2), &mut session);
        // Check that role 2 also gets added
        assert!(votes.get(&value).unwrap().contains(&Role(2)));
        // And that the corruption set is still empty
        assert!(session.corrupt_roles().is_empty());

        // Check that `my_role` gets added to the set of corruptions after trying to vote a second time
        PRSSState::add_vote(&mut votes, &value, Role(3), &mut session);
        assert!(votes.get(&value).unwrap().contains(&Role(3)));
        assert!(session.corrupt_roles().contains(&Role(3)));
        assert!(logs_contain(
            "is trying to vote for the same psi more than once and is thus malicious"
        ));
    }

    #[test]
    fn test_find_winning_psi_values() {
        let set = Vec::from([1, 2, 3]);
        let value = Value::U64(42);
        let true_psi_vals = HashMap::from([(&set, &value)]);
        let votes = HashMap::from([
            (Value::U64(1), HashSet::from([Role(1), Role(2)])),
            (value.clone(), HashSet::from([Role(1), Role(2), Role(3)])),
        ]);
        let count = HashMap::from([(set.clone(), votes)]);
        let result = PRSSState::find_winning_psi_values(&count);
        assert_eq!(result, true_psi_vals);
    }

    /// Test to identify a party which did not vote for the expected value in `handle_non_voting_parties`
    #[traced_test]
    #[test]
    fn identify_non_voting_party() {
        let parties = 3;
        let set = Vec::from([1, 2, 3]);
        let mut session = get_small_session_for_parties(parties, 0, Role(1));
        let value = Value::U64(42);
        let true_psi_vals = HashMap::from([(&set, &value)]);
        // Party 3 is not voting for the correct value
        let votes = HashMap::from([(value.clone(), HashSet::from([Role(1), Role(2)]))]);
        let count = HashMap::from([(set.clone(), votes)]);
        PRSSState::handle_non_voting_parties(&true_psi_vals, &count, &mut session);
        assert!(session.corrupt_roles.contains(&Role(3)));
        assert!(logs_contain(
            "did not vote for the correct psi value and is thus malicious"
        ));
    }

    #[test]
    fn sunshine_compute_result() {
        let parties = 1;
        let role = Role(1);
        let session = get_small_session_for_parties(parties, 0, Role(1));

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async {
                PRSSSetup::party_epoch_init_sess::<DummyAgreeRandom>(&session, 1).await
            })
            .unwrap();
        let mut state = prss_setup.new_prss_session_state(session.session_id());

        for set in prss_setup.sets {
            // Compute the reference value and use clone to ensure that the same counter is used for all parties
            let psi_next = state.clone().next(role.party_id()).unwrap();
            let local_psi = psi(
                &set.random_agreed_key,
                state.session_id,
                state.counter,
                state.prss_setup.log_n_choose_t,
            )
            .unwrap();
            let local_psi_value = Value::Ring128(local_psi);
            let true_psi_vals = HashMap::from([(&set.parties, &local_psi_value)]);

            let com_true_psi_vals = state.compute_result(&true_psi_vals, &session).unwrap();
            assert_eq!(&psi_next, com_true_psi_vals.get(&role).unwrap());
        }
    }

    /// Tests that compute_result fails as expected when a set is not present in the `true_psi_vals` given as input
    #[test]
    fn expected_set_not_present() {
        let parties = 10;
        let mut session = get_small_session_for_parties(parties, 0, Role(1));
        DistributedTestRuntime::add_prss::<DummyAgreeRandom>(&mut session);
        let mut state = session.prss().clone().unwrap();
        // Use an empty hash map to ensure that
        let psi_values = HashMap::new();
        assert!(state.compute_result(&psi_values, &session).is_err());
    }
}
