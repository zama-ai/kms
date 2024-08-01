/// Currently we cannot make this bench under #[cfg(test)] because it is used by the benches
/// One alternative would be to compile the benches with a special flag but unsure what happens
/// with the profiler when we do this.
/// TODO(Dragos) Investigate this afterwards.
pub mod tests_and_benches {

    use std::time::Duration;

    use crate::{
        algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed},
        networking::NetworkMode,
    };
    use aes_prng::AesRng;
    use futures::Future;
    use rand::SeedableRng;
    use tokio::task::JoinSet;

    use crate::{
        execution::runtime::{
            session::{LargeSession, SmallSession},
            test_runtime::{generate_fixed_identities, DistributedTestRuntime},
        },
        networking::Networking,
        session_id::SessionId,
    };

    /// Helper method for executing networked tests with multiple parties for small session.
    /// The `task` argument contains the code to be execute per party which returns a value of type [OutputT].
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the parties
    /// interactive computation.
    /// `expected_rounds` can be used to test that the protocol needs the specified amount of comm rounds, or be set to None to allow any number of rounds
    pub fn execute_protocol_small<Z: ErrorCorrect + RingEmbed + Invert, TaskOutputT, OutputT>(
        parties: usize,
        threshold: u8,
        expected_rounds: Option<usize>,
        network_mode: NetworkMode,
        delay_vec: Option<Vec<Duration>>,
        task: &mut dyn FnMut(SmallSession<Z>) -> TaskOutputT,
    ) -> Vec<OutputT>
    where
        TaskOutputT: Future<Output = OutputT>,
        TaskOutputT: Send + 'static,
        OutputT: Send + 'static,
    {
        let identities = generate_fixed_identities(parties);
        let delay_map = delay_vec.map(|delay_vec| {
            identities
                .iter()
                .enumerate()
                .filter_map(|(idx, identity)| {
                    delay_vec.get(idx).map(|delay| (identity.clone(), *delay))
                })
                .collect()
        });
        let test_runtime =
            DistributedTestRuntime::new(identities.clone(), threshold, network_mode, delay_map);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut tasks = JoinSet::new();
        for party_id in 0..parties {
            let session = test_runtime.small_session_for_party(
                session_id,
                party_id,
                Some(AesRng::seed_from_u64(party_id as u64)),
            );
            tasks.spawn(task(session));
        }
        let res = rt.block_on(async {
            let mut results = Vec::with_capacity(tasks.len());
            while let Some(v) = tasks.join_next().await {
                results.push(v.unwrap());
            }
            results
        });

        // test that the number of rounds is as expected
        if let Some(e_r) = expected_rounds {
            for n in test_runtime.user_nets {
                let rounds = std::sync::Arc::clone(&n).get_current_round().unwrap();
                assert_eq!(
                    rounds, e_r,
                    "incorrect number of expected communication rounds"
                );
            }
        }

        res
    }

    /// Helper method for executing networked tests with multiple parties for LargeSession.
    /// The `task` argument contains the code to be execute per party which returns a value of type [OutputT].
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the parties
    /// interactive computation.
    /// `expected_rounds` can be used to test that the protocol needs the specified amount of comm rounds, or be set to None to allow any number of rounds
    pub fn execute_protocol_large<Z: Ring, TaskOutputT, OutputT>(
        parties: usize,
        threshold: usize,
        expected_rounds: Option<usize>,
        network_mode: NetworkMode,
        delay_vec: Option<Vec<Duration>>,
        task: &mut dyn FnMut(LargeSession) -> TaskOutputT,
    ) -> Vec<OutputT>
    where
        TaskOutputT: Future<Output = OutputT>,
        TaskOutputT: Send + 'static,
        OutputT: Send + 'static,
    {
        let identities = generate_fixed_identities(parties);
        let delay_map = delay_vec.map(|delay_vec| {
            identities
                .iter()
                .enumerate()
                .filter_map(|(idx, identity)| {
                    delay_vec.get(idx).map(|delay| (identity.clone(), *delay))
                })
                .collect()
        });
        let test_runtime = DistributedTestRuntime::<Z>::new(
            identities.clone(),
            threshold as u8,
            network_mode,
            delay_map,
        );
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut tasks = JoinSet::new();
        for party_id in 0..parties {
            let session = test_runtime.large_session_for_party(session_id, party_id);
            tasks.spawn(task(session));
        }
        let res = rt.block_on(async {
            let mut results = Vec::with_capacity(tasks.len());
            while let Some(v) = tasks.join_next().await {
                results.push(v.unwrap());
            }
            results
        });

        // test that the number of rounds is as expected
        if let Some(e_r) = expected_rounds {
            for n in test_runtime.user_nets {
                let rounds = std::sync::Arc::clone(&n).get_current_round().unwrap();
                assert_eq!(rounds, e_r);
            }
        }

        res
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        algebra::structure_traits::Ring,
        execution::{
            constants::SMALL_TEST_KEY_PATH,
            runtime::{
                party::{Identity, Role},
                session::{
                    BaseSessionStruct, LargeSession, LargeSessionHandles, SessionParameters,
                },
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            tfhe_internals::{
                parameters::{Ciphertext64, NoiseFloodParameters},
                test_feature::{gen_key_set, KeySet},
            },
        },
        file_handling::read_element,
        networking::{local::LocalNetworkingProducer, NetworkMode, Networking},
        session_id::SessionId,
        tests::test_data_setup::tests::DEFAULT_SEED,
    };
    use crate::{
        execution::constants::{
            PARAMS_DIR, REAL_KEY_PATH, REAL_PARAM_PATH, SMALL_TEST_PARAM_PATH, TEMP_DKG_DIR,
        },
        file_handling::write_as_json,
        tests::test_data_setup::tests::{ensure_keys_exist, REAL_PARAMETERS, TEST_PARAMETERS},
    };
    use aes_prng::AesRng;
    use futures::Future;
    use itertools::Itertools;
    use rand::SeedableRng;
    use std::fs;
    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };
    use tfhe::{prelude::FheEncrypt, FheUint8};
    use tokio::task::{JoinError, JoinSet};

    #[derive(Default, Clone)]
    pub struct TestingParameters {
        pub num_parties: usize,
        pub threshold: usize,
        pub malicious_roles: Vec<Role>,
        pub roles_to_lie_to: Vec<usize>,
        pub dispute_pairs: Vec<(Role, Role)>,
        pub should_be_detected: bool,
        pub expected_rounds: Option<usize>,
    }

    impl TestingParameters {
        ///Init test parameters with
        /// - number of parties
        /// - threshold
        /// - index of malicious parties (starting at 0)
        /// - index of parties to lie to if applicable (starting at 0)
        /// - dispute pairs (starting at 0)
        /// - whether we expect the current test to be detected
        pub fn init(
            num_parties: usize,
            threshold: usize,
            malicious_roles_idx: &[usize],
            roles_to_lie_to: &[usize],
            dispute_pairs: &[(usize, usize)],
            should_be_detected: bool,
            expected_rounds: Option<usize>,
        ) -> Self {
            Self {
                num_parties,
                threshold,
                malicious_roles: roles_from_idxs(malicious_roles_idx),
                roles_to_lie_to: roles_to_lie_to.to_vec(),
                dispute_pairs: dispute_pairs
                    .iter()
                    .map(|(idx_a, idx_b)| {
                        (Role::indexed_by_zero(*idx_a), Role::indexed_by_zero(*idx_b))
                    })
                    .collect_vec(),
                should_be_detected,
                expected_rounds,
            }
        }

        ///Init test parameters with
        /// - number of parties
        /// - threshold
        /// - expected number of rounds (optional)
        ///
        /// Everything related to cheating is set to default (i.e. no cheating happens)
        pub fn init_honest(
            num_parties: usize,
            threshold: usize,
            expected_rounds: Option<usize>,
        ) -> Self {
            Self {
                num_parties,
                threshold,
                expected_rounds,
                ..Default::default()
            }
        }

        ///Init test parameters with
        /// - number of parties
        /// - threshold
        /// - dispute pairs (starting at 0)
        ///
        /// Everything else is set to default (i.e. no cheating happens)
        pub fn init_dispute(
            num_parties: usize,
            threshold: usize,
            dispute_pairs: &[(usize, usize)],
        ) -> Self {
            Self {
                num_parties,
                threshold,
                dispute_pairs: dispute_pairs
                    .iter()
                    .map(|(idx_a, idx_b)| {
                        (Role::indexed_by_zero(*idx_a), Role::indexed_by_zero(*idx_b))
                    })
                    .collect_vec(),
                ..Default::default()
            }
        }

        ///Retrieve a dispute map as well as the roles which are malicious due to disputes
        pub fn get_dispute_map(&self) -> (HashMap<&Role, Vec<Role>>, Vec<Role>) {
            let mut dispute_map = HashMap::new();
            for (role_a, role_b) in self.dispute_pairs.iter() {
                dispute_map
                    .entry(role_a)
                    .and_modify(|vec_dispute: &mut Vec<Role>| vec_dispute.push(*role_b))
                    .or_insert(vec![*role_b]);

                dispute_map
                    .entry(role_b)
                    .and_modify(|vec_dispute: &mut Vec<Role>| vec_dispute.push(*role_a))
                    .or_insert(vec![*role_a]);
            }
            let malicious_due_to_dispute = dispute_map
                .iter()
                .filter_map(|(role, vec_dispute)| {
                    if vec_dispute.len() > self.threshold {
                        Some(**role)
                    } else {
                        None
                    }
                })
                .collect_vec();
            (dispute_map, malicious_due_to_dispute)
        }
    }

    ///Generate a vector of roles from zero indexed vector of id
    pub fn roles_from_idxs(idx_roles: &[usize]) -> Vec<Role> {
        idx_roles
            .iter()
            .map(|idx_role| Role::indexed_by_zero(*idx_role))
            .collect_vec()
    }

    /// Deterministic key generation
    pub fn generate_keys(params: NoiseFloodParameters) -> KeySet {
        let mut seeded_rng = AesRng::seed_from_u64(DEFAULT_SEED);
        gen_key_set(params, &mut seeded_rng)
    }

    /// Indeterministic cipher generation.
    /// Encrypts a small message with deterministic randomness
    pub fn generate_cipher(_key_name: &str, message: u8) -> Ciphertext64 {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();
        let (ct, _id) = FheUint8::encrypt(message, &keys.client_key).into_raw_parts();
        ct
    }

    /// Generates dummy parameters for unit tests with role 1. Parameters contain a single party, session ID = 1 and threshold = 0
    pub fn get_dummy_parameters() -> SessionParameters {
        let mut role_assignment = HashMap::new();
        let id = Identity("localhost:5000".to_string());
        role_assignment.insert(Role::indexed_by_one(1), id.clone());
        SessionParameters {
            threshold: 0,
            session_id: SessionId(1),
            own_identity: id,
            role_assignments: role_assignment,
        }
    }

    /// Generates dummy parameters for unit tests with session ID = 1
    pub fn get_dummy_parameters_for_parties(
        amount: usize,
        threshold: u8,
        role: Role,
    ) -> SessionParameters {
        assert!(amount > 0);
        let mut role_assignment = HashMap::new();
        for i in 0..amount {
            role_assignment.insert(
                Role::indexed_by_zero(i),
                Identity(format!("localhost:{}", 5000 + i)),
            );
        }
        SessionParameters {
            threshold,
            session_id: SessionId(1),
            own_identity: role_assignment.get(&role).unwrap().clone(),
            role_assignments: role_assignment,
        }
    }

    /// Returns a base session to be used with a single party, with role 1, suitable for testing with dummy constructs
    pub fn get_base_session(
        network_mode: NetworkMode,
    ) -> BaseSessionStruct<AesRng, SessionParameters> {
        let parameters = get_dummy_parameters();
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        BaseSessionStruct {
            parameters,
            network: Arc::new(net_producer.user_net(id, network_mode, None)),
            rng: AesRng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
        }
    }

    /// Returns a base session to be used with multiple parties
    pub fn get_networkless_base_session_for_parties(
        amount: usize,
        threshold: u8,
        role: Role,
    ) -> BaseSessionStruct<AesRng, SessionParameters> {
        let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        BaseSessionStruct {
            parameters,
            network: Arc::new(net_producer.user_net(id, NetworkMode::Sync, None)),
            rng: AesRng::seed_from_u64(role.zero_based() as u64),
            corrupt_roles: HashSet::new(),
        }
    }

    /// Return a large session to be used with a single party, with role 1
    pub fn get_large_session(network_mode: NetworkMode) -> LargeSession {
        let base_session = get_base_session(network_mode);
        LargeSession::new(base_session)
    }

    /// Return a large session to be used with a multiple parties
    pub fn get_networkless_large_session_for_parties(
        amount: usize,
        threshold: u8,
        role: Role,
    ) -> LargeSession {
        let base_session = get_networkless_base_session_for_parties(amount, threshold, role);
        LargeSession::new(base_session)
    }

    /// Helper method for executing networked tests with multiple parties some honest some dishonest.
    /// The `task_honest` argument contains the code to be execute by honest parties which returns a value of type [OutputT].
    /// The `task_malicious` argument contains the code to be execute by malicious parties which returns a value of type [OutputT].
    /// The `malicious_roles` argument contains the list of roles which should execute the `task_malicious`
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the honest parties
    /// interactive computation.
    ///
    ///**NOTE: FOR ALL TESTS THE RNG SEED OF A PARTY IS ITS PARTY_ID, THIS IS ACTUALLY USED IN SOME TESTS TO CHECK CORRECTNESS.**
    #[allow(clippy::too_many_arguments)]
    pub fn execute_protocol_large_w_disputes_and_malicious<
        Z: Ring,
        TaskOutputT,
        OutputT,
        TaskOutputM,
        OutputM,
        P: Clone,
    >(
        params: &TestingParameters,
        dispute_pairs: &[(Role, Role)],
        malicious_roles: &[Role],
        malicious_strategy: P,
        network_mode: NetworkMode,
        delay_vec: Option<Vec<std::time::Duration>>,
        task_honest: &mut dyn FnMut(LargeSession) -> TaskOutputT,
        task_malicious: &mut dyn FnMut(LargeSession, P) -> TaskOutputM,
    ) -> (Vec<OutputT>, Vec<Result<OutputM, JoinError>>)
    where
        TaskOutputT: Future<Output = OutputT>,
        TaskOutputT: Send + 'static,
        OutputT: Send + 'static,
        TaskOutputM: Future<Output = OutputM>,
        TaskOutputM: Send + 'static,
        OutputM: Send + 'static,
    {
        let parties = params.num_parties;
        let threshold = params.threshold as u8;

        let identities = generate_fixed_identities(parties);
        let delay_map = delay_vec.map(|delay_vec| {
            identities
                .iter()
                .enumerate()
                .filter_map(|(idx, identity)| {
                    delay_vec.get(idx).map(|delay| (identity.clone(), *delay))
                })
                .collect()
        });
        let test_runtime = DistributedTestRuntime::<Z>::new(
            identities.clone(),
            threshold,
            network_mode,
            delay_map,
        );
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut honest_tasks = JoinSet::new();
        let mut malicious_tasks = JoinSet::new();
        for party_id in 0..parties {
            let mut session = test_runtime.large_session_for_party(session_id, party_id);

            if malicious_roles.contains(&Role::indexed_by_zero(party_id)) {
                let malicious_strategy_cloned = malicious_strategy.clone();
                malicious_tasks.spawn(task_malicious(session, malicious_strategy_cloned));
            } else {
                for (role_a, role_b) in dispute_pairs.iter() {
                    let _ = session.add_dispute(role_a, role_b);
                }
                honest_tasks.spawn(task_honest(session));
            }
        }
        let res = rt.block_on(async {
            let mut results_honest = Vec::with_capacity(honest_tasks.len());
            let mut results_malicious = Vec::with_capacity(honest_tasks.len());
            while let Some(v) = honest_tasks.join_next().await {
                results_honest.push(v.unwrap());
            }
            while let Some(v) = malicious_tasks.join_next().await {
                results_malicious.push(v);
            }
            (results_honest, results_malicious)
        });

        // test that the number of rounds is as expected
        if let Some(e_r) = params.expected_rounds {
            for n in test_runtime.user_nets {
                let rounds = std::sync::Arc::clone(&n).get_current_round().unwrap();
                assert_eq!(rounds, e_r);
            }
        }

        res
    }

    #[ctor::ctor]
    fn setup_data_for_integration() {
        // Ensure temp/dkg dir exists (also creates the temp dir)
        if let Err(e) = fs::create_dir_all(TEMP_DKG_DIR) {
            println!("Error creating temp/dkg directory {TEMP_DKG_DIR}: {e:?}");
        }
        // Ensure parameters dir exists to store generated parameters json files
        if let Err(e) = fs::create_dir_all(PARAMS_DIR) {
            println!("Error creating parameters directory {PARAMS_DIR}: {e:?}");
        }

        // write parameter JSON files
        write_as_json(SMALL_TEST_PARAM_PATH.to_string(), &TEST_PARAMETERS).unwrap();
        write_as_json(REAL_PARAM_PATH.to_string(), &REAL_PARAMETERS).unwrap();

        // make sure keys exist (generate them if they do not)
        ensure_keys_exist(SMALL_TEST_KEY_PATH, TEST_PARAMETERS);
        ensure_keys_exist(REAL_KEY_PATH, REAL_PARAMETERS);
    }
}
