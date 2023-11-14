#[cfg(test)]
pub mod tests {

    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use aes_prng::AesRng;
    use futures::Future;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tokio::task::{JoinError, JoinSet};

    use crate::{
        computation::SessionId,
        execution::{
            distributed::DistributedTestRuntime,
            party::{Identity, Role},
            session::{
                BaseSessionHandles, DisputeSet, LargeSession, LargeSessionHandles,
                ParameterHandles, SessionParameters, SmallSession,
            },
        },
        file_handling::read_element,
        lwe::{gen_key_set, Ciphertext64, KeySet, ThresholdLWEParameters},
        networking::local::LocalNetworkingProducer,
        tests::test_data_setup::tests::{DEFAULT_SEED, TEST_KEY_PATH},
    };

    ///Generate a vector of roles from zero indexed vector of id
    pub fn roles_from_idxs(idx_roles: &[usize]) -> Vec<Role> {
        idx_roles
            .iter()
            .map(|idx_role| Role::indexed_by_zero(*idx_role))
            .collect_vec()
    }

    /// Deterministic key generation
    pub fn generate_keys(params: ThresholdLWEParameters) -> KeySet {
        let mut seeded_rng = AesRng::seed_from_u64(DEFAULT_SEED);
        gen_key_set(params, &mut seeded_rng)
    }

    /// Deterministic cipher generation.
    /// Encrypts a small message with determistic randomness
    pub fn generate_cipher(_key_name: &str, message: u8) -> Ciphertext64 {
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let mod_log = keys
            .pk
            .threshold_lwe_parameters
            .input_cipher_parameters
            .usable_message_modulus_log
            .0;
        if message >= 1 << mod_log {
            panic!("Message cannot be handled in a single block with current parameters!");
        }
        let mut seeded_rng = AesRng::seed_from_u64(444);
        keys.pk
            .encrypt_w_bitlimit(&mut seeded_rng, message, mod_log)
    }

    /// Generates a list of list identities, setting their addresses as localhost:5000, localhost:5001, ...
    pub fn generate_identities(parties: usize) -> Vec<Identity> {
        let mut res = Vec::with_capacity(parties);
        for i in 1..=parties {
            let port = 4999 + i;
            res.push(Identity(format!("localhost:{port}")));
        }
        res
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

    /// Returns a small session to be used with a single party, with role 1, suitable for testing with dummy constructs
    pub fn get_small_session() -> SmallSession {
        let parameters = get_dummy_parameters();
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        SmallSession {
            parameters,
            network: Arc::new(net_producer.user_net(id)),
            rng: ChaCha20Rng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
            prss_state: None,
        }
    }

    /// Returns a small session to be used with multiple parties
    pub fn get_small_session_for_parties(amount: usize, threshold: u8, role: Role) -> SmallSession {
        let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        SmallSession {
            parameters,
            network: Arc::new(net_producer.user_net(id)),
            rng: ChaCha20Rng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
            prss_state: None,
        }
    }

    /// Return a large session to be used with a single party, with role 1
    pub fn get_large_session() -> LargeSession {
        let parameters = get_dummy_parameters();
        let id = parameters.own_identity.clone();
        let parties = parameters.amount_of_parties();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        LargeSession {
            parameters,
            network: Arc::new(net_producer.user_net(id)),
            rng: ChaCha20Rng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(parties),
        }
    }

    /// Return a large session to be used with a multiple partiess
    pub fn get_large_session_for_parties(amount: usize, threshold: u8, role: Role) -> LargeSession {
        let parameters = get_dummy_parameters_for_parties(amount, threshold, role);
        let id = parameters.own_identity.clone();
        let net_producer = LocalNetworkingProducer::from_ids(&[parameters.own_identity.clone()]);
        LargeSession {
            parameters,
            network: Arc::new(net_producer.user_net(id)),
            rng: ChaCha20Rng::seed_from_u64(42),
            corrupt_roles: HashSet::new(),
            disputed_roles: DisputeSet::new(amount),
        }
    }

    /// Helper method for executing networked tests with multiple parties.
    /// The `task` argument contains the code to be execute per party which returns a value of type [OutputT].
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the parties
    /// interactive computation.
    pub fn execute_protocol_small<TaskOutputT, OutputT>(
        parties: usize,
        threshold: u8,
        task: &mut dyn FnMut(SmallSession) -> TaskOutputT,
    ) -> Vec<OutputT>
    where
        TaskOutputT: Future<Output = OutputT>,
        TaskOutputT: Send + 'static,
        OutputT: Send + 'static,
    {
        let identities = generate_identities(parties);
        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut tasks = JoinSet::new();
        for party_id in 0..parties {
            let session = test_runtime
                .small_session_for_player(
                    session_id,
                    party_id,
                    Some(ChaCha20Rng::seed_from_u64(party_id as u64)),
                )
                .unwrap();
            tasks.spawn(task(session));
        }
        rt.block_on(async {
            let mut results = Vec::with_capacity(tasks.len());
            while let Some(v) = tasks.join_next().await {
                results.push(v.unwrap());
            }
            results
        })
    }

    /// Helper method for executing networked tests with multiple parties.
    /// The `task` argument contains the code to be execute per party which returns a value of type [OutputT].
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the parties
    /// interactive computation.
    pub fn execute_protocol<TaskOutputT, OutputT>(
        parties: usize,
        threshold: u8,
        task: &mut dyn FnMut(LargeSession) -> TaskOutputT,
    ) -> Vec<OutputT>
    where
        TaskOutputT: Future<Output = OutputT>,
        TaskOutputT: Send + 'static,
        OutputT: Send + 'static,
    {
        let identities = generate_identities(parties);
        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut tasks = JoinSet::new();
        for party_id in 0..parties {
            let session = test_runtime
                .small_session_for_player(
                    session_id,
                    party_id,
                    Some(ChaCha20Rng::seed_from_u64(party_id as u64)),
                )
                .unwrap();
            let session =
                LargeSession::new(session.parameters.clone(), session.network().clone()).unwrap();
            tasks.spawn(task(session));
        }
        rt.block_on(async {
            let mut results = Vec::with_capacity(tasks.len());
            while let Some(v) = tasks.join_next().await {
                results.push(v.unwrap());
            }
            results
        })
    }

    /// Helper method for executing networked tests with multiple parties some honest some dishoneset.
    /// The `task_honest` argument contains the code to be execute by honest parties which returns a value of type [OutputT].
    /// The `task_malicious` argument contains the code to be execute by malicious parties which returns a value of type [OutputT].
    /// The `malicious_roles` argument contains the list of roles which should execute the `task_malicious`
    /// The result of the computation is a vector of [OutputT] which contains the result of each of the honest parties
    /// interactive computation.
    ///
    ///**NOTE: FOR ALL TESTS THE RNG SEED OF A PARTY IS ITS PARTY_ID, THIS IS ACTUALLY USED IN SOME TESTS TO CHECK CORRECTNESS.**
    pub fn execute_protocol_w_disputes_and_malicious<
        TaskOutputT,
        OutputT,
        TaskOutputM,
        OutputM,
        P: Clone,
    >(
        parties: usize,
        threshold: u8,
        dispute_pairs: &[(Role, Role)],
        malicious_roles: &[Role],
        malicious_strategy: P,
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
        let identities = generate_identities(parties);
        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut honest_tasks = JoinSet::new();
        let mut malicious_tasks = JoinSet::new();
        for party_id in 0..parties {
            let session = test_runtime
                .small_session_for_player(
                    session_id,
                    party_id,
                    Some(ChaCha20Rng::seed_from_u64(party_id as u64)),
                )
                .unwrap();
            let mut session = LargeSession {
                parameters: session.parameters.clone(),
                network: session.network().clone(),
                rng: ChaCha20Rng::seed_from_u64(party_id as u64),
                corrupt_roles: HashSet::new(),
                disputed_roles: DisputeSet::new(parties),
            };
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
        rt.block_on(async {
            let mut results_honest = Vec::with_capacity(honest_tasks.len());
            let mut results_malicious = Vec::with_capacity(honest_tasks.len());
            while let Some(v) = honest_tasks.join_next().await {
                results_honest.push(v.unwrap());
            }
            while let Some(v) = malicious_tasks.join_next().await {
                results_malicious.push(v);
            }
            (results_honest, results_malicious)
        })
    }
}
