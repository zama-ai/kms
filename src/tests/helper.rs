#[cfg(test)]
pub mod tests {

    use std::{
        collections::{HashMap, HashSet},
        sync::Arc,
    };

    use aes_prng::AesRng;
    use futures::Future;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use tokio::task::JoinSet;

    use crate::{
        computation::SessionId,
        execution::{
            distributed::DistributedTestRuntime,
            party::{Identity, Role},
            session::{
                BaseSessionHandles, DisputeSet, LargeSession, ParameterHandles, SessionParameters,
                SmallSession,
            },
        },
        file_handling::read_element,
        lwe::{gen_key_set, Ciphertext64, KeySet, ThresholdLWEParameters},
        networking::local::LocalNetworkingProducer,
        tests::test_data_setup::tests::{DEFAULT_SEED, TEST_KEY_PATH},
    };

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
        role_assignment.insert(Role(1), id.clone());
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
                Role::from_zero(i),
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
}
