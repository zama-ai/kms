use super::{
    party::Role,
    session::{BaseSession, LargeSession, ParameterHandles, SessionParameters, SmallSession},
};
use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring},
    execution::{
        small_execution::{
            agree_random::DummyAgreeRandom,
            prf::PRSSConversions,
            prss::{AbortRealPrssInit, DerivePRSSState, PRSSInit, PRSSSetup},
        },
        tfhe_internals::private_keysets::PrivateKeySet,
    },
    networking::{
        local::{LocalNetworking, LocalNetworkingProducer},
        NetworkMode,
    },
    session_id::SessionId,
};
use aes_prng::AesRng;
use rand::SeedableRng;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tfhe::{core_crypto::prelude::LweKeyswitchKey, ServerKey};

// TODO The name and use of unwrap hints that this is a struct only to be used for testing, but it is also used in production, e.g. in grpc.rs
// Unsafe and test code should not be mixed with production code. See issue 173
//
// NOTE: Unfortunately generic params can not be used in const expression,
// so we need an explicit degree here although it is exactly Z::EXTENSION_DEGREE
pub struct DistributedTestRuntime<Z: Ring, const EXTENSION_DEGREE: usize> {
    pub threshold: u8,
    pub prss_setups: Option<HashMap<Role, PRSSSetup<Z>>>,
    pub keyshares: Option<Vec<PrivateKeySet<EXTENSION_DEGREE>>>,
    pub user_nets: HashMap<Role, Arc<LocalNetworking>>,
    pub roles: HashSet<Role>,
    pub server_key: Option<Arc<ServerKey>>,
    pub ks_key: Option<Arc<LweKeyswitchKey<Vec<u64>>>>,
}

/// Generates a list of parties
pub fn generate_fixed_roles(parties: usize) -> HashSet<Role> {
    (1..=parties).map(Role::indexed_from_one).collect()
}

impl<Z: Ring, const EXTENSION_DEGREE: usize> DistributedTestRuntime<Z, EXTENSION_DEGREE> {
    pub fn new(
        roles: HashSet<Role>,
        threshold: u8,
        network_mode: NetworkMode,
        delay_map: Option<HashMap<Role, Duration>>,
    ) -> Self {
        let net_producer = LocalNetworkingProducer::from_roles(&roles);
        let user_nets = roles
            .iter()
            .map(|role| {
                let delay = if let Some(delay_map) = &delay_map {
                    delay_map.get(role).copied()
                } else {
                    None
                };
                let net = net_producer.user_net(*role, network_mode, delay);
                (*role, Arc::new(net))
            })
            .collect::<HashMap<_, _>>();

        let prss_setups = None;

        DistributedTestRuntime {
            threshold,
            prss_setups,
            keyshares: None,
            user_nets,
            roles,
            server_key: None,
            ks_key: None,
        }
    }

    pub fn get_server_key(&self) -> Arc<ServerKey> {
        self.server_key.clone().unwrap()
    }

    pub fn setup_server_key(&mut self, server_key: Arc<ServerKey>) {
        self.server_key = Some(server_key);
    }

    /// store keyshares if you want to test sth related to them
    pub fn setup_sks(&mut self, keyshares: Vec<PrivateKeySet<EXTENSION_DEGREE>>) {
        self.keyshares = Some(keyshares);
    }

    pub fn setup_ks(&mut self, ks: Arc<LweKeyswitchKey<Vec<u64>>>) {
        self.ks_key = Some(ks);
    }

    pub fn get_ks_key(&self) -> Arc<LweKeyswitchKey<Vec<u64>>> {
        Arc::clone(&self.ks_key.clone().unwrap())
    }

    /// store prss setups if you want to test sth related to them
    pub fn setup_prss(&mut self, setups: Option<HashMap<Role, PRSSSetup<Z>>>) {
        self.prss_setups = setups;
    }

    pub fn large_session_for_party(&self, session_id: SessionId, party: Role) -> LargeSession {
        LargeSession::new(self.base_session_for_party(session_id, party, None))
    }

    pub fn base_session_for_party(
        &self,
        session_id: SessionId,
        party: Role,
        rng: Option<AesRng>,
    ) -> BaseSession {
        let net = self.user_nets[&party].clone();
        let parameters =
            SessionParameters::new(self.threshold, session_id, party, self.roles.clone()).unwrap();
        BaseSession::new(
            parameters,
            net,
            rng.unwrap_or_else(|| AesRng::seed_from_u64(party.one_based() as u64)),
        )
        .unwrap()
    }
}

impl<Z, const EXTENSION_DEGREE: usize> DistributedTestRuntime<Z, EXTENSION_DEGREE>
where
    Z: ErrorCorrect,
    Z: Invert,
    Z: PRSSConversions,
{
    pub async fn small_session_for_party(
        &self,
        session_id: SessionId,
        party: Role,
        rng: Option<AesRng>,
    ) -> SmallSession<Z> {
        let base_session = self.base_session_for_party(session_id, party, rng);
        Self::add_dummy_prss(base_session).await
    }

    // Setups and adds a PRSS state with DummyAgreeRandom to the current session
    pub async fn add_dummy_prss(mut session: BaseSession) -> SmallSession<Z> {
        // this only works for DummyAgreeRandom
        // for RealAgreeRandom this needs to happen async/in parallel, so the parties can actually talk to each other at the same time
        // ==> use a JoinSet where this is called and collect the results later.
        // see also setup_prss_sess() below
        let prss_setup = AbortRealPrssInit::<DummyAgreeRandom>::default()
            .init(&mut session)
            .await
            .unwrap();
        let sid = session.session_id();
        SmallSession::new_from_prss_state(session, prss_setup.new_prss_session_state(sid)).unwrap()
    }
}
