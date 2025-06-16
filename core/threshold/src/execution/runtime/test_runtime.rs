use super::{
    party::{Identity, Role, RoleAssignment},
    session::{BaseSession, LargeSession, ParameterHandles, SessionParameters, SmallSession},
};
use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring},
    execution::{
        endpoints::keygen::PrivateKeySet,
        small_execution::{
            agree_random::DummyAgreeRandom,
            prf::PRSSConversions,
            prss::{AbortRealPrssInit, DerivePRSSState, PRSSInit, PRSSSetup},
        },
    },
    networking::{
        local::{LocalNetworking, LocalNetworkingProducer},
        NetworkMode,
    },
    session_id::SessionId,
};
use aes_prng::AesRng;
use rand::SeedableRng;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tfhe::{core_crypto::prelude::LweKeyswitchKey, ServerKey};

// TODO The name and use of unwrap hints that this is a struct only to be used for testing, but it is also used in production, e.g. in grpc.rs
// Unsafe and test code should not be mixed with production code. See issue 173
//
// NOTE: Unfortunately generic params can not be used in const expression,
// so we need an explicit degree here although it is exactly Z::EXTENSION_DEGREE
pub struct DistributedTestRuntime<Z: Ring, const EXTENSION_DEGREE: usize> {
    pub identities: Vec<Identity>,
    pub threshold: u8,
    pub prss_setups: Option<HashMap<Role, PRSSSetup<Z>>>,
    pub keyshares: Option<Vec<PrivateKeySet<EXTENSION_DEGREE>>>,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
    pub server_key: Option<Arc<ServerKey>>,
    pub ks_key: Option<Arc<LweKeyswitchKey<Vec<u64>>>>,
}

/// Generates a list of list identities, setting their addresses as localhost:5000, localhost:5001, ...
pub fn generate_fixed_identities(parties: usize) -> Vec<Identity> {
    let mut res = Vec::with_capacity(parties);
    for i in 1..=parties {
        let port = 4999 + i;
        res.push(Identity(format!("localhost:{port}")));
    }
    res
}

impl<Z: Ring, const EXTENSION_DEGREE: usize> DistributedTestRuntime<Z, EXTENSION_DEGREE> {
    pub fn new(
        identities: Vec<Identity>,
        threshold: u8,
        network_mode: NetworkMode,
        delay_map: Option<HashMap<Identity, Duration>>,
    ) -> Self {
        let role_assignments: RoleAssignment = identities
            .clone()
            .into_iter()
            .enumerate()
            .map(|(role_id, identity)| (Role::indexed_from_zero(role_id), identity))
            .collect();

        let net_producer = LocalNetworkingProducer::from_ids(&identities);
        let user_nets: Vec<Arc<LocalNetworking>> = identities
            .iter()
            .map(|user_identity| {
                let delay = if let Some(delay_map) = &delay_map {
                    delay_map.get(user_identity).copied()
                } else {
                    None
                };
                let net = net_producer.user_net(user_identity.clone(), network_mode, delay);
                Arc::new(net)
            })
            .collect();

        let prss_setups = None;

        DistributedTestRuntime {
            identities,
            threshold,
            prss_setups,
            keyshares: None,
            user_nets,
            role_assignments,
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

    pub fn large_session_for_party(&self, session_id: SessionId, player_id: usize) -> LargeSession {
        LargeSession::new(self.base_session_for_party(session_id, player_id, None))
    }

    pub fn base_session_for_party(
        &self,
        session_id: SessionId,
        player_id: usize,
        rng: Option<AesRng>,
    ) -> BaseSession {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);
        let own_role = Role::indexed_from_zero(player_id);
        let identity = self.role_assignments[&own_role].clone();
        let parameters =
            SessionParameters::new(self.threshold, session_id, identity, role_assignments).unwrap();
        BaseSession::new(
            parameters,
            net,
            rng.unwrap_or_else(|| AesRng::seed_from_u64(own_role.one_based() as u64)),
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
    pub fn small_session_for_party(
        &self,
        session_id: SessionId,
        party_id: usize,
        rng: Option<AesRng>,
    ) -> SmallSession<Z> {
        let base_session = self.base_session_for_party(session_id, party_id, rng);
        Self::add_dummy_prss(base_session)
    }

    // Setups and adds a PRSS state with DummyAgreeRandom to the current session
    pub fn add_dummy_prss(mut session: BaseSession) -> SmallSession<Z> {
        // this only works for DummyAgreeRandom
        // for RealAgreeRandom this needs to happen async/in parallel, so the parties can actually talk to each other at the same time
        // ==> use a JoinSet where this is called and collect the results later.
        // see also setup_prss_sess() below
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async {
                AbortRealPrssInit::<DummyAgreeRandom>::default()
                    .init(&mut session)
                    .await
            })
            .unwrap();
        let sid = session.session_id();
        SmallSession::new_from_prss_state(session, prss_setup.new_prss_session_state(sid)).unwrap()
    }
}
