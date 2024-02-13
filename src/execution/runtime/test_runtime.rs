use super::{
    party::{Identity, Role, RoleAssignment},
    session::{
        LargeSession, ParameterHandles, SessionParameters, SmallSession, SmallSessionStruct,
    },
};
use crate::{
    algebra::structure_traits::Ring,
    computation::SessionId,
    execution::{
        sharing::shamir::ShamirRing,
        small_execution::{agree_random::DummyAgreeRandom, prss::PRSSSetup},
    },
    lwe::{BootstrappingKey, SecretKeyShare},
    networking::local::{LocalNetworking, LocalNetworkingProducer},
};
use aes_prng::AesRng;
use std::{collections::HashMap, sync::Arc};

// TODO The name and use of unwrap hints that this is a struct only to be used for testing, but it is laos used in production, e.g. in grpc.rs
// Unsafe and test code should not be mixed with production code. See issue 173
pub struct DistributedTestRuntime<Z: Ring> {
    pub identities: Vec<Identity>,
    pub threshold: u8,
    pub prss_setups: Option<HashMap<usize, PRSSSetup<Z>>>,
    pub keyshares: Option<Vec<SecretKeyShare>>,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
    pub conversion_keys: Option<Arc<BootstrappingKey>>,
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

impl<Z: ShamirRing> DistributedTestRuntime<Z> {
    pub fn new(identities: Vec<Identity>, threshold: u8) -> Self {
        let role_assignments: RoleAssignment = identities
            .clone()
            .into_iter()
            .enumerate()
            .map(|(role_id, identity)| (Role::indexed_by_zero(role_id), identity))
            .collect();

        let net_producer = LocalNetworkingProducer::from_ids(&identities);
        let user_nets: Vec<Arc<LocalNetworking>> = identities
            .iter()
            .map(|user_identity| {
                let net = net_producer.user_net(user_identity.clone());
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
            conversion_keys: None,
        }
    }

    pub fn get_ck(&self) -> Arc<BootstrappingKey> {
        Arc::clone(&self.conversion_keys.clone().unwrap())
    }

    pub fn setup_cks(&mut self, cks: Arc<BootstrappingKey>) {
        self.conversion_keys = Some(cks);
    }

    // store keyshares if you want to test sth related to them
    pub fn setup_sks(&mut self, keyshares: Vec<SecretKeyShare>) {
        self.keyshares = Some(keyshares);
    }

    // store prss setups if you want to test sth related to them
    pub fn setup_prss(&mut self, setups: Option<HashMap<usize, PRSSSetup<Z>>>) {
        self.prss_setups = setups;
    }

    // Setups and adds a PRSS state with DummyAgreeRandom to the current session
    pub fn add_dummy_prss(session: &mut SmallSession<Z>) {
        // this only works for DummyAgreeRandom
        // for RealAgreeRandom this needs to happen async/in parallel, so the parties can actually talk to each other at the same time
        // ==> use a JoinSet where this is called and collect the results later.
        // see also setup_prss_sess() below
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async {
                PRSSSetup::init_with_abort::<
                    DummyAgreeRandom,
                    AesRng,
                    SmallSessionStruct<Z, AesRng, SessionParameters>,
                >(session)
                .await
            })
            .unwrap();
        session.prss_state = Some(prss_setup.new_prss_session_state(session.session_id()));
    }

    pub fn small_session_for_player(
        &self,
        session_id: SessionId,
        player_id: usize,
        rng: Option<AesRng>,
    ) -> anyhow::Result<SmallSession<Z>> {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);

        let prss_setup = self
            .prss_setups
            .as_ref()
            .map(|per_party| per_party[&player_id].clone());

        let own_role = Role::indexed_by_zero(player_id);
        let identity = self.role_assignments[&own_role].clone();

        SmallSession::new(
            session_id,
            role_assignments,
            net,
            self.threshold,
            prss_setup,
            identity,
            rng,
        )
    }

    pub fn large_session_for_player(
        &self,
        session_id: SessionId,
        player_id: usize,
    ) -> anyhow::Result<LargeSession> {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);
        let own_role = Role::indexed_by_zero(player_id);
        let identity = self.role_assignments[&own_role].clone();
        let parameters =
            SessionParameters::new(self.threshold, session_id, identity, role_assignments)?;
        LargeSession::new(parameters, net)
    }
}
