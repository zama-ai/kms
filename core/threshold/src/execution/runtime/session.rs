use super::party::Role;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        structure_traits::{ErrorCorrect, Invert, Ring, RingWithExceptionalSequence},
    },
    error::error_handler::anyhow_error_and_log,
    execution::small_execution::{
        prf::PRSSConversions,
        prss::{DerivePRSSState, PRSSInit, PRSSPrimitives, RobustSecurePrssInit, SecurePRSSState},
    },
    networking::Networking,
    session_id::SessionId,
};
use aes_prng::AesRng;
use async_trait::async_trait;
use rand::{CryptoRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

pub type SingleSetNetworkingImpl = Arc<dyn Networking<Role> + Send + Sync>;

/// Enum to decide where to run (de)serialization
/// of MPC messages.
/// Everything related to ddec should probably stay
/// on Tokio as messages are small, but everything
/// related to DKG should be sent to rayon
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum DeSerializationRunTime {
    Tokio,
    Rayon,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct SessionParameters {
    threshold: u8,
    session_id: SessionId,
    my_role: Role,
    roles: HashSet<Role>,
    all_sorted_roles: Vec<Role>,
    deserialization_runtime: DeSerializationRunTime,
}

pub trait ParameterHandles: Sync + Send {
    fn threshold(&self) -> u8;
    fn session_id(&self) -> SessionId;
    fn my_role(&self) -> Role;
    fn num_parties(&self) -> usize;
    fn roles(&self) -> &HashSet<Role>;
    fn roles_mut(&mut self) -> &mut HashSet<Role>;
    fn to_parameters(&self) -> SessionParameters;
    fn get_all_sorted_roles(&self) -> &Vec<Role>;
    fn get_deserialization_runtime(&self) -> DeSerializationRunTime;
    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime);
}

impl SessionParameters {
    pub fn new(
        threshold: u8,
        session_id: SessionId,
        my_role: Role,
        roles: HashSet<Role>,
    ) -> anyhow::Result<Self> {
        if roles.len() <= threshold as usize {
            return Err(anyhow_error_and_log(format!(
                "Threshold {threshold} cannot be less than the amount of parties, {:?}",
                roles.len()
            )));
        }
        if !roles.contains(&my_role) {
            return Err(anyhow_error_and_log(format!(
                "My role {my_role} is not in the set of roles: {roles:?}"
            )));
        }
        let mut all_sorted_roles = roles.iter().cloned().collect::<Vec<_>>();
        all_sorted_roles.sort();
        let res = Self {
            threshold,
            session_id,
            my_role,
            roles,
            all_sorted_roles,
            deserialization_runtime: DeSerializationRunTime::Tokio,
        };

        Ok(res)
    }
}

impl ParameterHandles for SessionParameters {
    fn my_role(&self) -> Role {
        self.my_role
    }

    fn num_parties(&self) -> usize {
        self.roles.len()
    }

    fn threshold(&self) -> u8 {
        self.threshold
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn roles(&self) -> &HashSet<Role> {
        &self.roles
    }

    fn roles_mut(&mut self) -> &mut HashSet<Role> {
        &mut self.roles
    }

    fn to_parameters(&self) -> SessionParameters {
        self.clone()
    }

    fn get_all_sorted_roles(&self) -> &Vec<Role> {
        &self.all_sorted_roles
    }

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.deserialization_runtime
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.deserialization_runtime = serialization_runtime;
    }
}

// Note: BaseSession should NOT be Cloned (hence why we don't derive Clone)
// to avoid having multiple sessions with related RNGs and more importantly
// multiple sessions with the same networking instance (i.e. shared sid but different round counter).
pub struct BaseSession {
    pub parameters: SessionParameters,
    pub network: SingleSetNetworkingImpl,
    pub rng: AesRng,
    pub corrupt_roles: HashSet<Role>,
}

pub trait BaseSessionHandles: ParameterHandles {
    type RngType: Rng + CryptoRng + SeedableRng + Send + Sync;

    fn corrupt_roles(&self) -> &HashSet<Role>;
    fn add_corrupt(&mut self, role: Role) -> bool;
    fn rng(&mut self) -> &mut Self::RngType;
    fn network(&self) -> &SingleSetNetworkingImpl;
}

impl BaseSession {
    pub fn new(
        parameters: SessionParameters,
        network: SingleSetNetworkingImpl,
        rng: AesRng,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            parameters,
            network,
            rng,
            corrupt_roles: HashSet::new(),
        })
    }
}

impl ParameterHandles for BaseSession {
    fn my_role(&self) -> Role {
        self.parameters.my_role()
    }

    fn num_parties(&self) -> usize {
        self.parameters.num_parties()
    }

    fn threshold(&self) -> u8 {
        self.parameters.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.parameters.session_id()
    }

    fn roles(&self) -> &HashSet<Role> {
        self.parameters.roles()
    }

    fn roles_mut(&mut self) -> &mut HashSet<Role> {
        self.parameters.roles_mut()
    }

    fn to_parameters(&self) -> SessionParameters {
        self.parameters.clone()
    }

    fn get_all_sorted_roles(&self) -> &Vec<Role> {
        self.parameters.get_all_sorted_roles()
    }

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.parameters.get_deserialization_runtime()
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.parameters
            .set_deserialization_runtime(serialization_runtime);
    }
}

impl BaseSessionHandles for BaseSession {
    type RngType = AesRng;

    fn rng(&mut self) -> &mut Self::RngType {
        &mut self.rng
    }

    fn network(&self) -> &SingleSetNetworkingImpl {
        &self.network
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        &self.corrupt_roles
    }

    fn add_corrupt(&mut self, role: Role) -> bool {
        // Observe we never add ourself to the list of corrupt parties to keep the execution going
        // This is logically the attack model we expect and hence make testing malicious behaviour easier
        if role != self.my_role() {
            tracing::warn!("I'm {}, marking {role} as corrupt", self.my_role());
            self.corrupt_roles.insert(role)
        } else {
            false
        }
    }
}

pub trait ToBaseSession {
    fn to_base_session(self) -> BaseSession;
    fn get_mut_base_session(&mut self) -> &mut BaseSession;
}

pub type SmallSession64<const EXTENSION_DEGREE: usize> =
    SmallSession<crate::algebra::galois_rings::common::ResiduePoly<Z64, EXTENSION_DEGREE>>;
pub type SmallSession128<const EXTENSION_DEGREE: usize> =
    SmallSession<crate::algebra::galois_rings::common::ResiduePoly<Z128, EXTENSION_DEGREE>>;

pub trait SmallSessionHandles<Z: Ring>: BaseSessionHandles {
    type PRSSPrimitivesType: PRSSPrimitives<Z>;
    fn prss_as_mut(&mut self) -> &mut Self::PRSSPrimitivesType;
    /// Returns the non-mutable prss state if it exists or return an error
    fn prss(&self) -> Self::PRSSPrimitivesType;
}

pub struct SmallSession<Z: Ring> {
    pub base_session: BaseSession,
    pub prss_state: SecurePRSSState<Z>,
}

impl<Z> SmallSession<Z>
where
    Z: ErrorCorrect + Invert + PRSSConversions,
{
    pub async fn new_and_init_prss_state(mut base_session: BaseSession) -> anyhow::Result<Self>
    where
        Z: ErrorCorrect + Invert,
    {
        let prss_setup = RobustSecurePrssInit::default()
            .init(&mut base_session)
            .await?;
        let session_id = base_session.session_id();
        Self::new_from_prss_state(base_session, prss_setup.new_prss_session_state(session_id))
    }

    pub fn new_from_prss_state(
        base_session: BaseSession,
        prss_state: SecurePRSSState<Z>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base_session,
            prss_state,
        })
    }
}

impl<Z: Ring> ParameterHandles for SmallSession<Z> {
    fn my_role(&self) -> Role {
        self.base_session.my_role()
    }

    fn num_parties(&self) -> usize {
        self.base_session.num_parties()
    }

    fn threshold(&self) -> u8 {
        self.base_session.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.base_session.session_id()
    }

    fn roles(&self) -> &HashSet<Role> {
        self.base_session.roles()
    }

    fn roles_mut(&mut self) -> &mut HashSet<Role> {
        self.base_session.roles_mut()
    }

    fn to_parameters(&self) -> SessionParameters {
        self.base_session.to_parameters()
    }

    fn get_all_sorted_roles(&self) -> &Vec<Role> {
        self.base_session.get_all_sorted_roles()
    }

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.base_session.get_deserialization_runtime()
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.base_session
            .set_deserialization_runtime(serialization_runtime);
    }
}

impl<Z: Ring> BaseSessionHandles for SmallSession<Z> {
    type RngType = AesRng;

    fn rng(&mut self) -> &mut Self::RngType {
        self.base_session.rng()
    }

    fn network(&self) -> &SingleSetNetworkingImpl {
        self.base_session.network()
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        self.base_session.corrupt_roles()
    }

    fn add_corrupt(&mut self, role: Role) -> bool {
        self.base_session.add_corrupt(role)
    }
}

impl<Z: RingWithExceptionalSequence + Invert + PRSSConversions> SmallSessionHandles<Z>
    for SmallSession<Z>
{
    type PRSSPrimitivesType = SecurePRSSState<Z>;

    fn prss_as_mut(&mut self) -> &mut SecurePRSSState<Z> {
        &mut self.prss_state
    }

    fn prss(&self) -> SecurePRSSState<Z> {
        self.prss_state.to_owned()
    }
}

impl<Z: Ring> ToBaseSession for SmallSession<Z> {
    fn to_base_session(self) -> BaseSession {
        self.base_session
    }
    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        &mut self.base_session
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Debug)]
pub enum DisputeMsg {
    OK,
    CORRUPTION,
}

#[async_trait]
pub trait LargeSessionHandles: BaseSessionHandles {
    fn disputed_roles(&self) -> &DisputeSet;
    fn my_disputes(&self) -> &BTreeSet<Role>;
    fn add_dispute(&mut self, party_a: &Role, party_b: &Role);
}

pub struct LargeSession {
    pub base_session: BaseSession,
    pub disputed_roles: DisputeSet,
}
impl LargeSession {
    /// Make a new [LargeSession] without any corruptions or disputes
    pub fn new(base_session: BaseSession) -> Self {
        let num_parties = base_session.num_parties();
        Self {
            base_session,
            disputed_roles: DisputeSet::new(num_parties),
        }
    }
}
impl ParameterHandles for LargeSession {
    fn my_role(&self) -> Role {
        self.base_session.my_role()
    }

    fn num_parties(&self) -> usize {
        self.base_session.num_parties()
    }

    fn threshold(&self) -> u8 {
        self.base_session.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.base_session.session_id()
    }

    fn roles(&self) -> &HashSet<Role> {
        self.base_session.roles()
    }

    fn roles_mut(&mut self) -> &mut HashSet<Role> {
        self.base_session.roles_mut()
    }

    fn to_parameters(&self) -> SessionParameters {
        self.base_session.to_parameters()
    }

    fn get_all_sorted_roles(&self) -> &Vec<Role> {
        self.base_session.get_all_sorted_roles()
    }

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.base_session.get_deserialization_runtime()
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.base_session
            .set_deserialization_runtime(serialization_runtime);
    }
}
impl BaseSessionHandles for LargeSession {
    type RngType = AesRng;

    fn rng(&mut self) -> &mut Self::RngType {
        self.base_session.rng()
    }

    fn network(&self) -> &SingleSetNetworkingImpl {
        self.base_session.network()
    }

    fn corrupt_roles(&self) -> &HashSet<Role> {
        self.base_session.corrupt_roles()
    }

    fn add_corrupt(&mut self, role: Role) -> bool {
        let res = self.base_session.add_corrupt(role);
        //Make sure we now have this role in dispute with everyone
        for role_b in self.base_session.roles() {
            self.disputed_roles.add(&role, role_b);
        }
        res
    }
}

impl ToBaseSession for LargeSession {
    fn to_base_session(self) -> BaseSession {
        self.base_session
    }
    fn get_mut_base_session(&mut self) -> &mut BaseSession {
        &mut self.base_session
    }
}

#[async_trait]
impl LargeSessionHandles for LargeSession {
    fn disputed_roles(&self) -> &DisputeSet {
        &self.disputed_roles
    }

    fn my_disputes(&self) -> &BTreeSet<Role> {
        self.disputed_roles.get(&self.my_role())
    }

    fn add_dispute(&mut self, party_a: &Role, party_b: &Role) {
        self.disputed_roles.add(party_a, party_b);

        //Now check whether too many dispute w/ either
        //which result in adding that party to corrupt
        self.sync_dispute_corrupt(party_a);
        self.sync_dispute_corrupt(party_b);
    }
}

impl LargeSession {
    pub fn sync_dispute_corrupt(&mut self, role: &Role) {
        if self.disputed_roles.get(role).len() > self.threshold() as usize {
            tracing::warn!(
                "Party {role} is in conflict with too many parties, adding it to the corrupt set"
            );
            self.add_corrupt(*role);
        }
    }
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DisputeSet {
    disputed_roles: Vec<BTreeSet<Role>>,
}

impl DisputeSet {
    pub fn new(amount: usize) -> Self {
        let mut disputed_roles = Vec::with_capacity(amount);
        // Insert roles
        for _i in 1..=amount as u64 {
            disputed_roles.push(BTreeSet::new());
        }
        DisputeSet { disputed_roles }
    }

    pub fn add(&mut self, role_a: &Role, role_b: &Role) {
        // We don't allow disputes with oneself
        if role_a == role_b {
            return;
        }
        // Insert the first pair of disputes
        let disputed_roles = &mut self.disputed_roles;
        let a_disputes = role_a.get_mut_from(disputed_roles).unwrap_or_else(|| panic!("Can not access the dispute set of {role_a} when trying to add a dispute with {role_b}, the session was initalized without it."));
        let _ = a_disputes.insert(*role_b);

        // Insert the second pair of disputes
        let b_disputes = role_b.get_mut_from(disputed_roles).unwrap_or_else(|| panic!("Can not access the dispute set of {role_b} when trying to add a dispute with {role_a}, the session was initalized without it."));
        let _ = b_disputes.insert(*role_a);
    }

    pub fn get(&self, role: &Role) -> &BTreeSet<Role> {
        role.get_from(&self.disputed_roles).unwrap_or_else(|| {
            panic!(
                "There is no dispute set for role {role}, the session was initalized without it."
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SessionParameters;
    use crate::execution::runtime::party::Role;
    use crate::networking::NetworkMode;
    use crate::{
        execution::runtime::session::BaseSessionHandles, tests::helper::tests::get_base_session,
    };
    use crate::{
        execution::runtime::session::ParameterHandles,
        tests::helper::testing::get_dummy_parameters_for_parties,
    };

    #[test]
    fn too_large_threshold() {
        let parties = 3;
        let params = get_dummy_parameters_for_parties(parties, 0, Role::indexed_from_one(1));
        // Same amount of parties and threshold, which is not allowed
        assert!(SessionParameters::new(
            parties as u8,
            params.session_id(),
            params.my_role(),
            params.roles().clone(),
        )
        .is_err());
    }

    #[test]
    fn missing_self_identity() {
        let parties = 3;
        let mut params = get_dummy_parameters_for_parties(parties, 1, Role::indexed_from_one(1));
        // remove my role
        params.roles.remove(&Role::indexed_from_one(1));
        assert!(SessionParameters::new(
            params.threshold(),
            params.session_id(),
            params.my_role(),
            params.roles().clone(),
        )
        .is_err());
    }

    #[test]
    fn wont_add_self_to_corrupt() {
        //Network mode doesn't matter for this test, Sync by default
        let mut session = get_base_session(NetworkMode::Sync);
        // Check that I cannot add myself to the corruption set directly
        assert!(!session.add_corrupt(session.my_role()));
        assert_eq!(0, session.corrupt_roles().len());
    }
}
