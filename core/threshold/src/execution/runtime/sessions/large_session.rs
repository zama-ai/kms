use crate::{
    execution::runtime::{
        party::Role,
        sessions::{
            base_session::{
                BaseSession, BaseSessionHandles, GenericBaseSessionHandles,
                SingleSetNetworkingImpl, ToBaseSession,
            },
            session_parameters::{
                DeSerializationRunTime, GenericParameterHandles, ParameterHandles,
                SessionParameters,
            },
        },
    },
    session_id::SessionId,
};
use aes_prng::AesRng;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

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
impl GenericParameterHandles<Role> for LargeSession {
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

impl ParameterHandles for LargeSession {}

impl GenericBaseSessionHandles<Role> for LargeSession {
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

impl BaseSessionHandles for LargeSession {}

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
