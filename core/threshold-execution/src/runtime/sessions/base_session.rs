use crate::runtime::sessions::session_parameters::{
    DeSerializationRunTime, GenericParameterHandles, GenericSessionParameters, ParameterHandles,
};
use aes_prng::AesRng;
use rand::{CryptoRng, Rng, SeedableRng};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use threshold_types::network::Networking;
use threshold_types::role::{Role, RoleTrait, TwoSetsRole};
use threshold_types::session_id::SessionId;

pub type NetworkingImpl<R> = Arc<dyn Networking<R> + Send + Sync>;
pub type SingleSetNetworkingImpl = NetworkingImpl<Role>;
pub type TwoSetsNetworkingImpl = NetworkingImpl<TwoSetsRole>;

pub trait GenericBaseSessionHandles<R: RoleTrait>: GenericParameterHandles<R> {
    type RngType: Rng + CryptoRng + SeedableRng + Send + Sync;

    fn corrupt_roles(&self) -> &HashSet<R>;
    fn corrupt_reasons(&self) -> &HashMap<R, Vec<String>>;
    fn add_corrupt_with_reason(&mut self, role: R, reason: &str) -> bool;
    fn add_corrupt(&mut self, role: R) -> bool {
        self.add_corrupt_with_reason(role, "")
    }
    fn rng(&mut self) -> &mut Self::RngType;
    fn network(&self) -> &NetworkingImpl<R>;
}

pub trait ToBaseSession {
    fn to_base_session(self) -> BaseSession;
    fn get_mut_base_session(&mut self) -> &mut BaseSession;
}

// Hackish way to have something similar to trait alias
pub trait BaseSessionHandles: GenericBaseSessionHandles<Role> + ParameterHandles {}

// Note: BaseSession should NOT be Cloned (hence why we don't derive Clone)
// to avoid having multiple sessions with related RNGs and more importantly
// multiple sessions with the same networking instance (i.e. shared sid but different round counter).
pub struct GenericBaseSession<R: RoleTrait> {
    pub parameters: GenericSessionParameters<R>,
    pub network: NetworkingImpl<R>,
    pub rng: AesRng,
    pub corrupt_roles: HashSet<R>,
    pub corrupt_reasons: HashMap<R, Vec<String>>,
}

pub type BaseSession = GenericBaseSession<Role>;
pub type TwoSetsBaseSession = GenericBaseSession<TwoSetsRole>;

impl<R: RoleTrait> GenericBaseSession<R> {
    pub fn new(
        parameters: GenericSessionParameters<R>,
        network: NetworkingImpl<R>,
        rng: AesRng,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            parameters,
            network,
            rng,
            corrupt_roles: HashSet::new(),
            corrupt_reasons: HashMap::new(),
        })
    }
}

impl<R: RoleTrait> GenericParameterHandles<R> for GenericBaseSession<R> {
    fn my_role(&self) -> R {
        self.parameters.my_role()
    }

    fn num_parties(&self) -> usize {
        self.parameters.num_parties()
    }

    fn threshold(&self) -> R::ThresholdType {
        self.parameters.threshold()
    }

    fn session_id(&self) -> SessionId {
        self.parameters.session_id()
    }

    fn roles(&self) -> &HashSet<R> {
        self.parameters.roles()
    }

    fn roles_mut(&mut self) -> &mut HashSet<R> {
        self.parameters.roles_mut()
    }

    fn to_parameters(&self) -> GenericSessionParameters<R> {
        self.parameters.clone()
    }

    fn get_all_sorted_roles(&self) -> &Vec<R> {
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

impl ParameterHandles for BaseSession {}

impl<R: RoleTrait> GenericBaseSessionHandles<R> for GenericBaseSession<R> {
    type RngType = AesRng;

    fn rng(&mut self) -> &mut Self::RngType {
        &mut self.rng
    }

    fn network(&self) -> &NetworkingImpl<R> {
        &self.network
    }

    fn corrupt_roles(&self) -> &HashSet<R> {
        &self.corrupt_roles
    }

    fn corrupt_reasons(&self) -> &HashMap<R, Vec<String>> {
        &self.corrupt_reasons
    }

    fn add_corrupt_with_reason(&mut self, role: R, reason: &str) -> bool {
        // Observe we never add ourself to the list of corrupt parties to keep the execution going
        // This is logically the attack model we expect and hence make testing malicious behaviour easier
        if role != self.my_role() {
            tracing::warn!("I'm {}, marking {role} as corrupt", self.my_role());
            let inserted = self.corrupt_roles.insert(role);
            if !reason.is_empty() {
                self.corrupt_reasons
                    .entry(role)
                    .or_default()
                    .push(reason.to_string());
            }
            inserted
        } else {
            false
        }
    }
}

impl BaseSessionHandles for BaseSession {}

#[cfg(test)]
mod tests {
    use crate::runtime::sessions::base_session::GenericBaseSessionHandles;
    use crate::runtime::sessions::session_parameters::GenericParameterHandles;
    use crate::tests::helper::testing::get_networkless_base_session_for_parties;
    use crate::tests::helper::tests::get_base_session;
    use threshold_types::network::NetworkMode;
    use threshold_types::role::Role;

    #[test]
    fn wont_add_self_to_corrupt() {
        //Network mode doesn't matter for this test, Sync by default
        let mut session = get_base_session(NetworkMode::Sync);
        // Check that I cannot add myself to the corruption set directly
        assert!(!session.add_corrupt(session.my_role()));
        assert_eq!(0, session.corrupt_roles().len());
    }

    #[test]
    fn wont_add_self_with_reason_to_corrupt() {
        let mut session = get_base_session(NetworkMode::Sync);
        assert!(!session.add_corrupt_with_reason(session.my_role(), "some reason"));
        assert!(session.corrupt_roles().is_empty());
        assert!(session.corrupt_reasons().is_empty());
    }

    #[test]
    fn add_corrupt_with_reason_stores_reason() {
        let mut session = get_networkless_base_session_for_parties(3, 0, Role::indexed_from_one(1));
        let other = Role::indexed_from_one(2);
        assert!(session.add_corrupt_with_reason(other, "bad broadcast"));
        assert!(session.corrupt_roles().contains(&other));
        assert_eq!(
            session.corrupt_reasons().get(&other).unwrap(),
            &vec!["bad broadcast".to_string()]
        );
    }

    #[test]
    fn add_corrupt_default_stores_no_reason() {
        let mut session = get_networkless_base_session_for_parties(3, 0, Role::indexed_from_one(1));
        let other = Role::indexed_from_one(2);
        assert!(session.add_corrupt(other));
        assert!(session.corrupt_roles().contains(&other));
        // add_corrupt passes an empty reason, so no entry should appear in corrupt_reasons
        assert!(session.corrupt_reasons().is_empty());
    }

    #[test]
    fn add_corrupt_with_empty_reason_stores_no_reason() {
        let mut session = get_networkless_base_session_for_parties(3, 0, Role::indexed_from_one(1));
        let other = Role::indexed_from_one(2);
        assert!(session.add_corrupt_with_reason(other, ""));
        assert!(session.corrupt_roles().contains(&other));
        assert!(session.corrupt_reasons().is_empty());
    }

    #[test]
    fn add_corrupt_with_reason_accumulates_multiple_reasons() {
        let mut session = get_networkless_base_session_for_parties(3, 0, Role::indexed_from_one(1));
        let other = Role::indexed_from_one(2);
        // First add registers the role and the first reason
        assert!(session.add_corrupt_with_reason(other, "reason one"));
        // Second add returns false (already corrupt) but still appends the new reason
        assert!(!session.add_corrupt_with_reason(other, "reason two"));
        assert_eq!(
            session.corrupt_reasons().get(&other).unwrap(),
            &vec!["reason one".to_string(), "reason two".to_string()]
        );
    }
}
