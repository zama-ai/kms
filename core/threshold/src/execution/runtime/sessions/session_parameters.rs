use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::runtime::party::{Role, RoleTrait, TwoSetsRole},
    session_id::SessionId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

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

pub trait GenericParameterHandles<R: RoleTrait>: Sync + Send {
    fn threshold(&self) -> R::ThresholdType;
    fn session_id(&self) -> SessionId;
    fn my_role(&self) -> R;
    fn num_parties(&self) -> usize;
    fn roles(&self) -> &HashSet<R>;
    fn roles_mut(&mut self) -> &mut HashSet<R>;
    fn to_parameters(&self) -> GenericSessionParameters<R>;
    fn get_all_sorted_roles(&self) -> &Vec<R>;
    fn get_deserialization_runtime(&self) -> DeSerializationRunTime;
    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime);
}

// Hackish way to have something similar to trait alias
pub trait ParameterHandles: GenericParameterHandles<Role> {}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct GenericSessionParameters<R: RoleTrait> {
    threshold: R::ThresholdType,
    session_id: SessionId,
    my_role: R,
    roles: HashSet<R>,
    all_sorted_roles: Vec<R>,
    deserialization_runtime: DeSerializationRunTime,
}

pub type SessionParameters = GenericSessionParameters<Role>;

impl GenericSessionParameters<Role> {
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

impl GenericSessionParameters<TwoSetsRole> {
    pub fn new(
        threshold: (u8, u8),
        session_id: SessionId,
        my_role: TwoSetsRole,
        roles: HashSet<TwoSetsRole>,
    ) -> anyhow::Result<Self> {
        let (mut num_parties_in_set_1, mut num_parties_in_set_2) = (0, 0);
        roles.iter().for_each(|role| match role {
            TwoSetsRole::Set1(_) => num_parties_in_set_1 += 1,
            TwoSetsRole::Set2(_) => num_parties_in_set_2 += 1,
        });
        if num_parties_in_set_1 <= threshold.0 as usize {
            return Err(anyhow_error_and_log(format!(
                "Threshold {} cannot be less than the amount of parties in set 1, {:?}",
                threshold.0, num_parties_in_set_1
            )));
        }
        if num_parties_in_set_1 <= threshold.1 as usize {
            return Err(anyhow_error_and_log(format!(
                "Threshold {} cannot be less than the amount of parties in set 1, {:?}",
                threshold.1, num_parties_in_set_1
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

impl<R: RoleTrait> GenericParameterHandles<R> for GenericSessionParameters<R> {
    fn my_role(&self) -> R {
        self.my_role
    }

    fn num_parties(&self) -> usize {
        self.roles.len()
    }

    fn threshold(&self) -> R::ThresholdType {
        self.threshold
    }

    fn session_id(&self) -> SessionId {
        self.session_id
    }

    fn roles(&self) -> &HashSet<R> {
        &self.roles
    }

    fn roles_mut(&mut self) -> &mut HashSet<R> {
        &mut self.roles
    }

    fn to_parameters(&self) -> GenericSessionParameters<R> {
        self.clone()
    }

    fn get_all_sorted_roles(&self) -> &Vec<R> {
        &self.all_sorted_roles
    }

    fn get_deserialization_runtime(&self) -> DeSerializationRunTime {
        self.deserialization_runtime
    }

    fn set_deserialization_runtime(&mut self, serialization_runtime: DeSerializationRunTime) {
        self.deserialization_runtime = serialization_runtime;
    }
}

impl ParameterHandles for SessionParameters {}

#[cfg(test)]
mod tests {
    use super::SessionParameters;
    use crate::execution::runtime::party::Role;
    use crate::execution::runtime::sessions::session_parameters::GenericParameterHandles;
    use crate::tests::helper::testing::get_dummy_parameters_for_parties;

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
}
