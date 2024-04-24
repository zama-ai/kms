use std::sync::Arc;

use crate::execution::runtime::party::Identity;
use crate::execution::runtime::party::Role;
use crate::networking::local::LocalNetworkingProducer;
use crate::{execution::runtime::party::RoleAssignment, networking::local::LocalNetworking};

pub struct BGVTestRuntime {
    pub identities: Vec<Identity>,
    pub threshold: u8,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
}

impl BGVTestRuntime {
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

        BGVTestRuntime {
            identities,
            threshold,
            user_nets,
            role_assignments,
        }
    }
}
