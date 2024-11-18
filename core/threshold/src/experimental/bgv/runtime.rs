use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::Duration;

use crate::execution::runtime::party::Identity;
use crate::execution::runtime::party::Role;
use crate::networking::local::LocalNetworkingProducer;
use crate::networking::NetworkMode;
use crate::{execution::runtime::party::RoleAssignment, networking::local::LocalNetworking};

pub struct BGVTestRuntime {
    pub identities: Vec<Identity>,
    pub threshold: u8,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
}

impl BGVTestRuntime {
    pub fn new(
        identities: Vec<Identity>,
        threshold: u8,
        network_mode: NetworkMode,
        delayed_map: Option<HashMap<Identity, Duration>>,
    ) -> Self {
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
                let delay = if let Some(delayed_map) = &delayed_map {
                    delayed_map.get(user_identity).copied()
                } else {
                    None
                };
                let net = net_producer.user_net(user_identity.clone(), network_mode, delay);
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
