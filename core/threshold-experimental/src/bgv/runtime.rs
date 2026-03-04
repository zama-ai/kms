use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::time::Duration;

use networking::local::{LocalNetworking, LocalNetworkingProducer};
use threshold_types::network::NetworkMode;
use threshold_types::role::Role;

pub struct BGVTestRuntime {
    pub threshold: u8,
    pub user_nets: Vec<Arc<LocalNetworking<Role>>>,
    pub roles: HashSet<Role>,
}

impl BGVTestRuntime {
    pub fn new(
        roles: HashSet<Role>,
        threshold: u8,
        network_mode: NetworkMode,
        delayed_map: Option<HashMap<Role, Duration>>,
    ) -> Self {
        let net_producer = LocalNetworkingProducer::from_roles(&roles);
        let user_nets: Vec<Arc<LocalNetworking<Role>>> = roles
            .iter()
            .map(|role| {
                let delay = if let Some(delayed_map) = &delayed_map {
                    delayed_map.get(role).copied()
                } else {
                    None
                };
                let net = net_producer.user_net(*role, network_mode, delay);
                Arc::new(net)
            })
            .collect();

        BGVTestRuntime {
            threshold,
            user_nets,
            roles,
        }
    }
}
