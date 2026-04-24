use crate::choreography::tfhe_rs::requests::Status;
use crate::conf::choreo::{ChoreoConf, NetworkTopology};
use observability::telemetry::ContextPropagator;
use std::collections::HashMap;
use threshold_networking::choreography_gen::{
    StatusCheckRequest, choreography_client::ChoreographyClient,
};
use threshold_networking::constants::{MAX_EN_DECODE_MESSAGE_SIZE, NETWORK_TIMEOUT_LONG};
use threshold_types::party::Identity;
use threshold_types::role::Role;
use threshold_types::session_id::SessionId;
use tokio::{task::JoinSet, time::Duration};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Uri};

pub struct ChoreoRuntime {
    pub role_assignments: HashMap<Role, Identity>,
    pub channels: HashMap<Role, Channel>,
}

impl ChoreoRuntime {
    pub fn new_from_conf(conf: &ChoreoConf) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let topology = &conf.threshold_topology;
        let role_assignments: HashMap<Role, Identity> = topology.into();
        let host_channels = topology.choreo_physical_topology_into_network_topology()?;
        ChoreoRuntime::new_with_net_topology(role_assignments, host_channels)
    }

    pub(crate) fn new_with_net_topology(
        role_assignments: HashMap<Role, Identity>,
        network_topology: NetworkTopology,
    ) -> Result<ChoreoRuntime, Box<dyn std::error::Error>> {
        let channels = network_topology
            .iter()
            .map(|(role, host)| {
                let endpoint: &Uri = host;
                println!("connecting to endpoint: {:?}", endpoint);
                // Use the TLS_NODELAY mode to ensure everything gets sent immediately by disabling
                // Nagle's algorithm. Note that this decreases latency but increases network
                // bandwidth usage. If bandwidth is a concern, then this should be changed.
                let channel = Channel::builder(endpoint.clone())
                    .timeout(NETWORK_TIMEOUT_LONG)
                    .tcp_nodelay(true)
                    .connect_lazy();
                Ok((*role, channel))
            })
            .collect::<Result<_, Box<dyn std::error::Error>>>()?;

        Ok(ChoreoRuntime {
            role_assignments,
            channels,
        })
    }

    pub fn new_client(
        &self,
        channel: Channel,
    ) -> ChoreographyClient<InterceptedService<Channel, ContextPropagator>> {
        ChoreographyClient::with_interceptor(channel, ContextPropagator)
            .max_decoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
            .max_encoding_message_size(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    pub async fn initiate_status_check(
        &self,
        session_id: SessionId,
        retry: bool,
        interval: Duration,
        malicious_roles: Vec<Role>,
    ) -> anyhow::Result<Vec<(Role, Status)>> {
        let mut join_set = JoinSet::new();
        let serialized_sid = bc2wrap::serialize(&session_id)?;
        let request = StatusCheckRequest {
            request_id: serialized_sid,
        };
        let mut result = Vec::new();
        loop {
            self.channels.iter().for_each(|(role, channel)| {
                let mut client = self.new_client(channel.clone());
                let request = request.clone();
                let role = *role;
                join_set.spawn(async move { (role, client.status_check(request).await) });
            });

            while let Some(response) = join_set.join_next().await {
                let (role, response) = response?;
                let status: Status = bc2wrap::deserialize_safe(&response?.into_inner().status)?;
                result.push((role, status));
            }

            if !retry
                || result.iter().all(|(role, status)| {
                    *status != Status::Ongoing || malicious_roles.contains(role)
                })
            {
                return Ok(result);
            } else {
                println!("Status Check for Session ID {session_id} -- Still have running parties");
                result.sort_by_key(|(role, _)| role.one_based());
                for (role, status) in result.drain(..) {
                    println!("Role {role}, Status {status:?}");
                }
                tokio::time::sleep(interval).await;
            }
        }
    }
}
