use super::gen::gnetworking_client::GnetworkingClient;
use observability::telemetry::ContextPropagator;
use std::{collections::HashMap, time::Duration};
use tokio::task::JoinSet;
use tonic::{service::interceptor::InterceptedService, transport::Channel, Status};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::runtime::party::Identity,
    networking::{grpc::HealthTag, Role},
    session_id::SessionId,
};

const TIMEOUT_MAX_WAIT_S: u64 = 5;

pub struct HealthCheckSession {
    pub(crate) owner: Identity,
    pub(crate) my_role: Role,
    pub(crate) context_id: SessionId,
    pub(crate) connection_channels: HashMap<
        (Role, Identity),
        GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
    >,
}

pub enum HealthCheckStatus {
    Ok(Duration),
    Error((Duration, Status)),
    TimeOut(Duration),
}

pub type HealthCheckResult = HashMap<(Role, Identity), HealthCheckStatus>;

impl HealthCheckSession {
    pub fn new(
        owner: Identity,
        my_role: Role,
        context_id: SessionId,
        connection_channels: HashMap<
            (Role, Identity),
            GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        >,
    ) -> Self {
        Self {
            owner,
            my_role,
            context_id,
            connection_channels,
        }
    }

    pub fn get_my_role(&self) -> Role {
        self.my_role
    }

    pub fn get_my_id(&self) -> Identity {
        self.owner.clone()
    }

    pub fn get_num_parties(&self) -> usize {
        // Don't forget to count myself
        self.connection_channels.len() + 1
    }

    pub async fn run_healthcheck(&self) -> anyhow::Result<HealthCheckResult> {
        let tag = HealthTag {
            sender: self.owner.mpc_identity(),
            context_id: self.context_id,
        };

        let tag_serialized = bc2wrap::serialize(&tag)
            .map_err(|_| anyhow_error_and_log("Failed to serialize the Health Check Tag"))?;

        let mut tasks = JoinSet::new();
        for ((role, id), client) in self.connection_channels.iter() {
            let (role, id, client, tag_serialized) =
                (*role, id.clone(), client.clone(), tag_serialized.clone());
            tasks.spawn(async move {
                let start = std::time::Instant::now();
                let request = tonic::Request::new(super::gen::HealthCheckRequest {
                    tag: tag_serialized,
                });
                let response = tokio::time::timeout(
                    Duration::from_secs(TIMEOUT_MAX_WAIT_S),
                    client.clone().health_check(request),
                )
                .await;
                let duration = start.elapsed();

                let response = match response {
                    Ok(Ok(_)) => HealthCheckStatus::Ok(duration),
                    Ok(Err(e)) => HealthCheckStatus::Error((duration, e)),
                    Err(_e) => HealthCheckStatus::TimeOut(Duration::from_secs(TIMEOUT_MAX_WAIT_S)),
                };
                (role, id, response)
            });
        }

        let mut results = HashMap::new();
        while let Some(response) = tasks.join_next().await {
            if let Ok((role, identity, response)) = response {
                results.insert((role, identity), response);
            } else {
                tracing::error!("Error while joining on the tasks of the Health Check");
            }
        }
        Ok(results)
    }
}
