use super::ggen::gnetworking_client::GnetworkingClient;
use crate::grpc::HealthTag;
use error_utils::anyhow_error_and_log;
use observability::telemetry::ContextPropagator;
use std::{collections::HashMap, time::Duration};
use threshold_types::party::Identity;
use threshold_types::role::RoleTrait;
use tokio::task::JoinSet;
use tonic::{Status, service::interceptor::InterceptedService, transport::Channel};

pub struct HealthCheckSession<R: RoleTrait> {
    /// My own [`Identity`]
    pub(crate) owner: Identity,
    /// My own [`Role`]
    pub(crate) my_role: R,
    pub(crate) timeout: Duration,
    pub(crate) connection_channels:
        HashMap<(R, Identity), GnetworkingClient<InterceptedService<Channel, ContextPropagator>>>,
}

pub enum HealthCheckStatus {
    Ok(Duration),
    Error((Duration, Status)),
    TimeOut(Duration),
}

pub type HealthCheckResult<R> = HashMap<(R, Identity), HealthCheckStatus>;
pub type BandwidthBenchmarkResult<R> = HashMap<(R, Identity), usize>;

impl<R: RoleTrait> HealthCheckSession<R> {
    pub fn new(
        owner: Identity,
        my_role: R,
        timeout: Duration,
        connection_channels: HashMap<
            (R, Identity),
            GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        >,
    ) -> Self {
        Self {
            owner,
            my_role,
            timeout,
            connection_channels,
        }
    }

    pub fn get_my_role(&self) -> R {
        self.my_role
    }

    pub fn get_my_id(&self) -> Identity {
        self.owner.clone()
    }

    pub fn get_num_parties(&self) -> usize {
        // Don't forget to count myself
        self.connection_channels.len() + 1
    }

    pub async fn run_healthcheck(&self) -> anyhow::Result<HealthCheckResult<R>> {
        let tag = HealthTag {
            sender: self.owner.mpc_identity(),
        };

        let tag_serialized = bc2wrap::serialize(&tag)
            .map_err(|_| anyhow_error_and_log("Failed to serialize the Health Check Tag"))?;

        let mut tasks = JoinSet::new();
        for ((role, id), client) in self.connection_channels.iter() {
            let (role, id, client, tag_serialized, timeout) = (
                *role,
                id.clone(),
                client.clone(),
                tag_serialized.clone(),
                self.timeout,
            );
            tasks.spawn(Self::send(
                tag_serialized,
                client,
                timeout,
                vec![],
                role,
                id,
            ));
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

    pub async fn run_bandwidth_benchmark(
        &self,
        payload_size: usize,
        duration: Duration,
    ) -> anyhow::Result<BandwidthBenchmarkResult<R>> {
        // For duration, hit all the other parties with a payload of the given size.
        // As soon as the other party has answered, hit it with the next payload until the duration has elapsed.

        let tag = HealthTag {
            sender: self.owner.mpc_identity(),
        };

        let tag_serialized = bc2wrap::serialize(&tag).map_err(|_| {
            anyhow_error_and_log("Failed to serialize the Health Check Tag for Bandwidth Benchmark")
        })?;

        // Spawn a task for each party to run the bandwidth benchmark in parallel.
        let mut join_set = JoinSet::new();

        // Be safe and use random bytes as payload to avoid any compression that
        // could happen before TLS layer
        let payload = (0..payload_size)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<u8>>();

        for ((role, id), client) in self.connection_channels.iter() {
            let (role, id, client, tag_serialized, timeout) = (
                *role,
                id.clone(),
                client.clone(),
                tag_serialized.clone(),
                self.timeout,
            );

            let payload = payload.clone();
            join_set.spawn(async move {
                let mut total_bytes_sent = 0;
                let start = std::time::Instant::now();
                while start.elapsed() < duration {
                    Self::send(
                        tag_serialized.clone(),
                        client.clone(),
                        timeout,
                        payload.clone(),
                        role,
                        id.clone(),
                    )
                    .await;
                    total_bytes_sent += payload_size;
                }
                tracing::debug!("Total bytes sent to party {}: {}", id, total_bytes_sent);
                ((role, id), total_bytes_sent)
            });
        }

        Ok(join_set.join_all().await.into_iter().collect())
    }

    async fn send(
        tag_serialized: Vec<u8>,
        client: GnetworkingClient<InterceptedService<Channel, ContextPropagator>>,
        timeout: Duration,
        payload: Vec<u8>,
        role: R,
        id: Identity,
    ) -> (R, Identity, HealthCheckStatus) {
        let start = std::time::Instant::now();
        let request = tonic::Request::new(super::ggen::HealthCheckRequest {
            tag: tag_serialized,
            payload,
        });
        let response = tokio::time::timeout(timeout, client.clone().health_check(request)).await;
        let duration = start.elapsed();

        let response = match response {
            Ok(Ok(_)) => HealthCheckStatus::Ok(duration),
            Ok(Err(e)) => HealthCheckStatus::Error((duration, e)),
            Err(_e) => HealthCheckStatus::TimeOut(timeout),
        };
        (role, id, response)
    }
}
