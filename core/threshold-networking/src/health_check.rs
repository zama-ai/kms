use crate::ggen::gnetworking_client::GnetworkingClient;
use crate::grpc::HealthTag;
use error_utils::anyhow_error_and_log;
use observability::telemetry::ContextPropagator;
use rand::RngCore;
use std::{collections::HashMap, sync::Arc, time::Duration};
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

#[derive(Clone, Copy, Debug)]
pub enum BenchKind {
    Once,
    Duration(Duration),
}

pub type HealthCheckResult<R> = HashMap<(R, Identity), HealthCheckStatus>;
/// Maps each peer to acknowledged payload bytes, elapsed time, and every attempted RPC's status.
pub type BandwidthBenchmarkResult<R> =
    HashMap<(R, Identity), (usize, Duration, Vec<HealthCheckStatus>)>;

fn acknowledged_payload_bytes(payload_size: usize, answers: &[HealthCheckStatus]) -> usize {
    answers
        .iter()
        .filter(|answer| matches!(answer, HealthCheckStatus::Ok(_)))
        .count()
        * payload_size
}

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

    /// Measures acknowledged payload bytes per peer and retains failed attempts in the returned statuses.
    pub async fn run_bandwidth_benchmark(
        &self,
        payload_size: usize,
        duration: BenchKind,
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
        let mut payload = vec![0; payload_size];
        {
            let mut rng = rand::thread_rng();
            rng.fill_bytes(&mut payload);
        }
        // Peers share the retained source buffer. Each protobuf request still owns its payload copy.
        let payload = Arc::new(payload);
        for ((role, id), client) in self.connection_channels.iter() {
            let (role, id, client, tag_serialized, timeout) = (
                *role,
                id.clone(),
                client.clone(),
                tag_serialized.clone(),
                self.timeout,
            );

            let payload = Arc::clone(&payload);
            join_set.spawn(async move {
                let start = std::time::Instant::now();
                let mut answers = Vec::new();
                match duration {
                    BenchKind::Once => {
                        // For the "once" kind, we just send one payload and return the result.
                        answers.push(
                            Self::send(
                                tag_serialized.clone(),
                                client.clone(),
                                timeout,
                                payload.as_ref().clone(),
                                role,
                                id.clone(),
                            )
                            .await
                            .2,
                        );
                    }
                    BenchKind::Duration(target_duration) => {
                        // For the "duration" kind, we keep sending payloads until the target duration has elapsed.
                        while start.elapsed() < target_duration {
                            answers.push(
                                Self::send(
                                    tag_serialized.clone(),
                                    client.clone(),
                                    timeout,
                                    payload.as_ref().clone(),
                                    role,
                                    id.clone(),
                                )
                                .await
                                .2,
                            );
                        }
                    }
                }
                let total_bytes_sent = acknowledged_payload_bytes(payload_size, &answers);
                tracing::debug!(
                    "Acknowledged payload bytes for party {}: {}",
                    id,
                    total_bytes_sent
                );
                ((role, id), (total_bytes_sent, start.elapsed(), answers))
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
        let request = tonic::Request::new(crate::ggen::HealthCheckRequest {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_goodput_counts_only_successful_rpc_payloads() {
        let elapsed = Duration::from_millis(5);
        let answers = [
            HealthCheckStatus::Ok(elapsed),
            HealthCheckStatus::Error((elapsed, Status::unavailable("peer unavailable"))),
            HealthCheckStatus::TimeOut(elapsed),
            HealthCheckStatus::Ok(elapsed),
        ];
        assert_eq!(acknowledged_payload_bytes(8_320_000, &answers), 16_640_000);
    }

    #[test]
    fn benchmark_goodput_is_zero_without_successful_rpcs() {
        let elapsed = Duration::from_secs(1);
        let answers = [
            HealthCheckStatus::Error((elapsed, Status::resource_exhausted("queue full"))),
            HealthCheckStatus::TimeOut(elapsed),
        ];
        assert_eq!(acknowledged_payload_bytes(8_320_000, &answers), 0);
        assert_eq!(acknowledged_payload_bytes(8_320_000, &[]), 0);
    }
}
