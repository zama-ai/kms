use std::{collections::HashMap, ops::AddAssign, time::Duration};

use itertools::Itertools;
use kms_grpc::{
    ContextId,
    kms::v1::{
        BandwidthBenchmarkRequest, BandwidthBenchmarkResponse, LatencyInfo, PeerBandwidthInfo,
    },
};
use threshold_networking::health_check::HealthCheckStatus;
use tonic::{Request, Response, Status};

use crate::engine::{
    threshold::service::session::ImmutableSessionMaker,
    validation::{RequestIdParsingErr, parse_optional_grpc_request_id},
};

pub(crate) async fn run_bandwidth_benchmark(
    request: Request<BandwidthBenchmarkRequest>,
    session_maker: ImmutableSessionMaker,
) -> Result<Response<BandwidthBenchmarkResponse>, Status> {
    tracing::info!("Received bandwidth benchmark request: {:?}", request);
    let request = request.into_inner();
    let context_id: ContextId =
        parse_optional_grpc_request_id(&request.context_id, RequestIdParsingErr::Context)?;
    let payload_size = request.payload_size_per_session as usize;
    let num_sessions = request.number_sessions as usize;
    let duration = Duration::from_secs(request.duration);

    let mut join_set = tokio::task::JoinSet::new();
    for _ in 0..num_sessions {
        let session = session_maker
            .get_healthcheck_session(&context_id)
            .await
            .map_err(|e| {
                Status::internal(format!(
                    "Failed to create health check session for context {}: {}",
                    context_id, e
                ))
            })?;
        join_set.spawn(async move {
            session
                .run_bandwidth_benchmark(payload_size, duration)
                .await
        });
    }

    let mut results = HashMap::new();

    while let Some(result) = join_set.join_next().await {
        let result = result
            .map_err(|e| {
                Status::internal(format!("Failed to join bandwidth benchmark task: {}", e))
            })?
            .map_err(|e| Status::internal(format!("Bandwidth benchmark task failed: {}", e)))?;
        for ((role, id), (bytes_sent, duration, status)) in result {
            let (entry_sent, entry_duration, entry_status) = results
                .entry((role, id))
                .or_insert_with(|| (0, vec![], vec![]));
            entry_sent.add_assign(bytes_sent);
            entry_duration.push(duration);
            entry_status.extend(status);
        }
    }

    let peers_info = results
        .into_iter()
        .map(|((role, id), (bytes_sent, durations, status))| {
            // Fill up tha latency struct
            let latency = make_latency(status)
                .inspect_err(|e| tracing::warn!("Error computing latency info: {}", e))
                .ok();
            PeerBandwidthInfo {
                peer_id: role.one_based() as u32,
                endpoint: id.hostname().to_string(),
                bytes_sent: bytes_sent as u64,
                duration: (durations.iter().sum::<Duration>().as_secs_f64()
                    / durations.len() as f64) as u64,
                latency,
            }
        })
        .collect_vec();

    tracing::info!("Bandwidth benchmark completed. Results: {:?}", peers_info);

    Ok(Response::new(BandwidthBenchmarkResponse { peers_info }))
}

fn make_latency(status: Vec<HealthCheckStatus>) -> Result<LatencyInfo, String> {
    let latencies: Vec<u128> = status
        .iter()
        .map(|s| match s {
            HealthCheckStatus::Ok(duration) => Ok(duration.as_millis()),
            HealthCheckStatus::Error(_) => {
                Err("Some error sending at least one payload".to_string())
            }
            HealthCheckStatus::TimeOut(_) => {
                Err("Timeout sending at least one payload".to_string())
            }
        })
        .try_collect()?;

    let sorted_latencies = latencies.into_iter().sorted().collect_vec();

    let average = (sorted_latencies.iter().sum::<u128>() as f64 / status.len() as f64) as u64;
    let p50_idx = status.len() / 2;
    let p50 = sorted_latencies.get(p50_idx).copied().unwrap_or(0) as u64;
    let p90_idx = (status.len() * 90) / 100;
    let p90 = sorted_latencies.get(p90_idx).copied().unwrap_or(0) as u64;
    let p99_idx = (status.len() * 99) / 100;
    let p99 = sorted_latencies.get(p99_idx).copied().unwrap_or(0) as u64;
    let slowest = sorted_latencies.last().copied().unwrap_or(0) as u64;
    let fastest = sorted_latencies.first().copied().unwrap_or(0) as u64;

    Ok(LatencyInfo {
        average,
        p50,
        p90,
        p99,
        slowest,
        fastest,
    })
}
