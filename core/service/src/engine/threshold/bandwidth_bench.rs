use std::{collections::HashMap, ops::AddAssign, time::Duration};

use itertools::Itertools;
use kms_grpc::{
    ContextId,
    kms::v1::{
        BandwidthBenchmarkRequest, BandwidthBenchmarkResponse, BandwidthKind, LatencyInfo,
        PeerBandwidthInfo,
    },
};
use threshold_networking::health_check::{BenchKind, HealthCheckStatus};
use tonic::{Request, Response, Status};

use crate::engine::{
    threshold::service::session::ImmutableSessionMaker,
    validation::{RequestIdParsingErr, parse_optional_grpc_request_id},
};

/// Max per-session payload a caller may request. Bounds the `vec![0; payload_size]`
/// allocation in `run_bandwidth_benchmark`: an unbounded value aborts the process on OOM.
const MAX_BANDWIDTH_PAYLOAD_BYTES: u32 = 1 << 30; // 1 GiB
/// Max benchmark sessions a caller may request, bounding the task fan-out below.
const MAX_BANDWIDTH_SESSIONS: u32 = 1024;

pub(crate) async fn run_bandwidth_benchmark(
    request: Request<BandwidthBenchmarkRequest>,
    session_maker: ImmutableSessionMaker,
) -> Result<Response<BandwidthBenchmarkResponse>, Status> {
    let request = request.into_inner();
    tracing::info!("Received bandwidth benchmark request: {:?}", request);
    let context_id: ContextId =
        parse_optional_grpc_request_id(&request.context_id, RequestIdParsingErr::Context)?;
    // Bound both fields before casting: they are untrusted u64s that drive an allocation
    // and a task-spawn loop, so a crafted request could otherwise exhaust memory/tasks.
    if request.payload_size_per_session > MAX_BANDWIDTH_PAYLOAD_BYTES {
        return Err(Status::invalid_argument(format!(
            "payload_size_per_session {} exceeds the maximum of {} bytes",
            request.payload_size_per_session, MAX_BANDWIDTH_PAYLOAD_BYTES
        )));
    }
    if request.number_sessions == 0 || request.number_sessions > MAX_BANDWIDTH_SESSIONS {
        return Err(Status::invalid_argument(format!(
            "number_sessions {} must be in 1..={}",
            request.number_sessions, MAX_BANDWIDTH_SESSIONS
        )));
    }
    let payload_size = request.payload_size_per_session as usize;
    let num_sessions = request.number_sessions as usize;
    let kind: BandwidthKind = request.kind.try_into().map_err(|e| {
        Status::invalid_argument(format!(
            "Invalid bandwidth benchmark kind {}: {}",
            request.kind, e
        ))
    })?;
    let duration = match kind {
        BandwidthKind::Once => BenchKind::Once,
        BandwidthKind::Duration => BenchKind::Duration(Duration::from_secs(request.duration)),
    };

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
            // Fill up the latency struct
            let latency = make_latency(status)
                .inspect_err(|e| tracing::warn!("Error computing latency info: {}", e))
                .ok();
            let duration = match kind {
                BandwidthKind::Once => durations
                    .into_iter()
                    .map(|d| d.as_secs())
                    .max()
                    .unwrap_or(0),
                BandwidthKind::Duration => {
                    (durations.iter().sum::<Duration>().as_secs_f64() / durations.len() as f64)
                        as u64
                }
            };
            PeerBandwidthInfo {
                peer_id: role.one_based() as u32,
                endpoint: id.hostname().to_string(),
                bytes_sent: bytes_sent as u64,
                duration,
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
