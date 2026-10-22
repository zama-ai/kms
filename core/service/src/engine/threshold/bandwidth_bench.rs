use std::{collections::HashMap, ops::AddAssign, sync::Arc, time::Duration};

use itertools::Itertools;
use kms_grpc::{
    ContextId,
    kms::v1::{
        BandwidthBenchmarkRequest, BandwidthBenchmarkResponse, BandwidthKind, LatencyInfo,
        PeerBandwidthInfo,
    },
};
use threshold_networking::health_check::{BenchKind, HealthCheckStatus};
use tokio::sync::Semaphore;
use tonic::{Request, Response, Status};

use crate::{
    conf::BandwidthBenchmarkConfig,
    engine::{
        threshold::service::session::ImmutableSessionMaker,
        validation::{RequestIdParsingErr, parse_optional_grpc_request_id},
    },
};

/// Creates the permit pool that bounds concurrent [`run_bandwidth_benchmark`] executions to
/// `max_concurrent_runs`. One pool is held per server instance (not a process-global), so multiple
/// in-process nodes (e.g. in tests) stay independent.
pub(crate) fn new_bandwidth_bench_limiter(max_concurrent_runs: usize) -> Arc<Semaphore> {
    Arc::new(Semaphore::new(max_concurrent_runs))
}

pub(crate) async fn run_bandwidth_benchmark(
    request: Request<BandwidthBenchmarkRequest>,
    session_maker: ImmutableSessionMaker,
    bandwidth_bench_limiter: Arc<Semaphore>,
    config: &BandwidthBenchmarkConfig,
) -> Result<Response<BandwidthBenchmarkResponse>, Status> {
    let request = request.into_inner();
    tracing::info!("Received bandwidth benchmark request: {:?}", request);
    let context_id: ContextId =
        parse_optional_grpc_request_id(&request.context_id, RequestIdParsingErr::Context)?;
    // Bound these fields before casting: they are untrusted u32s that drive a per-session
    // `vec![0; payload_size]` allocation (cloned per peer) and a task-spawn loop, so a crafted
    // request could otherwise exhaust memory/tasks.
    if request.payload_size_per_session > config.max_payload_bytes {
        return Err(Status::invalid_argument(format!(
            "payload_size_per_session {} exceeds the maximum of {} bytes",
            request.payload_size_per_session, config.max_payload_bytes
        )));
    }
    if request.number_sessions == 0 || request.number_sessions > config.max_sessions {
        return Err(Status::invalid_argument(format!(
            "number_sessions {} must be in 1..={}",
            request.number_sessions, config.max_sessions
        )));
    }
    // Cap the aggregate base allocation across sessions (product can't overflow u64: both
    // operands are already bounded u32s above).
    let total_bytes =
        u64::from(request.payload_size_per_session) * u64::from(request.number_sessions);
    if total_bytes > config.max_total_bytes {
        return Err(Status::invalid_argument(format!(
            "payload_size_per_session * number_sessions ({total_bytes} bytes) exceeds the maximum of {} bytes",
            config.max_total_bytes
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
        BandwidthKind::Duration => {
            // Bound the (untrusted) duration: it drives a sustained send loop per peer, so an
            // unbounded value floods peers for the whole server request timeout.
            if request.duration > config.max_duration_secs {
                return Err(Status::invalid_argument(format!(
                    "duration {} exceeds the maximum of {} seconds",
                    request.duration, config.max_duration_secs
                )));
            }
            BenchKind::Duration(Duration::from_secs(request.duration))
        }
    };

    // Bound concurrent benchmark runs. Acquired after the input validation above so that
    // non-retryable `InvalidArgument` errors take precedence, then held for the rest of the
    // handler so the heavy work below (session creation, per-session payload allocation, and the
    // per-peer send loop) cannot be multiplied by an unbounded number of in-flight requests.
    // Reject requests once the pool is exhausted so callers retry after capacity becomes available.
    let _permit = bandwidth_bench_limiter.try_acquire_owned().map_err(|_| {
        Status::resource_exhausted(
            "too many concurrent bandwidth benchmark requests in flight; retry later",
        )
    })?;

    let started = std::time::Instant::now();
    let mut join_set = tokio::task::JoinSet::new();
    for index in 0..num_sessions {
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
            let result = session
                .run_bandwidth_benchmark(payload_size, duration)
                .await;
            tracing::info!(
                "Bandwidth benchmark session {}/{} finished after {:.1} s: {}",
                index + 1,
                num_sessions,
                started.elapsed().as_secs_f64(),
                match &result {
                    Ok(per_peer) => per_peer
                        .iter()
                        .map(|((role, _), (bytes, elapsed, answers))| {
                            let timeouts = answers
                                .iter()
                                .filter(|a| matches!(a, HealthCheckStatus::TimeOut(_)))
                                .count();
                            let errors = answers
                                .iter()
                                .filter(|a| matches!(a, HealthCheckStatus::Error(_)))
                                .count();
                            format!(
                                "{role}: {:.1} MiB in {:.1} s ({:.1} MiB/s, {} sends, {timeouts} timeouts, {errors} errors)",
                                *bytes as f64 / 1_048_576.0,
                                elapsed.as_secs_f64(),
                                *bytes as f64 / 1_048_576.0 / elapsed.as_secs_f64().max(1e-9),
                                answers.len(),
                            )
                        })
                        .collect::<Vec<_>>()
                        .join(", "),
                    Err(e) => format!("error: {e}"),
                }
            );
            result
        });
    }
    tracing::info!(
        "Bandwidth benchmark: {num_sessions} sessions created after {:.1} s, sending {payload_size}-byte payloads for {:?}",
        started.elapsed().as_secs_f64(),
        duration
    );

    let mut results = HashMap::new();

    while let Some(result) = join_set.join_next().await {
        let result = result
            .map_err(|e| {
                Status::internal(format!("Failed to join bandwidth benchmark task: {}", e))
            })?
            .map_err(|e| Status::internal(format!("Bandwidth benchmark task failed: {}", e)))?;
        for ((role, id), (bytes_sent, _, status)) in result {
            let (entry_sent, entry_status) =
                results.entry((role, id)).or_insert_with(|| (0, vec![]));
            entry_sent.add_assign(bytes_sent);
            entry_status.extend(status);
        }
    }

    // One interval covers setup and every session, including staggered starts and slow final RPCs.
    let elapsed = started.elapsed();
    let mut successes = 0usize;
    let mut timeouts = 0usize;
    let mut errors = 0usize;
    let mut acknowledged_bytes = 0usize;
    for (bytes, statuses) in results.values() {
        acknowledged_bytes += bytes;
        for status in statuses {
            match status {
                HealthCheckStatus::Ok(_) => successes += 1,
                HealthCheckStatus::TimeOut(_) => timeouts += 1,
                HealthCheckStatus::Error(_) => errors += 1,
            }
        }
    }
    let status = if successes == 0 {
        "no-success"
    } else if timeouts > 0 || errors > 0 {
        "partial"
    } else {
        "complete"
    };
    tracing::info!(
        "Bandwidth benchmark aggregate: status={status} sessions={num_sessions}/{num_sessions} acknowledged_bytes={acknowledged_bytes} attempts={} successes={successes} timeouts={timeouts} errors={errors} elapsed_s={:.6}",
        successes + timeouts + errors,
        elapsed.as_secs_f64(),
    );

    let peers_info = results
        .into_iter()
        .map(|((role, id), (bytes_sent, status))| {
            // Fill up the latency struct
            let latency = make_latency(status)
                .inspect_err(|e| tracing::warn!("Error computing latency info: {}", e))
                .ok();
            // The wire field stores whole seconds. Round up to avoid overstating goodput.
            let duration = elapsed.as_secs() + u64::from(elapsed.subsec_nanos() != 0);
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
    if status.is_empty() {
        return Err("No RPC attempts completed".to_string());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_latency_requires_successful_attempts() {
        assert!(make_latency(vec![]).is_err());
        assert!(make_latency(vec![HealthCheckStatus::TimeOut(Duration::from_secs(1))]).is_err());
        assert!(
            make_latency(vec![HealthCheckStatus::Error((
                Duration::from_millis(5),
                Status::unavailable("peer unavailable"),
            ))])
            .is_err()
        );
        let latency = make_latency(vec![
            HealthCheckStatus::Ok(Duration::from_millis(10)),
            HealthCheckStatus::Ok(Duration::from_millis(30)),
        ])
        .unwrap();
        assert_eq!(latency.average, 20);
        assert_eq!(latency.fastest, 10);
        assert_eq!(latency.slowest, 30);
    }

    #[test]
    fn bandwidth_bench_limiter_bounds_concurrency() {
        let max_concurrent_runs = BandwidthBenchmarkConfig::default().max_concurrent_runs;
        let limiter = new_bandwidth_bench_limiter(max_concurrent_runs);
        // The pool is intentionally small so concurrent runs are bounded.
        assert_eq!(limiter.available_permits(), max_concurrent_runs);

        // Hold every permit, then a further acquisition must be rejected rather than queued,
        // which is what makes `run_bandwidth_benchmark` return `ResourceExhausted` under load.
        let mut held = Vec::new();
        for _ in 0..max_concurrent_runs {
            held.push(
                Arc::clone(&limiter)
                    .try_acquire_owned()
                    .expect("a permit should be available"),
            );
        }
        assert!(Arc::clone(&limiter).try_acquire_owned().is_err());

        // Releasing a permit frees capacity for the next run.
        held.pop();
        assert!(Arc::clone(&limiter).try_acquire_owned().is_ok());
    }
}
