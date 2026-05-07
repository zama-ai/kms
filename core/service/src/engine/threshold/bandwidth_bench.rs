use std::{collections::HashMap, ops::AddAssign, time::Duration};

use itertools::Itertools;
use kms_grpc::{
    ContextId,
    kms::v1::{BandwidthBenchmarkRequest, BandwidthBenchmarkResponse, PeerBandwidthInfo},
};
use tonic::{Request, Response, Status};

use crate::engine::{
    threshold::service::session::ImmutableSessionMaker,
    validation::{RequestIdParsingErr, parse_optional_grpc_request_id},
};

pub(crate) async fn run_bandwidth_benchmark(
    request: Request<BandwidthBenchmarkRequest>,
    session_maker: ImmutableSessionMaker,
) -> Result<Response<BandwidthBenchmarkResponse>, Status> {
    let request = request.into_inner();
    let context_id: ContextId =
        parse_optional_grpc_request_id(&request.context_id, RequestIdParsingErr::Context)?;
    let payload_size = request.payload_size_per_session as usize;
    let num_sessions = request.number_sessions as usize;
    let duration = Duration::from_secs(request.duration_experiment_seconds);

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
                .expect("Bandwidth benchmark failed")
        });
    }

    let mut results = HashMap::new();

    while let Some(result) = join_set.join_next().await {
        let result = result.map_err(|e| {
            Status::internal(format!("Failed to join bandwidth benchmark task: {}", e))
        })?;
        for ((role, id), bytes_sent) in result {
            results
                .entry((role, id))
                .or_insert_with(|| 0)
                .add_assign(bytes_sent);
        }
    }

    let peers_info = results
        .into_iter()
        .map(|((role, id), bytes_sent)| PeerBandwidthInfo {
            peer_id: role.one_based() as u32,
            endpoint: id.hostname().to_string(),
            bytes_sent: bytes_sent as u64,
        })
        .collect_vec();

    Ok(Response::new(BandwidthBenchmarkResponse { peers_info }))
}
