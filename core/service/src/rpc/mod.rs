#[cfg(feature = "non-wasm")]
use crate::{
    anyhow_error_and_log,
    conf::ServiceEndpoint,
    kms::core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer},
};
#[cfg(feature = "non-wasm")]
use conf_trace::telemetry::{accept_trace, make_span, record_trace_id};
#[cfg(feature = "non-wasm")]
use std::net::ToSocketAddrs;
#[cfg(feature = "non-wasm")]
use tonic::transport::Server;
#[cfg(feature = "non-wasm")]
use tower_http::trace::TraceLayer;

#[cfg(feature = "non-wasm")]
pub mod central_rpc;
pub mod rpc_types;

#[cfg(feature = "non-wasm")]
pub async fn run_server<S: CoreServiceEndpoint>(
    config: ServiceEndpoint,
    kms_service: S,
) -> anyhow::Result<()> {
    let socket_addr = format!("{}:{}", config.listen_address, config.listen_port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    let trace_request = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace)
        .map_request(record_trace_id);

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<CoreServiceEndpointServer<S>>()
        .await;

    let server = Server::builder()
        .layer(trace_request)
        .timeout(tokio::time::Duration::from_secs(config.timeout_secs))
        .add_service(health_service)
        .add_service(
            CoreServiceEndpointServer::new(kms_service)
                .max_decoding_message_size(config.grpc_max_message_size)
                .max_encoding_message_size(config.grpc_max_message_size),
        );
    tracing::info!("Starting KMS core on socket {socket_addr}");
    server
        .serve(socket_addr)
        .await
        .map_err(|e| anyhow_error_and_log(format!("KMS core stopped: {}", e)))
}
