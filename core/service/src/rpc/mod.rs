#[cfg(feature = "non-wasm")]
use crate::{
    anyhow_error_and_log,
    conf::ServiceEndpoint,
    kms::core_service_endpoint_server::{CoreServiceEndpoint, CoreServiceEndpointServer},
    util::port_cleanup::ensure_port_available,
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

    // Ensure the port is available before starting
    ensure_port_available(socket_addr).await?;

    // Create shutdown channel
    let (tx, mut rx) = tokio::sync::broadcast::channel::<()>(1);

    // Set up signal handlers for graceful shutdown
    let shutdown_tx = tx.clone();
    tokio::spawn(async move {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install signal handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                tracing::info!("Received Ctrl+C signal");
            },
            _ = terminate => {
                tracing::info!("Received terminate signal");
            }
        }

        let _ = shutdown_tx.send(());
    });

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

    // Create graceful shutdown future
    let graceful = server.serve_with_shutdown(socket_addr, async {
        rx.recv().await.ok();
        tracing::info!("Starting graceful shutdown");

        // Set health check to not serving
        health_reporter
            .set_not_serving::<CoreServiceEndpointServer<S>>()
            .await;

        // Allow time for in-flight requests to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    });

    // Run the server with graceful shutdown
    match graceful.await {
        Ok(_) => {
            tracing::info!("Server shutdown completed successfully");
            Ok(())
        }
        Err(e) => {
            let err = anyhow_error_and_log(format!("KMS core stopped with error: {}", e));
            Err(err)
        }
    }
}
