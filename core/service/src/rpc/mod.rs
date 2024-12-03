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
use std::sync::Arc;
#[cfg(feature = "non-wasm")]
use tokio::sync::RwLock;
#[cfg(feature = "non-wasm")]
use tonic_health::pb::health_server::{Health, HealthServer};
#[cfg(feature = "non-wasm")]
use tonic_health::server::HealthReporter;

pub const INFLIGHT_REQUEST_WAITING_TIME: u64 = 1;

#[cfg(feature = "non-wasm")]
pub async fn prepare_shutdown_signals<F: std::future::Future<Output = ()> + Send + 'static>(
    external_signal: F,
    merged_signal: tokio::sync::oneshot::Sender<()>,
) {
    // these will eat the ctrl+c when we do it on tests,
    // so doing ctrl+c on tests won't stop the tests
    // so putting it under the cfg(not(test))
    #[cfg(all(not(test), not(feature = "testing")))]
    {
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
            }
            _ = terminate => {
                tracing::info!("Received terminate signal");
            }
            _ = external_signal => {
                tracing::info!("Received external shutdown signal");
            }
        }
    }
    #[cfg(any(test, feature = "testing"))]
    {
        external_signal.await;
    }

    // forward the shutdown signal to the
    let _ = merged_signal.send(());
}

/// * `shutdown_signal` - upon completion the server should shut itself down.
///   But it is not guaranteed that this future will ever complete since it might
///   be the pending future.
#[cfg(feature = "non-wasm")]
pub async fn run_server<
    S: CoreServiceEndpoint,
    F: std::future::Future<Output = ()> + Send + 'static,
>(
    config: ServiceEndpoint,
    kms_service: S,
    health_reporter: Arc<RwLock<HealthReporter>>,
    health_service: HealthServer<impl Health>,
    shutdown_signal: F,
) -> anyhow::Result<()> {
    let socket_addr_str = format!("{}:{}", config.listen_address, config.listen_port);
    let socket_addr = socket_addr_str
        .to_socket_addrs()?
        .next()
        .ok_or(anyhow::anyhow!(
            "failed to parse socket address {}",
            socket_addr_str
        ))?;

    // Ensure the port is available before starting
    if !crate::util::random_free_port::is_free(socket_addr.port(), &socket_addr.ip()).await {
        return Err(anyhow::anyhow!(
            "socket address {socket_addr} is not free for core/service"
        ));
    }

    // Create shutdown channel
    let (tx, rx) = tokio::sync::oneshot::channel();

    // Set up signal handlers for graceful shutdown
    tokio::spawn(prepare_shutdown_signals(shutdown_signal, tx));

    let trace_request = tower::ServiceBuilder::new()
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace)
        .map_request(record_trace_id);

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
        // await is the same as recv on a oneshot channel
        _ = rx.await;
        tracing::info!(
            "Starting graceful shutdown of core/service at {}",
            socket_addr
        );

        // Set health check to not serving
        {
            health_reporter
                .write()
                .await
                .set_not_serving::<CoreServiceEndpointServer<S>>()
                .await;
        }
        // Allow time for in-flight requests to complete
        tokio::time::sleep(tokio::time::Duration::from_secs(
            INFLIGHT_REQUEST_WAITING_TIME,
        ))
        .await;
    });

    // Run the server with graceful shutdown
    match graceful.await {
        Ok(_) => {
            tracing::info!(
                "core/service on {} shutdown completed successfully",
                socket_addr
            );
            Ok(())
        }
        Err(e) => {
            let err = anyhow_error_and_log(format!(
                "KMS core on {} stopped with error: {}",
                socket_addr, e
            ));
            Err(err)
        }
    }
}
