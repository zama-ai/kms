use crate::{anyhow_error_and_log, conf::ServiceEndpoint};

use kms_grpc::kms_service::v1::core_service_endpoint_server::{
    CoreServiceEndpoint, CoreServiceEndpointServer,
};
use kms_grpc::metastore_status::v1::meta_store_status_service_server::{
    MetaStoreStatusService, MetaStoreStatusServiceServer,
};
use observability::telemetry::make_span;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tonic::transport::{server::TcpIncoming, Server};
use tonic_health::pb::health_server::{Health, HealthServer};
use tonic_health::server::HealthReporter;
use tower_http::classify::{GrpcCode, GrpcFailureClass};
use tower_http::trace::TraceLayer;
use tracing::Span;

/// Trait for shutting down a server gracefully.
/// Starts shutdown in the background and returns a JoinHandle on the process.
#[tonic::async_trait]
pub trait Shutdown {
    fn shutdown(&self) -> anyhow::Result<JoinHandle<()>>;
}

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
pub async fn run_server<
    S: CoreServiceEndpoint + Shutdown,
    M: MetaStoreStatusService,
    F: std::future::Future<Output = ()> + Send + 'static,
>(
    config: ServiceEndpoint,
    listener: TcpListener,
    kms_service: Arc<S>,
    meta_store_status_service: Arc<M>,
    health_service: HealthServer<impl Health>,
    health_reporter: HealthReporter,
    shutdown_signal: F,
) -> anyhow::Result<()> {
    use crate::consts::DURATION_WAITING_ON_RESULT_SECONDS;

    let socket_addr = listener.local_addr()?;

    // Create shutdown channel
    let (tx, rx): (
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) = tokio::sync::oneshot::channel();

    // Set up signal handlers for graceful shutdown
    tokio::spawn(prepare_shutdown_signals(shutdown_signal, tx));

    let trace_request = tower::ServiceBuilder::new().layer(
        TraceLayer::new_for_grpc()
            .make_span_with(make_span)
            .on_failure(
                |error: GrpcFailureClass, _latency: Duration, _span: &Span| {
                    if let GrpcFailureClass::Code(status_code) = error {
                        // The server only returns SERVICE_UNAVAILABLE status code when the request is not done yet
                        if i32::from(status_code) == GrpcCode::Unavailable as i32 {
                            tracing::info!("Grpc info from KMS Core server: {}", error)
                        } else {
                            tracing::error!("Grpc error from KMS Core server: {}", error)
                        }
                    }
                },
            ),
    );
    let server = Server::builder()
        .http2_adaptive_window(Some(true))
        .layer(trace_request)
        // Make sure we never abort because we spent too much time on the blocking part of the get result
        // as we mean to do it.
        .timeout(tokio::time::Duration::from_secs(
            config.timeout_secs + DURATION_WAITING_ON_RESULT_SECONDS,
        ))
        .add_service(health_service)
        .add_service(
            CoreServiceEndpointServer::from_arc(Arc::clone(&kms_service))
                .max_decoding_message_size(config.grpc_max_message_size)
                .max_encoding_message_size(config.grpc_max_message_size),
        )
        .add_service(MetaStoreStatusServiceServer::from_arc(
            meta_store_status_service,
        ));

    tracing::info!("Starting KMS core on socket {socket_addr}");

    // Use the TLS_NODELAY mode to ensure everything gets sent immediately by disabling Nagle's algorithm.
    // Note that this decreases latency but increases network bandwidth usage. If bandwidth is a concern,
    // then this should be changed
    let tcp_incoming = TcpIncoming::from(listener).with_nodelay(Some(true));
    // Create graceful shutdown future
    let graceful = server.serve_with_incoming_shutdown(tcp_incoming, async {
        // await is the same as recv on a oneshot channel
        _ = rx.await;
        tracing::info!(
            "Starting graceful shutdown of core/service at {}",
            socket_addr
        );

        match kms_service.shutdown() {
            Ok(res) => {
                match res.await {
                    Ok(_) => {
                        tracing::info!("Successfully shutdown core/service at {}", socket_addr)
                    }
                    Err(e) => {
                        tracing::error!("Error while waiting for shutdown to complete: {}", e)
                    }
                }
                tracing::info!("Successfully shutdown core/service at {}", socket_addr);
            }
            Err(e) => {
                tracing::error!("Failed to shutdown core/service at {}: {}", socket_addr, e);
            }
        }
    });

    health_reporter
        .set_serving::<CoreServiceEndpointServer<S>>()
        .await;

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
            let err =
                anyhow_error_and_log(format!("KMS core on {socket_addr} stopped with error: {e}"));
            Err(err)
        }
    }
}
