use crate::conf::party::PartyConf;
use algebra::{
    base_ring::{Z64, Z128},
    galois_rings::common::ResiduePoly,
    structure_traits::{Derive, ErrorCorrect, Invert, Solve, Syndrome},
};
use observability::telemetry::make_span;
use std::sync::Arc;
use threshold_execution::online::preprocessing::{PreprocessorFactory, create_memory_factory, create_redis_factory};
use threshold_networking::constants::NETWORK_TIMEOUT_LONG;
use threshold_networking::grpc::{GrpcNetworkingManager, GrpcServer, TlsExtensionGetter};
use threshold_types::role::Role;
use tonic::transport::{Server, ServerTlsConfig, server::Router};
use tower_http::trace::TraceLayer;

pub trait ChoreoRoutingHelper<const EXTENSION_DEGREE: usize> {
    fn add_to_router<L>(
        &self,
        router: Router<L>,
        my_role: Role,
        networking: Arc<GrpcNetworkingManager>,
        factory: Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>,
    ) -> Router<L>;
}

pub async fn run<const EXTENSION_DEGREE: usize>(
    settings: &PartyConf,
    routing_helper: impl ChoreoRoutingHelper<EXTENSION_DEGREE>,
) -> Result<(), Box<dyn std::error::Error>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
{
    let my_role: Role = settings.protocol().host().into();

    let tls_conf = settings
        .certpaths
        .as_ref()
        .map(|certpaths| certpaths.get_client_tls_conf())
        .transpose()?;

    // the networking manager is shared between the two services
    let networking = Arc::new(GrpcNetworkingManager::new(
        tls_conf,
        settings.net_conf,
        false,
    )?);
    let networking_server = networking.new_server(TlsExtensionGetter::TlsConnectInfo);

    let factory = match &settings.redis {
        None => create_memory_factory::<EXTENSION_DEGREE>(),
        Some(conf) => create_redis_factory::<EXTENSION_DEGREE>(format!("{my_role}"), conf),
    };

    // create a server that uses TLS
    // if [try_use_tls] is true and settings.certpaths is not None
    let make_server = move |try_use_tls: bool| -> anyhow::Result<Server> {
        let server = match (try_use_tls, &settings.certpaths) {
            (true, Some(cert_bundle)) => {
                tracing::info!(
                    "attempting to build tls-enabled kms-core server with {cert_bundle:?}"
                );
                let identity = cert_bundle.get_identity()?;
                let ca_cert = cert_bundle.get_flattened_ca_list()?;
                let tls_config = ServerTlsConfig::new()
                    .identity(identity)
                    .client_ca_root(ca_cert);
                Server::builder()
                    .tls_config(tls_config)?
                    .timeout(NETWORK_TIMEOUT_LONG)
            }
            (_, _) => {
                tracing::warn!("attempting to build an insecure kms-core server");
                Server::builder().timeout(NETWORK_TIMEOUT_LONG)
            }
        };
        Ok(server)
    };

    // CHOREO
    // create a future for the choreography server
    let (choreo_health_reporter, choreo_health_service) = tonic_health::server::health_reporter();
    choreo_health_reporter.set_serving::<GrpcServer>().await;

    let choreo_grpc_layer = tower::ServiceBuilder::new()
        .timeout(NETWORK_TIMEOUT_LONG)
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span));

    let choreo_router = make_server(false)?
        .layer(choreo_grpc_layer)
        .add_service(choreo_health_service);

    let choreo_router =
        routing_helper.add_to_router(choreo_router, my_role, networking.clone(), factory);

    tracing::info!(
        "Successfully created choreo server with party id {:?} on port {:?}.",
        settings.protocol().host(),
        settings.protocol().host().choreoport()
    );

    let choreo_future = choreo_router
        .serve(format!("0.0.0.0:{}", settings.protocol().host().choreoport()).parse()?);

    // CORE
    // create a future for the core-to-core MPC server
    // Unfortunately, due to lifetime constraints of GrpcNetworkingManager
    // in async code, we need to keep [networking] in the same scope,
    // so the section below is similar to the "CHOREO" section.
    let (core_health_reporter, core_health_service) = tonic_health::server::health_reporter();
    core_health_reporter.set_serving::<GrpcServer>().await;
    let core_grpc_layer = tower::ServiceBuilder::new().timeout(NETWORK_TIMEOUT_LONG);

    let core_router = make_server(true)?
        .layer(core_grpc_layer)
        .http2_adaptive_window(Some(true))
        .add_service(core_health_service)
        .add_service(networking_server);

    let core_future =
        core_router.serve(format!("0.0.0.0:{}", settings.protocol().host().port()).parse()?);

    tracing::info!(
        "Successfully created core server with party id {:?} on port {:?}.",
        settings.protocol().host(),
        settings.protocol().host().port()
    );

    let res = futures::join!(choreo_future, core_future);
    match res {
        (Ok(_), Err(e)) => {
            tracing::error!("gRPC error: {}", e);
            Err(Box::new(e))
        }
        (Err(e), Ok(_)) => {
            tracing::error!("gRPC error: {}", e);
            Err(Box::new(e))
        }
        (Err(e1), Err(e2)) => {
            tracing::error!("gRPC errors: {}, {}", e1, e2);
            Err(Box::new(e1))
        }
        _ => Ok(()),
    }
}

