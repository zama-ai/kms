use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{Derive, ErrorCorrect, Invert, Solve, Syndrome};
#[cfg(not(feature = "experimental"))]
use crate::choreography::grpc::GrpcChoreography;
use crate::conf::party::PartyConf;
use crate::execution::online::preprocessing::{create_memory_factory, create_redis_factory};
use crate::execution::runtime::party::{Role, RoleAssignment};
#[cfg(feature = "experimental")]
use crate::experimental::choreography::grpc::ExperimentalGrpcChoreography;
#[cfg(not(feature = "experimental"))]
use crate::malicious_execution::malicious_moby::add_strategy_to_router;
use crate::networking::constants::NETWORK_TIMEOUT_LONG;
use crate::networking::grpc::{GrpcNetworkingManager, GrpcServer};
use observability::telemetry::make_span;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::{Server, ServerTlsConfig};
use tower_http::trace::TraceLayer;

pub async fn run<const EXTENSION_DEGREE: usize>(
    settings: &PartyConf,
) -> Result<(), Box<dyn std::error::Error>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
    ResiduePoly<Z128, EXTENSION_DEGREE>: Syndrome + ErrorCorrect + Invert + Solve + Derive,
{
    // TODO: This part is under discussion. We need to figure out how to handle the networking topology configuration
    // For the moment we are using a provided configuration on `threshold_decrypt` gRPC endpoint,
    // but it is not discarded to use a more dynamic approach.
    let docker_static_endpoints: RoleAssignment = settings
        .protocol()
        .peers()
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|peer| (peer.into(), peer.into()))
        .collect();

    let my_role: Role = settings.protocol().host().into();

    let tls_conf = settings
        .certpaths
        .as_ref()
        .map(|certpaths| certpaths.get_client_tls_conf())
        .transpose()?;

    // the networking manager is shared between the two services
    let networking = Arc::new(GrpcNetworkingManager::new(
        my_role,
        tls_conf,
        settings.net_conf,
        false,
        Arc::new(RwLock::new(docker_static_endpoints)),
    )?);
    let networking_server = networking.new_server();

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
                    .timeout(*NETWORK_TIMEOUT_LONG)
            }
            (_, _) => {
                tracing::warn!("attempting to build an insecure kms-core server");
                Server::builder().timeout(*NETWORK_TIMEOUT_LONG)
            }
        };
        Ok(server)
    };

    // CHOREO
    // create a future for the choreography server
    let (choreo_health_reporter, choreo_health_service) = tonic_health::server::health_reporter();
    choreo_health_reporter.set_serving::<GrpcServer>().await;

    let choreo_grpc_layer = tower::ServiceBuilder::new()
        .timeout(*NETWORK_TIMEOUT_LONG)
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span));

    let choreo_router = make_server(false)?
        .layer(choreo_grpc_layer)
        .add_service(choreo_health_service);

    #[cfg(not(feature = "experimental"))]
    let choreo_router = add_strategy_to_router(choreo_router, my_role, networking.clone(), factory);

    #[cfg(feature = "experimental")]
    let choreo_router = {
        let choreography =
            ExperimentalGrpcChoreography::new(my_role, networking.clone(), factory).into_server();
        choreo_router.add_service(choreography)
    };

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
    let core_grpc_layer = tower::ServiceBuilder::new().timeout(*NETWORK_TIMEOUT_LONG);

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

#[cfg(not(feature = "experimental"))]
pub type SecureGrpcChoreography<const EXTENSION_DEGREE: usize> = GrpcChoreography<
    EXTENSION_DEGREE,
    crate::execution::small_execution::prss::RobustSecurePrssInit,
    crate::execution::small_execution::offline::SecureSmallPreprocessing,
    crate::execution::large_execution::offline::SecureLargePreprocessing<
        ResiduePoly<Z64, EXTENSION_DEGREE>,
    >,
    crate::execution::large_execution::offline::SecureLargePreprocessing<
        ResiduePoly<Z128, EXTENSION_DEGREE>,
    >,
>;
