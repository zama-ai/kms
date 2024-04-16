use crate::choreography::grpc::GrpcChoreography;
use crate::conf::party::PartyConf;
use crate::conf::telemetry::{accept_trace, make_span};
use crate::execution::online::preprocessing::{create_memory_factory, create_redis_factory};
use crate::execution::runtime::party::{Identity, RoleAssignment};
use crate::networking::constants::NETWORK_TIMEOUT_LONG;
use crate::networking::grpc::{GrpcNetworkingManager, GrpcServer};
use tonic::transport::{Server, ServerTlsConfig};
use tower_http::trace::TraceLayer;

pub async fn run(settings: &PartyConf) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: This part is under discussion. We need to figure out how to handle the networking topology configuration
    // For the moment we are using a provided configuration on `threshold_decrypt` gRPC endpoint,
    // but it is not discarded to use a more dynamic approach.
    let _docker_static_endpoints: RoleAssignment = settings
        .protocol()
        .peers()
        .as_ref()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|peer| (peer.into(), peer.into()))
        .collect();

    let own_identity: Identity = settings.protocol().host().into();

    // the networking manager is shared between the two services
    let networking = GrpcNetworkingManager::new(own_identity.clone(), settings.certpaths.clone());
    let networking_server = networking.new_server();

    let factory = match &settings.redis {
        None => create_memory_factory(),
        Some(conf) => create_redis_factory(format!("{own_identity}"), conf),
    };

    let choreography = GrpcChoreography::new(
        own_identity,
        Box::new(move |session_id, roles| networking.make_session(session_id, roles)),
        factory,
    )
    .into_server();

    // create a server that uses TLS
    // if [try_use_tls] is true and settings.certpaths is not None
    let make_server = move |try_use_tls: bool| -> anyhow::Result<Server> {
        let server = match (try_use_tls, &settings.certpaths) {
            (true, Some(cert_bundle)) => {
                let identity = cert_bundle.get_identity()?;
                let ca_cert = cert_bundle.get_flattened_ca_list()?;
                let tls_config = ServerTlsConfig::new()
                    .identity(identity)
                    .client_ca_root(ca_cert);
                Server::builder()
                    .tls_config(tls_config)?
                    .timeout(*NETWORK_TIMEOUT_LONG)
            }
            (_, _) => Server::builder().timeout(*NETWORK_TIMEOUT_LONG),
        };
        Ok(server)
    };

    // CHOREO
    // create a future for the choreography server
    let (mut choreo_health_reporter, choreo_health_service) =
        tonic_health::server::health_reporter();
    choreo_health_reporter.set_serving::<GrpcServer>().await;

    let choreo_grpc_layer = tower::ServiceBuilder::new()
        .timeout(*NETWORK_TIMEOUT_LONG)
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace);

    let choreo_router = make_server(settings.choreo_use_tls)?
        .layer(choreo_grpc_layer)
        .add_service(choreo_health_service)
        .add_service(choreography);

    tracing::info!(
        "Sucessfully created choreo server with party id {:?} on port {:?}.",
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
    let (mut core_health_reporter, core_health_service) = tonic_health::server::health_reporter();
    core_health_reporter.set_serving::<GrpcServer>().await;

    let core_grpc_layer = tower::ServiceBuilder::new()
        .timeout(*NETWORK_TIMEOUT_LONG)
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace);

    let core_router = make_server(true)?
        .layer(core_grpc_layer)
        .add_service(core_health_service)
        .add_service(networking_server);

    let core_future =
        core_router.serve(format!("0.0.0.0:{}", settings.protocol().host().port()).parse()?);

    tracing::info!(
        "Sucessfully created core server with party id {:?} on port {:?}.",
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
