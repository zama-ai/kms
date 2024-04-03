use crate::choreography::grpc::GrpcChoreography;
use crate::conf::party::PartyConf;
use crate::conf::telemetry::{accept_trace, make_span};
use crate::execution::online::preprocessing::{create_memory_factory, create_redis_factory};
use crate::execution::runtime::party::{Identity, RoleAssignment};
use crate::networking::constants::NETWORK_TIMEOUT_LONG;
use crate::networking::grpc::{GrpcNetworkingManager, GrpcServer};
use tonic::transport::Server;
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

    let networking = GrpcNetworkingManager::without_tls(own_identity.clone());
    let networking_server = networking.new_server();

    let factory = match &settings.redis {
        None => create_memory_factory(),
        Some(conf) => create_redis_factory(format!("{own_identity}"), conf),
    };

    let choreography = GrpcChoreography::new(
        own_identity,
        Box::new(move |session_id, roles| networking.new_session(session_id, roles)),
        factory,
    )
    .into_server();

    let server = Server::builder().timeout(*NETWORK_TIMEOUT_LONG);
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<GrpcServer>().await;

    let grpc_layer = tower::ServiceBuilder::new()
        .timeout(*NETWORK_TIMEOUT_LONG)
        .layer(TraceLayer::new_for_grpc().make_span_with(make_span))
        .map_request(accept_trace);

    let router = server
        .layer(grpc_layer)
        .add_service(health_service)
        .add_service(networking_server)
        .add_service(choreography);

    tracing::info!(
        "Sucessfully created moby server with party id {:?}.",
        settings.protocol().host()
    );

    let addr = format!("0.0.0.0:{}", settings.protocol().host().port()).parse()?;
    let res = router.serve(addr).await;
    if let Err(e) = res {
        tracing::error!("gRPC error: {}", e);
    }
    Ok(())
}
