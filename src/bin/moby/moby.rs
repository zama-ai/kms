use distributed_decryption::choreography::grpc::GrpcChoreography;
use distributed_decryption::conf::{party::PartyConf, Settings};
use distributed_decryption::execution::runtime::party::{Identity, RoleAssignment};
use distributed_decryption::networking::grpc::{GrpcNetworkingManager, GrpcServer};
use tonic::transport::Server;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt::Layer, EnvFilter};

fn init_tracer() {
    let fmt_layer = Some(Layer::default());
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(env_filter) // The tracing formatter defaults to the max log level set by RUST_LOG
        .with(fmt_layer)
        .try_init()
        .unwrap_or_else(|e| println!("Failed to initialize telemetry subscriber: {}", e));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting up moby...");
    let settings: PartyConf = Settings::builder().build().init_conf()?;
    init_tracer();
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

    let choreography = GrpcChoreography::new(
        own_identity,
        Box::new(move |session_id, roles| networking.new_session(session_id, roles)),
    )
    .into_server();

    let mut server = Server::builder().timeout(std::time::Duration::from_secs(60));
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter.set_serving::<GrpcServer>().await;

    let router = server
        .add_service(health_service)
        .add_service(networking_server)
        .add_service(choreography);

    let addr = format!("0.0.0.0:{}", settings.protocol().host().port()).parse()?;

    tracing::info!(
        "Sucessfully created moby server with party id {:?}.",
        settings.protocol().host()
    );

    let res = router.serve(addr).await;
    if let Err(e) = res {
        tracing::error!("gRPC error: {}", e);
    }
    Ok(())
}
