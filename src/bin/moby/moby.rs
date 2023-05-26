use clap::Parser;
use distributed_decryption::choreography::grpc::GrpcChoreography;
use distributed_decryption::execution::player::Identity;
use distributed_decryption::execution::player::{Role, RoleAssignment};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use tonic::transport::Server;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser, Clone)]
pub struct Opt {
    #[structopt(short)]
    player_no: u64,

    #[structopt(env, long, default_value = "./examples")]
    /// Directory to read sessions from
    sessions: String,

    #[structopt(env, short, default_value = "10")]
    n_parties: u64,
}

fn init_tracer() {
    let fmt_layer = Some(tracing_subscriber::fmt::Layer::default());
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env()) // The tracing formatter defaults to the max log level set by RUST_LOG
        .with(fmt_layer)
        .try_init()
        .unwrap_or_else(|e| println!("Failed to initialize telemetry subscriber: {}", e));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracer();
    tracing::info!("starting up moby");
    let opt = Opt::parse();
    let port = 50000;

    let docker_static_endpoints: RoleAssignment = (1..opt.n_parties + 1)
        .map(|party_id| {
            let role = Role::from(party_id);
            let identity = Identity::from(&format!("p{party_id}:{port}"));
            (role, identity)
        })
        .collect();

    let own_identity = docker_static_endpoints
        .get(&Role::from(opt.player_no))
        .unwrap()
        .clone();

    let networking = GrpcNetworkingManager::without_tls(own_identity.clone());
    let networking_server = networking.new_server();

    let choreography = GrpcChoreography::new(
        own_identity,
        Box::new(move |session_id, roles| networking.new_session(session_id, roles)),
    );

    let mut server = Server::builder();

    let router = server
        .add_service(networking_server)
        .add_service(choreography.into_server());

    let addr = format!("0.0.0.0:{}", &port).parse()?;

    tracing::info!("created moby server...");

    let res = router.serve(addr).await;
    if let Err(e) = res {
        tracing::error!("gRPC error: {}", e);
    }
    Ok(())
}
