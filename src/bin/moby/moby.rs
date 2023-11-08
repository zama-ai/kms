use clap::Parser;
use distributed_decryption::choreography::grpc::GrpcChoreography;
use distributed_decryption::execution::party::Identity;
use distributed_decryption::execution::party::{Role, RoleAssignment};
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use tonic::transport::Server;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser, Clone)]
pub struct Opt {
    #[structopt(short)]
    /// Party ID (1...=n)
    party_id: usize,

    #[structopt(env, long, default_value = "50000")]
    /// Port to use for gRPC server, Moby in docker uses 50000 as dafault and is mapped via docker compose
    port: u16,

    #[structopt(env, short, default_value = "10")]
    /// Total number of parties in the moby cluster
    n_parties: usize,
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
    tracing::info!("Starting up moby...");
    let opt = Opt::parse();

    let docker_static_endpoints: RoleAssignment = (1..=opt.n_parties)
        .map(|party_id| {
            let role = Role::indexed_by_one(party_id);
            let identity = Identity::from(&format!("p{party_id}:{}", opt.port));
            (role, identity)
        })
        .collect();

    let own_identity = docker_static_endpoints
        .get(&Role::indexed_by_one(opt.party_id))
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

    let addr = format!("0.0.0.0:{}", &opt.port).parse()?;

    tracing::info!(
        "Sucessfully created moby server with party id {}.",
        opt.party_id
    );

    let res = router.serve(addr).await;
    if let Err(e) = res {
        tracing::error!("gRPC error: {}", e);
    }
    Ok(())
}
