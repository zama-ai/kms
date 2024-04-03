use clap::Parser;
use distributed_decryption::choreography::grpc::GrpcChoreography;
use distributed_decryption::execution::online::preprocessing::create_memory_factory;
use distributed_decryption::execution::runtime::party::Identity;
use distributed_decryption::networking::grpc::GrpcNetworkingManager;
use tonic::transport::Server;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser, Clone)]
pub struct Opt {
    #[structopt(long)]
    identity: String,

    #[structopt(env, long, default_value = "50000")]
    /// Port to use for gRPC server
    port: u16,
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
    tracing::info!("flamin starting up");
    let opt = Opt::parse();

    let own_identity = Identity::from(opt.identity);

    let networking = GrpcNetworkingManager::without_tls(own_identity.clone());

    let networking_server = networking.new_server();
    let choreography = GrpcChoreography::new(
        own_identity,
        Box::new(move |session_id, roles| networking.new_session(session_id, roles)),
        create_memory_factory(),
    );

    let mut server = Server::builder();

    let router = server
        .add_service(networking_server)
        .add_service(choreography.into_server());

    let addr = format!("0.0.0.0:{}", &opt.port).parse()?;

    tracing::info!("created flamin server...");

    let res = router.serve(addr).await;
    if let Err(e) = res {
        tracing::error!("gRPC error: {}", e);
    }
    Ok(())
}
