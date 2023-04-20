//! CLI tool for interacting with a group of mobys
use clap::Parser;
use distributed_decryption::choreography::grpc::FlamingoRuntime;
use distributed_decryption::circuit::Circuit;
use distributed_decryption::computation::SessionId;
use distributed_decryption::execution::player::Identity;
use distributed_decryption::execution::player::Role;
use distributed_decryption::execution::player::RoleAssignment;

#[derive(Parser, Debug)]
#[clap(name = "cometctl")]
#[clap(about = "A simple CLI tool for interacting with a Flamin cluster")]
pub struct Cli {
    /// Circuit path to use
    #[clap(long)]
    circuit_path: String,

    #[clap(long)]
    /// Session id to use
    session_id: u128,

    #[clap(long)]
    /// Directory to read certificates from
    certs: Option<String>,

    #[clap(long)]
    /// Own identity; `certs` must be specified
    identity: Option<String>,

    #[clap(short)]
    n_parties: u64,

    #[clap(short)]
    threshold: u8,

    #[structopt(env, long, default_value = "50000")]
    port: u16,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let tls_config = None;
    let port = args.port;

    let docker_role_assignments: RoleAssignment = (1..args.n_parties + 1)
        .map(|party_id| {
            let role = Role::from(party_id);
            let identity = Identity::from(&format!("p{party_id}:{port}"));
            (role, identity)
        })
        .collect();

    let threshold = args.threshold;
    let comp_bytes = std::fs::read(&args.circuit_path)?;
    let computation = Circuit::try_from(&comp_bytes[..]).unwrap();

    let runtime = FlamingoRuntime::new(docker_role_assignments, tls_config)?;
    let session_id = SessionId::from(args.session_id);

    tracing::debug!("launching moby with: {:?}", &computation);

    runtime
        .launch_computation(&session_id, &computation, threshold)
        .await?;

    Ok(())
}
