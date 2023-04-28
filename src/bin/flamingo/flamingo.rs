//! CLI tool for interacting with a group of flamins

use clap::Parser;
use distributed_decryption::choreography::grpc::ChoreoRuntime;
use distributed_decryption::choreography::parse_session_config_file_with_computation;
use distributed_decryption::computation::SessionId;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(name = "cometctl")]
#[clap(about = "A simple CLI tool for interacting with a Flamin cluster")]
pub struct Cli {
    /// Session config file to use
    session_config: PathBuf,

    #[clap(long)]
    /// Session id to use
    session_id: u128,

    #[clap(long)]
    /// Directory to read certificates from
    certs: Option<String>,

    #[clap(long)]
    /// Own identity; `certs` must be specified
    identity: Option<String>,
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let tls_config = None;

    let (role_assignments, computation, threshold) =
        parse_session_config_file_with_computation(&args.session_config)?;
    let runtime = ChoreoRuntime::new(role_assignments, tls_config)?;
    let session_id = SessionId::from(args.session_id);

    tracing::debug!("launching flamingo with: {:?}", &computation);

    runtime
        .launch_computation(&session_id, &computation, threshold)
        .await?;

    Ok(())
}
