//! CLI tool for interacting with a group of mobys
use std::collections::HashMap;
use std::time::Duration;

use clap::{Parser, Subcommand};
use distributed_decryption::choreography::grpc::FlamingoRuntime;
use distributed_decryption::circuit::Circuit;
use distributed_decryption::computation::SessionId;
use distributed_decryption::execution::player::Identity;
use distributed_decryption::execution::player::Role;
use distributed_decryption::execution::player::RoleAssignment;
use ndarray::Array1;
use ndarray_stats::QuantileExt;

#[derive(Parser, Debug)]
#[clap(name = "cometctl")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short)]
    n_parties: u64,

    #[structopt(env, long, default_value = "50000")]
    port: u16,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch computation on cluster (non-blocking)
    Launch {
        /// Circuit path to use
        #[clap(long)]
        circuit_path: String,

        #[clap(long)]
        /// Session id to use
        session_id: u128,

        #[clap(long, default_value_t = 1)]
        /// Session range to use
        session_range: u128,

        #[clap(long)]
        /// Directory to read certificates from
        certs: Option<String>,

        #[clap(long)]
        /// Own identity; `certs` must be specified
        identity: Option<String>,

        #[clap(short)]
        threshold: u8,

        #[clap(long, default_value_t = 1)]
        /// benchmark iterations
        iterations: u128,
    },
    /// Retrieve results of computation from cluster (blocking)
    Results {
        #[clap(long)]
        /// Session id to use
        session_id: u128,

        #[clap(long, default_value_t = 1)]
        session_range: u128,
    },
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

    match args.command {
        Commands::Launch {
            circuit_path,
            session_id,
            session_range,
            certs: _certs,
            identity: _identity,
            threshold,
            iterations,
        } => {
            let runtime = FlamingoRuntime::new(docker_role_assignments, tls_config)?;
            let threshold = threshold;
            let comp_bytes = std::fs::read(&circuit_path)?;
            let computation = Circuit::try_from(&comp_bytes[..]).unwrap();

            tracing::info!(
                "launching moby with: {:?} and {} iterations",
                &computation,
                iterations
            );

            // run iterations of benchmarks in a row
            for i in 0..session_range {
                let session_id = SessionId::from(session_id + i);
                runtime
                    .launch_computation(&session_id, &computation, threshold)
                    .await?;
            }
        }
        Commands::Results {
            session_id,
            session_range,
        } => {
            let runtime = FlamingoRuntime::new(docker_role_assignments, tls_config)?;
            // online times for each party for all iterations
            let mut all_online_times: HashMap<Role, Vec<Duration>> = HashMap::new();

            for i in 0..session_range {
                let session_id = SessionId::from(session_id + i);
                let results = runtime.retrieve_results(&session_id).await?;
                if let Some(elapsed_time) = results.elapsed_time {
                    for (role, duration) in elapsed_time {
                        all_online_times
                            .entry(role)
                            .or_insert_with(Vec::new)
                            .push(duration);
                    }
                }
            }

            for (role, p_online_times) in all_online_times {
                let micros = Array1::from_vec(
                    p_online_times
                        .iter()
                        .map(|x| x.as_micros() as f64)
                        .collect(),
                );
                tracing::info!(
                            "Party {role}: Online times of {} iterations in microseconds: Mean: {:.2} - Min: {:.2} -  Max: {:.2} -  StdDev: {:.2};",
                            session_range,
                            micros.mean().unwrap(),
                            micros.min()?,
                            micros.max()?,
                            micros.std(0.0),
                        );
            }
        }
    }

    Ok(())
}
