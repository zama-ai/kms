//! CLI tool for interacting with a group of mobys
use clap::{Parser, Subcommand};
use distributed_decryption::choreography::grpc::ChoreoRuntime;
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
        session_range: u32,
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
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;
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
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;

            let session_id = SessionId::from(session_id);
            let results = runtime.retrieve_results(&session_id, session_range).await?;

            // collect results as microseconds and convert to milliseconds
            if let Some(elapsed_times) = results.elapsed_times {
                for (role, p_online_times) in elapsed_times {
                    let micros = Array1::from_vec(
                        p_online_times
                            .iter()
                            .map(|x| x.as_micros() as f64 / 1000.0)
                            .collect(),
                    );

                    // print results als milliseconds
                    tracing::info!(
                            "Party {role}: Online times of {} iterations in milliseconds: Mean: {:.2} - Median {:.2} - Min: {:.2} - Max: {:.2} - StdDev: {:.2};",
                            session_range,
                            micros.mean().unwrap(),
                            *micros.mapv(|x| (x * 1000.0) as u128).quantile_axis_mut(
                                ndarray::Axis(0),
                                noisy_float::types::n64(0.5),
                                &ndarray_stats::interpolate::Midpoint,
                            )?.first().unwrap() as f64 / 1000.0,
                            micros.min()?,
                            micros.max()?,
                            micros.std(0.0),
                        );
                }
            }
        }
    }

    Ok(())
}
