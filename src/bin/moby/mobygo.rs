//! CLI tool for interacting with a group of mobys
use std::collections::HashMap;

use clap::Parser;
use distributed_decryption::choreography::grpc::FlamingoRuntime;
use distributed_decryption::circuit::Circuit;
use distributed_decryption::computation::SessionId;
use distributed_decryption::execution::player::Identity;
use distributed_decryption::execution::player::Role;
use distributed_decryption::execution::player::RoleAssignment;
use ndarray::Array1;

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

    #[clap(long, default_value_t = 1)]
    /// benchmark iterations
    iterations: u128,
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

    tracing::info!(
        "launching moby with: {:?} and {} iterations",
        &computation,
        args.iterations
    );

    // online times for each party for all iterations
    let mut all_online_times: HashMap<Role, Vec<u32>> = HashMap::new();

    // run iterations of benchmarks in a row
    for i in 0..args.iterations {
        let session_id = SessionId::from(args.session_id + i);
        let timings = runtime
            .launch_computation(&session_id, &computation, threshold)
            .await?;

        tracing::debug!("Iteration {i}: All online times: {timings:?}");

        for (role, ot) in timings {
            all_online_times
                .entry(role)
                .or_insert_with(Vec::new)
                .push(ot);
        }
    }

    for (role, p_online_times) in all_online_times {
        let ndot = Array1::from_vec(p_online_times.iter().map(|x| *x as f64).collect());
        tracing::info!(
                            "Party {role}: Online times of {} iterations in microseconds: Mean: {:.2} - Median: {:.2} -  Min: {:.2} -  Max: {:.2} -  StdDev: {:.2};",
                            args.iterations,
                            ndot.mean().unwrap(),
                            p_online_times[p_online_times.len()/2],
                            p_online_times.iter().min().unwrap(),
                            p_online_times.iter().max().unwrap(),
                            ndot.std(0.0),
                        );
    }

    Ok(())
}
