//! CLI tool for interacting with a group of mobys
use aes_prng::AesRng;
use clap::{Parser, Subcommand};
use distributed_decryption::circuit::Circuit;
use distributed_decryption::computation::SessionId;
use distributed_decryption::error::error_handler::anyhow_error_and_log;
use distributed_decryption::execution::party::Identity;
use distributed_decryption::execution::party::Role;
use distributed_decryption::execution::party::RoleAssignment;
use distributed_decryption::file_handling::read_as_json;
use distributed_decryption::lwe::PublicKey;
use distributed_decryption::lwe::ThresholdLWEParameters;
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    execution::session::{DecryptionMode, SetupMode},
};
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use rand::SeedableRng;

#[derive(Parser, Debug)]
#[clap(name = "mobygo")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short)]
    n_parties: u64,

    #[structopt(env, long, default_value_t = 50000)]
    port: u16,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch circuit computation on cluster of mobys (non-blocking)
    Launch {
        /// Circuit path to use
        #[clap(long)]
        circuit_path: String,

        #[clap(long, default_value_t = 1)]
        /// Session range to use
        session_range: u32,

        #[clap(short)]
        /// Threshold (max. number of dishonest parties)
        threshold: u8,

        #[clap(short, default_value_t = 1)]
        /// Message to encrypt
        message: u8,

        #[clap(long, default_value = "pk.bin")]
        /// Filename of the public key
        pubkey: String,
    },
    /// Decrypt on cluster of mobys (non-blocking)
    Decrypt {
        #[clap(short, long)]
        /// Threshold (max. number of dishonest parties)
        threshold: u8,

        #[clap(short, long, default_value_t = 2)]
        /// decryption protocol: 1: PRSS, 2: Proto2
        protocol: u8,

        #[clap(long, default_value = "pk.bin")]
        /// Filename of the public key
        pubkey: String,
    },
    /// Initialize the moby workers with a key share and a PRSS setup
    Init {
        #[clap(long, default_value_t = 1)]
        /// Key epoch id to use
        epoch: u128,

        #[clap(long)]
        /// Directory to read certificates from
        certs: Option<String>,

        #[clap(long)]
        /// Own identity; `certs` must be specified
        identity: Option<String>,

        #[clap(short, long)]
        /// Threshold (max. number of dishonest parties)
        threshold: u8,

        #[clap(long, default_value = "pk.bin")]
        /// Filename of the public key
        pubkey: String,

        #[clap(short, long, default_value_t = 1)]
        /// Initialize decryption protocols: 1: All Protocols, 2: Only Proto2, No PRSS
        protocol: u8,
    },
    /// Retrieve one or many results of computation from cluster of mobys
    Results {
        #[clap(long)]
        /// (Initial) Session id to query
        session_id: u128,

        #[clap(long, default_value_t = 1)]
        /// Number of consecutive session results to query
        session_range: u32,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let mut rng = AesRng::seed_from_u64(0);
    let tls_config = None;
    let port = args.port;

    let docker_role_assignments: RoleAssignment = (1..=args.n_parties)
        .map(|party_id| {
            let role = Role::from(party_id);
            let identity = Identity::from(&format!("p{party_id}:{port}"));
            (role, identity)
        })
        .collect();

    match args.command {
        Commands::Launch {
            circuit_path,
            session_range,
            threshold,
            message,
            pubkey,
        } => {
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;
            let comp_bytes = std::fs::read(&circuit_path)?;
            let computation = Circuit::try_from(&comp_bytes[..]).unwrap();

            tracing::info!(
                "Launching mobygo: computation: {:?}, iterations: {}, parties: {}, threshold: {}",
                &computation,
                session_range,
                args.n_parties,
                threshold,
            );

            // read pk from file (Init must have been called before)
            let pk_serialized = std::fs::read(pubkey.as_str())?;
            let pk: PublicKey = bincode::deserialize(&pk_serialized)?;

            let ct = pk.encrypt(&mut rng, message);

            // run multiple iterations of benchmarks in a row
            for _i in 0..session_range {
                if let Ok(sid) = runtime
                    .initiate_launch_computation_debug(&computation, threshold, &ct)
                    .await
                {
                    tracing::info!("Session id: {:?}", sid);
                }
            }
        }
        Commands::Init {
            epoch,
            certs: _certs,
            identity: _identity,
            threshold,
            pubkey,
            protocol,
        } => {
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;

            let setup_mode = match protocol {
                1 => Ok(SetupMode::AllProtos),
                2 => Ok(SetupMode::NoPrss),
                _ => Err(anyhow_error_and_log("Invalid SetupMode".to_string())),
            }?;

            let default_params: ThresholdLWEParameters =
                read_as_json("temp/default_params.json".to_string())?;

            // keys can be set once per epoch (currently stored in a SessionID)
            // TODO so far we only use the default parameters
            let pk = runtime
                .initiate_keygen(
                    &SessionId::from(epoch),
                    threshold,
                    default_params,
                    setup_mode,
                )
                .await?;

            // write received pk to file
            let serialized_pk = bincode::serialize(&pk)?;
            std::fs::write(pubkey.as_str(), serialized_pk)?;
        }
        Commands::Decrypt {
            threshold,
            protocol,
            pubkey,
        } => {
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;

            tracing::info!(
                "Launching mobygo decryption: parties: {}, threshold: {}",
                args.n_parties,
                threshold,
            );

            let message: u8 = 5;

            // read pk from file (Init must have been called before)
            let pk_serialized = std::fs::read(pubkey.as_str())?;
            let pk: PublicKey = bincode::deserialize(&pk_serialized)?;

            let ct = pk.encrypt(&mut rng, message);

            let mode = match protocol {
                1 => Ok(DecryptionMode::PRSSDecrypt),
                2 => Ok(DecryptionMode::Proto2Decrypt),
                _ => Err(anyhow_error_and_log(
                    "Decryption mode not supported!".to_string(),
                )),
            }?;

            let session_id = runtime
                .initiate_threshold_decryption(&mode, threshold, &ct)
                .await?;

            tracing::info!("Session id: {:?}", session_id);
        }
        Commands::Results {
            session_id,
            session_range,
        } => {
            let runtime = ChoreoRuntime::new(docker_role_assignments, tls_config)?;

            let session_id_obj = SessionId::from(session_id);
            let results = runtime
                .initiate_retrieve_results(&session_id_obj, session_range)
                .await?;

            // collect results as microseconds for precision and convert to milliseconds for readability
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
                            "Party {role}: Online times of {} iterations in milliseconds: Mean: {:.2} - Median: {:.2} - Min: {:.2} - Max: {:.2} - StdDev: {:.2};",
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

            tracing::info!("Decryption Results: {:?}", results.outputs);
        }
    };

    Ok(())
}
