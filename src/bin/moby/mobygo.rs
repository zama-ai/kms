//! CLI tool for interacting with a group of mobys
use aes_prng::AesRng;
use clap::{Parser, Subcommand};
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        runtime::party::{Identity, Role, RoleAssignment},
        runtime::session::{DecryptionMode, SetupMode},
    },
    file_handling::{self, read_as_json},
    lwe::{PublicKey, ThresholdLWEParameters},
};
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use prettytable::{Attr, Cell, Row, Table};
use rand::{distributions::Uniform, Rng, SeedableRng};
use std::{collections::HashMap, sync::Arc};
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
#[clap(name = "mobygo")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short)]
    n_parties: usize,

    #[structopt(env, long, default_value_t = 50000)]
    port: u16,

    #[structopt(env, long)]
    /// Number of messages to test
    number_messages: Option<usize>,

    #[clap(long, default_value = "temp/sessions.bin")]
    session_store: String,
}

#[derive(Parser, Debug)]
pub struct DecryptOptions {
    #[clap(short, long)]
    /// Threshold (max. number of dishonest parties)
    threshold: u8,

    #[clap(short, long, default_value_t = 2)]
    /// decryption protocol: 1: PRSS, 2: Proto2
    protocol: u8,

    #[clap(long, default_value = "pk.bin")]
    /// Filename of the public key
    pubkey: String,
}

#[derive(Parser, Debug)]
pub struct InitOptions {
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

    #[clap(long, default_value = "temp/test_params.json")]
    /// Filename of the LWE parameters
    lwe_params_file: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decrypt on cluster of mobys (non-blocking)
    Decrypt(DecryptOptions),

    /// Initialize the moby workers with a key share and a PRSS setup
    Init(InitOptions),
    /// Retrieve one or many results of computation from cluster of mobys
    Results,
}

async fn init_command(
    runtime: &ChoreoRuntime,
    init_opts: InitOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let setup_mode = match init_opts.protocol {
        1 => Ok(SetupMode::AllProtos),
        2 => Ok(SetupMode::NoPrss),
        _ => Err(anyhow_error_and_log("Invalid SetupMode".to_string())),
    }?;

    let default_params: ThresholdLWEParameters = read_as_json(init_opts.lwe_params_file)?;

    // keys can be set once per epoch (currently stored in a SessionID)
    // TODO so far we only use the default parameters
    let pk = runtime
        .initiate_keygen(
            &SessionId::from(init_opts.epoch),
            init_opts.threshold,
            default_params,
            setup_mode,
        )
        .await?;

    tracing::info!("Public key received");

    // write received pk to file
    let serialized_pk = bincode::serialize(&pk)?;
    std::fs::write(&init_opts.pubkey, serialized_pk)?;
    Ok(())
}

async fn decrypt_command(
    runtime: ChoreoRuntime,
    decrypt_opts: DecryptOptions,
    parties: usize,
    rng: &mut AesRng,
    number_messages: Option<usize>,
) -> Result<Vec<SessionId>, Box<dyn std::error::Error>> {
    let possible_messages = Uniform::from(0..=255);
    let number_messages = number_messages.unwrap_or_else(|| {
        let mut rng_msg = rand::thread_rng();
        rng_msg.gen_range(4..100)
    });
    let messages = rand::thread_rng()
        .sample_iter(possible_messages)
        .take(number_messages)
        .collect::<Vec<u8>>();

    tracing::info!(
        "Launching mobygo decryption: parties: {}, threshold: {}, messages: {}",
        parties,
        decrypt_opts.threshold,
        number_messages
    );

    // read pk from file (Init must have been called before)
    let pk_serialized = std::fs::read(decrypt_opts.pubkey.as_str())?;
    let pk: PublicKey = bincode::deserialize(&pk_serialized)?;

    let cyphers = messages
        .iter()
        .map(|m| pk.encrypt(rng, *m as u64))
        .collect::<Vec<_>>();

    let mode = match decrypt_opts.protocol {
        1 => Ok(DecryptionMode::PRSSDecrypt),
        2 => Ok(DecryptionMode::LargeDecrypt),
        _ => Err(anyhow_error_and_log(
            "Decryption mode not supported!".to_string(),
        )),
    }?;

    let mut join_set = JoinSet::new();

    let rt = Arc::new(runtime);
    let mode = Arc::new(mode);
    cyphers.into_iter().for_each(|ct| {
        let rt = rt.clone();
        let mode = mode.clone();
        join_set.spawn(async move {
            rt.initiate_threshold_decryption(&mode, decrypt_opts.threshold, ct.as_ref())
                .await
        });
    });
    tracing::info!("Collecting all sessions ids");
    let mut vec = Vec::new();
    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(session_id) => match session_id {
                Ok(session_id) => {
                    vec.push(session_id);
                }
                Err(e) => {
                    tracing::error!("Error during session id retrieval: {}", e);
                    return Err(e.into());
                }
            },
            Err(e) => {
                tracing::error!("Error during decryption: {}", e);
                return Err(e.into());
            }
        }
    }

    if vec.len() != number_messages {
        anyhow_error_and_log(format!(
            "Number of results ({}) does not match number of messages ({})",
            vec.len(),
            number_messages
        ));
    }

    Ok(vec)
}

async fn results_command(
    runtime: &ChoreoRuntime,
    session_store: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let sessions: Vec<SessionId> = file_handling::read_element(session_store)?;

    let mut table = Table::new();
    table.add_row(Row::new(vec![
        Cell::new("Session Id").with_style(Attr::Bold),
        Cell::new("Results").with_style(Attr::Bold),
    ]));
    for session_id in &sessions {
        collect_results(runtime, &mut table, session_id).await?;
    }
    table.printstd();

    Ok(())
}

async fn collect_results(
    runtime: &ChoreoRuntime,
    table: &mut Table,
    session_id: &SessionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let results = runtime.initiate_retrieve_results(session_id, 1).await?;

    // collect results as microseconds for precision and convert to milliseconds for readability
    if let Some(elapsed_times) = results.elapsed_times {
        let mut table_party = Table::new();
        table_party.add_row(Row::new(vec![
            Cell::new("Party").with_style(Attr::Bold),
            Cell::new("Mean").with_style(Attr::Bold),
            Cell::new("Median").with_style(Attr::Bold),
            Cell::new("Min").with_style(Attr::Bold),
            Cell::new("Max").with_style(Attr::Bold),
            Cell::new("StdDev").with_style(Attr::Bold),
        ]));
        for (role, p_online_times) in elapsed_times {
            let micros = Array1::from_vec(
                p_online_times
                    .iter()
                    .map(|x| x.as_micros() as f64 / 1000.0)
                    .collect(),
            );

            table_party.add_row(Row::new(vec![
                Cell::new(&format!("{}", role)),
                Cell::new(&format!("{:.2}ms", micros.mean().unwrap())),
                Cell::new(&format!(
                    "{:.2}ms",
                    *micros
                        .mapv(|x| (x * 1000.0) as u128)
                        .quantile_axis_mut(
                            ndarray::Axis(0),
                            noisy_float::types::n64(0.5),
                            &ndarray_stats::interpolate::Midpoint,
                        )?
                        .first()
                        .unwrap() as f64
                        / 1000.0
                )),
                Cell::new(&format!("{:.2}ms", micros.min()?)),
                Cell::new(&format!("{:.2}ms", micros.max()?)),
                Cell::new(&format!("{:.2}ms", micros.std(0.0))),
            ]));
        }
        table.add_row(Row::new(vec![
            Cell::new(&format!("{:1x}", session_id.0)),
            Cell::new(&format!("{}", table_party)),
        ]));
    } else {
        tracing::error!(
            "No elapsed times received for session id {:#1x}",
            session_id.0
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();
    tracing_subscriber::fmt::init();

    let mut rng = AesRng::from_entropy();
    let tls_config = None;
    let port = args.port;
    let number_messages = args.number_messages;

    let docker_role_assignments: RoleAssignment = (1..=args.n_parties)
        .map(|party_id| {
            let role = Role::indexed_by_one(party_id);
            let identity = Identity::from(&format!("p{party_id}:{port}"));
            (role, identity)
        })
        .collect();

    let host_assignments: HashMap<Role, String> = (1..=args.n_parties)
        .map(|party_id| {
            let role = Role::indexed_by_one(party_id);
            (role, format!("localhost:{}", port + party_id as u16))
        })
        .collect();

    let runtime =
        ChoreoRuntime::new_with_hosts(docker_role_assignments, tls_config, host_assignments)?;

    match args.command {
        Commands::Init(init_opts) => {
            init_command(&runtime, init_opts).await?;
        }
        Commands::Decrypt(decrypt_opts) => {
            let session_ids = decrypt_command(
                runtime,
                decrypt_opts,
                args.n_parties,
                &mut rng,
                number_messages,
            )
            .await?;
            tracing::info!(
                "Storing session ids: {:?} - into {:?}",
                session_ids,
                args.session_store
            );
            file_handling::write_element(args.session_store.to_string(), &session_ids)?;
            tracing::info!("Session ids stored in {:?}.", args.session_store);
        }
        Commands::Results => {
            results_command(&runtime, args.session_store).await?;
        }
    };

    Ok(())
}
