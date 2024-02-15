//! CLI tool for interacting with a group of mobys
use clap::{Parser, Subcommand};
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    computation::SessionId,
    conf::{choreo::ChoreoConf, Settings},
    error::error_handler::anyhow_error_and_log,
    execution::runtime::party::RoleAssignment,
    file_handling::{self, read_as_json},
    lwe::{PublicKey, ThresholdLWEParameters},
};
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use prettytable::{Attr, Cell, Row, Table};
use rand::{distributions::Uniform, rngs::ThreadRng, Rng};
use std::sync::Arc;
use tokio::task::JoinSet;

#[derive(Parser, Debug)]
#[clap(name = "mobygo")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short, long, default_value = "config/mobygo.toml")]
    conf_file: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decrypt on cluster of mobys (non-blocking)
    Decrypt,

    /// Initialize the moby workers with a key share and a PRSS setup
    Init,
    /// Retrieve one or many results of computation from cluster of mobys
    Results,
}

async fn init_command(
    runtime: &ChoreoRuntime,
    init_opts: &ChoreoConf,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_params: ThresholdLWEParameters = read_as_json(init_opts.params_file.to_owned())?;

    // keys can be set once per epoch (currently stored in a SessionID)
    // TODO so far we only use the default parameters
    let pk = runtime
        .initiate_keygen(
            &SessionId::from(init_opts.epoch()),
            init_opts.threshold_topology.threshold,
            default_params,
            init_opts.setup_mode.clone(),
        )
        .await?;

    tracing::info!("Public key received");

    // write received pk to file
    let serialized_pk = bincode::serialize(&pk)?;
    std::fs::write(init_opts.pub_key_file(), serialized_pk)?;
    Ok(())
}

async fn decrypt_command(
    runtime: ChoreoRuntime,
    decrypt_opts: &ChoreoConf,
    rng: &mut ThreadRng,
) -> Result<Vec<SessionId>, Box<dyn std::error::Error>> {
    let possible_messages = Uniform::from(0..=255);
    let number_messages = decrypt_opts.number_messages.unwrap_or_else(|| {
        let mut rng_msg = rand::thread_rng();
        rng_msg.gen_range(4..100)
    });
    let messages = rand::thread_rng()
        .sample_iter(possible_messages)
        .take(number_messages)
        .collect::<Vec<u8>>();

    tracing::info!(
        "Launching mobygo decryption: parties: {}, threshold: {}, messages: {}",
        decrypt_opts.threshold_topology.peers.len(),
        decrypt_opts.threshold_topology.threshold,
        number_messages
    );

    // read pk from file (Init must have been called before)
    let pk_serialized = std::fs::read(decrypt_opts.pub_key_file())?;
    let pk: PublicKey = bincode::deserialize(&pk_serialized)?;

    let cyphers = messages
        .iter()
        .map(|m| pk.encrypt(rng, *m as u64))
        .collect::<Vec<_>>();

    let mut join_set = JoinSet::new();

    let rt = Arc::new(runtime);
    let mode = Arc::new(decrypt_opts.decrypt_mode.clone());
    cyphers.into_iter().for_each(|ct| {
        let rt = rt.clone();
        let mode = mode.clone();
        let threshold = decrypt_opts.threshold_topology.threshold;
        join_set.spawn(async move {
            rt.initiate_threshold_decryption(&mode, threshold, ct.as_ref())
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

    let mut rng = rand::thread_rng();
    let tls_config = None;
    let conf: ChoreoConf = Settings::builder()
        .path(&args.conf_file)
        .build()
        .init_conf()?;

    let topology = &conf.threshold_topology;

    let docker_role_assignments: RoleAssignment = topology.into();

    let host_channels = topology.try_into()?;

    let runtime =
        ChoreoRuntime::new_with_net_topology(docker_role_assignments, tls_config, host_channels)?;
    match args.command {
        Commands::Init => {
            init_command(&runtime, &conf).await?;
        }
        Commands::Decrypt => {
            let session_ids = decrypt_command(runtime, &conf, &mut rng).await?;
            tracing::info!(
                "Storing session ids: {:?} - into {:?}",
                session_ids,
                conf.session_file_path()
            );
            file_handling::write_element(conf.session_file_path(), &session_ids)?;
            tracing::info!("Session ids stored in {:?}.", conf.session_file_path());
        }
        Commands::Results => {
            results_command(&runtime, conf.session_file_path()).await?;
        }
    };

    Ok(())
}
