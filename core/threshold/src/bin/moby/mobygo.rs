//! CLI tool for interacting with a group of mobys
use anyhow::anyhow;
use clap::{Parser, Subcommand};
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    computation::SessionId,
    conf::{choreo::ChoreoConf, telemetry::init_tracing, Settings},
    execution::{
        runtime::party::RoleAssignment, tfhe_internals::parameters::DkgParamsAvailable,
        tfhe_internals::parameters::NoiseFloodParameters,
    },
    file_handling::{self, read_as_json},
};
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use prettytable::{Attr, Cell, Row, Table};
use rand::{distributions::Uniform, Rng};
use std::{panic::Location, sync::Arc};
use tfhe::{prelude::FheEncrypt, FheUint8};
use tokio::task::JoinSet;
use tonic::transport::ClientTlsConfig;

#[derive(Parser, Debug)]
#[clap(name = "mobygo")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short, long, default_value = "config/mobygo.toml")]
    conf_file: String,

    #[clap(short, long, value_enum)]
    dkg_params: Option<DkgParamsAvailable>,

    #[clap(short, long)]
    num_sessions_preproc: Option<u32>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decrypt on cluster of mobys (non-blocking)
    Decrypt,
    /// Initialize the moby workers with a key share and a PRSS setup
    Init,
    //Start DKG preprocessing
    Preprocessing,
    /// Retrieve one or many results of computation from cluster of mobys
    Results,
    /// Run the CRS ceremony between the workers and store/return the CRS
    StartCrsCeremony,
    /// Retrieve the CRS, might be empty if the ceremony is not finished
    RetrieveCrs,
}

async fn start_crs_ceremony_command(
    runtime: &ChoreoRuntime,
    init_opts: &ChoreoConf,
) -> Result<(), Box<dyn std::error::Error>> {
    let wd = match init_opts.witness_dim {
        Some(wd) => wd,
        None => {
            let msg = format!(
                "Witness Dimension required in CRS ceremony, but it's not set at {}",
                Location::caller(),
            );
            tracing::error!(msg);
            return Err(anyhow!(msg).into());
        }
    };

    // the CRS can be set once per epoch (currently stored in a SessionID)
    runtime
        .initiate_crs_ceremony(
            &SessionId::from(init_opts.epoch()),
            init_opts.threshold_topology.threshold,
            wd,
        )
        .await?;
    Ok(())
}

async fn retrieve_crs_command(
    runtime: &ChoreoRuntime,
    init_opts: &ChoreoConf,
) -> Result<(), Box<dyn std::error::Error>> {
    let (crs, dur) = runtime
        .initiate_retrieve_crs(&SessionId::from(init_opts.epoch()))
        .await?;
    tracing::info!(
        "CRS received at epoch {}, generation took {dur} seconds.",
        init_opts.epoch()
    );

    // write received CRS to file
    let serialized_crs = bincode::serialize(&crs)?;
    std::fs::write(init_opts.crs_file(), serialized_crs)?;
    Ok(())
}

async fn preproc_command(
    runtime: ChoreoRuntime,
    init_opts: &ChoreoConf,
    dkg_params: Option<DkgParamsAvailable>,
    num_sessions: Option<u32>,
) -> Result<(), Box<dyn std::error::Error>> {
    let params = match dkg_params {
        Some(params) => params.to_param(),
        None => panic!("Need to specify some Dkg params"),
    };

    let num_sessions = match num_sessions {
        Some(value) => value,
        None => panic!("Need to specify number of sessions to use in dkg preproc"),
    };

    runtime
        .initate_preproc(params, init_opts.threshold_topology.threshold, num_sessions)
        .await?;

    Ok(())
}
async fn init_command(
    runtime: &ChoreoRuntime,
    init_opts: &ChoreoConf,
) -> Result<(), Box<dyn std::error::Error>> {
    let default_params: NoiseFloodParameters = read_as_json(init_opts.params_file.to_owned())?;

    // keys can be set once per epoch (currently stored in a SessionID)
    let pk = runtime
        .initiate_keygen(
            &SessionId::from(init_opts.epoch()),
            init_opts.threshold_topology.threshold,
            default_params,
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

    // read pk from file (Init must have been called before!)
    let pk_serialized = std::fs::read(decrypt_opts.pub_key_file())?;
    let pk: tfhe::CompactPublicKey = bincode::deserialize(&pk_serialized)?;

    let ciphers = messages
        .iter()
        .map(|m| {
            let (ct, _id) = FheUint8::encrypt(*m, &pk).into_raw_parts();
            ct
        })
        .collect::<Vec<_>>();

    let mut join_set = JoinSet::new();

    let rt = Arc::new(runtime);
    let mode = Arc::new(decrypt_opts.decrypt_mode.clone());
    ciphers.into_iter().for_each(|ct| {
        let rt = rt.clone();
        let mode = mode.clone();
        let threshold = decrypt_opts.threshold_topology.threshold;
        join_set.spawn(async move {
            rt.initiate_threshold_decryption(&mode, threshold, &ct)
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
        let msg = format!(
            "Number of results ({}) does not match number of messages ({})",
            vec.len(),
            number_messages
        );
        tracing::error!(msg);
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

    let conf: ChoreoConf = Settings::builder()
        .path(&args.conf_file)
        .build()
        .init_conf()?;

    let tls_config = match (&conf.cert_file, &conf.key_file, &conf.ca_file) {
        (Some(cert), Some(key), Some(ca)) => {
            let client_cert = std::fs::read_to_string(cert)?;
            let client_key = std::fs::read_to_string(key)?;
            let client_identity = tonic::transport::Identity::from_pem(client_cert, client_key);

            let server_root_ca_cert = std::fs::read_to_string(ca)?;
            let server_root_ca_cert = tonic::transport::Certificate::from_pem(server_root_ca_cert);

            // we use local host since the choreographer should always communicate
            // to the ddec/core locally
            Some(
                ClientTlsConfig::new()
                    .domain_name("localhost")
                    .ca_certificate(server_root_ca_cert)
                    .identity(client_identity),
            )
        }
        _ => None,
    };

    init_tracing(conf.tracing.clone())?;

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
            let session_ids = decrypt_command(runtime, &conf).await?;
            tracing::info!(
                "Storing session ids: {:?} - into {:?}",
                session_ids,
                conf.session_file_path()
            );
            file_handling::write_element(conf.session_file_path(), &session_ids)?;
            tracing::info!("Session ids stored in {:?}.", conf.session_file_path());
        }
        Commands::Preprocessing => {
            preproc_command(runtime, &conf, args.dkg_params, args.num_sessions_preproc).await?;
        }
        Commands::Results => {
            results_command(&runtime, conf.session_file_path()).await?;
        }
        Commands::StartCrsCeremony => {
            start_crs_ceremony_command(&runtime, &conf).await?;
        }
        Commands::RetrieveCrs => {
            retrieve_crs_command(&runtime, &conf).await?;
        }
    };

    Ok(())
}
