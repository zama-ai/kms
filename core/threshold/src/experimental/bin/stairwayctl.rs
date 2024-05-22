//! CLI tool for interacting with a group of stairways
use aes_prng::AesRng;
use clap::{Parser, Subcommand};
use distributed_decryption::experimental::algebra::ntt::Const;
use distributed_decryption::experimental::constants::PLAINTEXT_MODULUS;
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    conf::{choreo::ChoreoConf, telemetry::init_tracing, Settings},
    execution::runtime::party::RoleAssignment,
    experimental::{
        algebra::ntt::N65536,
        bgv::basics::{bgv_pk_encrypt, PublicBgvKeySet},
    },
    file_handling::{self},
    session_id::SessionId,
};
use itertools::Itertools;
use ndarray::Array1;
use ndarray_stats::QuantileExt;
use prettytable::{Attr, Cell, Row, Table};
use rand::RngCore;
use rand::SeedableRng;
use std::sync::Arc;
use tokio::task::JoinSet;
use tonic::transport::ClientTlsConfig;

#[derive(Parser, Debug)]
#[clap(name = "stariwayctl")]
#[clap(about = "A simple CLI tool for interacting with a Stairway cluster. \
The config file contains the topology of the network as well as an optional \
TLS configuration. If the certificates and keys exist, then TLS will \
be used to communicate with the core (from stairwayctl). \
Otherwise TCP is used.")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    #[clap(short, long, default_value = "config/stairwayctl.toml")]
    conf_file: String,

    #[clap(short, long)]
    num_sessions_preproc: Option<u32>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decrypt on cluster of stairways (non-blocking)
    Decrypt,
    /// Initialize the stairways workers with a key share and a PRSS setup
    Init,
    /// Retrieve one or many results of computation from cluster of stairways
    Results,
}

async fn init_command(
    runtime: &ChoreoRuntime,
    init_opts: &ChoreoConf,
) -> Result<(), Box<dyn std::error::Error>> {
    // keys can be set once per epoch (currently stored in a SessionID)
    let pk = runtime
        .local_bgv_keygen(init_opts.threshold_topology.threshold)
        .await?;

    tracing::info!("Public key received");

    // write received pk to file
    let serialized_pk = bincode::serialize(&pk)?;
    std::fs::write(init_opts.pub_key_file(), serialized_pk)?;
    Ok(())
}

async fn bgv_decrypt_command(
    runtime: ChoreoRuntime,
    decrypt_opts: &ChoreoConf,
) -> Result<Vec<SessionId>, Box<dyn std::error::Error>> {
    let mut rng = AesRng::from_entropy();
    let num_messages = decrypt_opts.number_messages.unwrap_or(1);

    let ms = (0..num_messages)
        .map(|_| {
            let m: Vec<u32> = (0..N65536::VALUE)
                .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
                .collect();
            m
        })
        .collect_vec();

    tracing::info!(
        "Launching stairwayctl decryption: parties: {}, threshold: {}, messages: {}",
        decrypt_opts.threshold_topology.peers.len(),
        decrypt_opts.threshold_topology.threshold,
        num_messages,
    );

    // read pk from file (Init must have been called before!)
    let pk_serialized = std::fs::read(decrypt_opts.pub_key_file())?;
    let pk: PublicBgvKeySet = bincode::deserialize(&pk_serialized)?;

    let ciphertexts = (0..num_messages)
        .map(|i| bgv_pk_encrypt(&mut rng, &ms[i], &pk))
        .collect_vec();

    let mut join_set = JoinSet::new();

    let rt = Arc::new(runtime);
    let mode = Arc::new(decrypt_opts.decrypt_mode.clone());
    ciphertexts.into_iter().for_each(|ct| {
        let rt = rt.clone();
        let mode = mode.clone();
        let threshold = decrypt_opts.threshold_topology.threshold;
        join_set.spawn(async move {
            rt.experimental_threshold_decrypt(&mode, threshold, &ct)
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

    if vec.len() != num_messages {
        let msg = format!(
            "Number of results ({}) does not match number of messages ({})",
            vec.len(),
            num_messages
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
    let results = runtime.experimental_retrieve_results(session_id, 1).await?;

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

    // we need to set the protocol in URI correctly
    // depending on whether the certificates are present
    let host_channels =
        topology.choreo_physical_topology_into_network_topology(tls_config.is_some())?;

    let runtime =
        ChoreoRuntime::new_with_net_topology(docker_role_assignments, tls_config, host_channels)?;
    match args.command {
        Commands::Init => {
            init_command(&runtime, &conf).await?;
        }
        Commands::Decrypt => {
            let session_ids = bgv_decrypt_command(runtime, &conf).await?;
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
