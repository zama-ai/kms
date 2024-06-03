//! CLI tool for interacting with a group of stairways
use std::time::Duration;

use aes_prng::AesRng;
use clap::{Args, Parser, Subcommand};
use distributed_decryption::{
    choreography::choreographer::ChoreoRuntime,
    conf::{choreo::ChoreoConf, telemetry::init_tracing, Settings},
    execution::runtime::party::RoleAssignment,
    experimental::{
        algebra::{
            levels::{LevelEll, LevelKsw},
            ntt::{Const, N65536},
        },
        bgv::basics::{bgv_pk_encrypt, PublicKey},
        choreography::requests::SupportedRing,
        constants::PLAINTEXT_MODULUS,
    },
    session_id::SessionId,
};
use itertools::Itertools;
use rand::{random, RngCore, SeedableRng};
use tonic::transport::ClientTlsConfig;

#[derive(Args, Debug)]
struct PrssInitArgs {
    /// Ring for which to initialize the PRSS.
    #[clap(long)]
    ring: SupportedRing,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,
}

#[derive(Args, Debug)]
struct PreprocKeyGenArgs {
    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,
}

#[derive(Args, Debug)]
struct ThresholdKeyGenArgs {
    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Otional argument for the session ID that corresponds to the correlated randomness to be consumed during the Distributed Key Generation.
    /// (If no ID is given, we use dummy preprocessing)
    #[clap(long = "preproc-sid")]
    session_id_preproc: Option<u128>,
}

#[derive(Args, Debug)]
struct ThresholdKeyGenResultArgs {
    /// Session ID that corresponds to the session ID of the Distributed Key Generation we want to retrieve.
    /// (If params is provided, then the new Key Generated will be stored under this session ID)
    #[clap(long = "sid")]
    session_id: u128,

    /// Path of the folder where to store the keys
    #[clap(long, default_value = "./temp/")]
    storage_path: String,

    /// If true, runs a centralised Key Generation and reshare the output such as to set up a key for testing purposes.
    /// (The stairway cluster will then refer to this new key using the provided session ID)
    #[clap(long = "generate-params")]
    params: Option<bool>,
}

#[derive(Args, Debug)]
struct ThresholdDecryptArgs {
    /// Path to the public key file
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// Number of Ciphertexts to encrypt
    #[clap(long)]
    num_msgs: u128,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,
}

#[derive(Args, Debug)]
struct ThresholdDecryptResultArgs {
    /// Session ID of the Threshold Decryption we want to retrieve the result from.
    /// (Output of the threshold-decrypt command)
    #[clap(long = "sid")]
    session_id_decrypt: u128,
}

#[derive(Args, Debug)]
struct StatusCheckArgs {
    /// Session ID of the task to check the status of
    #[clap(long = "sid")]
    session_id: u128,

    /// If the flag is set, we keep checking status until all parties are done
    #[clap(long = "keep-retry")]
    retry: Option<bool>,

    /// If keep-retry, specify the time in seconds we wait between every checks
    /// default to 10 seconds
    #[clap(long = "interval", requires("retry"))]
    interval: Option<u64>,
}

#[derive(Parser, Debug)]
#[clap(name = "stairwayctl")]
#[clap(about = "A simple CLI tool for interacting with a stairway cluster.")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Config file with the network configuration (and an optional TLS configuration).
    #[clap(short, long, default_value = "config/stairway.toml")]
    conf_file: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start PRSS Init on cluster of stairway
    PrssInit(PrssInitArgs),
    /// Start DKG preprocessing on cluster of stairways
    PreprocKeyGen(PreprocKeyGenArgs),
    /// Start DKG on cluster of stairways
    ThresholdKeyGen(ThresholdKeyGenArgs),
    /// Retrieve the public key to be used for encryption.
    /// (Can also generate a key for testing purposes)
    ThresholdKeyGenResult(ThresholdKeyGenResultArgs),
    /// Start DDec on cluster of stairways
    ThresholdDecrypt(ThresholdDecryptArgs),
    /// Retrieve DDec result from cluster
    ThresholdDecryptResult(ThresholdDecryptResultArgs),
    /// Checks the status of a task based on its session ID
    StatusCheck(StatusCheckArgs),
}

async fn prss_init_command(
    runtime: &ChoreoRuntime,
    choreo_conf: &ChoreoConf,
    params: PrssInitArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = params.session_id.unwrap_or(random());

    runtime
        .bgv_inititate_prss_init(
            SessionId(session_id),
            params.ring,
            choreo_conf.threshold_topology.threshold,
        )
        .await?;

    println!("PRSS Init started with session ID: {session_id}");
    Ok(())
}

async fn preproc_keygen_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: PreprocKeyGenArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = params.session_id.unwrap_or(random());

    let session_id = runtime
        .bgv_initiate_preproc_keygen(
            SessionId(session_id),
            choreo_conf.threshold_topology.threshold,
        )
        .await?;

    println!("Preprocessing for Distributed Key Generation started.\n  The correlated randomness will be stored under session ID: {session_id}");
    Ok(())
}

async fn threshold_keygen_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdKeyGenArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = params.session_id.unwrap_or(random());

    let session_id = runtime
        .bgv_initiate_threshold_keygen(
            SessionId(session_id),
            params
                .session_id_preproc
                .map_or_else(|| None, |id| Some(SessionId(id))),
            choreo_conf.threshold_topology.threshold,
        )
        .await?;

    println!("Threshold Key Generation started. The new key will be stored under session ID:  {session_id}");
    Ok(())
}

async fn threshold_keygen_result_command(
    runtime: ChoreoRuntime,
    params: ThresholdKeyGenResultArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys = runtime
        .bgv_initiate_threshold_keygen_result(SessionId(params.session_id), params.params)
        .await?;

    let serialized_pk = bincode::serialize(&(params.session_id, keys))?;
    std::fs::write(format!("{}/pk.bin", params.storage_path), serialized_pk)?;
    println!("Key stored in {}/pk.bin", params.storage_path);
    Ok(())
}

async fn threshold_decrypt_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdDecryptArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let num_msgs = params.num_msgs;
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (key_sid, pk): (SessionId, PublicKey<LevelEll, LevelKsw, N65536>) =
        bincode::deserialize(&pk_serialized)?;

    let mut rng = AesRng::from_entropy();
    let ms = (0..num_msgs)
        .map(|_| {
            let m: Vec<u32> = (0..N65536::VALUE)
                .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
                .collect();
            m
        })
        .collect_vec();
    let ciphertexts = (0..num_msgs as usize)
        .map(|i| bgv_pk_encrypt(&mut rng, &ms[i], &pk))
        .collect_vec();

    println!("Encrypted the following messages : {:?}", ms);

    let session_id = params.session_id.unwrap_or(random());
    let session_id = runtime
        .bgv_initiate_threshold_decrypt(
            SessionId(session_id),
            key_sid,
            ciphertexts,
            choreo_conf.threshold_topology.threshold,
        )
        .await?;

    println!(
        "Distributed Decryption started. The resulting plaintexts will be stored under session ID: {:?}",
        session_id
    );
    Ok(())
}

async fn threshold_decrypt_result_command(
    runtime: ChoreoRuntime,
    params: ThresholdDecryptResultArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let ptxts = runtime
        .bgv_initiate_threshold_decrypt_result(SessionId(params.session_id_decrypt))
        .await?;

    println!(
        "Retrieved plaintexts for session ID {}: \n\t {:?}",
        params.session_id_decrypt, ptxts
    );
    Ok(())
}

async fn status_check_command(
    runtime: ChoreoRuntime,
    params: StatusCheckArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = SessionId(params.session_id);
    let retry = params.retry.map_or_else(|| false, |val| val);
    let interval = params
        .interval
        .map_or_else(|| Duration::from_secs(10), Duration::from_secs);
    let mut results = runtime
        .initiate_status_check(session_id, retry, interval)
        .await?;

    results.sort_by_key(|(role, _)| role.one_based());
    println!("Status Check for Session ID {session_id} -- Finished");
    for (role, status) in results {
        println!("Role {role}, Status {:?}", status);
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

    //NOTE: Do we really care about choreographer using TLS to communicate with stairway cluster ?
    // Also what's up with domain_name localhost ?
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

    let role_assignments: RoleAssignment = topology.into();

    // we need to set the protocol in URI correctly
    // depending on whether the certificates are present
    let host_channels =
        topology.choreo_physical_topology_into_network_topology(tls_config.is_some())?;

    let runtime =
        ChoreoRuntime::new_with_net_topology(role_assignments, tls_config, host_channels)?;
    match args.command {
        Commands::PrssInit(params) => {
            prss_init_command(&runtime, &conf, params).await?;
        }
        Commands::PreprocKeyGen(params) => {
            preproc_keygen_command(runtime, conf, params).await?;
        }
        Commands::ThresholdKeyGen(params) => {
            threshold_keygen_command(runtime, conf, params).await?;
        }
        Commands::ThresholdKeyGenResult(params) => {
            threshold_keygen_result_command(runtime, params).await?;
        }
        Commands::ThresholdDecrypt(params) => {
            threshold_decrypt_command(runtime, conf, params).await?;
        }
        Commands::ThresholdDecryptResult(params) => {
            threshold_decrypt_result_command(runtime, params).await?;
        }
        Commands::StatusCheck(params) => {
            status_check_command(runtime, params).await?;
        }
    };
    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}
