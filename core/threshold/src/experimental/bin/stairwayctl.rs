//! CLI tool for interacting with a group of stairways
use tokio::time::{self, Duration};

use aes_prng::AesRng;
use clap::{Args, Parser, Subcommand};
use conf_trace::{
    conf::{Settings, TelemetryConfig},
    telemetry::init_tracing,
};
use itertools::Itertools;
use rand::{random, RngCore, SeedableRng};
use threshold_fhe::{
    choreography::choreographer::ChoreoRuntime,
    conf::choreo::ChoreoConf,
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

#[derive(Args, Debug)]
struct PrssInitArgs {
    /// Ring for which to initialize the PRSS.
    #[clap(long)]
    ring: SupportedRing,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
}

#[derive(Args, Debug)]
struct PreprocKeyGenArgs {
    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Number of sessions to run in parallel to produce the correlated randomness.
    #[clap(long = "num-sessions")]
    num_sessions_preproc: u32,

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
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

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
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

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
}

#[derive(Args, Debug)]
struct ThresholdDecryptArgs {
    /// Path to the public key file
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// Number of Ciphertexts to decrypt per session
    #[clap(long = "num-ctxt-per-session")]
    num_ctxt_per_session: u128,

    /// Number of session to spawn in parallel
    #[clap(long = "num-parallel-sessions")]
    num_parallel_sessions: u128,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
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
            SessionId::from(session_id),
            params.ring,
            choreo_conf.threshold_topology.threshold,
            params.seed,
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
            SessionId::from(session_id),
            params.num_sessions_preproc,
            choreo_conf.threshold_topology.threshold,
            params.seed,
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
            SessionId::from(session_id),
            params
                .session_id_preproc
                .map_or_else(|| None, |id| Some(SessionId::from(id))),
            choreo_conf.threshold_topology.threshold,
            params.seed,
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
        .bgv_initiate_threshold_keygen_result(
            SessionId::from(params.session_id),
            params.params,
            params.seed,
        )
        .await?;

    let serialized_pk = bc2wrap::serialize(&(params.session_id, keys))?;
    std::fs::write(format!("{}/pk.bin", params.storage_path), serialized_pk)?;
    println!("Key stored in {}/pk.bin", params.storage_path);
    Ok(())
}

async fn threshold_decrypt_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdDecryptArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    //Create a Vec<Ctxt> where each inner vec will be handled by
    //a different session
    //Each ctxt will be copied num_ctxt_per_session time on the
    //server side (doing that to be able to run some throughput benches
    //whilst avoiding http max size issue)
    let num_ctxt_per_session = params.num_ctxt_per_session;
    let num_sessions = params.num_parallel_sessions;
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (key_sid, pk): (SessionId, PublicKey<LevelEll, LevelKsw, N65536>) =
        bc2wrap::deserialize(&pk_serialized)?;

    let mut rng = AesRng::from_entropy();
    let ms = (0..num_sessions)
        .map(|_| {
            let m: Vec<u32> = (0..N65536::VALUE)
                .map(|_| (rng.next_u64() % PLAINTEXT_MODULUS.get().0) as u32)
                .collect();
            m
        })
        .collect_vec();
    let ciphertexts = (0..num_sessions as usize)
        .map(|i| bgv_pk_encrypt(&mut rng, &ms[i], &pk))
        .collect_vec();

    println!("Encrypted the following messages : {:?}", ms);

    let session_id = params.session_id.unwrap_or(random());
    let session_id = runtime
        .bgv_initiate_threshold_decrypt(
            SessionId::from(session_id),
            key_sid,
            ciphertexts,
            num_ctxt_per_session as usize,
            choreo_conf.threshold_topology.threshold,
            params.seed,
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
        .bgv_initiate_threshold_decrypt_result(SessionId::from(params.session_id_decrypt))
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
    let session_id = SessionId::from(params.session_id);
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
        .env_prefix("DDEC")
        .build()
        .init_conf()?;

    let telemetry = conf.telemetry.clone().unwrap_or_else(|| {
        TelemetryConfig::builder()
            .tracing_service_name("stairwayctl".to_string())
            .build()
    });

    let tracer_provider = init_tracing(&telemetry).await?;

    let runtime = ChoreoRuntime::new_from_conf(&conf)?;
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

    //Sleep to let some time for the process to export all the spans before exit
    time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Explicitly shut down telemetry to ensure all data is properly exported
    if let Err(e) = tracer_provider.shutdown() {
        eprintln!("Error shutting down tracer provider: {}", e);
    }

    Ok(())
}
