//! CLI tool for interacting with a group of mobys
#![cfg(feature = "choreographer")]

use clap::{Args, Parser, Subcommand};
use itertools::Itertools;
use observability::{
    conf::{Settings, TelemetryConfig},
    telemetry::init_tracing,
};
use rand::{distributions::Uniform, random, Rng};
use tfhe::{
    integer::BooleanBlock, set_server_key, CompactPublicKey, FheBool, FheUint128, FheUint16,
    FheUint160, FheUint2048, FheUint256, FheUint32, FheUint4, FheUint64, FheUint8,
};
use threshold_fhe::{
    choreography::{
        choreographer::ChoreoRuntime,
        grpc::SupportedRing,
        requests::{SessionType, TfheType, ThroughtputParams},
    },
    conf::choreo::ChoreoConf,
    execution::{
        endpoints::decryption::{DecryptionMode, RadixOrBoolCiphertext},
        tfhe_internals::{
            parameters::DkgParamsAvailable, public_keysets::FhePubKeySet, utils::expanded_encrypt,
        },
    },
    session_id::SessionId,
};
use tokio::time;

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
    /// DKG Params for which to generate the correlated randomness.
    #[clap(long, value_enum)]
    dkg_params: DkgParamsAvailable,

    /// Number of sessions to run in parallel to produce the correlated randomness.
    #[clap(long = "num-sessions")]
    num_sessions_preproc: u32,

    /// Percentage of the offline phase we actually want to run (default to 100)
    #[clap(long = "percentage-offline", default_value = "100")]
    percentage_offline: u32,

    /// Session type either Large or Small
    #[clap(long, value_enum)]
    session_type: SessionType,

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
struct ThresholdKeyGenArgs {
    /// DKG Params for which to run the Distributed Key Generation.
    #[clap(long, value_enum)]
    dkg_params: DkgParamsAvailable,

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

    /// If provided, runs a centralised Key Generation and reshare the output such as to set up a key for testing purposes.
    /// (The moby cluster will then refer to this new key using the provided session ID)
    #[clap(long = "generate-params")]
    params: Option<DkgParamsAvailable>,

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
}

#[derive(Args, Debug)]
struct PreprocDecryptArgs {
    /// Decryption Mode for which to generate the correlated randomness.
    #[clap(long, value_enum)]
    decryption_mode: DecryptionMode,

    /// Path to the public key file (used to retrieve the key sid needed to derive correct parameters)
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// TFHE-rs type to use. Must match with preprocessing if one is given
    #[clap(long = "tfhe-type", value_enum)]
    tfhe_type: TfheType,

    /// Number of Ciphertext to prepare preprocessing for (default to 1).
    /// Must match with preprocessing if one is given.
    #[clap(long = "num-ctxts", default_value = "1")]
    num_ctxts: usize,

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
struct EncryptArgs {
    /// Path to the public key file
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// TFHE-rs type to use
    #[clap(long = "tfhe-type", value_enum)]
    tfhe_type: TfheType,

    /// Value to encrypt
    #[clap(long = "value")]
    value: u64,

    /// Optional path to output file
    #[clap(long = "output-file", default_value = "./temp/ctxt.bin")]
    output_file: String,
}

#[derive(Args, Debug)]
struct ThresholdDecryptFromFileArgs {
    /// Decryption Mode to use for the threshold decryption.
    #[clap(long, value_enum)]
    decryption_mode: DecryptionMode,

    /// Path to the public key file
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// Path to ciphertext file
    #[clap(long = "input-file", default_value = "./temp/ctxt.bin")]
    input_file: String,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Session ID that corresponds to the correlated randomness to be consumed during the Distributed Decryption
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
struct ThresholdDecryptArgs {
    /// Decryption Mode to use for the threshold decryption.
    #[clap(long, value_enum)]
    decryption_mode: DecryptionMode,

    /// Path to the public key file
    #[clap(long = "path-pubkey", default_value = "./temp/pk.bin")]
    pub_key_file: String,

    /// TFHE-rs type to use, must match with the preprocessing
    #[clap(long = "tfhe-type", value_enum)]
    tfhe_type: TfheType,

    /// Number of ciphertexts to create must match with the preprocessing (default to 1)
    #[clap(long = "num-ctxts", default_value = "1")]
    num_ctxts: usize,

    /// Optional argument to force the session ID to be used. (Sampled at random if nothing is given)
    #[clap(long = "sid")]
    session_id: Option<u128>,

    /// Optional argument to perform throughput tests,
    /// tells how many ctxt we try to decrypt in parallel
    #[clap(long = "throughput-copies")]
    throughput_copies: Option<usize>,

    /// Optional argument to perform throughput tests,
    /// telling how many sessions we use in parallel
    #[clap(long = "throughput-sessions", requires_all=["throughput_copies"])]
    throughput_sessions: Option<usize>,

    /// Session ID that corresponds to the correlated randomness to be consumed during the Distributed Decryption
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
struct ThresholdDecryptResultArgs {
    /// Session ID of the Threshold Decryption we want to retrieve the result from.
    /// (Output of the threshold-decrypt command)
    #[clap(long = "sid")]
    session_id_decrypt: u128,
}

#[derive(Args, Debug)]
struct CrsGenArgs {
    /// Parameter to generate a CRS for
    #[clap(long = "parameters")]
    params: DkgParamsAvailable,

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
struct CrsGenResultArgs {
    /// Session ID of the CRS Gen we want to retrieve the result from.
    /// (Output of the crs-gen command)
    #[clap(long = "sid")]
    session_id_crs: u128,

    /// Path of the folder where to store the crs
    #[clap(long, default_value = "./temp/")]
    storage_path: String,
}

#[derive(Args, Debug)]
struct ReshareArgs {
    /// Session ID of the key to reshare
    #[clap(long = "old-key-sid")]
    old_key_sid: u128,

    /// Session type either Large or Small (affects preprocessing)
    #[clap(long, value_enum)]
    session_type: SessionType,

    /// Session ID under which the reshared key will be stored
    #[clap(long = "new-key-sid")]
    new_key_sid: Option<u128>,

    /// Optional argument to set the master seed used by the parties.
    /// Parties will then add their party index to the seed.
    /// Sampled at random if nothing is given
    #[clap(long = "seed")]
    seed: Option<u64>,
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
#[clap(name = "mobygo")]
#[clap(about = "A simple CLI tool for interacting with a Moby cluster.")]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,

    /// Config file with the network configuration (and an optional TLS configuration).
    #[clap(short, long, default_value = "config/mobygo.toml")]
    conf_file: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start PRSS Init on cluster of mobys
    PrssInit(PrssInitArgs),
    /// Start DKG preprocessing on cluster of mobys
    PreprocKeyGen(PreprocKeyGenArgs),
    /// Start DKG on cluster of mobys
    ThresholdKeyGen(ThresholdKeyGenArgs),
    /// Retrieve the public key to be used for encryption.
    /// (Can also generate a key for testing purposes)
    ThresholdKeyGenResult(ThresholdKeyGenResultArgs),
    Encrypt(EncryptArgs),
    /// Start DDec preprocessing on cluster of mobys
    PreprocDecrypt(PreprocDecryptArgs),
    /// Start DDec on cluster of mobys
    ThresholdDecrypt(ThresholdDecryptArgs),
    /// Start DDec on cluster of mobys with ciphertexts from a file
    ThresholdDecryptFromFile(ThresholdDecryptFromFileArgs),
    /// Retrieve DDec result from cluster
    ThresholdDecryptResult(ThresholdDecryptResultArgs),
    /// Start CRS generation
    CrsGen(CrsGenArgs),
    /// Retrieve CRS result from cluster
    CrsGenResult(CrsGenResultArgs),
    /// Reshare the secret key amongst the parties
    Reshare(ReshareArgs),
    /// Checks the status of a task based on its session ID
    StatusCheck(StatusCheckArgs),
}

async fn crs_gen_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: CrsGenArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = params.session_id.unwrap_or(random());

    let session_id = runtime
        .initiate_crs_gen(
            SessionId::from(session_id),
            params.params,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!(
        "CRS ceremony started. The resulting CRS will be stored under session ID: {session_id}"
    );
    Ok(())
}

async fn crs_gen_result_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: CrsGenResultArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let crs = runtime
        .initiate_crs_gen_result(
            SessionId::from(params.session_id_crs),
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    let serialized_crs = bc2wrap::serialize(&crs)?;
    std::fs::write(format!("{}/crs.bin", params.storage_path), serialized_crs)?;
    println!("CRS stored in {}/crs.bin", params.storage_path);
    Ok(())
}

async fn prss_init_command(
    runtime: &ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: PrssInitArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = params.session_id.unwrap_or(random());

    runtime
        .inititate_prss_init(
            SessionId::from(session_id),
            params.ring,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
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
        .initiate_preproc_keygen(
            SessionId::from(session_id),
            params.session_type,
            params.dkg_params,
            params.num_sessions_preproc,
            params.percentage_offline,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
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
        .initiate_threshold_keygen(
            SessionId::from(session_id),
            params.dkg_params,
            params
                .session_id_preproc
                .map_or_else(|| None, |id| Some(SessionId::from(id))),
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!("Threshold Key Generation started. The new key will be stored under session ID:  {session_id}");

    Ok(())
}

async fn threshold_keygen_result_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdKeyGenResultArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let keys = runtime
        .initiate_threshold_keygen_result(
            SessionId::from(params.session_id),
            params.params,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    let serialized_pk = bc2wrap::serialize(&(params.session_id, keys))?;
    std::fs::write(format!("{}/pk.bin", params.storage_path), serialized_pk)?;
    println!("Key stored in {}/pk.bin", params.storage_path);
    Ok(())
}

async fn preproc_decrypt_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: PreprocDecryptArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (key_sid, _): (SessionId, FhePubKeySet) = bc2wrap::deserialize(&pk_serialized)?;
    let session_id = params.session_id.unwrap_or(random());
    let num_ctxts = params.num_ctxts;
    let ctxt_type = params.tfhe_type;
    let session_id = runtime
        .initiate_preproc_decrypt(
            SessionId::from(session_id),
            key_sid,
            params.decryption_mode,
            num_ctxts as u128,
            ctxt_type,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;
    println!("Preprocessing for Distributed Decryption started.\n  The correlated randomness will be stored under session ID: {session_id}");
    Ok(())
}

fn encrypt_messages(
    messages: Vec<u64>,
    tfhe_type: TfheType,
    compact_key: &CompactPublicKey,
) -> Vec<RadixOrBoolCiphertext> {
    match tfhe_type {
        TfheType::Bool => messages
            .iter()
            .map(|msg| {
                let ct: FheBool = expanded_encrypt(compact_key, *msg, 1).unwrap();
                RadixOrBoolCiphertext::Bool(BooleanBlock::new_unchecked(ct.into_raw_parts()))
            })
            .collect_vec(),
        TfheType::U4 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint4 = expanded_encrypt(compact_key, *msg, 4).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U8 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint8 = expanded_encrypt(compact_key, *msg, 8).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U16 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint16 = expanded_encrypt(compact_key, *msg, 16).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U32 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint32 = expanded_encrypt(compact_key, *msg, 32).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U64 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint64 = expanded_encrypt(compact_key, *msg, 64).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U128 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint128 = expanded_encrypt(compact_key, *msg, 128).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U160 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint160 = expanded_encrypt(compact_key, *msg, 160).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U256 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint256 = expanded_encrypt(compact_key, *msg, 256).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
        TfheType::U2048 => messages
            .iter()
            .map(|msg| {
                let ct: FheUint2048 = expanded_encrypt(compact_key, *msg, 2048).unwrap();
                RadixOrBoolCiphertext::Radix(ct.into_raw_parts().0)
            })
            .collect_vec(),
    }
}

async fn encrypt_command(params: EncryptArgs) -> Result<(), Box<dyn std::error::Error>> {
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (_key_sid, pk): (SessionId, FhePubKeySet) = bc2wrap::deserialize(&pk_serialized)?;
    let compact_key = pk.public_key;

    set_server_key(pk.server_key);
    let ctxt = encrypt_messages(vec![params.value], params.tfhe_type.clone(), &compact_key)
        .pop()
        .unwrap();

    println!(
        "Writing resulting ciphertext to file: {}",
        params.output_file
    );

    let serialized_ctxt = bc2wrap::serialize(&(params.tfhe_type, ctxt))?;

    tokio::fs::write(params.output_file, serialized_ctxt).await?;

    Ok(())
}

async fn threshold_decrypt_from_file_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdDecryptFromFileArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (key_sid, _pk): (SessionId, FhePubKeySet) = bc2wrap::deserialize(&pk_serialized)?;

    let ctxt_serialized = tokio::fs::read(params.input_file).await?;
    let (tfhe_type, ctxt): (TfheType, RadixOrBoolCiphertext) =
        bc2wrap::deserialize(&ctxt_serialized)?;

    let session_id = params.session_id.unwrap_or(random());
    let session_id = runtime
        .initiate_threshold_decrypt(
            SessionId::from(session_id),
            key_sid,
            params.decryption_mode,
            params
                .session_id_preproc
                .map_or_else(|| None, |id| Some(SessionId::from(id))),
            vec![ctxt],
            None,
            tfhe_type,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!(
        "Distributed Decryption started. The resulting plaintexts will be stored under session ID: {session_id:?}"
    );

    Ok(())
}

async fn threshold_decrypt_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdDecryptArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let tfhe_type = params.tfhe_type;
    let num_messages = params.num_ctxts;
    let pk_serialized = std::fs::read(params.pub_key_file)?;
    let (key_sid, pk): (SessionId, FhePubKeySet) = bc2wrap::deserialize(&pk_serialized)?;
    let compact_key = pk.public_key;

    //Required to be able to expand the CompactCiphertextList if the encryption and compute keys
    //are different (i.e. need access to PKSK)
    set_server_key(pk.server_key);
    let max_value = if tfhe_type.get_num_bits_rep() >= 64 {
        u64::MAX
    } else {
        (1 << tfhe_type.get_num_bits_rep()) - 1
    };
    let messages = rand::thread_rng()
        .sample_iter(Uniform::<u64>::from(0..=max_value))
        .take(num_messages)
        .collect_vec();

    let ctxts = encrypt_messages(messages.clone(), tfhe_type.clone(), &compact_key);

    println!("Encrypted the following message : {messages:?}");

    let session_id = params.session_id.unwrap_or(random());
    let throughput = if let Some(num_copies) = params.throughput_copies {
        let num_sessions = params.throughput_sessions.unwrap_or(1);
        Some(ThroughtputParams {
            num_copies,
            num_sessions,
        })
    } else {
        None
    };
    let session_id = runtime
        .initiate_threshold_decrypt(
            SessionId::from(session_id),
            key_sid,
            params.decryption_mode,
            params
                .session_id_preproc
                .map_or_else(|| None, |id| Some(SessionId::from(id))),
            ctxts,
            throughput,
            tfhe_type,
            choreo_conf.threshold_topology.threshold,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!(
        "Distributed Decryption started. The resulting plaintexts will be stored under session ID: {session_id:?}"
    );

    Ok(())
}

async fn threshold_decrypt_result_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ThresholdDecryptResultArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let ptxts = runtime
        .initiate_threshold_decrypt_result(
            SessionId::from(params.session_id_decrypt),
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!(
        "Retrieved plaintexts for session ID {}: \n\t {:?}",
        params.session_id_decrypt, ptxts
    );
    Ok(())
}

async fn reshare_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: ReshareArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_key_id = SessionId::from(params.new_key_sid.unwrap_or(random()));
    let new_sid = runtime
        .initiate_reshare(
            choreo_conf.threshold_topology.threshold,
            SessionId::from(params.old_key_sid),
            new_key_id,
            params.session_type,
            params.seed,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    println!("After resharing, new key will be available under {new_sid:?}");

    Ok(())
}

async fn status_check_command(
    runtime: ChoreoRuntime,
    choreo_conf: ChoreoConf,
    params: StatusCheckArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let session_id = SessionId::from(params.session_id);
    let retry = params.retry.map_or_else(|| false, |val| val);
    let interval = params.interval.map_or_else(
        || tokio::time::Duration::from_secs(10),
        tokio::time::Duration::from_secs,
    );
    let mut results = runtime
        .initiate_status_check(
            session_id,
            retry,
            interval,
            choreo_conf.malicious_roles.unwrap_or_default(),
        )
        .await?;

    results.sort_by_key(|(role, _)| role.one_based());
    println!("Status Check for Session ID {session_id} -- Finished");
    for (role, status) in results {
        println!("Role {role}, Status {status:?}");
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

    println!("Malicious roles: {:?}", conf.malicious_roles);

    let telemetry = conf.telemetry.clone().unwrap_or_else(|| {
        TelemetryConfig::builder()
            .tracing_service_name("mobygo".to_string())
            .build()
    });

    let tracer_provider = init_tracing(&telemetry).await?;

    let runtime = ChoreoRuntime::new_from_conf(&conf)?;
    match args.command {
        Commands::PrssInit(params) => {
            prss_init_command(&runtime, conf, params).await?;
        }
        Commands::PreprocKeyGen(params) => {
            preproc_keygen_command(runtime, conf, params).await?;
        }
        Commands::ThresholdKeyGen(params) => {
            threshold_keygen_command(runtime, conf, params).await?;
        }
        Commands::ThresholdKeyGenResult(params) => {
            threshold_keygen_result_command(runtime, conf, params).await?;
        }
        Commands::PreprocDecrypt(params) => {
            preproc_decrypt_command(runtime, conf, params).await?;
        }
        Commands::ThresholdDecrypt(params) => {
            threshold_decrypt_command(runtime, conf, params).await?;
        }
        Commands::ThresholdDecryptResult(params) => {
            threshold_decrypt_result_command(runtime, conf, params).await?;
        }
        Commands::CrsGen(params) => {
            crs_gen_command(runtime, conf, params).await?;
        }
        Commands::CrsGenResult(params) => {
            crs_gen_result_command(runtime, conf, params).await?;
        }
        Commands::StatusCheck(params) => {
            status_check_command(runtime, conf, params).await?;
        }
        Commands::Reshare(params) => {
            reshare_command(runtime, conf, params).await?;
        }
        Commands::Encrypt(encrypt_args) => {
            encrypt_command(encrypt_args).await?;
        }
        Commands::ThresholdDecryptFromFile(threshold_decrypt_from_file_args) => {
            threshold_decrypt_from_file_command(runtime, conf, threshold_decrypt_from_file_args)
                .await?;
        }
    };

    //Sleep to let some time for the process to export all the spans before exit
    time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Explicitly shut down telemetry to ensure all data is properly exported
    if let Err(e) = tracer_provider.shutdown() {
        eprintln!("Error shutting down tracer provider: {e}");
    }

    Ok(())
}
