use clap::{Parser, Subcommand, ValueEnum};
use core::fmt;
use kms_lib::consts::{DEFAULT_PARAM, TEST_PARAM};
use kms_lib::storage::StorageForText;
use kms_lib::util::key_setup::ThresholdSigningKeyConfig;
use kms_lib::{
    conf::{init_trace, AWSConfig},
    consts::SIGNING_KEY_ID,
    kms::RequestId,
    util::key_setup::ensure_central_crs_exists,
};
use kms_lib::{
    consts::{
        DEFAULT_AMOUNT_PARTIES, DEFAULT_CENTRAL_CRS_ID, DEFAULT_CENTRAL_KEY_ID,
        DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_KEY_ID_4P, OTHER_CENTRAL_DEFAULT_ID,
    },
    storage::{make_storage, Storage, StorageType},
    util::key_setup::{ensure_central_keys_exist, ensure_central_server_signing_keys_exist},
};
use kms_lib::{
    rpc::rpc_types::{PrivDataType, PubDataType},
    storage::delete_at_request_id,
    util::key_setup::{
        ensure_threshold_crs_exists, ensure_threshold_keys_exist,
        ensure_threshold_server_signing_keys_exist,
    },
};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Parser)]
#[clap(name = "Zama KMS Key Material Generator")]
#[clap(about = "A CLI tool for generating key materials. \
    In the centralized mode, it will generate FHE keys, signing keys and the CRS. \
    In the threshold mode, it will generate FHE key shares and the signing keys, \
    the FHE key shares should be used for testing only. \
    Use the threshold protocols to generate FHE key shares. \
    But observe that threshold mode should only be used for testing since keys will get generated centrally. \n
    For example, to generate centralized keys with the default parameters \
    run: \n
    ./kms-gen-keys centralized \n
    Multiple options are supported which can be explored with \
    kms-key-gen --help")]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
    /// What to construct, options are "all", "signing-keys", "fhe-keys" or "crs".
    #[clap(short, long, default_value_t = ConstructCommand::All, value_enum)]
    cmd: ConstructCommand,

    /// AWS region to use for S3 storage
    #[clap(long, default_value = "eu-west-3")]
    aws_region: String,
    /// Optional AWS IMDS API endpoint
    #[clap(long, default_value = None)]
    aws_imds_endpoint: Option<Url>,
    /// Optional AWS S3 API endpoint
    #[clap(long, default_value = None)]
    aws_s3_endpoint: Option<Url>,
    /// Optional AWS KMS API endpoint
    #[clap(long, default_value = None)]
    aws_kms_endpoint: Option<Url>,
    /// Optional root key ID
    #[clap(long, default_value = None)]
    root_key_id: Option<String>,
    /// Optional parameter for the private storage URL
    #[clap(long, default_value = None)]
    priv_url: Option<Url>,
    /// Optional parameter for the public storage URL
    #[clap(long, default_value = None)]
    pub_url: Option<Url>,
    /// Specify whether to use test parameters or not.
    #[clap(long, default_value_t = false)]
    param_test: bool,
    /// Whether to generate keys deterministically,
    /// only use this option for testing.
    /// The determinism is not guaranteed to be the same between releases.
    #[clap(long, default_value_t = false)]
    deterministic: bool,
    /// Whether to overwrite ALL the existing keys,
    #[clap(long, default_value_t = false)]
    overwrite: bool,
    /// Only show existing keys, do not generate any
    #[clap(long, default_value_t = false)]
    show_existing: bool,
}

#[derive(Clone, Subcommand, Default, Debug, Serialize, Deserialize, ValueEnum, PartialEq)]
enum ConstructCommand {
    #[default]
    All,
    SigningKeys,
    FheKeys,
    Crs,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Generate centralized FHE keys, signing keys and the CRS.
    Centralized {
        /// Whether to output the private FHE key separately,
        #[clap(long, default_value_t = false)]
        write_privkey: bool,
    },

    /// Generate shares of FHE key shares and signing keys.
    /// The FHE key shares should only be used for testing.
    /// At the moment it's only limited to 4 parties.
    Threshold {
        /// When using `--cmd signing-keys`, this option can be set
        /// to generate the signing key for a specific party.
        /// If it's not used, then the signing keys are generated for all parties.
        #[clap(long, default_value = None)]
        signing_key_party_id: Option<usize>,
    },
}

struct CentralCmdArgs<'a, S: Storage> {
    pub_storage: &'a mut S,
    priv_storage: &'a mut S,
    deterministic: bool,
    overwrite: bool,
    write_privkey: bool,
    show_existing: bool,
}

struct ThresholdCmdArgs<'a, S: Storage> {
    pub_storages: &'a mut [S],
    priv_storages: &'a mut [S],
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    signing_key_party_id: Option<usize>,
}

/// Execute the KMS key generation
/// Key generation is supported for 2 different modes; centralized and threshold.
/// However, the threshold mode should only be used for testing since keys will get generated centrally.
///
/// For example, to generate centralized keys with the default blockchain parameters
///  run:
/// ```
/// ./kms-gen-keys centralized
/// ```
/// Or from cargo:
/// ```
/// cargo run -F testing --bin kms-gen-keys centralized
/// ```
/// Multiple options are supported which can be explored with
/// ```
/// ./kms-key-gen --help
/// ```
#[tokio::main]
async fn main() {
    init_trace().unwrap();
    let args = Args::parse();
    let aws_config = AWSConfig {
        region: args.aws_region,
        imds_endpoint: args.aws_imds_endpoint,
        s3_endpoint: args.aws_s3_endpoint,
        awskms_endpoint: args.aws_kms_endpoint,
    };
    // create storage
    let amount_storages = match args.mode {
        Mode::Centralized { write_privkey: _ } => 1,
        Mode::Threshold {
            signing_key_party_id: _,
        } => DEFAULT_AMOUNT_PARTIES,
    };
    let mut pub_storages = Vec::with_capacity(amount_storages);
    let mut priv_storages = Vec::with_capacity(amount_storages);
    for i in 1..=amount_storages {
        let party_id = match args.mode {
            Mode::Centralized { write_privkey: _ } => None,
            Mode::Threshold {
                signing_key_party_id: _,
            } => Some(i),
        };
        let root_key_id = args
            .root_key_id
            .as_ref()
            .map(|k| Url::parse(format!("awskms://{}", k).as_str()).unwrap());
        pub_storages.push(
            make_storage(
                Some(aws_config.clone()),
                args.pub_url.clone(),
                None,
                StorageType::PUB,
                party_id,
            )
            .await
            .unwrap(),
        );
        priv_storages.push(
            make_storage(
                Some(aws_config.clone()),
                args.priv_url.clone(),
                root_key_id.clone(),
                StorageType::PRIV,
                party_id,
            )
            .await
            .unwrap(),
        );
    }
    // generate keys
    match args.mode {
        Mode::Centralized { write_privkey } => {
            let mut cmdargs = CentralCmdArgs {
                pub_storage: &mut pub_storages[0],
                priv_storage: &mut priv_storages[0],
                deterministic: args.deterministic,
                overwrite: args.overwrite,
                write_privkey,
                show_existing: args.show_existing,
            };

            if args.cmd == ConstructCommand::All {
                handle_central_cmd(args.param_test, &mut cmdargs, ConstructCommand::SigningKeys)
                    .await;
                handle_central_cmd(args.param_test, &mut cmdargs, ConstructCommand::FheKeys).await;
                handle_central_cmd(args.param_test, &mut cmdargs, ConstructCommand::Crs).await;
            } else {
                handle_central_cmd(args.param_test, &mut cmdargs, args.cmd).await;
            }
        }
        Mode::Threshold {
            signing_key_party_id,
        } => {
            let mut cmdargs = ThresholdCmdArgs {
                pub_storages: &mut pub_storages,
                priv_storages: &mut priv_storages,
                deterministic: args.deterministic,
                overwrite: args.deterministic,
                show_existing: args.show_existing,
                // the `signing_party_id` is only used when the cmd is signing-keys
                signing_key_party_id: match args.cmd {
                    ConstructCommand::SigningKeys => signing_key_party_id,
                    _ => None,
                },
            };

            if args.cmd == ConstructCommand::All {
                handle_threshold_cmd(args.param_test, &mut cmdargs, ConstructCommand::SigningKeys)
                    .await;
                handle_threshold_cmd(args.param_test, &mut cmdargs, ConstructCommand::FheKeys)
                    .await;
                handle_threshold_cmd(args.param_test, &mut cmdargs, ConstructCommand::Crs).await;
            } else {
                handle_threshold_cmd(args.param_test, &mut cmdargs, args.cmd).await;
            }
        }
    }
}

async fn handle_central_cmd<'a, S: StorageForText>(
    param_test: bool,
    args: &mut CentralCmdArgs<'a, S>,
    cmd: ConstructCommand,
) {
    let params = if param_test {
        TEST_PARAM
    } else {
        DEFAULT_PARAM
    };

    match cmd {
        ConstructCommand::All => {
            panic!("\"All\" command must be handled in an outer call");
        }
        ConstructCommand::SigningKeys => {
            process_signing_key_cmds(
                args.pub_storage,
                args.priv_storage,
                &SIGNING_KEY_ID,
                args.show_existing,
                args.overwrite,
            )
            .await;
            if !ensure_central_server_signing_keys_exist(
                args.pub_storage,
                args.priv_storage,
                &SIGNING_KEY_ID,
                args.deterministic,
            )
            .await
            {
                tracing::warn!("Signing keys already exist, skipping generation");
            }
        }
        ConstructCommand::FheKeys => {
            process_fhe_cmds(
                args.pub_storage,
                args.priv_storage,
                &DEFAULT_CENTRAL_KEY_ID,
                args.show_existing,
                args.overwrite,
            )
            .await;
            if !ensure_central_keys_exist(
                args.pub_storage,
                args.priv_storage,
                params,
                &DEFAULT_CENTRAL_KEY_ID,
                &OTHER_CENTRAL_DEFAULT_ID,
                args.deterministic,
                args.write_privkey,
            )
            .await
            {
                tracing::warn!(
                    "FHE keys with default ID {} already exist, skipping generation",
                    DEFAULT_CENTRAL_KEY_ID.to_string()
                );
            }
        }
        ConstructCommand::Crs => {
            process_crs_cmds(
                args.pub_storage,
                args.priv_storage,
                &DEFAULT_CENTRAL_CRS_ID,
                args.show_existing,
                args.overwrite,
            )
            .await;
            if !ensure_central_crs_exists(
                args.pub_storage,
                args.priv_storage,
                params,
                &DEFAULT_CENTRAL_CRS_ID,
                args.deterministic,
            )
            .await
            {
                tracing::warn!(
                    "CRS with default ID {} already exist, skipping generation",
                    DEFAULT_CENTRAL_CRS_ID.to_string()
                );
            }
        }
    }
}

async fn handle_threshold_cmd<'a, S: StorageForText>(
    param_test: bool,
    args: &mut ThresholdCmdArgs<'a, S>,
    cmd: ConstructCommand,
) {
    let params = if param_test {
        TEST_PARAM
    } else {
        DEFAULT_PARAM
    };

    match cmd {
        ConstructCommand::All => panic!("\"All\" command must be handled in an outer call"),
        ConstructCommand::SigningKeys => {
            for (pub_storage, priv_storage) in args
                .pub_storages
                .iter_mut()
                .zip(args.priv_storages.iter_mut())
            {
                process_signing_key_cmds(
                    pub_storage,
                    priv_storage,
                    &SIGNING_KEY_ID,
                    args.show_existing,
                    args.overwrite,
                )
                .await;
            }
            if !ensure_threshold_server_signing_keys_exist(
                args.pub_storages,
                args.priv_storages,
                &SIGNING_KEY_ID,
                args.deterministic,
                match args.signing_key_party_id {
                    Some(i) => ThresholdSigningKeyConfig::OneParty(i),
                    None => ThresholdSigningKeyConfig::AllParties(DEFAULT_AMOUNT_PARTIES),
                },
            )
            .await
            {
                tracing::warn!(
                    "Threshold signing keys with ID {} already exist, skipping generation",
                    DEFAULT_THRESHOLD_KEY_ID_4P.to_string()
                );
            }
        }
        ConstructCommand::FheKeys => {
            for (pub_storage, priv_storage) in args
                .pub_storages
                .iter_mut()
                .zip(args.priv_storages.iter_mut())
            {
                process_fhe_cmds(
                    pub_storage,
                    priv_storage,
                    &DEFAULT_THRESHOLD_KEY_ID_4P,
                    args.show_existing,
                    args.overwrite,
                )
                .await;
            }
            if !ensure_threshold_keys_exist(
                args.pub_storages,
                args.priv_storages,
                params,
                &DEFAULT_THRESHOLD_KEY_ID_4P,
                args.deterministic,
            )
            .await
            {
                tracing::warn!(
                    "Threshold FHE keys with ID {} already exist, skipping generation",
                    DEFAULT_THRESHOLD_KEY_ID_4P.to_string()
                );
            }
        }
        ConstructCommand::Crs => {
            for (pub_storage, priv_storage) in args
                .pub_storages
                .iter_mut()
                .zip(args.priv_storages.iter_mut())
            {
                process_crs_cmds(
                    pub_storage,
                    priv_storage,
                    &DEFAULT_THRESHOLD_CRS_ID_4P,
                    args.show_existing,
                    args.overwrite,
                )
                .await;
            }
            if !ensure_threshold_crs_exists(
                args.pub_storages,
                args.priv_storages,
                params,
                &DEFAULT_THRESHOLD_CRS_ID_4P,
                args.deterministic,
            )
            .await
            {
                tracing::warn!(
                    "Threshold CRS for 4 parties with default ID {} already exist, skipping generation",
                    DEFAULT_THRESHOLD_CRS_ID_4P.to_string()
                );
            }
        }
    }
}
async fn process_crs_cmds<S: Storage>(
    pub_storage: &mut S,
    priv_storage: &mut S,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    process_cmd(
        pub_storage,
        vec![&PubDataType::CRS],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
    process_cmd(
        priv_storage,
        vec![&PrivDataType::CrsInfo],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
}

async fn process_fhe_cmds<S: Storage>(
    pub_storage: &mut S,
    priv_storage: &mut S,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    process_cmd(
        pub_storage,
        vec![
            &PubDataType::PublicKey,
            &PubDataType::ServerKey,
            &PubDataType::SnsKey,
        ],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
    process_cmd(
        priv_storage,
        vec![&PrivDataType::FheKeyInfo, &PrivDataType::SigningKey],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
}

async fn process_signing_key_cmds<S: Storage>(
    pub_storage: &mut S,
    priv_storage: &mut S,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    process_cmd(
        pub_storage,
        vec![&PubDataType::VerfKey],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
    process_cmd(
        pub_storage,
        vec![&PubDataType::VerfAddress],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
    process_cmd(
        priv_storage,
        vec![&PrivDataType::SigningKey],
        req_id,
        show_existing,
        overwrite,
    )
    .await;
}

async fn process_cmd<S: Storage, D: fmt::Display>(
    storage: &mut S,
    data_types: Vec<D>,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    for dt in data_types {
        let data_type = &dt.to_string();
        if show_existing {
            show_key(storage, data_type).await;
            return;
        }
        if overwrite {
            tracing::info!(
                "Deleting {} under request ID {:} from storage \"{}\"...",
                data_type,
                &req_id.to_string(),
                storage.info()
            );
            // Ignore an error as it is likely because the data does not exist
            let _ = delete_at_request_id(storage, req_id, data_type).await;
        }
    }
}

async fn show_key<S: Storage>(storage: &S, data_type: &str) {
    let urlmap = storage.all_urls(data_type).await.unwrap();
    for (k, v) in urlmap {
        // TODO read the key material and print extra info
        let exists = storage.data_exists(&v).await.unwrap();
        println!("{data_type}, {k}, {v}, exists={exists}");
    }
}
