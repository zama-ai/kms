use clap::{Parser, Subcommand, ValueEnum};
use core::fmt;
use futures_util::future::OptionFuture;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::{
    conf::{
        AwsKmsKeySpec, AwsKmsKeychain, FileStorage, Keychain, S3Storage, Storage as StorageConf,
    },
    consts::SIGNING_KEY_ID,
    cryptography::attestation::make_security_module,
    util::key_setup::{
        ensure_central_server_signing_keys_exist, ensure_threshold_server_signing_key_exists,
    },
    vault::{
        Vault,
        aws::build_aws_sdk_config,
        keychain::{awskms::build_aws_kms_client, make_keychain_proxy},
        storage::{Storage, StorageType, delete_at_request_id, make_storage, s3::build_s3_client},
    },
};
use observability::conf::TelemetryConfig;
use observability::telemetry::init_tracing;
use std::{num::NonZeroUsize, path::PathBuf, sync::Arc};
use strum::EnumIs;
use url::Url;

#[derive(Parser)]
#[clap(name = "Zama KMS Signing Key and Certificate Generator")]
#[clap(
    about = "A CLI tool for generating server signing keys and TLS certificates. \
    In centralized mode it produces a single signing key plus its verification material. \
    In threshold mode it produces the signing key and self-signed CA certificate for one party; \
    run it once per party in a multi-party deployment. \
    Multiple options are supported which can be explored with \
    kms-gen-keys --help"
)]
struct Args {
    #[clap(subcommand)]
    mode: Mode,

    /// AWS region to use for S3 storage
    #[clap(long, default_value = "eu-west-3")]
    aws_region: String,
    /// Optional AWS IMDS API endpoint
    #[clap(long, default_value = None)]
    aws_imds_endpoint: Option<Url>,
    /// Optional AWS STS API endpoint
    #[clap(long, default_value = None)]
    aws_sts_endpoint: Option<Url>,
    /// Optional AWS S3 API endpoint
    #[clap(long, default_value = None)]
    aws_s3_endpoint: Option<Url>,
    /// Optional AWS KMS API endpoint
    #[clap(long, default_value = None)]
    aws_kms_endpoint: Option<Url>,
    /// Optional AWS KMS key id that encrypts the private storage
    #[clap(long, default_value = None)]
    root_key_id: Option<String>,
    /// Optional AWS KMS key spec that encrypts the private storage
    #[clap(long, default_value = None, value_enum)]
    root_key_spec: Option<AwsKmsKeySpec>,
    /// Use a software-emulated AWS Nitro security module instead of the real
    /// NSM device. Only available with the `insecure` Cargo feature. See
    /// `kms-server-bin.md` for more information.
    #[cfg(feature = "insecure")]
    #[clap(long, default_value_t = false)]
    mock_enclave: bool,
    #[clap(long, default_value_t = StorageCommand::File, value_enum)]
    private_storage: StorageCommand,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["private_s3_bucket", "private_s3_prefix"],
    )]
    private_file_path: Option<PathBuf>,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["private_s3_bucket", "private_s3_prefix"],
    )]
    private_file_prefix: Option<String>,
    #[clap(
        long,
        default_value = None,
        required_if_eq("private_storage", "s3"),
        conflicts_with_all = ["private_file_path", "private_file_prefix"],
    )]
    private_s3_bucket: Option<String>,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["private_file_path", "private_file_prefix"],
    )]
    private_s3_prefix: Option<String>,

    #[clap(long, default_value_t = StorageCommand::File, value_enum)]
    public_storage: StorageCommand,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["public_s3_bucket", "public_s3_prefix"],
    )]
    public_file_path: Option<PathBuf>,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["public_s3_bucket", "public_s3_prefix"],
    )]
    public_file_prefix: Option<String>,
    #[clap(
        long,
        default_value = None,
        required_if_eq("public_storage", "s3"),
        conflicts_with_all = ["public_file_path", "public_file_prefix"],
    )]
    public_s3_bucket: Option<String>,
    #[clap(
        long,
        default_value = None,
        conflicts_with_all = ["public_file_path", "public_file_prefix"],
    )]
    public_s3_prefix: Option<String>,
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

#[derive(Clone, Subcommand, Default, ValueEnum, EnumIs)]
enum StorageCommand {
    #[default]
    File,
    S3,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Generate the centralized server signing key.
    Centralized,

    /// Generate the signing key and self-signed CA certificate for one
    /// threshold party.
    ///
    /// One invocation generates the material for exactly one party; callers
    /// that operate multiple parties (docker-compose loops, Helm per-pod jobs,
    /// the enclave bootstrap script) invoke `kms-gen-keys threshold` once per
    /// party.
    Threshold {
        /// Index of the party to generate keys for (1-based).
        #[clap(long)]
        signing_key_party_id: NonZeroUsize,

        /// Subject used in the issued TLS certificate.
        #[clap(long, default_value = "kms-party")]
        tls_subject: String,

        /// Whether to include a wildcard SAN entry for the CA certificates
        #[clap(long, default_value_t = false)]
        tls_wildcard: bool,
    },
}

struct CentralCmdArgs<'a, PubS: Storage, PrivS: Storage> {
    pub_storage: &'a mut PubS,
    priv_storage: &'a mut PrivS,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
}

struct ThresholdCmdArgs<'a, PubS: Storage, PrivS: Storage> {
    pub_storage: &'a mut PubS,
    priv_storage: &'a mut PrivS,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    signing_key_party_id: NonZeroUsize,
    tls_subject: String,
    tls_wildcard: bool,
}

/// Generate the server signing keys and TLS material for a KMS deployment.
///
/// Two modes are supported:
/// - `centralized` produces a single signing key.
/// - `threshold` produces one party's signing key and self-signed CA certificate for mTLS.
///
/// Examples:
/// ```
/// cargo run --bin kms-gen-keys -- centralized
/// cargo run --bin kms-gen-keys -- --help
/// ```
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Initialize telemetry with stdout tracing only and disabled metrics
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    init_tracing(&telemetry).await?;

    let aws_sdk_config = build_aws_sdk_config(
        args.aws_region,
        args.aws_imds_endpoint,
        args.aws_sts_endpoint,
    )
    .await;
    // AWS S3 client
    let need_s3_client = args.public_storage.is_s_3() || args.private_storage.is_s_3();
    let s3_client = if need_s3_client {
        Some(build_s3_client(&aws_sdk_config, args.aws_s3_endpoint).await?)
    } else {
        None
    };
    // AWS KMS client
    let need_awskms_client = args.root_key_id.is_some();
    let awskms_client = if need_awskms_client {
        Some(build_aws_kms_client(&aws_sdk_config, args.aws_kms_endpoint).await)
    } else {
        None
    };
    // security module (used for remote attestation with AWS KMS only so far)
    let security_module = if need_awskms_client {
        Some(Arc::new(make_security_module(
            #[cfg(feature = "insecure")]
            args.mock_enclave,
        )?))
    } else {
        None
    };

    // create storages (one pub + one priv per invocation; multi-party
    // deployments invoke this binary once per party)
    let mut pub_storage = make_storage(
        match args.public_storage {
            StorageCommand::File => args.public_file_path.as_ref().map(|path| {
                StorageConf::File(FileStorage {
                    path: path.to_path_buf(),
                    prefix: args.public_file_prefix.clone(),
                })
            }),
            StorageCommand::S3 => Some(StorageConf::S3(S3Storage {
                // clap's `required_if_eq` on `public_s3_bucket` guarantees this
                // is `Some` whenever public_storage == s3.
                bucket: args
                    .public_s3_bucket
                    .as_ref()
                    .expect("clap-required: public_s3_bucket")
                    .clone(),
                prefix: args.public_s3_prefix.clone(),
            })),
        },
        StorageType::PUB,
        s3_client.clone(),
    )?;
    let private_keychain = OptionFuture::from(
        args.root_key_id
            .as_ref()
            .zip(args.root_key_spec.as_ref())
            .map(|(root_key_id, root_key_spec)| {
                Keychain::AwsKms(AwsKmsKeychain {
                    root_key_id: root_key_id.clone(),
                    root_key_spec: root_key_spec.clone(),
                })
            })
            .as_ref()
            .map(|k| {
                make_keychain_proxy(
                    k,
                    awskms_client.clone(),
                    security_module.as_ref().map(Arc::clone),
                    Some(&pub_storage),
                    false,
                )
            }),
    )
    .await
    .transpose()?;
    let mut priv_vault = Vault {
        storage: make_storage(
            match args.private_storage {
                StorageCommand::File => args.private_file_path.as_ref().map(|path| {
                    StorageConf::File(FileStorage {
                        path: path.to_path_buf(),
                        prefix: args.private_file_prefix.clone(),
                    })
                }),
                StorageCommand::S3 => Some(StorageConf::S3(S3Storage {
                    // clap's `required_if_eq` on `private_s3_bucket` guarantees
                    // this is `Some` whenever private_storage == s3.
                    bucket: args
                        .private_s3_bucket
                        .as_ref()
                        .expect("clap-required: private_s3_bucket")
                        .clone(),
                    prefix: args.private_s3_prefix.clone(),
                })),
            },
            StorageType::PRIV,
            s3_client.clone(),
        )?,
        keychain: private_keychain,
    };

    // generate keys
    match args.mode {
        Mode::Centralized => {
            let mut cmdargs = CentralCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                deterministic: args.deterministic,
                overwrite: args.overwrite,
                show_existing: args.show_existing,
            };
            handle_central_cmd(&mut cmdargs).await;
        }
        Mode::Threshold {
            signing_key_party_id,
            tls_subject,
            tls_wildcard,
        } => {
            let mut cmdargs = ThresholdCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                deterministic: args.deterministic,
                overwrite: args.overwrite,
                show_existing: args.show_existing,
                signing_key_party_id,
                tls_subject,
                tls_wildcard,
            };
            handle_threshold_cmd(&mut cmdargs).await;
        }
    }
    tracing::info!("Keygen finished successfully.");
    Ok(())
}

async fn handle_central_cmd<PubS: Storage, PrivS: Storage>(
    args: &mut CentralCmdArgs<'_, PubS, PrivS>,
) {
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

async fn handle_threshold_cmd<PubS: Storage, PrivS: Storage>(
    args: &mut ThresholdCmdArgs<'_, PubS, PrivS>,
) {
    process_signing_key_cmds(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        args.show_existing,
        args.overwrite,
    )
    .await;
    ensure_threshold_server_signing_key_exists(
        args.pub_storage,
        args.priv_storage,
        &SIGNING_KEY_ID,
        args.deterministic,
        args.signing_key_party_id.get(),
        args.tls_subject.clone(),
        args.tls_wildcard,
    )
    .await
    .expect("Could not access storage");
}

async fn process_signing_key_cmds<PubS: Storage, PrivS: Storage>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    req_id: &RequestId,
    show_existing: bool,
    overwrite: bool,
) {
    process_cmd(
        pub_storage,
        vec![
            &PubDataType::VerfKey,
            &PubDataType::VerfAddress,
            &PubDataType::CACert,
        ],
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
    let ids = storage.all_data_ids(data_type).await.unwrap();
    for id in ids {
        // TODO read the key material and print extra info
        let exists = storage.data_exists(&id, data_type).await.unwrap();
        println!("{data_type}, {id}, exists={exists}");
    }
}
