use anyhow::{Context, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use core::fmt;
use futures_util::future::OptionFuture;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::{
    conf::{
        AWSConfig, AwsKmsKeySpec, AwsKmsKeychain, CoreConfig, EnclaveBootstrapConfig,
        FileStorage as FileStorageConfig, Keychain, S3Storage as S3StorageConfig,
        Storage as StorageConfig, VaultConfig, init_conf,
        threshold::{PeerConf, ThresholdPartyConf},
    },
    consts::{KEY_PATH_PREFIX, SIGNING_KEY_ID},
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
use serde::{Deserialize, Serialize};
use std::{num::NonZeroUsize, path::PathBuf, sync::Arc};
use strum::EnumIs;
use url::Url;
use validator::{Validate, ValidationErrors};

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
    /// Read key-generation settings from a TOML config file.
    ///
    /// This accepts the keygen-only enclave config and the full kms-server
    /// config. When present, the mode subcommand and storage/AWS CLI flags are
    /// ignored; `deterministic`, `overwrite`, and `show-existing` still apply.
    #[clap(long, default_value = None)]
    config_file: Option<String>,

    #[clap(subcommand)]
    mode: Option<Mode>,

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

#[derive(Clone, Copy, Subcommand, Default, ValueEnum, EnumIs)]
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

#[derive(Clone, Debug, PartialEq)]
enum KeygenMode {
    Centralized,
    Threshold {
        signing_key_party_id: NonZeroUsize,
        tls_subject: String,
        tls_wildcard: bool,
    },
}

#[derive(Clone, Debug)]
struct KmsGenKeysRunConfig {
    mode: KeygenMode,
    aws: Option<AWSConfig>,
    public_storage: Option<StorageConfig>,
    private_storage: Option<StorageConfig>,
    private_keychain: Option<Keychain>,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    #[cfg(feature = "insecure")]
    mock_enclave: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(untagged)]
enum KmsGenKeysConfigFile {
    Keygen(Box<KmsGenKeysOnlyConfig>),
    Server(Box<CoreConfig>),
}

impl Validate for KmsGenKeysConfigFile {
    fn validate(&self) -> Result<(), ValidationErrors> {
        match self {
            Self::Keygen(config) => config.validate(),
            Self::Server(config) => config.validate(),
        }
    }
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KmsGenKeysOnlyConfig {
    keygen: Option<KeygenConfig>,
    #[validate(nested)]
    aws: Option<AWSConfig>,
    #[validate(nested)]
    public_vault: Option<VaultConfig>,
    #[validate(nested)]
    private_vault: Option<VaultConfig>,
    #[validate(nested)]
    backup_vault: Option<VaultConfig>,
    #[validate(nested)]
    threshold: Option<KeygenThresholdConfig>,
    #[validate(nested)]
    enclave_bootstrap: Option<EnclaveBootstrapConfig>,
    #[cfg(feature = "insecure")]
    mock_enclave: Option<bool>,
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KeygenConfig {
    enabled: Option<bool>,
}

#[derive(Serialize, Deserialize, Validate, Clone, Debug)]
#[serde(deny_unknown_fields)]
struct KeygenThresholdConfig {
    #[validate(range(min = 1))]
    my_id: Option<usize>,
    #[validate(length(min = 1))]
    tls_subject: Option<String>,
    tls_wildcard: Option<bool>,
    #[validate(nested)]
    peers: Option<Vec<PeerConf>>,
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

fn resolve_args(args: &Args) -> anyhow::Result<KmsGenKeysRunConfig> {
    if let Some(config_file) = args.config_file.as_deref() {
        ensure!(
            args.mode.is_none(),
            "--config-file cannot be combined with a mode subcommand"
        );
        let config = init_conf::<KmsGenKeysConfigFile>(config_file)
            .with_context(|| format!("failed to load kms-gen-keys config file {config_file}"))?;
        config
            .validate()
            .context("invalid kms-gen-keys config file")?;
        return resolve_config_file(
            config,
            args.deterministic,
            args.overwrite,
            args.show_existing,
            #[cfg(feature = "insecure")]
            args.mock_enclave,
        );
    }

    let mode = args
        .mode
        .clone()
        .context("kms-gen-keys requires either --config-file or a mode subcommand")?;
    resolve_cli_args(args, mode)
}

fn resolve_config_file(
    config: KmsGenKeysConfigFile,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    #[cfg(feature = "insecure")] cli_mock_enclave: bool,
) -> anyhow::Result<KmsGenKeysRunConfig> {
    match config {
        KmsGenKeysConfigFile::Keygen(config) => resolve_keygen_config_file(
            *config,
            deterministic,
            overwrite,
            show_existing,
            #[cfg(feature = "insecure")]
            cli_mock_enclave,
        ),
        KmsGenKeysConfigFile::Server(config) => resolve_server_config_file(
            *config,
            deterministic,
            overwrite,
            show_existing,
            #[cfg(feature = "insecure")]
            cli_mock_enclave,
        ),
    }
}

fn resolve_keygen_config_file(
    config: KmsGenKeysOnlyConfig,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    #[cfg(feature = "insecure")] cli_mock_enclave: bool,
) -> anyhow::Result<KmsGenKeysRunConfig> {
    if config
        .keygen
        .as_ref()
        .and_then(|keygen| keygen.enabled)
        .is_some_and(|enabled| !enabled)
    {
        bail!("[keygen].enabled is false");
    }

    let mode = resolve_keygen_config_mode(config.threshold.as_ref())?;
    let public_storage = config.public_vault.map(|vault| vault.storage);
    let (private_storage, private_keychain) = config
        .private_vault
        .map(|vault| (Some(vault.storage), vault.keychain))
        .unwrap_or((None, None));

    Ok(KmsGenKeysRunConfig {
        mode,
        aws: config.aws,
        public_storage,
        private_storage,
        private_keychain,
        deterministic,
        overwrite,
        show_existing,
        #[cfg(feature = "insecure")]
        mock_enclave: cli_mock_enclave || config.mock_enclave.unwrap_or(false),
    })
}

fn resolve_server_config_file(
    config: CoreConfig,
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    #[cfg(feature = "insecure")] cli_mock_enclave: bool,
) -> anyhow::Result<KmsGenKeysRunConfig> {
    let mode = resolve_server_config_mode(config.threshold.as_ref())?;
    let public_storage = config.public_vault.map(|vault| vault.storage);
    let (private_storage, private_keychain) = config
        .private_vault
        .map(|vault| (Some(vault.storage), vault.keychain))
        .unwrap_or((None, None));

    Ok(KmsGenKeysRunConfig {
        mode,
        aws: config.aws,
        public_storage,
        private_storage,
        private_keychain,
        deterministic,
        overwrite,
        show_existing,
        #[cfg(feature = "insecure")]
        mock_enclave: cli_mock_enclave || config.mock_enclave.unwrap_or(false),
    })
}

fn resolve_keygen_config_mode(
    threshold: Option<&KeygenThresholdConfig>,
) -> anyhow::Result<KeygenMode> {
    let Some(threshold) = threshold else {
        return Ok(KeygenMode::Centralized);
    };

    let my_id = threshold
        .my_id
        .context("threshold.my_id is required when generating threshold signing keys")?;
    let signing_key_party_id =
        NonZeroUsize::new(my_id).context("threshold.my_id must be non-zero")?;
    let tls_subject = resolve_threshold_tls_subject(
        threshold.tls_subject.as_deref(),
        threshold.peers.as_deref(),
        my_id,
    )?;

    Ok(KeygenMode::Threshold {
        signing_key_party_id,
        tls_subject,
        tls_wildcard: threshold.tls_wildcard.unwrap_or(false),
    })
}

fn resolve_server_config_mode(
    threshold: Option<&ThresholdPartyConf>,
) -> anyhow::Result<KeygenMode> {
    let Some(threshold) = threshold else {
        return Ok(KeygenMode::Centralized);
    };

    let my_id = threshold
        .my_id
        .context("threshold.my_id is required when generating threshold signing keys")?;
    let signing_key_party_id =
        NonZeroUsize::new(my_id).context("threshold.my_id must be non-zero")?;
    let tls_subject = resolve_threshold_tls_subject(None, threshold.peers.as_deref(), my_id)?;

    Ok(KeygenMode::Threshold {
        signing_key_party_id,
        tls_subject,
        tls_wildcard: false,
    })
}

fn resolve_threshold_tls_subject(
    explicit_subject: Option<&str>,
    peers: Option<&[PeerConf]>,
    my_id: usize,
) -> anyhow::Result<String> {
    if let Some(subject) = explicit_subject
        .map(str::trim)
        .filter(|subject| !subject.is_empty())
    {
        return Ok(subject.to_string());
    }

    let peers = peers.context(
        "threshold.tls_subject is not set and threshold.peers is missing; cannot derive TLS subject",
    )?;
    let peer = peers.iter().find(|peer| peer.party_id == my_id).ok_or_else(|| {
        anyhow::anyhow!(
            "threshold.tls_subject is not set and threshold.peers has no entry for party {my_id}"
        )
    })?;
    let subject = peer
        .mpc_identity
        .as_deref()
        .map(str::trim)
        .filter(|identity| !identity.is_empty())
        .unwrap_or_else(|| peer.address.trim());
    ensure!(
        !subject.is_empty(),
        "cannot derive TLS subject for party {my_id} from an empty peer identity/address"
    );
    Ok(subject.to_string())
}

fn resolve_cli_args(args: &Args, mode: Mode) -> anyhow::Result<KmsGenKeysRunConfig> {
    Ok(KmsGenKeysRunConfig {
        mode: match mode {
            Mode::Centralized => KeygenMode::Centralized,
            Mode::Threshold {
                signing_key_party_id,
                tls_subject,
                tls_wildcard,
            } => KeygenMode::Threshold {
                signing_key_party_id,
                tls_subject,
                tls_wildcard,
            },
        },
        aws: Some(AWSConfig {
            region: args.aws_region.clone(),
            role_arn: None,
            imds_endpoint: args.aws_imds_endpoint.clone(),
            sts_endpoint: args.aws_sts_endpoint.clone(),
            s3_endpoint: args.aws_s3_endpoint.clone(),
            awskms_endpoint: args.aws_kms_endpoint.clone(),
        }),
        public_storage: resolve_cli_storage(
            "public",
            args.public_storage,
            &args.public_file_path,
            &args.public_file_prefix,
            &args.public_s3_bucket,
            &args.public_s3_prefix,
        )?,
        private_storage: resolve_cli_storage(
            "private",
            args.private_storage,
            &args.private_file_path,
            &args.private_file_prefix,
            &args.private_s3_bucket,
            &args.private_s3_prefix,
        )?,
        private_keychain: resolve_cli_keychain(args)?,
        deterministic: args.deterministic,
        overwrite: args.overwrite,
        show_existing: args.show_existing,
        #[cfg(feature = "insecure")]
        mock_enclave: args.mock_enclave,
    })
}

fn resolve_cli_storage(
    name: &str,
    storage: StorageCommand,
    file_path: &Option<PathBuf>,
    file_prefix: &Option<String>,
    s3_bucket: &Option<String>,
    s3_prefix: &Option<String>,
) -> anyhow::Result<Option<StorageConfig>> {
    match storage {
        StorageCommand::File => Ok((file_path.is_some() || file_prefix.is_some()).then(|| {
            StorageConfig::File(FileStorageConfig {
                path: file_path
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(KEY_PATH_PREFIX)),
                prefix: file_prefix.clone(),
            })
        })),
        StorageCommand::S3 => Ok(Some(StorageConfig::S3(S3StorageConfig {
            bucket: s3_bucket.clone().with_context(|| {
                format!("--{name}-s3-bucket is required with --{name}-storage s3")
            })?,
            prefix: s3_prefix.clone(),
        }))),
    }
}

fn resolve_cli_keychain(args: &Args) -> anyhow::Result<Option<Keychain>> {
    match (&args.root_key_id, &args.root_key_spec) {
        (Some(root_key_id), Some(root_key_spec)) => Ok(Some(Keychain::AwsKms(AwsKmsKeychain {
            root_key_id: root_key_id.clone(),
            root_key_spec: root_key_spec.clone(),
        }))),
        (None, None) => Ok(None),
        (Some(_), None) => bail!("--root-key-spec is required when --root-key-id is set"),
        (None, Some(_)) => bail!("--root-key-id is required when --root-key-spec is set"),
    }
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
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize telemetry with stdout tracing only and disabled metrics
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    init_tracing(&telemetry).await?;

    let resolved = resolve_args(&args)?;

    // AWS S3 client
    let need_s3_client = resolved
        .public_storage
        .as_ref()
        .is_some_and(StorageConfig::is_s_3)
        || resolved
            .private_storage
            .as_ref()
            .is_some_and(StorageConfig::is_s_3);
    // AWS KMS client
    let need_awskms_client = resolved
        .private_keychain
        .as_ref()
        .is_some_and(Keychain::is_aws_kms);
    let aws_sdk_config = if need_s3_client || need_awskms_client || resolved.aws.is_some() {
        let aws = resolved
            .aws
            .as_ref()
            .context("[aws] config is required when using S3 storage or an AWS KMS keychain")?;
        Some(
            build_aws_sdk_config(
                aws.region.clone(),
                aws.imds_endpoint.clone(),
                aws.sts_endpoint.clone(),
            )
            .await,
        )
    } else {
        None
    };
    let s3_client = if need_s3_client {
        Some(
            build_s3_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS config is built when S3 storage is configured"),
                resolved
                    .aws
                    .as_ref()
                    .and_then(|aws| aws.s3_endpoint.clone()),
            )
            .await?,
        )
    } else {
        None
    };
    let awskms_client = if need_awskms_client {
        Some(
            build_aws_kms_client(
                aws_sdk_config
                    .as_ref()
                    .expect("AWS config is built when AWS KMS keychain is configured"),
                resolved
                    .aws
                    .as_ref()
                    .and_then(|aws| aws.awskms_endpoint.clone()),
            )
            .await,
        )
    } else {
        None
    };
    // security module (used for remote attestation with AWS KMS only so far)
    let security_module = if need_awskms_client {
        Some(Arc::new(make_security_module(
            #[cfg(feature = "insecure")]
            resolved.mock_enclave,
        )?))
    } else {
        None
    };

    // create storages (one pub + one priv per invocation; multi-party
    // deployments invoke this binary once per party)
    let mut pub_storage = make_storage(
        resolved.public_storage.clone(),
        StorageType::PUB,
        s3_client.clone(),
    )?;
    let private_keychain = OptionFuture::from(resolved.private_keychain.as_ref().map(|k| {
        make_keychain_proxy(
            k,
            awskms_client.clone(),
            security_module.as_ref().map(Arc::clone),
            Some(&pub_storage),
            false,
        )
    }))
    .await
    .transpose()?;
    let mut priv_vault = Vault {
        storage: make_storage(resolved.private_storage, StorageType::PRIV, s3_client)?,
        keychain: private_keychain,
    };

    // generate keys
    match resolved.mode {
        KeygenMode::Centralized => {
            let mut cmdargs = CentralCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                deterministic: resolved.deterministic,
                overwrite: resolved.overwrite,
                show_existing: resolved.show_existing,
            };
            handle_central_cmd(&mut cmdargs).await;
        }
        KeygenMode::Threshold {
            signing_key_party_id,
            tls_subject,
            tls_wildcard,
        } => {
            let mut cmdargs = ThresholdCmdArgs {
                pub_storage: &mut pub_storage,
                priv_storage: &mut priv_vault,
                deterministic: resolved.deterministic,
                overwrite: resolved.overwrite,
                show_existing: resolved.show_existing,
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
        args.signing_key_party_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> KmsGenKeysOnlyConfig {
        KmsGenKeysOnlyConfig {
            keygen: Some(KeygenConfig {
                enabled: Some(true),
            }),
            aws: None,
            public_vault: None,
            private_vault: None,
            backup_vault: None,
            threshold: None,
            enclave_bootstrap: None,
            #[cfg(feature = "insecure")]
            mock_enclave: None,
        }
    }

    fn threshold_config(my_id: Option<usize>) -> KeygenThresholdConfig {
        KeygenThresholdConfig {
            my_id,
            tls_subject: None,
            tls_wildcard: None,
            peers: None,
        }
    }

    fn peer(party_id: usize, address: &str, mpc_identity: Option<&str>) -> PeerConf {
        PeerConf {
            party_id,
            address: address.to_string(),
            mpc_identity: mpc_identity.map(ToString::to_string),
            port: 50001,
            tls_cert: None,
            verification_address: None,
        }
    }

    fn resolve_config_for_test(
        config: KmsGenKeysConfigFile,
    ) -> anyhow::Result<KmsGenKeysRunConfig> {
        resolve_config_file(
            config,
            false,
            false,
            false,
            #[cfg(feature = "insecure")]
            false,
        )
    }

    fn resolved_tls_subject(resolved: KmsGenKeysRunConfig) -> String {
        match resolved.mode {
            KeygenMode::Threshold { tls_subject, .. } => tls_subject,
            KeygenMode::Centralized => panic!("expected threshold mode"),
        }
    }

    #[test]
    fn config_file_resolves_centralized_defaults() {
        let resolved =
            resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(base_config()))).unwrap();

        assert_eq!(resolved.mode, KeygenMode::Centralized);
        assert!(resolved.public_storage.is_none());
        assert!(resolved.private_storage.is_none());
        assert!(resolved.private_keychain.is_none());
    }

    #[test]
    fn threshold_tls_subject_prefers_explicit_config() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.tls_subject = Some(" explicit-party ".to_string());
        threshold.peers = Some(vec![peer(2, "peer-address", Some("peer-identity"))]);
        config.threshold = Some(threshold);

        let resolved =
            resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config))).unwrap();

        assert_eq!(resolved_tls_subject(resolved), "explicit-party");
    }

    #[test]
    fn threshold_tls_subject_uses_matching_peer_identity() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.peers = Some(vec![
            peer(1, "party-one-address", Some("party-one")),
            peer(2, "party-two-address", Some("party-two")),
        ]);
        config.threshold = Some(threshold);

        let resolved =
            resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config))).unwrap();

        assert_eq!(resolved_tls_subject(resolved), "party-two");
    }

    #[test]
    fn threshold_tls_subject_falls_back_to_peer_address() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(1));
        threshold.peers = Some(vec![peer(1, "party-one-address", Some("   "))]);
        config.threshold = Some(threshold);

        let resolved =
            resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config))).unwrap();

        assert_eq!(resolved_tls_subject(resolved), "party-one-address");
    }

    #[test]
    fn threshold_config_requires_my_id() {
        let mut config = base_config();
        let mut threshold = threshold_config(None);
        threshold.tls_subject = Some("party-one".to_string());
        config.threshold = Some(threshold);

        let err = resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config)))
            .unwrap_err()
            .to_string();

        assert!(err.contains("threshold.my_id"));
    }

    #[test]
    fn threshold_config_requires_matching_peer_when_subject_is_not_explicit() {
        let mut config = base_config();
        let mut threshold = threshold_config(Some(2));
        threshold.peers = Some(vec![peer(1, "party-one-address", None)]);
        config.threshold = Some(threshold);

        let err = resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config)))
            .unwrap_err()
            .to_string();

        assert!(err.contains("no entry for party 2"));
    }

    #[test]
    fn config_file_preserves_aws_storage_and_keychain() {
        let mut config = base_config();
        config.aws = Some(AWSConfig {
            region: "us-east-1".to_string(),
            role_arn: Some("arn:aws:iam::123456789012:role/kms".to_string()),
            imds_endpoint: Some(Url::parse("http://127.0.0.1:5000").unwrap()),
            sts_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
            s3_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
            awskms_endpoint: Some(Url::parse("http://127.0.0.1:4566").unwrap()),
        });
        config.public_vault = Some(VaultConfig {
            storage: StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p1".to_string()),
            }),
            keychain: None,
        });
        config.private_vault = Some(VaultConfig {
            storage: StorageConfig::File(FileStorageConfig {
                path: PathBuf::from("/keys"),
                prefix: Some("PRIV-p1".to_string()),
            }),
            keychain: Some(Keychain::AwsKms(AwsKmsKeychain {
                root_key_id: "root-key".to_string(),
                root_key_spec: AwsKmsKeySpec::Symm,
            })),
        });

        let resolved =
            resolve_config_for_test(KmsGenKeysConfigFile::Keygen(Box::new(config))).unwrap();

        assert_eq!(
            resolved.aws.as_ref().map(|aws| aws.region.as_str()),
            Some("us-east-1")
        );
        assert_eq!(
            resolved.public_storage,
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p1".to_string()),
            }))
        );
        assert_eq!(
            resolved.private_storage,
            Some(StorageConfig::File(FileStorageConfig {
                path: PathBuf::from("/keys"),
                prefix: Some("PRIV-p1".to_string()),
            }))
        );
        assert_eq!(
            resolved.private_keychain,
            Some(Keychain::AwsKms(AwsKmsKeychain {
                root_key_id: "root-key".to_string(),
                root_key_spec: AwsKmsKeySpec::Symm,
            }))
        );
    }

    #[test]
    fn server_config_uses_core_config_threshold_shape() {
        let config = init_conf::<KmsGenKeysConfigFile>("config/default_1").unwrap();
        config.validate().unwrap();

        let resolved = resolve_config_for_test(config).unwrap();

        assert_eq!(resolved_tls_subject(resolved), "p1");
    }

    #[test]
    fn keygen_toml_deserializes_and_resolves() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("kms-gen-keys.toml");
        std::fs::write(
            &config_path,
            r#"
[keygen]
enabled = true

[threshold]
my_id = 2
tls_subject = "kms-core-2"

[aws]
region = "eu-west-3"
s3_endpoint = "http://127.0.0.1:4566"
awskms_endpoint = "http://127.0.0.1:4566"

[public_vault.storage.s3]
bucket = "public-bucket"
prefix = "PUB-p2"

[private_vault.storage.s3]
bucket = "private-bucket"
prefix = "PRIV-p2"

[private_vault.keychain.aws_kms]
root_key_id = "root-key"
root_key_spec = "symm"
"#,
        )
        .unwrap();

        let config = init_conf::<KmsGenKeysConfigFile>(config_path.to_str().unwrap()).unwrap();
        config.validate().unwrap();
        let resolved = resolve_config_for_test(config).unwrap();

        assert_eq!(resolved_tls_subject(resolved.clone()), "kms-core-2");
        assert_eq!(
            resolved.public_storage,
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "public-bucket".to_string(),
                prefix: Some("PUB-p2".to_string()),
            }))
        );
        assert_eq!(
            resolved.private_storage,
            Some(StorageConfig::S3(S3StorageConfig {
                bucket: "private-bucket".to_string(),
                prefix: Some("PRIV-p2".to_string()),
            }))
        );
    }
}
