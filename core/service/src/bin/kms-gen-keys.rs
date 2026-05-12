use clap::{Parser, Subcommand, ValueEnum};
use core::fmt;
use futures_util::future::OptionFuture;
use itertools::Itertools;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::{
    conf::{
        AwsKmsKeySpec, AwsKmsKeychain, FileStorage, Keychain, S3Storage, Storage as StorageConf,
    },
    consts::SIGNING_KEY_ID,
    cryptography::attestation::make_security_module,
    util::key_setup::{
        ThresholdSigningKeyConfig, ensure_central_server_signing_keys_exist,
        ensure_threshold_server_signing_keys_exist,
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
use std::{path::PathBuf, sync::Arc};
use strum::EnumIs;
use url::Url;

#[derive(Parser)]
#[clap(name = "Zama KMS Signing Key and Certificate Generator")]
#[clap(
    about = "A CLI tool for generating server signing keys and TLS certificates. \
    In centralized mode it produces a single signing key plus its verification material. \
    In threshold mode it produces per-party signing keys and the self-signed CA certificates \
    used for mTLS between parties. \
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
    #[clap(long, default_value = None)]
    private_file_path: Option<PathBuf>,
    #[clap(long, default_value = None)]
    private_file_prefix: Option<String>,
    #[clap(long, default_value = None)]
    private_s3_bucket: Option<String>,
    #[clap(long, default_value = None)]
    private_s3_prefix: Option<String>,

    #[clap(long, default_value_t = StorageCommand::File, value_enum)]
    public_storage: StorageCommand,
    #[clap(long, default_value = None)]
    public_file_path: Option<PathBuf>,
    #[clap(long, default_value = None)]
    public_file_prefix: Option<String>,
    #[clap(long, default_value = None)]
    public_s3_bucket: Option<String>,
    #[clap(long, default_value = None)]
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

    /// Generate per-party signing keys and self-signed CA certificates for a threshold deployment.
    Threshold {
        /// Generate the signing key for a specific party only.
        /// If unset, signing keys are generated for all parties.
        ///
        /// If set, the party ID cannot be higher than `num_parties`.
        #[clap(long, default_value = None)]
        signing_key_party_id: Option<usize>,

        /// Set the total number of parties.
        ///
        /// This configuration is required even when `signing_key_party_id``
        /// is given.
        #[clap(long, default_value_t = 4)]
        num_parties: usize,

        /// Set the subject in the issued TLS certificate, if
        /// --signing-key-party-id is set, or the prefix for the subject in
        /// certificates for all parties if not.
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
    pub_storages: &'a mut [PubS],
    priv_storages: &'a mut [PrivS],
    deterministic: bool,
    overwrite: bool,
    show_existing: bool,
    signing_key_party_id: Option<usize>,
    num_parties: usize,
    tls_subject: String,
    tls_wildcard: bool,
}

impl<'a, PubS: Storage, PrivS: Storage> ThresholdCmdArgs<'a, PubS, PrivS> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        pub_storages: &'a mut [PubS],
        priv_storages: &'a mut [PrivS],
        deterministic: bool,
        overwrite: bool,
        show_existing: bool,
        signing_key_party_id: Option<usize>,
        num_parties: usize,
        tls_subject: String,
        tls_wildcard: bool,
    ) -> anyhow::Result<Self> {
        if num_parties < 2 {
            anyhow::bail!("the number of parties should be larger or equal to 2");
        }
        if let Some(id) = signing_key_party_id
            && id > num_parties
        {
            anyhow::bail!(
                "party ID ({}) cannot be greater than num_parties ({})",
                id,
                num_parties
            );
        }
        if let Some(id) = signing_key_party_id
            && id == 0
        {
            anyhow::bail!("party ID cannot be 0",);
        }
        Ok(Self {
            pub_storages,
            priv_storages,
            deterministic,
            overwrite,
            show_existing,
            signing_key_party_id,
            num_parties,
            tls_subject,
            tls_wildcard,
        })
    }
}

/// Generate the server signing keys and TLS material for a KMS deployment.
///
/// Two modes are supported:
/// - `centralized` produces a single signing key.
/// - `threshold` produces per-party signing keys and self-signed CA certificates for mTLS.
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

    // create storages
    let amount_storages = match args.mode {
        Mode::Centralized => 1,
        Mode::Threshold {
            signing_key_party_id: _,
            num_parties: n,
            tls_subject: _,
            tls_wildcard: _,
        } => n,
    };
    let mut pub_storages = Vec::with_capacity(amount_storages);
    let mut priv_vaults = Vec::with_capacity(amount_storages);
    for _i in 1..=amount_storages {
        let pub_proxy_storage = make_storage(
            match args.public_storage {
                StorageCommand::File => args.public_file_path.as_ref().map(|path| {
                    StorageConf::File(FileStorage {
                        path: path.to_path_buf(),
                        prefix: args.public_file_prefix.clone(),
                    })
                }),
                StorageCommand::S3 => Some(StorageConf::S3(S3Storage {
                    bucket: args
                        .public_s3_bucket
                        .as_ref()
                        .expect("S3 bucket must be set for public storage")
                        .clone(),
                    prefix: args.public_s3_prefix.clone(),
                })),
            },
            StorageType::PUB,
            s3_client.clone(),
        )
        .unwrap();
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
                        Some(&pub_proxy_storage),
                        false,
                    )
                }),
        )
        .await
        .transpose()?;
        pub_storages.push(pub_proxy_storage);
        priv_vaults.push(Vault {
            storage: make_storage(
                match args.private_storage {
                    StorageCommand::File => args.private_file_path.as_ref().map(|path| {
                        StorageConf::File(FileStorage {
                            path: path.to_path_buf(),
                            prefix: args.private_file_prefix.clone(),
                        })
                    }),
                    StorageCommand::S3 => Some(StorageConf::S3(S3Storage {
                        bucket: args
                            .private_s3_bucket
                            .as_ref()
                            .expect("S3 bucket must be set for private storage")
                            .clone(),
                        prefix: args.private_s3_prefix.clone(),
                    })),
                },
                StorageType::PRIV,
                s3_client.clone(),
            )
            .unwrap(),
            keychain: private_keychain,
        });
    }
    // generate keys
    match args.mode {
        Mode::Centralized => {
            let mut cmdargs = CentralCmdArgs {
                pub_storage: &mut pub_storages[0],
                priv_storage: &mut priv_vaults[0],
                deterministic: args.deterministic,
                overwrite: args.overwrite,
                show_existing: args.show_existing,
            };
            handle_central_cmd(&mut cmdargs).await;
        }
        Mode::Threshold {
            signing_key_party_id,
            num_parties,
            tls_subject,
            tls_wildcard,
        } => {
            let mut cmdargs = ThresholdCmdArgs::new(
                &mut pub_storages,
                &mut priv_vaults,
                args.deterministic,
                args.overwrite,
                args.show_existing,
                signing_key_party_id,
                num_parties,
                tls_subject,
                tls_wildcard,
            )?;
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
    // Will panic if the number of public and private storages is not equal
    for (pub_storage, priv_storage) in args
        .pub_storages
        .iter_mut()
        .zip_eq(args.priv_storages.iter_mut())
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
            Some(i) => ThresholdSigningKeyConfig::OneParty(i, args.tls_subject.clone()),
            None => ThresholdSigningKeyConfig::AllParties(
                (1..=args.num_parties)
                    .map(|i| format!("{}-{}", args.tls_subject, i))
                    .collect(),
            ),
        },
        args.tls_wildcard,
    )
    .await
    .expect("Could not access storage")
    {
        tracing::warn!("Threshold signing keys already exist, skipping generation");
    }
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
