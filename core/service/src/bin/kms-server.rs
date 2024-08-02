use clap::{Parser, Subcommand};
use kms_lib::conf::centralized::CentralizedConfig;
use kms_lib::conf::init_conf_trace;
use kms_lib::conf::storage::StorageConfigWith;
use kms_lib::conf::threshold::ThresholdConfig;
use kms_lib::rpc::central_rpc::server_handle as kms_server_handle;
use kms_lib::rpc::central_rpc_proxy::server_handle as kms_proxy_server_handle;
use kms_lib::storage::{url_to_pathbuf, FileStorage, StorageType};
use kms_lib::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
use kms_lib::util::aws::{EnclaveS3Storage, S3Storage};
use kms_lib::StorageProxy;

pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
#[clap(name = "KMS server")]
#[clap(
    about = "We support two types of execution modes, `centralized` or `threshold`. \
    See the help page for additional details (`kms-server --help`). \n
    Use the following to run a threshold KMS node with the default configuration \
    (from `core/service/config/default_1.toml`): \n
    ./kms-server centralized \n
    or using cargo from the `core/service` directory: \n
    cargo run --bin kms-server centralized \n
    Observe that some optional arguments may be added, in particular the location for key material storage. \
    More specifically for both the centralized and threshold  execution modes, \
    the configuration file used can be specified with the `--config-file` argument. \
    E.g.\n
    ./kms-server centralized --config-file config/default_centralized.toml \n
    If no configuration file is specified, the default configuration will be used \
    (e.g. config/default_centralized.toml for the centralize case). \n
    Note that key material and TLS certificates MUST exist when starting the server and be stored in the path specified by the configuration file. \n
    Please consult the `kms-gen-keys` and `kms-gen-tls-certs` binaries for details on generating key material and certificates."
)]
struct KmsArgs {
    #[clap(subcommand)]
    mode: ExecutionMode,
}

#[derive(Subcommand, Clone)]
enum ExecutionMode {
    Threshold {
        // TODO at the moment this is just the threshold specific configuration,
        // eventually we will generalize the configuration to also include
        // parameter and key locations.
        #[clap(
            long,
            default_value = "config/default_1.toml",
            help = "path to the configuration file"
        )]
        config_file: String,
    },
    Centralized {
        #[clap(
            long,
            default_value = "config/default_centralized.toml",
            help = "path to the configuration file"
        )]
        config_file: String,
    },
    NitroEnclaveProxy {
        /// Enclave application CID for proxying
        #[clap(
            long,
            default_value = "config/default_centralized_enclave_proxy.toml",
            help = "path to the configuration file"
        )]
        config_file: String,
    },
}

/// Starts a KMS server.
/// We support two execution modes, `centralized` or `threshold`.
/// See the help page for additional details.
/// For example, use the following to run a threshold KMS node with the default configuration
/// (from `core/service/config/default_1.toml`):
/// ```
/// ./kms-server centralized
/// ```
/// or using cargo from the `core/service` directory:
/// ```
/// cargo run --bin kms-server centralized
/// ```
///
/// Observe that some optional arguments may be added, in particular the location for key material storage.. More specifically for both the centralized and threshold
/// execution modes, the configuration file used can be specified with the `--config-file` argument.
/// E.g.
/// ```
/// cargo run --bin kms-server centralized --config-file config/default_centralized.toml
/// ```
/// If no configuration file is specified, the default configuration will be used
/// (e.g. config/default_centralized.toml for the centralize case).
///
/// Note that key material MUST exist when starting the server and be stored in the path specified by the configuration file.
/// Please consult the `kms-gen-keys` binary for details on generating key material.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = KmsArgs::parse();
    match args.mode {
        ExecutionMode::Threshold { config_file } => {
            let config: StorageConfigWith<ThresholdConfig> = init_conf_trace(&config_file)?;

            let pub_storage = match config.public_storage_url()? {
                Some(url) => match url.scheme() {
                    "s3" => StorageProxy::S3(
                        S3Storage::new_threshold(
                            config.aws_region.clone().unwrap(),
                            config.aws_s3_proxy.clone(),
                            url.host_str().unwrap().to_string(),
                            Some(url.path().to_string()),
                            StorageType::PUB,
                            config.rest.my_id,
                        )
                        .await,
                    ),
                    _ => StorageProxy::File(FileStorage::new_threshold(
                        Some(url_to_pathbuf(&url).as_path()),
                        StorageType::PUB,
                        config.rest.my_id,
                    )?),
                },
                None => StorageProxy::File(FileStorage::new_threshold(
                    None,
                    StorageType::PUB,
                    config.rest.my_id,
                )?),
            };
            let priv_storage = match config.private_storage_url()? {
                Some(url) => match url.scheme() {
                    "s3" => StorageProxy::EnclaveS3(
                        EnclaveS3Storage::new_threshold(
                            config.aws_region.clone().unwrap(),
                            config.aws_s3_proxy.clone().unwrap(),
                            config.aws_kms_proxy.clone().unwrap(),
                            url.host_str().unwrap().to_string(),
                            Some(url.path().to_string()),
                            StorageType::PRIV,
                            config.rest.my_id,
                            config.root_key_id.clone().unwrap(),
                        )
                        .await?,
                    ),
                    _ => StorageProxy::File(FileStorage::new_threshold(
                        Some(url_to_pathbuf(&url).as_path()),
                        StorageType::PRIV,
                        config.rest.my_id,
                    )?),
                },
                None => StorageProxy::File(FileStorage::new_threshold(
                    None,
                    StorageType::PRIV,
                    config.rest.my_id,
                )?),
            };

            let server =
                threshold_server_init(config.clone().into(), pub_storage, priv_storage, false)
                    .await?;
            threshold_server_start(
                config.rest.listen_address_client,
                config.rest.listen_port_client,
                config.rest.timeout_secs,
                config.rest.grpc_max_message_size,
                server,
            )
            .await
        }
        ExecutionMode::Centralized { config_file } => {
            let config: StorageConfigWith<CentralizedConfig> = init_conf_trace(&config_file)?;
            let pub_storage = match config.public_storage_url()? {
                Some(url) => match url.scheme() {
                    "s3" => StorageProxy::S3(
                        S3Storage::new_centralized(
                            config.aws_region.clone().unwrap(),
                            config.aws_s3_proxy.clone(),
                            url.host_str().unwrap().to_string(),
                            Some(url.path().to_string()),
                            StorageType::PUB,
                        )
                        .await,
                    ),
                    _ => StorageProxy::File(FileStorage::new_centralized(
                        Some(url_to_pathbuf(&url).as_path()),
                        StorageType::PUB,
                    )?),
                },
                None => StorageProxy::File(FileStorage::new_centralized(None, StorageType::PUB)?),
            };
            let priv_storage = match config.private_storage_url()? {
                Some(url) => match url.scheme() {
                    "s3" => StorageProxy::EnclaveS3(
                        EnclaveS3Storage::new_centralized(
                            config.aws_region.clone().unwrap(),
                            config.aws_s3_proxy.clone().unwrap(),
                            config.aws_kms_proxy.clone().unwrap(),
                            url.host_str().unwrap().to_string(),
                            Some(url.path().to_string()),
                            StorageType::PRIV,
                            config.root_key_id.clone().unwrap(),
                        )
                        .await?,
                    ),
                    _ => StorageProxy::File(FileStorage::new_centralized(
                        Some(url_to_pathbuf(&url).as_path()),
                        StorageType::PRIV,
                    )?),
                },
                None => StorageProxy::File(FileStorage::new_centralized(None, StorageType::PRIV)?),
            };
            kms_server_handle(config.into(), pub_storage, priv_storage).await
        }
        ExecutionMode::NitroEnclaveProxy { config_file } => {
            let config: StorageConfigWith<CentralizedConfig> = init_conf_trace(&config_file)?;
            kms_proxy_server_handle(config.clone().into(), config.enclave_vsock.unwrap()).await
        }
    }?;
    Ok(())
}
