use clap::{Parser, Subcommand};
use kms_lib::conf::centralized::CentralizedConfig;
use kms_lib::conf::init_conf_trace;
use kms_lib::conf::threshold::ThresholdConfig;
use kms_lib::rpc::central_rpc::server_handle as kms_server_handle;
use kms_lib::rpc::central_rpc_proxy::server_handle as kms_proxy_server_handle;
use kms_lib::storage::{FileStorage, StorageType};
use kms_lib::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
use kms_lib::util::aws::{EnclaveS3Storage, S3Storage};

pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
#[clap(name = "KMS server")]
#[clap(
    about = "We support three different storage modes, `dev`, `proxy` or `enclave`. \
    For each storage mode, we support two types of execution modes, `centralized` or `threshold`. \
    Not every combination is supported. \
    Namely, the `threshold` mode only works when the storage mode is `dev`. \
    See the help page for additional details (`kms-server --help`). \n
    For example, use the following to run a threshold KMS node with the default configuration \
    (from `core/service/config/default_1.toml`): \n
    ./kms-server dev centralized \n
    or using cargo from the `core/service` directory: \n
    cargo run --bin kms-server dev centralized \n
    Oberserve that some optional arugments may be added. More specifically for both the centralized and threshold \
    execution modes, the configuration file used can be specified with the `--config-file` argument. \
    E.g.\n
    ./kms-server dev centralized --config-file config/default_centralized.toml \n
    If no configuration file is specified, the default configuration will be used \
    (e.g. config/default_centralized.toml for the centralize case). \n
    Note that key material and TLS certificates MUST exist when starting the server and be stored in the path specified by the configuration file. \n
    Please consult the `kms-gen-keys` and `kms-gen-tls-certs` binaries for details on generating key material and certificates."
)]
struct KmsArgs {
    #[clap(subcommand)]
    mode: StorageMode,
}

#[derive(Clone, Subcommand)]
enum StorageMode {
    /// Start the KMS in the development mode.
    /// This mode does not use the Nitro secure enclave to protect private keys, but instead relies on the local file system.
    Dev {
        /// Select one of the two execution modes between threshold and centralized.
        #[clap(subcommand)]
        exec_mode: ExecutionMode,
    },
    /// Run as a gRPC proxy for the Nitro secure enclave application
    Proxy {
        /// Select one of the two execution modes between threshold and centralized.
        #[clap(subcommand)]
        exec_mode: ExecutionMode,
        /// Enclave application CID for proxying
        #[clap(long, default_value = "vsock://16:5000")]
        enclave_vsock: String,
    },
    /// Run as a Nitro secure enclave application
    Enclave {
        /// Select one of the two execution modes between threshold and centralized.
        #[clap(subcommand)]
        exec_mode: ExecutionMode,
        /// S3 bucket for storing public key blobs
        #[arg(long)]
        #[clap(default_value = "zama_kms_public_blobs")]
        pub_blob_bucket: String,
        /// S3 bucket for storing encrypted private key blobs
        #[arg(long)]
        #[clap(default_value = "zama_kms_private_blobs")]
        priv_blob_bucket: String,
        /// AWS KMS symmetric key ID for encrypting key blobs
        #[arg(long)]
        #[clap(default_value = "zama_kms_root_key")]
        root_key_id: String,
        /// AWS region that the enclave application must use
        #[arg(long)]
        #[clap(default_value = "eu-west-3")]
        aws_region: String,
        /// TCP-vsock proxy for AWS S3
        #[clap(default_value = "https://localhost:7000")]
        aws_s3_proxy: String,
        /// TCP-vsock proxy for AWS KMS
        #[clap(default_value = "https://localhost:8000")]
        aws_kms_proxy: String,
    },
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
}

/// Starts a KMS server.
/// We support different three different storage modes, `dev`, `proxy` or `enclave`.
/// For each storage mode, we support two types of execution modes, `centralized` or `threshold`.
/// Not every combination is supported.
/// Namely, the `threshold` mode only worked when the storage mode is `dev`.
/// See the help page for additional details.
/// For example, use the following to run a threshold KMS node with the default configuration
/// (from `core/service/config/default_1.toml`):
/// ```
/// ./kms-server dev centralized
/// ```
/// or using cargo from the `core/service` directory:
/// ```
/// cargo run --bin kms-server dev centralized
/// ```
///
/// Oberserve that some optional arugments may be added. More specifically for both the centralized and threshold
/// execution modes, the configuration file used can be specified with the `--config-file` argument.
/// E.g.
/// ```
/// cargo run --bin kms-server dev centralized --config-file config/default_centralized.toml
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
        StorageMode::Dev { exec_mode } => match exec_mode {
            ExecutionMode::Threshold { config_file } => {
                let full_config: ThresholdConfig = init_conf_trace(&config_file)?;
                let pub_storage = FileStorage::new_threshold(
                    full_config.public_storage_path(),
                    StorageType::PUB,
                    full_config.rest.my_id,
                )
                .unwrap();
                let priv_storage = FileStorage::new_threshold(
                    full_config.private_storage_path(),
                    StorageType::PRIV,
                    full_config.rest.my_id,
                )
                .unwrap();
                let config = full_config.rest;

                let server =
                    threshold_server_init(config.clone(), pub_storage, priv_storage, false).await?;
                threshold_server_start(
                    config.listen_address_client,
                    config.listen_port_client,
                    config.timeout_secs,
                    config.grpc_max_message_size,
                    server,
                )
                .await
            }
            ExecutionMode::Centralized { config_file } => {
                let config: CentralizedConfig = init_conf_trace(&config_file)?;
                let pub_storage =
                    FileStorage::new_centralized(config.public_storage_path(), StorageType::PUB)
                        .unwrap();
                let priv_storage =
                    FileStorage::new_centralized(config.private_storage_path(), StorageType::PRIV)
                        .unwrap();
                kms_server_handle(config.into(), pub_storage, priv_storage).await
            }
        },
        StorageMode::Proxy {
            enclave_vsock,
            exec_mode,
        } => match exec_mode {
            ExecutionMode::Threshold { .. } => {
                unimplemented!("this mode is not implemented")
            }
            ExecutionMode::Centralized { config_file } => {
                let config: CentralizedConfig = init_conf_trace(&config_file)?;
                kms_proxy_server_handle(config.into(), &enclave_vsock).await
            }
        },
        StorageMode::Enclave {
            aws_region,
            aws_s3_proxy,
            aws_kms_proxy,
            pub_blob_bucket,
            priv_blob_bucket,
            root_key_id,
            exec_mode,
        } => match exec_mode {
            ExecutionMode::Threshold { .. } => {
                unimplemented!("this mode is not implemented")
            }
            ExecutionMode::Centralized { config_file } => {
                let config: CentralizedConfig = init_conf_trace(&config_file)?;
                let pub_storage =
                    S3Storage::new(aws_region.clone(), aws_s3_proxy.clone(), pub_blob_bucket).await;
                let priv_storage = EnclaveS3Storage::new(
                    aws_region,
                    aws_s3_proxy,
                    aws_kms_proxy,
                    priv_blob_bucket,
                    root_key_id,
                )
                .await?;
                kms_server_handle(config.into(), pub_storage, priv_storage).await
            }
        },
    }?;
    Ok(())
}
