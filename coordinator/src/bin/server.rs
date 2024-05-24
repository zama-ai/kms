use clap::{Parser, Subcommand};
use kms_lib::consts::DEFAULT_CENTRAL_KEY_ID;
use kms_lib::cryptography::central_kms::SoftwareKmsKeys;
use kms_lib::cryptography::der_types::{PrivateSigKey, PublicSigKey};
use kms_lib::cryptography::nitro_enclave::gen_nitro_enclave_keys;
use kms_lib::rpc::central_rpc::server_handle as kms_server_handle;
use kms_lib::rpc::central_rpc_proxy::server_handle as kms_proxy_server_handle;
use kms_lib::storage::{FileStorage, StorageType};
use kms_lib::threshold::threshold_kms::{
    threshold_server_init, threshold_server_start, ThresholdConfig,
};
use kms_lib::util::aws::{
    build_aws_kms_client, build_s3_client, nitro_enclave_decrypt_app_key, s3_get_blob,
    EnclaveStorage,
};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};
use url::Url;

pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
struct KmsArgs {
    #[clap(subcommand)]
    mode: StorageMode,
}

#[derive(Clone, Subcommand)]
enum StorageMode {
    /// Start the KMS in the centralized mode.
    /// This mode does not use the Nitro secure enclave to protect private keys
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
        /// S3 bucket for storing encrypted key blobs
        #[arg(long)]
        #[clap(default_value = "zama_kms_blobs")]
        blob_bucket: String,
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
            default_value = "http://0.0.0.0:50051",
            help = "Server URL with a protocol (either http or https)."
        )]
        url: String,
    },
}

fn parse_url(s: &str) -> anyhow::Result<SocketAddr> {
    let url = Url::parse(s)?;
    if url.scheme() != "http" && url.scheme() != "https" && url.scheme() != "" {
        return Err(anyhow::anyhow!(
            "Invalid scheme in URL. Only http and https are supported."
        ));
    }
    let host_str: &str = url
        .host_str()
        .ok_or(anyhow::anyhow!("Invalid host in URL."))?;
    let port: u16 = url
        .port_or_known_default()
        .ok_or(anyhow::anyhow!("Invalid port in URL."))?;
    let socket: SocketAddr = format!("{}:{}", host_str, port).parse()?;

    Ok(socket)
}

/// Starts a KMS server.
/// We support different three different storage modes, `dev`, `proxy` or `enclave`.
/// For each storage mode, we support two types of execution modes, `centralized` or `threshold`.
/// Not every combination is supported.
/// Namely, the `threshold` mode only worked when the storage mode is `dev`.
/// See the help page for additional details.
/// For example, use the following to run a threshold KMS node:
/// ```
/// kms-server dev threshold
/// ```
///
/// Note that for some modes, key materials must be generated beforehand.
/// Please consult the `kms-gen-keys` binary for details.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();
    let args = KmsArgs::parse();

    match args.mode {
        StorageMode::Dev { exec_mode } => match exec_mode {
            ExecutionMode::Threshold { config_file } => {
                let config = ThresholdConfig::init_config(&config_file)?;
                let pub_storage = FileStorage::new(&StorageType::PUB.to_string());
                let priv_storage = FileStorage::new(&StorageType::PRIV.to_string());
                let server =
                    threshold_server_init(config.clone(), pub_storage, priv_storage).await?;
                threshold_server_start(config.url, config.base_port, config.timeout_secs, server)
                    .await
            }
            ExecutionMode::Centralized { url } => {
                let pub_storage = FileStorage::new(&StorageType::PUB.to_string());
                let priv_storage = FileStorage::new(&StorageType::PRIV.to_string());
                let socket = parse_url(&url)?;
                kms_server_handle(socket, pub_storage, priv_storage).await
            }
        },
        StorageMode::Proxy {
            enclave_vsock,
            exec_mode,
        } => match exec_mode {
            ExecutionMode::Threshold { .. } => {
                unimplemented!("this mode is not implemented")
            }
            ExecutionMode::Centralized { url } => {
                let socket = parse_url(&url)?;
                kms_proxy_server_handle(socket, &enclave_vsock).await
            }
        },
        StorageMode::Enclave {
            aws_region,
            aws_s3_proxy,
            aws_kms_proxy,
            blob_bucket,
            root_key_id,
            exec_mode,
        } => {
            match exec_mode {
                ExecutionMode::Threshold { .. } => {
                    unimplemented!("this mode is not implemented")
                }
                ExecutionMode::Centralized { url } => {
                    // set up AWS API
                    let s3_client = build_s3_client(aws_region.clone(), aws_s3_proxy).await;
                    let aws_kms_client = build_aws_kms_client(aws_region, aws_kms_proxy).await;
                    let enclave_keys = gen_nitro_enclave_keys()?;

                    // fetch key blobs
                    tracing::info!("Fetching the FHE keys");
                    let fhe_sk_blob = s3_get_blob(
                        &s3_client,
                        &blob_bucket,
                        format!("{}-private.bin", (*DEFAULT_CENTRAL_KEY_ID).clone()).as_str(),
                    )
                    .await?;
                    let sig_sk: PrivateSigKey =
                        s3_get_blob(&s3_client, &blob_bucket, SIG_SK_BLOB_KEY).await?;
                    let sig_pk: PublicSigKey =
                        s3_get_blob(&s3_client, &blob_bucket, SIG_PK_BLOB_KEY).await?;

                    // decrypt the encrypted FHE private key
                    tracing::info!("Decrypting the FHE private key");
                    let fhe_sk =
                        nitro_enclave_decrypt_app_key(&aws_kms_client, &enclave_keys, fhe_sk_blob)
                            .await?;

                    // start the KMS
                    let _keys = SoftwareKmsKeys {
                        key_info: HashMap::from([((*DEFAULT_CENTRAL_KEY_ID).clone(), fhe_sk)]),
                        sig_sk,
                        sig_pk,
                    };
                    // TODO this should be glued together with Nitro properly after mergning #442
                    let pub_storage = FileStorage::new(&StorageType::PUB.to_string());
                    let priv_storage = EnclaveStorage {
                        s3_client,
                        aws_kms_client,
                        blob_bucket,
                        root_key_id,
                        enclave_keys,
                    };
                    let socket = parse_url(&url)?;
                    kms_server_handle(socket, pub_storage, priv_storage).await
                }
            }
        }
    }?;
    Ok(())
}
