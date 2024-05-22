use clap::{Parser, Subcommand};
use kms_lib::consts::{
    DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CRS_ID, DEFAULT_KEY_ID,
};
use kms_lib::cryptography::central_kms::SoftwareKmsKeys;
use kms_lib::cryptography::der_types::{PrivateSigKey, PublicSigKey};
use kms_lib::cryptography::nitro_enclave::gen_nitro_enclave_keys;
use kms_lib::rpc::central_rpc::server_handle as kms_server_handle;
use kms_lib::rpc::central_rpc_proxy::server_handle as kms_proxy_server_handle;
use kms_lib::storage::{FileStorage, StorageType};
use kms_lib::util::aws::{
    build_aws_kms_client, build_s3_client, nitro_enclave_decrypt_app_key, s3_get_blob,
    EnclaveStorage,
};
use kms_lib::{write_default_crs_store, write_default_keys};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};
use url::Url;

pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
    /// Server URL without specifying protocol (e.g. 0.0.0.0:50051)
    #[clap(default_value = "http://0.0.0.0:50051")]
    url: String,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Do not use the Nitro secure enclave to protect private keys
    Dev,
    /// Run as a gRPC proxy for the Nitro secure enclave application
    Proxy {
        /// Enclave application CID for proxying
        #[arg(long)]
        #[clap(default_value = "vsock://16:5000")]
        enclave_vsock: String,
    },
    /// Run as a Nitro secure enclave application
    Enclave {
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

// Starts a server where the first argument is the URL and following arguments are key handles of
// existing keys.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();
    let args = Args::parse();
    let url = Url::parse(args.url.as_str())?;
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

    match args.mode {
        Mode::Dev => {
            if !Path::new(DEFAULT_CENTRAL_KEYS_PATH).exists() {
                tracing::info!(
                    "Could not find default keys. Generating new keys with default parameters and ID \"{}\"...", (*DEFAULT_KEY_ID).clone()
                );
                write_default_keys(DEFAULT_CENTRAL_KEYS_PATH).await;
            };
            if !Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
                tracing::info!(
                    "Could not find default CRS store. Generating new CRS store with default parameters and handle \"{}\"...", (*DEFAULT_CRS_ID).clone()
                );
                write_default_crs_store().await;
            };

            let pub_storage = FileStorage::new(&StorageType::PUB.to_string());
            let priv_storage = FileStorage::new(&StorageType::PRIV.to_string());
            kms_server_handle(socket, pub_storage, priv_storage).await
        }
        Mode::Proxy { enclave_vsock } => kms_proxy_server_handle(socket, &enclave_vsock).await,
        Mode::Enclave {
            aws_region,
            aws_s3_proxy,
            aws_kms_proxy,
            blob_bucket,
            root_key_id,
        } => {
            // set up AWS API
            let s3_client = build_s3_client(aws_region.clone(), aws_s3_proxy).await;
            let aws_kms_client = build_aws_kms_client(aws_region, aws_kms_proxy).await;
            let enclave_keys = gen_nitro_enclave_keys()?;

            // fetch key blobs
            tracing::info!("Fetching the FHE keys");
            let fhe_sk_blob = s3_get_blob(
                &s3_client,
                &blob_bucket,
                format!("{}-private.bin", (*DEFAULT_KEY_ID).clone()).as_str(),
            )
            .await?;
            let sig_sk: PrivateSigKey =
                s3_get_blob(&s3_client, &blob_bucket, SIG_SK_BLOB_KEY).await?;
            let sig_pk: PublicSigKey =
                s3_get_blob(&s3_client, &blob_bucket, SIG_PK_BLOB_KEY).await?;

            // decrypt the encrypted FHE private key
            tracing::info!("Decrypting the FHE private key");
            let fhe_sk =
                nitro_enclave_decrypt_app_key(&aws_kms_client, &enclave_keys, fhe_sk_blob).await?;

            // start the KMS
            let _keys = SoftwareKmsKeys {
                key_info: HashMap::from([((*DEFAULT_KEY_ID).clone(), fhe_sk)]),
                sig_sk,
                sig_pk,
            };
            if !Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
                tracing::info!(
                    "Could not find default CRS store. Generating new CRS store with default parameters and handle \"{}\"...", (*DEFAULT_CRS_ID).clone()
                );
                write_default_crs_store().await;
            };

            let pub_storage = FileStorage::new(&StorageType::PUB.to_string());
            let priv_storage = EnclaveStorage {
                s3_client,
                aws_kms_client,
                blob_bucket,
                root_key_id,
                enclave_keys,
            };
            kms_server_handle(socket, pub_storage, priv_storage).await
        }
    }?;
    Ok(())
}
