use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use anyhow::{bail, ensure};
use aws_config::Region;
use aws_nitro_enclaves_nsm_api::{
    api::{Request as NSMRequest, Response as NSMResponse},
    driver as nsm_driver,
};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo as KMSRecipientInfo};
use aws_sdk_kms::Client as AmazonKMSClient;
use aws_sdk_s3::Client as S3Client;
use clap::{Parser, ValueEnum};
use cms::enveloped_data::{EnvelopedData, RecipientInfo as PKCS7RecipientInfo};
use der::{Decode, DecodeValue, Header, SliceReader};
use kms_lib::consts::{
    CRS_PATH_PREFIX, DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CRS_HANDLE,
    DEFAULT_SOFTWARE_CENTRAL_KEY_PATH, KEY_HANDLE,
};
use kms_lib::core::kms_core::{CrsHashMap, SoftwareKmsKeys};
use kms_lib::file_handling::read_element;
use kms_lib::{
    core::der_types::{PrivateSigKey, PublicSigKey},
    rpc::kms_proxy_rpc::server_handle as kms_proxy_server_handle,
    rpc::kms_rpc::server_handle as kms_server_handle,
};
use kms_lib::{write_default_crs_store, write_default_keys};
use rand::rngs::OsRng;
use rsa::{pkcs1::EncodeRsaPublicKey, sha2::Sha256, Oaep, RsaPrivateKey, RsaPublicKey};
use serde::{de::DeserializeOwned, Serialize};
use serde_bytes::ByteBuf;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};
use url::Url;

pub const FHE_SK_BLOB_KEY: &str = "fhe_private_key";
pub const SIG_SK_BLOB_KEY: &str = "private_sig_key";
pub const SIG_PK_BLOB_KEY: &str = "public_sig_key";

#[derive(Parser)]
struct Args {
    mode: Mode,
    /// Enclave application CID for proxying
    #[arg(long)]
    #[clap(default_value = "vsock://16:5000")]
    enclave_vsock: String,
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
    /// S3 bucket for storing encrypted key blobs
    #[arg(long)]
    #[clap(default_value = "zama_kms_blobs")]
    blob_bucket: String,
    /// AWS KMS symmetric key ID for encrypting key blobs
    #[arg(long)]
    #[clap(default_value = "zama_kms_blob_key")]
    blob_key_id: String,
    /// Server URL without specifying protocol (e.g. 0.0.0.0:50051)
    #[clap(default_value = "http://0.0.0.0:50051")]
    url: String,
}

#[derive(Clone, ValueEnum)]
enum Mode {
    /// Do not use the Nitro secure enclave to protect private keys
    Dev,
    /// Run as a gRPC proxy for the Nitro secure enclave application
    Proxy,
    /// Run as a Nitro secure enclave application
    Enclave,
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
            let keys: SoftwareKmsKeys = if Path::new(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH).exists() {
                read_element(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH)?
            } else {
                tracing::info!(
                    "Could not find default keys. Generating new keys with default parameters and handle \"{}\"...", KEY_HANDLE
                );
                write_default_keys(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH)
            };

            let crs_store: CrsHashMap = if Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
                read_element(DEFAULT_CENTRAL_CRS_PATH)?
            } else {
                tracing::info!(
                      "Could not find default CRS store. Generating new CRS store with default parameters and handle \"{}\"...", DEFAULT_CRS_HANDLE
                  );
                write_default_crs_store(CRS_PATH_PREFIX)
            };

            kms_server_handle(socket, keys, Some(crs_store)).await
        }
        Mode::Proxy => kms_proxy_server_handle(socket, &args.enclave_vsock).await,
        Mode::Enclave => {
            // set up AWS API
            let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(Region::new(args.aws_region.clone()))
                .endpoint_url(args.aws_s3_proxy)
                .load()
                .await;
            tracing::info!("After s3_config");
            let kms_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(Region::new(args.aws_region))
                .endpoint_url(args.aws_kms_proxy)
                .load()
                .await;
            tracing::info!("After kms_config");
            let s3_client = S3Client::new(&s3_config);
            tracing::info!("After s3_client");
            let aws_kms_client = AmazonKMSClient::new(&kms_config);
            tracing::info!("After kms_client");

            // generate a Nitro enclave keypair
            let enclave_sk = RsaPrivateKey::new(&mut OsRng, 2048)?;
            let enclave_pk = RsaPublicKey::from(&enclave_sk);
            let enclave_pk_der = enclave_pk.to_pkcs1_der()?;
            let enclave_pk_der_bytes = enclave_pk_der.as_ref().to_vec();

            // request Nitro enclave attestation
            let nsm_fd = nsm_driver::nsm_init();
            let nsm_request = NSMRequest::Attestation {
                public_key: Some(ByteBuf::from(enclave_pk_der_bytes)),
                user_data: None,
                // The nonce can potentially be used in protocols that do not allow using the same
                // attestation twice. The AWS KMS API allows reusing attestations (in fact, there
                // does not seem to be a way to forbid it), so we are not setting the nonce.
                nonce: None,
            };
            let NSMResponse::Attestation { document } =
                nsm_driver::nsm_process_request(nsm_fd, nsm_request)
            else {
                nsm_driver::nsm_exit(nsm_fd);
                bail!("Nitro enclave attestation request failed");
            };
            nsm_driver::nsm_exit(nsm_fd);

            // fetch key blobs
            let fhe_sk_blob_bytes =
                s3_get_blob_bytes(&s3_client, &args.blob_bucket, FHE_SK_BLOB_KEY).await?;
            let sig_sk: PrivateSigKey =
                s3_get_blob(&s3_client, &args.blob_bucket, SIG_SK_BLOB_KEY).await?;
            let sig_pk: PublicSigKey =
                s3_get_blob(&s3_client, &args.blob_bucket, SIG_PK_BLOB_KEY).await?;

            tracing::info!("Fetched key blobs. Before decrypting...");
            // re-encrypt the encrypted private key blob
            // on the Nitro enclave public key
            let fhe_sk_response = aws_kms_client
                .decrypt()
                .key_id(args.blob_key_id)
                .ciphertext_blob(Blob::new(fhe_sk_blob_bytes))
                .recipient(
                    KMSRecipientInfo::builder()
                        .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                        .attestation_document(Blob::new(document))
                        .build(),
                )
                .send()
                .await?;

            tracing::info!("Decrypted key blobs. Before ensure...");
            // peek inside the re-encrypted key PKCS7 envelope
            ensure!(
                fhe_sk_response.ciphertext_for_recipient.is_some(),
                "Decryption request came back empty"
            );
            let fhe_sk_response_ciphertext_bytes = fhe_sk_response
                .ciphertext_for_recipient
                .unwrap()
                .into_inner();
            let fhe_sk_envelope_header =
                Header::from_der(fhe_sk_response_ciphertext_bytes.as_slice())?;
            let mut fhe_sk_envelope_reader =
                SliceReader::new(fhe_sk_response_ciphertext_bytes.as_slice())?;
            let fhe_sk_envelope: EnvelopedData =
                EnvelopedData::decode_value(&mut fhe_sk_envelope_reader, fhe_sk_envelope_header)?;
            ensure!(
                fhe_sk_envelope.recip_infos.0.len() == 1,
                "Re-encrypted key envelope must have exactly one recipient"
            );
            let PKCS7RecipientInfo::Ktri(ktri) = fhe_sk_envelope.recip_infos.0.get(0).unwrap()
            else {
                bail!("Re-encrypted key envelope does not contain a session key");
            };
            ensure!(
                ktri.version == fhe_sk_envelope.version,
                "Re-encrypted key envelope malformed"
            );
            let fhe_sk_enc_session_key = ktri.enc_key.as_bytes();
            // NOTE: `cms` doesn't parse OIDs yet but it would be good to validate that
            // encrypted_content.content_type == pkcs7_data and that
            // encrypted_content.content_enc_alg.oid == aes_256_cbc
            ensure!(
                fhe_sk_envelope
                    .encrypted_content
                    .content_enc_alg
                    .parameters
                    .is_some(),
                "Re-encrypted key envelope does not contain an initialization vector"
            );
            let iv = fhe_sk_envelope
                .encrypted_content
                .content_enc_alg
                .parameters
                .unwrap();
            ensure!(
                fhe_sk_envelope
                    .encrypted_content
                    .encrypted_content
                    .is_some(),
                "Re-encrypted key envelope does not contain a payload"
            );
            let fhe_sk_ciphertext = fhe_sk_envelope.encrypted_content.encrypted_content.unwrap();

            // decrypt the PKCS7 envelope session key
            let fhe_sk_session_key =
                enclave_sk.decrypt(Oaep::new::<Sha256>(), fhe_sk_enc_session_key)?;

            // decrypt the key ciphertext for recipient enclave
            let fhe_sk_bytes = cbc::Decryptor::<aes::Aes256>::new(
                fhe_sk_session_key.as_slice().into(),
                iv.value().into(),
            )
            .decrypt_padded_vec_mut::<Pkcs7>(fhe_sk_ciphertext.as_bytes())
            .map_err(|e| anyhow::anyhow!(format!("{}", e)))?;
            let fhe_sk = bincode::deserialize_from(fhe_sk_bytes.as_slice())?;

            // start the KMS
            let keys = SoftwareKmsKeys {
                client_keys: HashMap::from([(KEY_HANDLE.to_string(), fhe_sk)]),
                sig_sk,
                sig_pk,
            };
            let crs_store: CrsHashMap = if Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
                read_element(DEFAULT_CENTRAL_CRS_PATH)?
            } else {
                tracing::info!(
                    "Could not find default CRS store. Generating new CRS store with default parameters and handle \"{}\"...", DEFAULT_CRS_HANDLE
                );
                write_default_crs_store(CRS_PATH_PREFIX)
            };

            kms_server_handle(socket, keys, Some(crs_store)).await
        }
    }?;
    Ok(())
}

async fn s3_get_blob<T: DeserializeOwned + Serialize>(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
) -> anyhow::Result<T> {
    let blob_bytes = s3_get_blob_bytes(s3_client, bucket, key).await?;
    Ok(bincode::deserialize_from(blob_bytes.as_slice())?)
}

async fn s3_get_blob_bytes(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Vec<u8>> {
    let blob_response = s3_client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await?;
    let mut blob_bytes: Vec<u8> = Vec::with_capacity(32768);
    let mut blob_bytestream = blob_response.body.into_async_read();
    blob_bytestream.read_to_end(&mut blob_bytes).await?;
    Ok(blob_bytes)
}
