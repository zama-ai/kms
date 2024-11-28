use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::nitro_enclave::{
    decrypt_ciphertext_for_recipient, decrypt_on_data_key, encrypt_on_data_key,
    nitro_enclave_get_random, request_nitro_enclave_attestation, APP_BLOB_NONCE_SIZE,
};
use crate::some_or_err;
use aws_config::{
    imds::{client::Client as IMDSClient, credentials::ImdsCredentialsProvider},
    Region, SdkConfig,
};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec::Aes256;
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo as KMSRecipientInfo};
use aws_sdk_kms::Client as AmazonKMSClient;
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        interceptors::{context::BeforeTransmitInterceptorContextMut, Intercept},
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use http::{header::HOST, HeaderValue};
use hyper_rustls::HttpsConnectorBuilder;
use ordermap::OrderMap;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::Unversionize;
use tfhe_versionable::{Versionize, VersionsDispatch};
use tokio::io::AsyncReadExt;
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

#[derive(Serialize, Deserialize, VersionsDispatch)]
pub enum AppKeyBlobVersioned {
    V0(AppKeyBlob),
}

/// Container type for encrypted application keys (such as FHE private keys)
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(AppKeyBlobVersioned)]
pub struct AppKeyBlob {
    pub root_key_id: String,
    pub data_key_blob: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

impl Named for AppKeyBlob {
    const NAME: &'static str = "AppKeyBlob";
}

/// Given the address of a vsock-to-TCP proxy, constructs an AWS SDK configuration for requesting AWS credentials inside of a Nitro enclave.
pub async fn build_aws_sdk_config(aws_region: String, aws_imds_endpoint: Option<Url>) -> SdkConfig {
    let config_loader = match aws_imds_endpoint {
        Some(p) => {
            let imds_client = IMDSClient::builder()
                .endpoint(p)
                .expect("IMDS endpoint invalid")
                .build();
            let credentials_provider = ImdsCredentialsProvider::builder()
                .imds_client(imds_client)
                .build();
            aws_config::defaults(aws_config::BehaviorVersion::latest())
                .credentials_provider(credentials_provider)
        }
        None => aws_config::defaults(aws_config::BehaviorVersion::latest()),
    };
    config_loader.region(Region::new(aws_region)).load().await
}

/// Accessing AWS S3 endpoints through a proxy might require rewriting the Host
/// HTTP header. We use the AWS SDK interceptor mechanism to do that.
#[derive(Debug)]
struct HostHeaderInterceptor {
    host: String,
}

impl Intercept for HostHeaderInterceptor {
    fn name(&self) -> &'static str {
        "HostHeaderInterceptor"
    }

    fn modify_before_signing(
        &self,
        context: &mut BeforeTransmitInterceptorContextMut<'_>,
        _runtime_components: &RuntimeComponents,
        _cfg: &mut ConfigBag,
    ) -> Result<(), BoxError> {
        context
            .request_mut()
            .headers_mut()
            .insert(HOST, HeaderValue::from_str(self.host.as_str())?);
        Ok(())
    }
}

pub(crate) struct S3Cache {
    cache: OrderMap<(String, String), Vec<u8>>,
    max_cache_size: usize,
}

impl S3Cache {
    pub(crate) fn new(max_cache_size: usize) -> Self {
        Self {
            cache: OrderMap::new(),
            max_cache_size,
        }
    }

    pub(crate) fn insert(&mut self, bucket: &str, key: &str, data: &[u8]) -> Option<Vec<u8>> {
        let out = self
            .cache
            .insert((bucket.to_string(), key.to_string()), data.to_vec());

        if self.cache.len() > self.max_cache_size {
            _ = self.cache.remove_index(0);
        }

        out
    }

    pub(crate) fn get(&self, bucket: &str, key: &str) -> Option<&Vec<u8>> {
        // do we have to use to_string()?
        self.cache.get(&(bucket.to_string(), key.to_string()))
    }
}

/// Given the address of a vsock-to-TCP proxy, constructs an S3 client for use inside of a Nitro
/// enclave.
pub async fn build_s3_client(
    aws_sdk_config: &SdkConfig,
    aws_s3_endpoint: Option<Url>,
) -> anyhow::Result<S3Client> {
    let region = aws_sdk_config.region().expect("AWS region must be set");
    let s3_config = match aws_s3_endpoint {
        Some(p) => {
            // Overrides the hostname checked by the AWS API endpoint
            let host_header_interceptor = HostHeaderInterceptor {
                host: format!("s3.{}.amazonaws.com", region),
            };
            match p.scheme() {
                "https" => {
                    let https_connector = HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .https_only()
                        // Overrides the hostname checked during the TLS handshake
                        .with_server_name(format!("s3.{}.amazonaws.com", region))
                        .enable_http1()
                        .build();
                    let http_client = HyperClientBuilder::new().build(https_connector);
                    aws_sdk_s3::config::Builder::from(aws_sdk_config)
                        // Overrides the hostname used for the TCP connection
                        .endpoint_url(p)
                        .interceptor(host_header_interceptor)
                        .http_client(http_client)
                        // Virtual-hosting style S3 URLs don't work well with endpoint overrides
                        .force_path_style(true)
                        .build()
                }
                "http" => {
                    aws_sdk_s3::config::Builder::from(aws_sdk_config)
                        // Overrides the hostname used for the TCP connection
                        .endpoint_url(p)
                        .interceptor(host_header_interceptor)
                        // Virtual-hosting style S3 URLs don't work well with endpoint overrides
                        .force_path_style(true)
                        .build()
                }
                _ => {
                    anyhow::bail!("Only HTTP and HTTPS URL schemes are supported for S3 endpoints")
                }
            }
        }
        None => aws_sdk_s3::config::Builder::from(aws_sdk_config).build(),
    };
    Ok(S3Client::from_conf(s3_config))
}

pub(crate) async fn s3_get_blob<T: DeserializeOwned + Unversionize + Named>(
    s3_client: &S3Client,
    bucket: &str,
    path: &str,
    cache: &mut S3Cache,
) -> anyhow::Result<T> {
    let blob_bytes = match cache.get(bucket, path) {
        Some(buf) => {
            tracing::info!("found bucket={bucket}, path={path} from cache");
            buf.clone()
        }
        None => {
            let data = s3_get_blob_bytes(s3_client, bucket, path).await?;
            cache.insert(bucket, path, &data);
            data
        }
    };
    let mut buf = std::io::Cursor::new(blob_bytes);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

async fn s3_get_blob_bytes(
    s3_client: &S3Client,
    bucket: &str,
    path: &str,
) -> anyhow::Result<Vec<u8>> {
    let blob_response = s3_client
        .get_object()
        .bucket(bucket)
        .key(path)
        .send()
        .await?;
    let mut blob_bytes: Vec<u8> = Vec::with_capacity(PREALLOCATED_BLOB_SIZE);
    let mut blob_bytestream = blob_response.body.into_async_read();
    blob_bytestream.read_to_end(&mut blob_bytes).await?;
    Ok(blob_bytes)
}

pub(crate) async fn s3_put_blob<T: Serialize + Versionize + Named>(
    s3_client: &S3Client,
    bucket: &str,
    path: &str,
    blob: &T,
    cache: &mut S3Cache,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    safe_serialize(blob, &mut buf, SAFE_SER_SIZE_LIMIT)?;

    cache.insert(bucket, path, &buf);
    s3_put_blob_bytes(s3_client, bucket, path, buf).await
}

pub async fn s3_put_blob_bytes(
    s3_client: &S3Client,
    bucket: &str,
    path: &str,
    blob_bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let result = s3_client
        .put_object()
        .bucket(bucket)
        .key(path)
        .body(ByteStream::from(blob_bytes))
        .send()
        .await;

    match result {
        Ok(_) => Ok(()),
        Err(err) => {
            tracing::error!("{:?} {:?}", err.meta(), err.code());
            Err(anyhow::anyhow!("AWS error, please refer to other logs."))
        }
    }
}

/// Given the address of a vsock-to-TCP proxy, constructs an AWS KMS client for use inside of a
/// Nitro enclave.
pub async fn build_aws_kms_client(
    aws_sdk_config: &SdkConfig,
    aws_kms_endpoint: Url,
) -> AmazonKMSClient {
    let region = aws_sdk_config.region().expect("AWS region must be set");
    let https_connector = HttpsConnectorBuilder::new()
        .with_native_roots()
        .https_only()
        // Overrides the hostname checked during the TLS handshake
        .with_server_name(format!("kms.{}.amazonaws.com", region))
        .enable_http1()
        .build();
    let http_client = HyperClientBuilder::new().build(https_connector);
    let kms_config = aws_sdk_kms::config::Builder::from(aws_sdk_config)
        // Overrides the hostname used for the TCP connection
        .endpoint_url(aws_kms_endpoint)
        .http_client(http_client)
        .build();
    AmazonKMSClient::from_conf(kms_config)
}

/// Request a data key from AWS KMS and encrypt an application key (such as the FHE private key) on
/// it. Stores a copy of the data key encrypted on the root key (stored in AWS KMS) together with
/// the encrypted application key.
pub async fn nitro_enclave_encrypt_app_key<T: Serialize + Versionize + Named>(
    aws_kms_client: &AmazonKMSClient,
    enclave_sk: &RsaPrivateKey,
    enclave_pk: &RsaPublicKey,
    root_key_id: &String,
    app_key: &T,
) -> anyhow::Result<AppKeyBlob> {
    // request enclave attestation before making an AWS KMS request, so the
    // attestation is fresh and not older than 5 minutes
    let enclave_attestation = request_nitro_enclave_attestation(enclave_pk)?;

    // request the data key from AWS KMS to encrypt the app key
    let gen_data_key_response = aws_kms_client
        .generate_data_key()
        .key_id(root_key_id)
        .key_spec(Aes256)
        .recipient(
            KMSRecipientInfo::builder()
                .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                .attestation_document(Blob::new(enclave_attestation))
                .build(),
        )
        .send()
        .await?;

    // decrypt the data key with the Nitro enclave private key
    let gen_data_key_response_ciphertext_blob = some_or_err(
        gen_data_key_response.ciphertext_for_recipient,
        "No ciphertext for recipient returned in data key generation response from AWS KMS"
            .to_string(),
    )?;
    let data_key = decrypt_ciphertext_for_recipient(
        gen_data_key_response_ciphertext_blob.into_inner(),
        enclave_sk,
    )?;

    // encrypt the app key under the data key
    let mut blob_bytes = Vec::new();
    safe_serialize(app_key, &mut blob_bytes, SAFE_SER_SIZE_LIMIT)?;
    let iv = nitro_enclave_get_random(APP_BLOB_NONCE_SIZE)?;
    let auth_tag = encrypt_on_data_key(&mut blob_bytes, &data_key, &iv)?;
    Ok(AppKeyBlob {
        root_key_id: root_key_id.to_string(),
        data_key_blob: some_or_err(
            gen_data_key_response.ciphertext_blob,
            "No ciphertext blob returned in data key generation response from AWS KMS".to_string(),
        )?
        .into_inner(),
        ciphertext: blob_bytes,
        iv,
        auth_tag,
    })
}

/// Requests the AWS KMS to decrypt a data key using a root key (managed by AWS KMS) and uses that
/// data key to decrypt an application key (such as an FHE private key).
pub async fn nitro_enclave_decrypt_app_key<T: DeserializeOwned + Unversionize + Named>(
    aws_kms_client: &AmazonKMSClient,
    enclave_sk: &RsaPrivateKey,
    enclave_pk: &RsaPublicKey,
    app_key_blob: &mut AppKeyBlob,
) -> anyhow::Result<T> {
    // request enclave attestation before making an AWS KMS request, so the
    // attestation is fresh and not older than 5 minutes
    let enclave_attestation = request_nitro_enclave_attestation(enclave_pk)?;

    // decrypt the data key under which the app key was encrypted
    let decrypt_data_key_response = aws_kms_client
        .decrypt()
        .key_id(&app_key_blob.root_key_id)
        .ciphertext_blob(Blob::new(app_key_blob.data_key_blob.clone()))
        .recipient(
            KMSRecipientInfo::builder()
                .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                .attestation_document(Blob::new(enclave_attestation))
                .build(),
        )
        .send()
        .await?;
    let decrypt_data_key_response_ciphertext_bytes = some_or_err(
        decrypt_data_key_response.ciphertext_for_recipient,
        "No blob returned in decryption response from AWS".to_string(),
    )?;
    let data_key = decrypt_ciphertext_for_recipient(
        decrypt_data_key_response_ciphertext_bytes.into_inner(),
        enclave_sk,
    )?;

    // decrypt the app key
    decrypt_on_data_key(
        &mut app_key_blob.ciphertext,
        &data_key,
        &app_key_blob.iv,
        &app_key_blob.auth_tag,
    )?;
    let mut buf = std::io::Cursor::new(&app_key_blob.ciphertext);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::S3Cache;

    #[test]
    fn ordered_map() {
        let mut om = S3Cache::new(2);
        let bucket = "abc".to_string();
        let key = "efg".to_string();
        let data = vec![1, 2, 3];
        om.insert(&bucket, &key, &data);
        assert_eq!(om.cache.len(), 1);
        assert_eq!(*om.get(&bucket, &key).as_ref().unwrap(), &data);

        // insert the same thing preserves the length
        om.insert(&bucket, &key, &data);
        assert_eq!(om.cache.len(), 1);

        // insert a new item
        let key2 = "key2".to_string();
        om.insert(&bucket, &key2, &data);
        assert_eq!(om.cache.len(), 2);
        assert_eq!(*om.get(&bucket, &key).as_ref().unwrap(), &data);
        assert_eq!(*om.get(&bucket, &key2).as_ref().unwrap(), &data);

        // insert a third item causes the first item to be lost
        let key3 = "key3".to_string();
        om.insert(&bucket, &key3, &data);
        assert_eq!(om.cache.len(), 2);
        assert_eq!(om.get(&bucket, &key), None);
        assert_eq!(*om.get(&bucket, &key2).as_ref().unwrap(), &data);
        assert_eq!(*om.get(&bucket, &key3).as_ref().unwrap(), &data);
    }
}
