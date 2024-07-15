use crate::anyhow_error_and_log;
use crate::cryptography::nitro_enclave::{
    decrypt_ciphertext_for_recipient, decrypt_on_data_key, encrypt_on_data_key,
    gen_nitro_enclave_keys, nitro_enclave_get_random, NitroEnclaveKeys, APP_BLOB_NONCE_SIZE,
};
use crate::storage::{Storage, StorageReader, StorageType};
use anyhow::ensure;
use aws_config::Region;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::DataKeySpec::Aes256;
use aws_sdk_kms::types::{KeyEncryptionMechanism, RecipientInfo as KMSRecipientInfo};
use aws_sdk_kms::Client as AmazonKMSClient;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client as S3Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

pub struct S3Storage {
    pub s3_client: S3Client,
    pub blob_bucket: String,
    pub blob_key_prefix: String,
}

impl S3Storage {
    pub fn centralized_prefix(
        optional_prefix: Option<String>,
        storage_type: StorageType,
    ) -> String {
        match optional_prefix {
            Some(prefix) => format!("{prefix}/{storage_type}"),
            None => format!("{storage_type}"),
        }
    }

    pub fn threshold_prefix(
        optional_prefix: Option<String>,
        storage_type: StorageType,
        party_id: usize,
    ) -> String {
        match optional_prefix {
            Some(prefix) => format!("{prefix}/{storage_type}-p{party_id}"),
            None => format!("{storage_type}-p{party_id}"),
        }
    }

    pub async fn new(
        aws_region: String,
        aws_s3_proxy: String,
        blob_bucket: String,
        blob_key_prefix: String,
    ) -> Self {
        let s3_client = build_s3_client(aws_region, aws_s3_proxy).await;
        S3Storage {
            s3_client,
            blob_bucket,
            blob_key_prefix,
        }
    }
}

#[tonic::async_trait]
impl StorageReader for S3Storage {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        let s3_bucket = url
            .host_str()
            .ok_or_else(|| anyhow_error_and_log("No S3 bucket specified"))?;
        let s3_key = url
            .path_segments()
            .ok_or_else(|| anyhow_error_and_log("URL cannot be a base"))?
            .last()
            .ok_or_else(|| anyhow_error_and_log("No S3 key specified"))?;
        let result = self
            .s3_client
            .head_object()
            .bucket(s3_bucket)
            .key(s3_key)
            .send()
            .await;
        match result {
            Ok(_) => Ok(true),
            Err(sdk_error) => match sdk_error.as_service_error().map(|e| e.is_not_found()) {
                Some(_) => Ok(false),
                None => Err(sdk_error.into()),
            },
        }
    }

    async fn read_data<T: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<T> {
        ensure!(url.scheme() == "s3", "Storage URL is not an S3 URL");
        ensure!(
            url.host().is_some(),
            "Storage URL does not have an S3 bucket name"
        );
        ensure!(url.path() != "", "Storage URL does not have an S3 key name");
        let bucket = url.host().unwrap().to_string();
        let key = url.path().to_string();

        s3_get_blob(&self.s3_client, &bucket, &key).await
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        if data_id.contains('/') || data_type.contains('/') {
            return Err(anyhow_error_and_log(
                "Could not store data, data_id or data_type contains '/'".to_string(),
            ));
        }
        Ok(Url::parse(
            format!(
                "s3://{}/{}/{}/{}",
                self.blob_bucket, self.blob_key_prefix, data_type, data_id
            )
            .as_str(),
        )?)
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        let mut urls = HashMap::new();
        let result = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.blob_bucket)
            .delimiter("/")
            .prefix(format!("{}/", data_type))
            .send()
            .await?;
        let contents = result
            .contents
            .ok_or_else(|| anyhow_error_and_log("No S3 bucket contents returned"))?;
        for obj in contents {
            if let Some(key) = obj.key {
                urls.insert(key.clone(), self.compute_url(&key, data_type)?);
            }
        }
        Ok(urls)
    }

    fn info(&self) -> String {
        format!("enclave storage with bucket {}", self.blob_bucket)
    }
}

#[tonic::async_trait]
impl Storage for S3Storage {
    /// If one reads "public" not as in "public key" but as in "not a secret", it makes sense to
    /// implement storage of encrypted private keys in the `PublicStorage` trait. Encrypted secrets
    /// can be published, if the root key stays secret.
    async fn store_data<T: Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        ensure!(url.scheme() == "s3", "Storage URL is not an S3 URL");
        ensure!(
            url.host().is_some(),
            "Storage URL does not have an S3 bucket name"
        );
        ensure!(url.path() != "", "Storage URL does not have an S3 key name");
        let bucket = url.host().unwrap().to_string();
        let key = url.path().to_string();

        s3_put_blob(&self.s3_client, &bucket, &key, data).await
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        let s3_bucket = url
            .host_str()
            .ok_or_else(|| anyhow_error_and_log("No S3 bucket specified"))?;
        let s3_key = url
            .path_segments()
            .ok_or_else(|| anyhow_error_and_log("URL cannot be a base"))?
            .last()
            .ok_or_else(|| anyhow_error_and_log("No S3 key specified"))?;
        let _ = self
            .s3_client
            .delete_object()
            .bucket(s3_bucket)
            .key(s3_key)
            .send()
            .await;
        Ok(())
    }
}

/// Keeps together everything needed for running a chain of trust for working with application
/// secret keys (such as FHE private keys). The root key encrypt data keys which encrypt application
/// keys. The root key is stored in AWS KMS and never leaves it. Encrypted application keys
/// (together with the corresponding data keys) are stored on S3. Enclave keys permit secure
/// decryption of data keys by AWS KMS.
pub struct EnclaveS3Storage {
    pub s3_storage: S3Storage,
    pub aws_kms_client: AmazonKMSClient,
    pub root_key_id: String,
    pub enclave_keys: NitroEnclaveKeys,
}

impl EnclaveS3Storage {
    pub async fn new(
        aws_region: String,
        aws_s3_proxy: String,
        aws_kms_proxy: String,
        blob_bucket: String,
        blob_key_prefix: String,
        root_key_id: String,
    ) -> anyhow::Result<Self> {
        let s3_storage = S3Storage::new(
            aws_region.clone(),
            aws_s3_proxy,
            blob_bucket,
            blob_key_prefix,
        )
        .await;
        let aws_kms_client = build_aws_kms_client(aws_region, aws_kms_proxy).await;
        let enclave_keys = gen_nitro_enclave_keys()?;
        Ok(EnclaveS3Storage {
            s3_storage,
            aws_kms_client,
            root_key_id,
            enclave_keys,
        })
    }
}

#[tonic::async_trait]
impl StorageReader for EnclaveS3Storage {
    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        self.s3_storage.compute_url(data_id, data_type)
    }

    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        self.s3_storage.data_exists(url).await
    }

    async fn read_data<T: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<T> {
        let mut encrypted_data = self.s3_storage.read_data(url).await?;
        nitro_enclave_decrypt_app_key(
            &self.aws_kms_client,
            &self.enclave_keys,
            &mut encrypted_data,
        )
        .await
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        self.s3_storage.all_urls(data_type).await
    }

    fn info(&self) -> String {
        self.s3_storage.info()
    }
}

#[tonic::async_trait]
impl Storage for EnclaveS3Storage {
    /// If one reads "public" not as in "public key" but as in "not a secret", it makes sense to
    /// implement storage of encrypted private keys in the `PublicStorage` trait. Encrypted secrets
    /// can be published, if the root key stays secret.
    async fn store_data<T: Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let encrypted_data = nitro_enclave_encrypt_app_key(
            &self.aws_kms_client,
            &self.enclave_keys,
            &self.root_key_id,
            data,
        )
        .await?;

        self.s3_storage.store_data(&encrypted_data, url).await
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        self.s3_storage.delete_data(url).await
    }
}

/// Container type for encrypted application keys (such as FHE private keys)
#[derive(Serialize, Deserialize)]
pub struct AppKeyBlob {
    pub root_key_id: String,
    pub data_key_blob: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub iv: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

/// Given the address of a vsock-to-TCP proxy, constructs an S3 client for use inside of a Nitro
/// enclave.
pub async fn build_s3_client(region: String, proxy: String) -> S3Client {
    let s3_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(proxy)
        .load()
        .await;
    S3Client::new(&s3_config)
}

pub async fn s3_get_blob<T: DeserializeOwned>(
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
    let mut blob_bytes: Vec<u8> = Vec::with_capacity(PREALLOCATED_BLOB_SIZE);
    let mut blob_bytestream = blob_response.body.into_async_read();
    blob_bytestream.read_to_end(&mut blob_bytes).await?;
    Ok(blob_bytes)
}

pub async fn s3_put_blob<T: Serialize + ?Sized>(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    blob: &T,
) -> anyhow::Result<()> {
    s3_put_blob_bytes(s3_client, bucket, key, bincode::serialize(blob)?).await
}

async fn s3_put_blob_bytes(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    blob_bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let _ = s3_client
        .put_object()
        .bucket(bucket)
        .key(key)
        .body(ByteStream::from(blob_bytes))
        .send()
        .await?;
    Ok(())
}

/// Given the address of a vsock-to-TCP proxy, constructs an AWS KMS client for use inside of a
/// Nitro enclave.
pub async fn build_aws_kms_client(region: String, proxy: String) -> AmazonKMSClient {
    let kms_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(Region::new(region))
        .endpoint_url(proxy)
        .load()
        .await;
    AmazonKMSClient::new(&kms_config)
}

/// Request AWS KMS to re-encrypt a secret (usually, a data key on which application keys, such as
/// FHE private keys, are encrypted) from a key stored in AWS KMS (usually, the root key) on the
/// Nitro enclave public key, then decrypt the re-encrypted secret using the Nitro enclave private
/// key.
async fn aws_kms_decrypt_blob(
    aws_kms_client: &AmazonKMSClient,
    nitro_enclave_keys: &NitroEnclaveKeys,
    root_key_id: &String,
    blob_bytes: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let decrypt_response = aws_kms_client
        .decrypt()
        .key_id(root_key_id)
        .ciphertext_blob(Blob::new(blob_bytes.to_owned()))
        .recipient(
            KMSRecipientInfo::builder()
                .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                .attestation_document(Blob::new(nitro_enclave_keys.attestation_document.clone()))
                .build(),
        )
        .send()
        .await?;

    ensure!(
        decrypt_response.ciphertext_for_recipient.is_some(),
        "Decryption request came back empty"
    );
    let decrypt_response_ciphertext_bytes = decrypt_response
        .ciphertext_for_recipient
        .unwrap()
        .into_inner();
    decrypt_ciphertext_for_recipient(
        decrypt_response_ciphertext_bytes,
        &nitro_enclave_keys.enclave_sk,
    )
}

/// Request a data key from AWS KMS and encrypt an application key (such as the FHE private key) on
/// it. Stores a copy of the data key encrypted on the root key (stored in AWS KMS) together with
/// the encrypted application key.
pub async fn nitro_enclave_encrypt_app_key<T: Serialize + ?Sized>(
    aws_kms_client: &AmazonKMSClient,
    nitro_enclave_keys: &NitroEnclaveKeys,
    root_key_id: &String,
    app_key: &T,
) -> anyhow::Result<AppKeyBlob> {
    let mut blob_bytes = Vec::new();
    let _ = bincode::serialize_into(&mut blob_bytes, app_key);

    // request the data key from AWS KMS to encrypt the blob on
    let gen_data_key_response = aws_kms_client
        .generate_data_key()
        .key_id(root_key_id)
        .key_spec(Aes256)
        .recipient(
            KMSRecipientInfo::builder()
                .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
                .attestation_document(Blob::new(nitro_enclave_keys.attestation_document.clone()))
                .build(),
        )
        .send()
        .await?;

    // decrypt the data key with the Nitro enclave private key
    ensure!(
        gen_data_key_response.ciphertext_for_recipient.is_some(),
        "Data key generation request came back empty"
    );
    let gen_data_key_response_ciphertext_bytes = gen_data_key_response
        .ciphertext_for_recipient
        .unwrap()
        .into_inner();
    let data_key = decrypt_ciphertext_for_recipient(
        gen_data_key_response_ciphertext_bytes,
        &nitro_enclave_keys.enclave_sk,
    )?;

    let iv = nitro_enclave_get_random(APP_BLOB_NONCE_SIZE)?;

    // encrypt the blob on the data key
    let auth_tag = encrypt_on_data_key(&mut blob_bytes, &data_key, &iv)?;
    Ok(AppKeyBlob {
        root_key_id: root_key_id.to_string(),
        data_key_blob: gen_data_key_response.ciphertext_blob.unwrap().into_inner(),
        ciphertext: blob_bytes,
        iv,
        auth_tag,
    })
}

/// Requests the AWS KMS to decrypt a data key using a root key (managed by AWS KMS) and uses that
/// data key to decrypt an application key (such as an FHE private key).
pub async fn nitro_enclave_decrypt_app_key<T: DeserializeOwned>(
    aws_kms_client: &AmazonKMSClient,
    nitro_enclave_keys: &NitroEnclaveKeys,
    app_key_blob: &mut AppKeyBlob,
) -> anyhow::Result<T> {
    let data_key = aws_kms_decrypt_blob(
        aws_kms_client,
        nitro_enclave_keys,
        &app_key_blob.root_key_id,
        &app_key_blob.data_key_blob,
    )
    .await?;
    decrypt_on_data_key(
        &mut app_key_blob.ciphertext,
        &data_key,
        &app_key_blob.iv,
        &app_key_blob.auth_tag,
    )?;
    Ok(bincode::deserialize_from(
        app_key_blob.ciphertext.as_slice(),
    )?)
}

#[tokio::test]
async fn aws_storage_url() {
    let storage = S3Storage::new(
        "aws_region".to_string(),
        "aws_kms_proxy".to_string(),
        "blob_bucket".to_string(),
        "blob_key_prefix".to_string(),
    )
    .await;

    let url = storage.compute_url("id", "type").unwrap();
    assert_eq!(
        url,
        Url::parse("s3://blob_bucket/blob_key_prefix/type/id").unwrap()
    );

    assert!(storage.compute_url("as/df", "type").is_err());
    assert!(storage.compute_url("id", "as/df").is_err());
}
