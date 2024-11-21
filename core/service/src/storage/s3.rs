use super::{Storage, StorageForText, StorageReader, StorageType};
use crate::cryptography::nitro_enclave::ENCLAVE_SK_SIZE;
use crate::util::aws::{
    build_aws_kms_client, build_aws_sdk_config, build_s3_client, nitro_enclave_decrypt_app_key,
    nitro_enclave_encrypt_app_key, s3_get_blob, s3_put_blob, s3_put_blob_bytes,
};
use crate::{anyhow_error_and_log, some_or_err};
use anyhow::ensure;
use aws_config::SdkConfig;
use aws_sdk_kms::Client as AmazonKMSClient;
use aws_sdk_s3::Client as S3Client;
#[cfg(feature = "non-wasm")]
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use tfhe::{named::Named, Unversionize, Versionize};
use url::Url;

pub struct S3Storage {
    pub aws_sdk_config: SdkConfig,
    pub s3_client: S3Client,
    pub blob_bucket: String,
    pub blob_path: String,
}

impl S3Storage {
    pub async fn new(
        aws_region: String,
        aws_imds_endpoint: Option<Url>,
        aws_s3_endpoint: Option<Url>,
        blob_bucket: String,
        path: Option<String>,
        storage_type: StorageType,
        party_id: Option<usize>,
    ) -> anyhow::Result<Self> {
        let extra_prefix = match party_id {
            Some(party_id) => format!("{storage_type}-p{party_id}"),
            None => format!("{storage_type}"),
        };
        let blob_path = match path {
            Some(path) => format!(
                "{}/{extra_prefix}",
                path.trim_start_matches('/').trim_end_matches('/'),
            ),
            None => extra_prefix,
        };
        let aws_sdk_config = build_aws_sdk_config(aws_region, aws_imds_endpoint).await;
        let s3_client = build_s3_client(&aws_sdk_config, aws_s3_endpoint).await?;
        Ok(S3Storage {
            aws_sdk_config,
            s3_client,
            blob_bucket,
            blob_path,
        })
    }

    /// Validates and parses an S3 URL into a bucket and path.
    fn parse_url(url: &Url) -> anyhow::Result<(String, String)> {
        ensure!(url.scheme() == "s3", "Storage URL is not an S3 URL");
        ensure!(
            url.path() != "/",
            "Storage URL does not have an S3 key name"
        );
        let bucket = some_or_err(url.host(), "No host present in URL".to_string())?.to_string();
        let path = url
            .path()
            .trim_start_matches('/')
            .trim_end_matches('/')
            .to_string();
        Ok((bucket, path))
    }
}

#[tonic::async_trait]
impl StorageReader for S3Storage {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        let (bucket, key) = S3Storage::parse_url(url)?;

        tracing::info!(
            "Checking if object exists in bucket {} under key {}",
            bucket,
            key
        );

        let result = self
            .s3_client
            .head_object()
            .bucket(bucket)
            .key(key)
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

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        let (bucket, key) = S3Storage::parse_url(url)?;

        tracing::info!("Reading object from bucket {} under key {}", bucket, key);

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
                self.blob_bucket, self.blob_path, data_type, data_id
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
            .prefix(format!("{}/{}/", &self.blob_path, data_type))
            .send()
            .await?;
        for cur_res in result.contents() {
            if let Some(key) = &cur_res.key {
                let trimmed_key = key.trim();
                // Find the elements with the right prefix
                // Find the id of file which is always the last segment when splitting on "/"
                if let Some(cur_id) = trimmed_key.split('/').last() {
                    urls.insert(cur_id.to_string(), self.compute_url(cur_id, data_type)?);
                }
            }
        }
        Ok(urls)
    }

    fn info(&self) -> String {
        format!("S3 storage with bucket {}", self.blob_bucket)
    }
}

#[tonic::async_trait]
impl Storage for S3Storage {
    /// If one reads "public" not as in "public key" but as in "not a secret", it makes sense to
    /// implement storage of encrypted private keys in the `PublicStorage` trait. Encrypted secrets
    /// can be published, if the root key stays secret.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let (bucket, key) = S3Storage::parse_url(url)?;

        tracing::info!("Storing object in bucket {} under key {}", bucket, key);

        s3_put_blob(&self.s3_client, &bucket, &key, data).await
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        let (bucket, key) = S3Storage::parse_url(url)?;

        tracing::info!("Deleting object from bucket {} under key {}", bucket, key);

        let _ = self
            .s3_client
            .delete_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await;
        Ok(())
    }
}

#[tonic::async_trait]
impl StorageForText for S3Storage {
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        let (bucket, key) = S3Storage::parse_url(url)?;

        tracing::info!("Storing text in bucket {} under key {}", bucket, key);

        s3_put_blob_bytes(&self.s3_client, &bucket, &key, text.as_bytes().to_vec()).await
    }
}

/// Keeps together everything needed for running a chain of trust for working
/// with application secret keys (such as FHE private keys). The root key
/// encrypt data keys which encrypt application keys. The root key is stored in
/// AWS KMS and never leaves it. Encrypted application keys (together with the
/// corresponding data keys) are stored on S3. The enclave keypair permits
/// secure decryption of data keys by AWS KMS.
pub struct EnclaveS3Storage {
    s3_storage: S3Storage,
    aws_kms_client: AmazonKMSClient,
    root_key_id: String,
    enclave_sk: RsaPrivateKey,
    enclave_pk: RsaPublicKey,
}

impl EnclaveS3Storage {
    pub async fn new(
        s3_storage: S3Storage,
        aws_kms_endpoint: Url,
        root_key_id: String,
    ) -> anyhow::Result<Self> {
        let aws_kms_client =
            build_aws_kms_client(&s3_storage.aws_sdk_config, aws_kms_endpoint).await;
        let enclave_sk = RsaPrivateKey::new(&mut OsRng, ENCLAVE_SK_SIZE)?;
        let enclave_pk = RsaPublicKey::from(&enclave_sk);
        Ok(EnclaveS3Storage {
            s3_storage,
            aws_kms_client,
            root_key_id,
            enclave_sk,
            enclave_pk,
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

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        let mut encrypted_data = self.s3_storage.read_data(url).await?;
        nitro_enclave_decrypt_app_key(
            &self.aws_kms_client,
            &self.enclave_sk,
            &self.enclave_pk,
            &mut encrypted_data,
        )
        .await
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        self.s3_storage.all_urls(data_type).await
    }

    fn info(&self) -> String {
        format!(
            "Nitro enclave storage with bucket {}",
            self.s3_storage.blob_bucket
        )
    }
}

#[tonic::async_trait]
impl Storage for EnclaveS3Storage {
    /// If one reads "public" not as in "public key" but as in "not a secret", it makes sense to
    /// implement storage of encrypted private keys in the `PublicStorage` trait. Encrypted secrets
    /// can be published, if the root key stays secret.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let encrypted_data = nitro_enclave_encrypt_app_key(
            &self.aws_kms_client,
            &self.enclave_sk,
            &self.enclave_pk,
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

cfg_if::cfg_if! {
    if #[cfg(feature = "s3_tests")]{
        pub const BUCKET_NAME: &str = "jot2re-kms-key-test";
        pub const AWS_REGION: &str = "eu-north-1";
    // this points to a locally running Minio
    pub const AWS_S3_ENDPOINT: &str = "http://localhost:9000";
    }
}
/// Observe that certain tests require an S3 instance setup.
/// There are run with the extra arguent `-F s3_tests`.
/// Note that we pay for each of these tests, in the order of single digit cents per tests.
///
/// To setup a test environment for S3 proceed as follows:
///
/// 1. Creating access keys:
///    a. Log into aws.amazon.com
///    b. In the top right corner of the page there'll be your AWS account name. Click on it, and in the drop-down menu go to "security credentials".
///    c. Select “Create access keys”
///    d. Make sure to locally store the AWS access key ID and secret access key.
/// 2. Create S3 bucket
///    a. Search for “S3 console” in the search bar after logging into aws.amazon.com
///    b. Click “Create a bucket”
///    c. Make a “general bucket” and remember the name you gave it
///    d. Download the AWS CLI tool
///    e. Run `aws configure` to set it up with the correct information for your bucket
///    f. Validate it works with `aws s3 ls`
/// 3. Test S3 storage
///    a. Update the const's BUCKET_NAME and AWS_REGION below to reflect what you created.
///    b. Now you can run the tests :)
///         cargo test --lib -F s3_tests s3_
#[cfg(test)]
pub mod tests {
    use super::*;
    use url::Url;

    #[cfg(feature = "s3_tests")]
    use crate::storage::tests::*;

    #[tokio::test]
    async fn aws_storage_url() {
        let storage = S3Storage::new(
            "aws_region".to_string(),
            Some(Url::parse("http://aws_imds_proxy").unwrap()),
            Some(Url::parse("https://aws_s3_proxy").unwrap()),
            "blob_bucket".to_string(),
            Some("blob_key_prefix".to_string()),
            StorageType::PUB,
            None,
        )
        .await
        .unwrap();

        let url = storage.compute_url("id", "type").unwrap();
        assert_eq!(
            url,
            Url::parse("s3://blob_bucket/blob_key_prefix/PUB/type/id").unwrap()
        );

        assert!(storage.compute_url("as/df", "type").is_err());
        assert!(storage.compute_url("id", "as/df").is_err());
    }

    #[cfg(feature = "s3_tests")]
    #[tokio::test]
    async fn s3_storage_helper_methods() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut pub_storage = S3Storage::new(
            AWS_REGION.to_string(),
            None,
            None,
            BUCKET_NAME.to_string(),
            Some(temp_dir.path().to_str().unwrap().to_string()),
            StorageType::PUB,
            None,
        )
        .await
        .unwrap();
        test_storage_read_store_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
    }
}
