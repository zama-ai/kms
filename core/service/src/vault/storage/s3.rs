use super::{Storage, StorageCache, StorageForBytes, StorageReader, StorageType};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use aws_config::SdkConfig;
use aws_sdk_s3::{error::ProvideErrorMetadata, primitives::ByteStream, Client as S3Client};
use aws_smithy_runtime::client::http::hyper_014::HyperClientBuilder;
use aws_smithy_runtime_api::{
    box_error::BoxError,
    client::{
        interceptors::{context::BeforeTransmitInterceptorContextMut, Intercept},
        runtime_components::RuntimeComponents,
    },
};
use aws_smithy_types::config_bag::ConfigBag;
use http_legacy::{header::HOST, HeaderValue};
use hyper_rustls::HttpsConnectorBuilder;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use std::{collections::HashSet, str::FromStr};
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};
use threshold_fhe::execution::runtime::party::Role;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

#[derive(Debug, Clone)]
pub struct S3Storage {
    pub s3_client: S3Client,
    pub bucket: String,
    pub prefix: String,
    cache: Option<Arc<Mutex<StorageCache>>>,
}

impl S3Storage {
    pub fn new(
        s3_client: S3Client,
        bucket: String,
        prefix: Option<String>,
        storage_type: StorageType,
        party_role: Option<Role>,
        cache: Option<StorageCache>,
    ) -> anyhow::Result<Self> {
        let extra_prefix = match party_role {
            Some(party_role) => format!("{storage_type}-p{party_role}"),
            None => format!("{storage_type}"),
        };
        let prefix = match prefix {
            Some(p) => format!("{p}/{extra_prefix}"),
            None => extra_prefix,
        };
        Ok(S3Storage {
            s3_client,
            bucket,
            prefix,
            cache: cache.map(|x| Arc::new(Mutex::new(x))),
        })
    }

    fn item_key(&self, data_id: &RequestId, data_type: &str) -> String {
        format!("{}/{}/{}", self.prefix, data_type, data_id)
    }

    /// Helper to update cache after successful S3 operation
    async fn update_cache(&self, key: &str, data: &[u8]) {
        if let Some(cache) = &self.cache {
            let cache = Arc::clone(cache);
            let mut guarded_cache = cache.lock().await;
            match guarded_cache.insert(&self.bucket, key, data) {
                Some(old_data) => {
                    let size_changed = old_data.len() != data.len();
                    let data_changed = old_data != data;
                    tracing::debug!("Updated cache entry for bucket={}, key={}, size_changed={}, data_changed={}, size={}", 
                        &self.bucket, key, size_changed, data_changed, data.len());
                }
                None => {
                    tracing::debug!(
                        "Added new cache entry for bucket={}, key={}, size={}",
                        &self.bucket,
                        key,
                        data.len()
                    );
                }
            }
        }
    }

    /// Helper to delete cache entry (remove from cache)
    async fn delete_cache(&self, key: &str) {
        if let Some(cache) = &self.cache {
            let cache = Arc::clone(cache);
            let mut guarded_cache = cache.lock().await;
            match guarded_cache.remove(&self.bucket, key) {
                Some(_) => {
                    tracing::debug!(
                        "Removed cache entry for bucket={}, key={}",
                        &self.bucket,
                        key
                    );
                }
                None => {
                    tracing::warn!(
                        "Attempted to remove non-existent cache entry for bucket={}, key={}",
                        &self.bucket,
                        key
                    );
                }
            }
        }
    }

    /// Helper to get data from cache or S3 with cache population
    async fn get_with_cache(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        match &self.cache {
            Some(cache) => {
                let cache = Arc::clone(cache);
                let mut guarded_cache = cache.lock().await;
                match guarded_cache.get(&self.bucket, key) {
                    Some(buf) => {
                        tracing::info!(
                            "found bucket={}, path={} in storage cache",
                            &self.bucket,
                            key
                        );
                        Ok(buf.clone())
                    }
                    None => {
                        let data = s3_get_blob(&self.s3_client, &self.bucket, key).await?;
                        guarded_cache.insert(&self.bucket, key, &data);
                        Ok(data)
                    }
                }
            }
            None => s3_get_blob(&self.s3_client, &self.bucket, key).await,
        }
    }
}

impl StorageReader for S3Storage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Checking if object exists in bucket {} under key {}",
            self.bucket,
            key
        );

        let result = self
            .s3_client
            .head_object()
            .bucket(self.bucket.clone())
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
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Reading object from bucket {} under key {}",
            self.bucket,
            key
        );

        let buf = self.get_with_cache(key).await?;
        safe_deserialize(&mut std::io::Cursor::new(buf), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let mut ids = HashSet::new();
        let result = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .delimiter("/")
            .prefix(format!("{}/{}/", &self.prefix, data_type))
            .send()
            .await?;
        for cur_res in result.contents() {
            if let Some(key) = &cur_res.key {
                let trimmed_key = key.trim();
                // Find the elements with the right prefix
                // Find the id of file which is always the last segment when splitting on "/"
                if let Some(cur_id) = trimmed_key.split('/').next_back() {
                    ids.insert(RequestId::from_str(cur_id)?);
                }
            }
        }
        Ok(ids)
    }

    fn info(&self) -> String {
        format!("S3 storage with bucket {}", self.bucket)
    }
}

impl Storage for S3Storage {
    /// If one reads "public" not as in "public key" but as in "not a secret", it makes sense to
    /// implement storage of encrypted private keys in the `PublicStorage` trait. Encrypted secrets
    /// can be published, if the root key stays secret.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(());
        }
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Storing object in bucket {} under key {}",
            &self.bucket,
            key
        );
        let mut buf = Vec::new();
        safe_serialize(data, &mut buf, SAFE_SER_SIZE_LIMIT)?;

        // Store in S3 FIRST - only update cache if S3 operation succeeds
        s3_put_blob(&self.s3_client, &self.bucket, key, buf.clone()).await?;

        // Update cache ONLY after successful S3 storage
        self.update_cache(key, &buf).await;

        Ok(())
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Deleting object from bucket {} under key {}",
            &self.bucket,
            key
        );

        // Remove from cache BEFORE deleting from S3 to prevent stale cache reads
        self.delete_cache(key).await;

        // Attempt S3 deletion but don't fail on errors
        if let Err(e) = self
            .s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            tracing::error!("S3 delete failed: {:?}", e);
        }

        Ok(())
    }
}

impl StorageForBytes for S3Storage {
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(());
        }
        let key = &self.item_key(data_id, data_type);

        tracing::info!("Storing text in bucket {} under key {}", &self.bucket, key);

        // Store in S3 FIRST - only update cache if S3 operation succeeds
        s3_put_blob(&self.s3_client, &self.bucket, key, bytes.to_vec()).await?;

        // Update cache ONLY after successful S3 storage
        self.update_cache(key, bytes).await;

        Ok(())
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Reading text from bucket {} under key {}",
            &self.bucket,
            key
        );

        // Check cache first, then S3 if not found
        self.get_with_cache(key).await
    }
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
                host: format!("s3.{region}.amazonaws.com"),
            };
            match p.scheme() {
                "https" => {
                    let https_connector = HttpsConnectorBuilder::new()
                        .with_native_roots()
                        .https_only()
                        // Overrides the hostname checked during the TLS handshake
                        .with_server_name(format!("s3.{region}.amazonaws.com"))
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

pub(crate) async fn s3_get_blob(
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

pub(crate) async fn s3_put_blob(
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
            Err(anyhow::anyhow!(
                "AWS error, please refer to other logs.: {err}"
            ))
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(feature = "s3_tests")]{
        pub const BUCKET_NAME: &str = "ci-kms-key-test";
        pub const AWS_REGION: &str = "eu-north-1";
        // this points to a locally running Minio
        pub const AWS_S3_ENDPOINT: &str = "http://127.0.0.1:9000";
    }
}

// Observe that certain tests require an S3 instance setup.
// There are run with the extra argument `-F s3_tests`.
// Note that we pay for each of these tests, in the order of single digit cents per tests.
//
// To setup the testing environment locally with Minio, proceed as follows:
// 1. Install and run Minio in Docker
//    a. Simplest way is to just run `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up` as this ensure Minio is configured and started correctly.
// 2. Setup the bucket. With in the `dev-s3-mock-1` container in Docker execute the following commands:
//   a. First open Docker desktop and navitage to `Volumes` and find `zama-core-threshold_minio_secrets` and cope the content of `access_key` and the content of `secret_key`.
//   b. Run `mc alias set testminio http://127.0.0.1:9000 <access_key> <secret_key>` (and replace `<access_key>` respectively `<secret_key>` with the values copied above and ssuming no change to [`AWS_S3_ENDPOINT`])
//   c. Run `mc mb testminio/ci-kms-key-test` (Assuming no change to [`BUCKET_NAME`])
//   d. Run `mc anonymous set public testminio/ci-kms-key-test`
// 3. Update the environment variables in the shell where you run the tests:
//   a. Execute the following:
//   ```bash
//      AWS_ACCESS_KEY_ID=<access_key> &&
//      export AWS_ACCESS_KEY_ID &&
//      AWS_SECRET_ACCESS_KEY=<secret_key> &&
//      export AWS_SECRET_ACCESS_KEY
//   ```
//   where `<access_key>` and `<secret_key>` are the values copied above.
// 4. Now you can execute the tests: `cargo test --lib -F s3_tests s3_`
//
// To instead setup a test environment for a real S3 proceed as follows:
//
// 1. Creating access keys:
//    a. Log into aws.amazon.com
//    b. In the top right corner of the page there'll be your AWS account name. Click on it, and in the drop-down menu go to "security credentials".
//    c. Select “Create access keys”
//    d. Make sure to locally store the AWS access key ID and secret access key.
// 2. Create S3 bucket
//    a. Search for “S3 console” in the search bar after logging into aws.amazon.com
//    b. Click “Create a bucket”
//    c. Make a “general bucket” and remember the name you gave it
//    d. Download the AWS CLI tool
//    e. Run `aws configure` to set it up with the correct information for your bucket
//    f. Validate it works with `aws s3 ls`
// 3. Test S3 storage
//    a. Update the const's BUCKET_NAME and AWS_REGION below to reflect what you created.
//    b. Now you can run the tests :)
//    cargo test --lib -F s3_tests s3_
#[cfg(feature = "s3_tests")]
#[cfg(test)]
mod tests {
    use super::*;
    use super::{AWS_S3_ENDPOINT, BUCKET_NAME};
    use crate::vault::storage::tests::{
        test_batch_helper_methods, test_storage_read_store_methods,
        test_store_bytes_does_not_overwrite_existing_bytes,
        test_store_data_does_not_overwrite_existing_data,
    };

    #[tokio::test]
    async fn s3_storage_helper_methods() {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let mut pub_storage = S3Storage::new(
            s3_client,
            BUCKET_NAME.to_string(),
            Some(
                temp_dir
                    .path()
                    .to_str()
                    .unwrap()
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_string(),
            ),
            StorageType::PUB,
            None,
            None,
        )
        .unwrap();
        test_storage_read_store_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
    }

    /// Test that files don't get silently overwritten
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_overwrite_logic_files() {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
            .await
            .unwrap();
        let temp_dir = tempfile::tempdir().unwrap();
        let mut pub_storage = S3Storage::new(
            s3_client,
            BUCKET_NAME.to_string(),
            Some(
                temp_dir
                    .path()
                    .to_str()
                    .unwrap()
                    .trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_string(),
            ),
            StorageType::PUB,
            None,
            None,
        )
        .unwrap();
        test_store_bytes_does_not_overwrite_existing_bytes(&mut pub_storage).await;
        test_store_data_does_not_overwrite_existing_data(&mut pub_storage).await;
        assert!(logs_contain(
            "already exists. Keeping the data without overwriting"
        ));
    }
}
