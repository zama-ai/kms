use super::{Storage, StorageCache, StorageForText, StorageReader, StorageType};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::{anyhow_error_and_log, some_or_err};
use anyhow::ensure;
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
use http::{header::HOST, HeaderValue};
use hyper_rustls::HttpsConnectorBuilder;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

pub struct S3Storage {
    pub s3_client: S3Client,
    pub blob_bucket: String,
    pub blob_path: String,
    cache: Option<Arc<Mutex<StorageCache>>>,
}

impl S3Storage {
    pub fn new(
        s3_client: S3Client,
        blob_bucket: String,
        path: Option<String>,
        storage_type: StorageType,
        party_id: Option<usize>,
        cache: Option<StorageCache>,
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
        Ok(S3Storage {
            s3_client,
            blob_bucket,
            blob_path,
            cache: cache.map(|x| Arc::new(Mutex::new(x))),
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
        let buf = match &self.cache {
            Some(cache) => {
                let cache = Arc::clone(cache);
                let mut guarded_cache = cache.lock().await;
                match guarded_cache.get(&bucket, &key) {
                    Some(buf) => {
                        tracing::info!("found bucket={bucket}, path={key} in storage cache");
                        buf.clone()
                    }
                    None => {
                        let data = s3_get_blob(&self.s3_client, &bucket, &key).await?;
                        guarded_cache.insert(&bucket, &key, &data);
                        data
                    }
                }
            }
            None => s3_get_blob(&self.s3_client, &bucket, &key).await?,
        };
        safe_deserialize(&mut std::io::Cursor::new(buf), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e))
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
        let mut buf = Vec::new();
        safe_serialize(data, &mut buf, SAFE_SER_SIZE_LIMIT)?;
        self.cache.as_ref().map(|cache| async {
            Arc::clone(cache).lock().await.insert(&bucket, &key, &buf);
        });
        s3_put_blob(&self.s3_client, &bucket, &key, buf).await
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

        s3_put_blob(&self.s3_client, &bucket, &key, text.as_bytes().to_vec()).await
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
            Err(anyhow::anyhow!("AWS error, please refer to other logs."))
        }
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
    use crate::vault::storage::tests::*;

    #[tokio::test]
    async fn aws_storage_url() {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = S3Client::new(&config);
        let storage = S3Storage::new(
            s3_client,
            "blob_bucket".to_string(),
            Some("blob_key_prefix".to_string()),
            StorageType::PUB,
            None,
            None,
        )
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
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = S3Client::new(&config);
        let temp_dir = tempfile::tempdir().unwrap();
        let mut pub_storage = S3Storage::new(
            s3_client,
            BUCKET_NAME.to_string(),
            Some(temp_dir.path().to_str().unwrap().to_string()),
            StorageType::PUB,
            None,
            None,
        )
        .unwrap();
        test_storage_read_store_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
    }
}
