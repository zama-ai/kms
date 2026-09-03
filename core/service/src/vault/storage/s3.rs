use super::{RootEntries, Storage, StorageReader, StorageType, StoreWriteOutcome};
use crate::vault::storage::{StorageExt, StorageReaderExt, all_data_ids_from_all_epochs_impl};
use crate::{consts::SAFE_SER_SIZE_LIMIT, vault::storage_prefix_safety};
use aws_config::{self, Region, SdkConfig};
use aws_sdk_s3::{Client as S3Client, error::ProvideErrorMetadata, primitives::ByteStream};
use kms_grpc::{RequestId, identifiers::EpochId};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(test)]
use std::cell::RefCell;
use std::{collections::HashSet, str::FromStr};
use tfhe::{
    Unversionize, Versionize,
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
};
use tokio::io::AsyncReadExt;
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

#[derive(Debug, Clone)]
pub struct S3Storage {
    pub s3_client: S3Client,
    pub bucket: String,
    pub prefix: String,
}

/// Read-only S3 storage wrapper, should not implement Storage trait.
pub struct ReadOnlyS3Storage {
    inner: S3Storage,
}

impl ReadOnlyS3Storage {
    pub fn new(
        s3_client: S3Client,
        bucket: String,
        storage_type: StorageType,
        storage_prefix: Option<&str>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: S3Storage::new(s3_client, bucket, storage_type, storage_prefix)?,
        })
    }
}

impl StorageReader for ReadOnlyS3Storage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        self.inner.data_exists(data_id, data_type).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.inner.read_data(data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.inner.load_bytes(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids(data_type).await
    }

    async fn all_data_types(&self) -> anyhow::Result<RootEntries> {
        self.inner.all_data_types().await
    }

    fn info(&self) -> String {
        self.inner.info()
    }
}

impl S3Storage {
    pub fn new(
        s3_client: S3Client,
        bucket: String,
        storage_type: StorageType,
        storage_prefix: Option<&str>,
    ) -> anyhow::Result<Self> {
        let prefix = match storage_prefix {
            Some(prefix) => {
                storage_prefix_safety(storage_type, prefix)?;
                prefix.to_string()
            }
            None => format!("{storage_type}"),
        };
        Ok(S3Storage {
            s3_client,
            bucket,
            prefix,
        })
    }

    fn item_key(&self, data_id: &RequestId, data_type: &str) -> String {
        format!("{}/{}/{}", self.prefix, data_type, data_id)
    }

    fn item_key_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> String {
        format!("{}/{}/{}/{}", self.prefix, data_type, epoch_id, data_id)
    }

    async fn data_exists_at_key(&self, key: &str) -> anyhow::Result<bool> {
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
            // Only a genuine "not found" error means the object is absent. Any
            // other error (403 Access Denied, 500, 503 Slow Down, ...) must
            // propagate to callers.
            Err(sdk_error) => {
                if sdk_error
                    .as_service_error()
                    .is_some_and(|e| e.is_not_found())
                {
                    Ok(false)
                } else {
                    Err(sdk_error.into())
                }
            }
        }
    }

    async fn store_data_at_key<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        key: &str,
        data: &T,
    ) -> anyhow::Result<()> {
        tracing::info!(
            "Storing object in bucket {} under key {}",
            &self.bucket,
            key
        );
        let mut buf = Vec::new();
        safe_serialize(data, &mut buf, SAFE_SER_SIZE_LIMIT)?;

        let size = buf.len() as f64;
        s3_put_blob(&self.s3_client, &self.bucket, key, buf).await?;

        // Record the persisted payload size, keyed by the element's type name (see `observe_size`).
        observability::metrics::METRICS.observe_size(<T as Named>::NAME, size);

        Ok(())
    }

    /// Deletes the object at the given key.
    ///
    /// This operation is idempotent on S3, so this succeeds when the object
    /// does not exist.
    async fn delete_data_at_key(&mut self, key: &str) -> anyhow::Result<()> {
        tracing::info!(
            "Deleting object from bucket {} under key {}",
            &self.bucket,
            key
        );

        self.s3_client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("S3 delete failed for key {key}: {e}"))?;

        Ok(())
    }

    /// List every object key (from `contents`) and common prefix (from `common_prefixes`)
    /// under `prefix`, following `ListObjectsV2` continuation tokens so the result is the
    /// full listing rather than a single (≤1000-entry) page. Keys and prefixes are trimmed.
    async fn list_all(&self, prefix: &str) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        let mut keys = Vec::new();
        let mut common_prefixes = Vec::new();
        let mut continuation_token = None;
        loop {
            let result = self
                .s3_client
                .list_objects_v2()
                .bucket(&self.bucket)
                .delimiter("/")
                .prefix(prefix)
                .set_continuation_token(continuation_token)
                .send()
                .await?;
            for cur_res in result.contents() {
                if let Some(key) = &cur_res.key {
                    keys.push(key.trim().to_string());
                }
            }
            for cur_res in result.common_prefixes() {
                if let Some(p) = &cur_res.prefix {
                    common_prefixes.push(p.trim().to_string());
                }
            }
            if result.is_truncated().unwrap_or(false) {
                continuation_token = result.next_continuation_token().map(str::to_string);
            } else {
                break;
            }
        }
        Ok((keys, common_prefixes))
    }
}

impl StorageReader for S3Storage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let key = &self.item_key(data_id, data_type);
        self.data_exists_at_key(key).await
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

        let buf = s3_get_blob(&self.s3_client, &self.bucket, key).await?;
        safe_deserialize(&mut std::io::Cursor::new(buf), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let key = &self.item_key(data_id, data_type);

        tracing::info!(
            "Reading bytes from bucket {} under key {}",
            &self.bucket,
            key
        );

        s3_get_blob(&self.s3_client, &self.bucket, key).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let (keys, _) = self
            .list_all(&format!("{}/{}/", self.prefix, data_type))
            .await?;
        let mut ids = HashSet::new();
        for key in keys {
            // The id is always the last segment when splitting the key on "/".
            if let Some(cur_id) = key.split('/').next_back() {
                ids.insert(RequestId::from_str(cur_id)?);
            }
        }
        Ok(ids)
    }

    async fn all_data_types(&self) -> anyhow::Result<RootEntries> {
        // The trailing "/" keeps a prefix such as "PUB-p1" from matching "PUB-p10".
        let root = format!("{}/", self.prefix);
        let (keys, common_prefixes) = self.list_all(&root).await?;
        let mut res = RootEntries::default();
        // Folders arrive as common prefixes, objects directly under the root as keys.
        for folder in common_prefixes {
            if let Some(name) = folder.strip_prefix(&root) {
                let name = name.trim_end_matches('/');
                if !name.is_empty() {
                    res.folders.insert(name.to_string());
                }
            }
        }
        for key in keys {
            if let Some(name) = key.strip_prefix(&root)
                && !name.is_empty()
            {
                res.objects.insert(name.to_string());
            }
        }
        Ok(res)
    }

    fn info(&self) -> String {
        format!("S3 storage with bucket {}", self.bucket)
    }
}

impl StorageReaderExt for S3Storage {
    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);
        self.data_exists_at_key(key).await
    }

    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);

        tracing::info!(
            "Reading object from bucket {} under key {}",
            self.bucket,
            key
        );

        let buf = s3_get_blob(&self.s3_client, &self.bucket, key).await?;
        safe_deserialize(&mut std::io::Cursor::new(buf), SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow::anyhow!(e))
    }

    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        let (keys, _) = self
            .list_all(&format!("{}/{}/{}/", self.prefix, data_type, epoch_id))
            .await?;
        let mut ids = HashSet::new();
        for key in keys {
            // The id is always the last segment when splitting the key on "/".
            if let Some(cur_id) = key.split('/').next_back() {
                ids.insert(RequestId::from_str(cur_id)?);
            }
        }
        Ok(ids)
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let (_, common_prefixes) = self
            .list_all(&format!("{}/{}/", self.prefix, data_type))
            .await?;
        let mut ids = HashSet::new();
        // With delimiter="/", epoch_ids appear as "directories" in common_prefixes,
        // not as objects in contents()
        for key in common_prefixes {
            // Ensure we only count "directories" by checking for the trailing "/"
            if key.ends_with('/') {
                // Remove the '/' at the end and take the last segment after splitting on "/" to get epoch_id
                if let Some(cur_id) = key.trim_end_matches('/').split('/').next_back() {
                    ids.insert(EpochId::from_str(cur_id)?);
                }
            }
        }
        Ok(ids)
    }

    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        all_data_ids_from_all_epochs_impl(self, data_type)
            .await
            .map(|(ids, _)| ids)
    }

    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);

        tracing::info!(
            "Reading bytes from bucket {} under key {}",
            &self.bucket,
            key
        );

        s3_get_blob(&self.s3_client, &self.bucket, key).await
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
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let key = &self.item_key(data_id, data_type);
        self.store_data_at_key(key, data).await?;
        Ok(StoreWriteOutcome::Created)
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let key = &self.item_key(data_id, data_type);

        tracing::info!("Storing bytes in bucket {} under key {}", &self.bucket, key);

        s3_put_blob(&self.s3_client, &self.bucket, key, bytes.to_vec()).await?;

        Ok(StoreWriteOutcome::Created)
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let key = &self.item_key(data_id, data_type);
        self.delete_data_at_key(key).await
    }
}

impl StorageExt for S3Storage {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await?
        {
            tracing::warn!(
                "The data {}-{} at epoch {} already exists. Keeping the data without overwriting",
                data_id,
                data_type,
                epoch_id
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);
        self.store_data_at_key(key, data).await?;
        Ok(StoreWriteOutcome::Created)
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await?
        {
            tracing::warn!(
                "The data {}-{} at epoch {} already exists. Keeping the data without overwriting",
                data_id,
                data_type,
                epoch_id
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);

        tracing::info!("Storing bytes in bucket {} under key {}", &self.bucket, key);

        s3_put_blob(&self.s3_client, &self.bucket, key, bytes.to_vec()).await?;

        Ok(StoreWriteOutcome::Created)
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let key = &self.item_key_at_epoch(data_id, epoch_id, data_type);
        self.delete_data_at_key(key).await
    }
}

/// Split an S3 URL into its protocol, domain and bucket name.
/// For example:
/// The URL https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/ will be split into
/// protocol: "https://", domain: "s3.eu-west-1.amazonaws.com", bucket: "zama-zws-dev-tkms-b6q87"
///
/// The URL http://localhost:9000/kms will be split into
/// protocol: "http://", domain: "localhost:9000", bucket: "kms"
///
/// The URL file:///tmp/somepath will be split into
/// protocol: "file://", domain: "", bucket: "/tmp/somepath"
///
/// Code is adapted from
/// https://github.com/zama-ai/fhevm/blob/dac153662361758c9a563e766473692f8acf1074/coprocessor/fhevm-engine/gw-listener/src/aws_s3.rs#L140C1-L174C1
pub fn split_url(s3_bucket_url: &String) -> anyhow::Result<(String, String, String)> {
    tracing::info!("Splitting S3 url: {}", s3_bucket_url);
    let parsed = url::Url::parse(s3_bucket_url.as_str())?;
    let protocol = format!("{}://", parsed.scheme());

    // Build domain as host + optional port
    let domain = match (parsed.host_str(), parsed.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_string(),
        _ => String::new(),
    };

    // Extract bucket from path or domain
    let path_bucket = parsed
        .path()
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_owned();

    if path_bucket.is_empty() {
        tracing::warn!(
            "Bucket is empty, attempting to deduce from domain {:?}",
            parsed
        );
        // e.g BBBBBB.s3.eu-west-1.amazonaws.com, the bucket is part of the domain
        let bucket_from_domain = bucket_from_domain(&parsed)?;
        // Remove bucket subdomain from domain string
        let domain = domain
            .replace(&(bucket_from_domain.clone() + "."), "")
            .trim_end_matches('/')
            .to_string();

        tracing::info!(
            s3_bucket_url,
            protocol,
            domain,
            bucket_from_domain,
            "Bucket from domain"
        );
        Ok((protocol, domain, bucket_from_domain))
    } else if protocol == "file://" {
        // For file:// URLs, the full path is the "bucket" (filesystem root)
        let full_path = parsed.path().to_string();
        tracing::info!(
            s3_bucket_url,
            protocol,
            domain,
            bucket = full_path,
            "File URL"
        );
        Ok((protocol, domain, full_path))
    } else {
        tracing::info!(
            s3_bucket_url,
            protocol,
            domain,
            path_bucket,
            "Parsed S3 url"
        );
        Ok((protocol, domain, path_bucket))
    }
}

fn bucket_from_domain(url: &url::Url) -> anyhow::Result<String> {
    let Some(domain) = url.domain() else {
        anyhow::bail!("Cannot deduce the bucket name from url {:?}", url);
    };
    let domain_parts = domain.split('.').collect::<Vec<&str>>();
    if domain_parts.len() < 2 {
        tracing::warn!(
            "Cannot deduce the bucket name from url {:?}. Returning default bucket used in testing",
            url
        );
        Ok("kms".to_owned())
    } else {
        Ok(domain_parts[0].to_owned())
    }
}

// This builds an anonymous S3 client, useful for accessing public S3 buckets.
pub async fn build_anonymous_s3_client(
    aws_s3_endpoint: &str,
    region: String,
) -> anyhow::Result<S3Client> {
    let aws_region = Region::new(region);
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_region)
        .no_credentials()
        .load()
        .await;

    let s3_config_builder = aws_sdk_s3::config::Builder::from(&sdk_config)
        .endpoint_url(url::Url::parse(aws_s3_endpoint)?)
        .force_path_style(true);
    let s3_config = s3_config_builder.build();
    Ok(S3Client::from_conf(s3_config))
}

/// Constructs an S3 client for use inside of a Nitro enclave.
pub async fn build_s3_client(
    aws_sdk_config: &SdkConfig,
    aws_s3_endpoint: Option<Url>,
) -> anyhow::Result<S3Client> {
    let s3_config = match aws_s3_endpoint {
        Some(p) => match p.scheme() {
            "https" | "http" => aws_sdk_s3::config::Builder::from(aws_sdk_config)
                .endpoint_url(p)
                // Virtual-hosting style S3 URLs don't work well with endpoint overrides.
                .force_path_style(true)
                .build(),
            _ => anyhow::bail!("Only HTTP and HTTPS URL schemes are supported for S3 endpoints"),
        },
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

/// Find the AWS region from an S3 bucket URL.
/// For example:
/// The URL https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/ will return "eu-west-1".
pub fn find_region_from_s3_url(s3_bucket_url: &str) -> anyhow::Result<String> {
    let parsed_url = url::Url::parse(s3_bucket_url)?;
    let domain = parsed_url
        .domain()
        .ok_or(anyhow::anyhow!("Cannot parse domain from URL"))?;
    let domain_parts: Vec<&str> = domain.split('.').collect();
    if domain_parts.len() < 4 {
        tracing::warn!(
            "Cannot deduce the region from url {:?}. Using default us-east-1",
            s3_bucket_url
        );
        return Ok("us-east-1".to_owned()); // default region
    }
    let dot_com_pos = domain_parts.len() - 1;
    let expected_s3_pos = dot_com_pos - 3;
    let expected_region_pos = dot_com_pos - 2;
    // e.g s3.eu-west-1.amazonaws.com
    if domain_parts[expected_s3_pos] == "s3" {
        Ok(domain_parts[expected_region_pos].to_owned())
    } else {
        tracing::warn!(
            "Cannot deduce the region from url {:?}. Using default us-east-1",
            s3_bucket_url
        );
        Ok("us-east-1".to_owned()) // default region
    }
}

/// Bucket name expected by the in-memory mock S3 backend in tests.
#[cfg(all(test, feature = "non-wasm", feature = "testing"))]
pub(crate) const MOCK_BUCKET: &str = "test-bucket";

/// Build an [`S3Storage`] backed by a fresh in-memory mock S3 client, so the storage tests
/// exercise the real `S3Storage` + `aws_sdk_s3` code paths with no network / MinIO.
///
/// Lives outside [`tests`] because other modules' test suites (e.g. `engine::migration`) use it.
/// Kept `async` to match the call sites (the previous MinIO-backed helper was async).
#[cfg(all(test, feature = "non-wasm", feature = "testing"))]
pub async fn create_s3_storage(storage_type: StorageType, prefix: &str) -> S3Storage {
    let s3_client = mock_s3::build_mock_s3_client(mock_s3::new_store());
    S3Storage::new(
        s3_client,
        MOCK_BUCKET.to_string(),
        storage_type,
        Some(prefix),
    )
    .unwrap()
}

/// In-memory mock of the S3 operations used by [`S3Storage`], built on `aws-smithy-mocks`.
///
/// A bucket is modelled as a shared `key -> bytes` map. One `mock!` rule per operation
/// (`put`/`get`/`head`/`delete`/`list_objects_v2`) reads and writes that map, so stored data can
/// be read back exactly like a real bucket. `list_objects_v2` reproduces S3's `delimiter="/"`
/// behaviour (direct objects in `contents`, sub-"directories" in `common_prefixes`) because the
/// epoch-enumeration helpers ([`StorageReaderExt::all_epoch_ids_for_data`] etc.) depend on it.
#[cfg(all(test, feature = "non-wasm", feature = "testing"))]
pub(crate) mod mock_s3 {
    use super::*;
    use aws_sdk_s3::operation::{
        delete_object::DeleteObjectOutput,
        get_object::{GetObjectError, GetObjectOutput},
        head_object::{HeadObjectError, HeadObjectOutput},
        list_objects_v2::ListObjectsV2Output,
        put_object::PutObjectOutput,
    };
    use aws_sdk_s3::types::{
        CommonPrefix, Object,
        error::{NoSuchKey, NotFound},
    };
    use aws_smithy_mocks::{MockResponse, RuleMode, mock, mock_client};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::{Arc, Mutex};

    /// In-memory object store shared by every rule of a single mock client, keyed by full object
    /// key. Tests use a single logical bucket, so the mock ignores the request's bucket name.
    pub(crate) type SharedStore = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

    /// Create a fresh, empty [`SharedStore`].
    pub(crate) fn new_store() -> SharedStore {
        Arc::new(Mutex::new(BTreeMap::new()))
    }

    /// Build a mocked [`S3Client`] whose operations are served from `store`.
    pub(crate) fn build_mock_s3_client(store: SharedStore) -> S3Client {
        let put_store = Arc::clone(&store);
        let put = mock!(aws_sdk_s3::Client::put_object).then_compute_output(move |input| {
            let key = input.key().expect("put_object requires a key").to_string();
            // `s3_put_blob` builds the body from an in-memory `Vec`, so `bytes()` is always `Some`.
            let bytes = input
                .body()
                .bytes()
                .expect("mock put_object expects an in-memory body")
                .to_vec();
            put_store.lock().unwrap().insert(key, bytes);
            PutObjectOutput::builder().build()
        });

        let get_store = Arc::clone(&store);
        let get = mock!(aws_sdk_s3::Client::get_object).then_compute_response(move |input| {
            let key = input.key().expect("get_object requires a key");
            match get_store.lock().unwrap().get(key) {
                Some(bytes) => MockResponse::Output(
                    GetObjectOutput::builder()
                        .body(ByteStream::from(bytes.clone()))
                        .build(),
                ),
                None => {
                    MockResponse::Error(GetObjectError::NoSuchKey(NoSuchKey::builder().build()))
                }
            }
        });

        let head_store = Arc::clone(&store);
        let head = mock!(aws_sdk_s3::Client::head_object).then_compute_response(move |input| {
            let key = input.key().expect("head_object requires a key");
            if head_store.lock().unwrap().contains_key(key) {
                MockResponse::Output(HeadObjectOutput::builder().build())
            } else {
                MockResponse::Error(HeadObjectError::NotFound(NotFound::builder().build()))
            }
        });

        let delete_store = Arc::clone(&store);
        let delete = mock!(aws_sdk_s3::Client::delete_object).then_compute_output(move |input| {
            let key = input.key().expect("delete_object requires a key");
            delete_store.lock().unwrap().remove(key);
            DeleteObjectOutput::builder().build()
        });

        let list_store = Arc::clone(&store);
        let list = mock!(aws_sdk_s3::Client::list_objects_v2).then_compute_output(move |input| {
            let prefix = input.prefix().unwrap_or("");
            let delimiter = input.delimiter();
            let guard = list_store.lock().unwrap();
            let mut contents = Vec::new();
            let mut common_prefixes = BTreeSet::new();
            for key in guard.keys() {
                let Some(rest) = key.strip_prefix(prefix) else {
                    continue;
                };
                match delimiter.and_then(|d| rest.find(d).map(|i| i + d.len())) {
                    // `rest` contains the delimiter: collapse into a common prefix that includes
                    // everything up to and including the first delimiter (S3 semantics).
                    Some(end) => {
                        common_prefixes.insert(format!("{prefix}{}", &rest[..end]));
                    }
                    // No delimiter after the prefix: a direct object.
                    None => {
                        contents.push(Object::builder().key(key.clone()).build());
                    }
                }
            }
            let common_prefixes: Vec<_> = common_prefixes
                .into_iter()
                .map(|p| CommonPrefix::builder().prefix(p).build())
                .collect();
            ListObjectsV2Output::builder()
                .is_truncated(false)
                .set_contents((!contents.is_empty()).then_some(contents))
                .set_common_prefixes((!common_prefixes.is_empty()).then_some(common_prefixes))
                .build()
        });

        mock_client!(
            aws_sdk_s3,
            RuleMode::MatchAny,
            [&put, &get, &head, &delete, &list],
            |c| c.force_path_style(true)
        )
    }
}

// These tests exercise the real `S3Storage` + `aws_sdk_s3` code paths against an in-process
// mock S3 (see [`mock_s3`]) — no MinIO, no network, no credentials. They run as part of the
// normal `cargo test -F testing` suite.
#[cfg(all(test, feature = "non-wasm", feature = "testing"))]
mod tests {
    use super::*;
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::operation::{
        head_object::{HeadObjectError, HeadObjectOutput},
        list_objects_v2::ListObjectsV2Output,
    };
    use aws_sdk_s3::types::{Object, error::NotFound};
    use aws_smithy_mocks::{Rule, RuleMode, mock, mock_client};

    use crate::vault::storage::tests::{
        test_batch_helper_methods, test_epoch_methods, test_storage_read_store_methods,
        test_store_bytes_does_not_overwrite_existing_bytes,
        test_store_data_does_not_overwrite_existing_data, test_store_data_records_payload_size,
    };

    #[tokio::test]
    async fn s3_storage_helper_methods() {
        let mut pub_storage =
            create_s3_storage(StorageType::PUB, std::stringify!(s3_storage_helper_methods)).await;
        test_storage_read_store_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
        test_store_data_records_payload_size(&mut pub_storage).await;
    }

    #[tokio::test]
    async fn test_epoch_methods_in_s3() {
        let mut priv_storage =
            create_s3_storage(StorageType::PRIV, std::stringify!(test_epoch_methods_in_s3)).await;
        test_epoch_methods(&mut priv_storage).await;
    }

    #[tokio::test]
    async fn test_all_data_ids_from_all_epochs_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_all_data_ids_from_all_epochs_s3),
        )
        .await;
        crate::vault::storage::tests::test_all_data_ids_from_all_epochs(&mut priv_storage).await;
    }

    #[tokio::test]
    async fn test_crs_public_key_data_types_s3() {
        let mut pub_storage = create_s3_storage(
            StorageType::PUB,
            std::stringify!(test_crs_public_key_data_types_s3),
        )
        .await;
        crate::vault::storage::tests::test_crs_public_key_data_types(&mut pub_storage).await;
    }

    /// An object directly under the prefix belongs to no data type, so it is listed apart from
    /// the folders even when its name is one.
    #[tokio::test]
    async fn all_data_types_lists_root_objects_apart_from_folders() {
        let store = mock_s3::new_store();
        let mut storage = S3Storage::new(
            mock_s3::build_mock_s3_client(store.clone()),
            MOCK_BUCKET.to_string(),
            StorageType::PUB,
            None,
        )
        .unwrap();
        let id = crate::engine::base::derive_request_id("root-object").unwrap();
        let pk_type = kms_grpc::rpc_types::PubDataType::PublicKey.to_string();
        let crs_type = kms_grpc::rpc_types::PubDataType::CRS.to_string();
        storage.store_bytes(b"crs", &id, &crs_type).await.unwrap();
        store
            .lock()
            .unwrap()
            .insert(format!("{}/{pk_type}", storage.prefix), b"x".to_vec());

        assert_eq!(
            storage.all_data_types().await.unwrap(),
            RootEntries {
                folders: HashSet::from([crs_type]),
                objects: HashSet::from([pk_type]),
            }
        );
    }

    /// Several parties share one bucket, each under its own prefix. A party's listing must stay
    /// inside its prefix, including the `PUB-p1` versus `PUB-p10` case that only the trailing
    /// slash separates.
    #[tokio::test]
    async fn all_data_types_is_scoped_to_own_prefix() {
        let store = mock_s3::new_store();
        let storage_for = |prefix: &str| {
            S3Storage::new(
                mock_s3::build_mock_s3_client(store.clone()),
                MOCK_BUCKET.to_string(),
                StorageType::PUB,
                Some(prefix),
            )
            .unwrap()
        };
        let own = storage_for("PUB-p1");
        let mut p2 = storage_for("PUB-p2");
        let mut p10 = storage_for("PUB-p10");
        let id = crate::engine::base::derive_request_id("other-party").unwrap();
        let pk_type = kms_grpc::rpc_types::PubDataType::PublicKey.to_string();
        let crs_type = kms_grpc::rpc_types::PubDataType::CRS.to_string();
        p2.store_bytes(b"crs", &id, &crs_type).await.unwrap();
        p10.store_bytes(b"pk", &id, &pk_type).await.unwrap();

        assert_eq!(own.all_data_types().await.unwrap(), RootEntries::default());
        assert!(own.all_data_ids(&pk_type).await.unwrap().is_empty());
        assert_eq!(
            p10.all_data_types().await.unwrap().folders,
            HashSet::from([pk_type])
        );
        assert_eq!(
            p2.all_data_types().await.unwrap().folders,
            HashSet::from([crs_type])
        );
    }

    /// Test that files don't get silently overwritten
    #[tokio::test]
    async fn test_overwrite_logic_files() {
        let mut pub_storage = create_s3_storage(
            StorageType::PUB,
            std::stringify!(test_overwrite_logic_files),
        )
        .await;
        test_store_bytes_does_not_overwrite_existing_bytes(&mut pub_storage).await;
        test_store_data_does_not_overwrite_existing_data(&mut pub_storage).await;
    }

    #[tokio::test]
    async fn test_store_load_bytes_at_epoch_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_store_load_bytes_at_epoch_s3),
        )
        .await;
        crate::vault::storage::tests::test_store_load_bytes_at_epoch(&mut priv_storage).await;
    }

    #[tokio::test]
    async fn test_mixed_epoch_and_non_epoch_data_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_mixed_epoch_and_non_epoch_data_s3),
        )
        .await;
        crate::vault::storage::tests::test_all_epoch_ids_and_data_ids_with_mixed_storage(
            &mut priv_storage,
        )
        .await;
    }

    #[tokio::test]
    async fn test_epoch_ids_with_only_non_epoch_data_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_epoch_ids_with_only_non_epoch_data_s3),
        )
        .await;
        crate::vault::storage::tests::test_all_epoch_ids_for_data_with_only_non_epoch_data(
            &mut priv_storage,
        )
        .await;
    }

    #[tokio::test]
    async fn test_data_ids_with_only_epoch_data_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_data_ids_with_only_epoch_data_s3),
        )
        .await;
        crate::vault::storage::tests::test_all_data_ids_with_only_epoch_data(&mut priv_storage)
            .await;
    }

    #[tokio::test]
    async fn test_store_bytes_at_epoch_does_not_overwrite_s3() {
        let mut priv_storage = create_s3_storage(
            StorageType::PRIV,
            std::stringify!(test_store_bytes_at_epoch_does_not_overwrite_s3),
        )
        .await;
        crate::vault::storage::tests::test_store_bytes_at_epoch_does_not_overwrite(
            &mut priv_storage,
        )
        .await;
    }

    /// `data_exists_at_key` distinguishes three `head_object` outcomes: success ⇒ `true`, a genuine
    /// "not found" service error ⇒ `false`, and any other service error (403/500/503/…) ⇒ propagated
    /// as `Err`, so a transient failure is never silently mistaken for an absent object.
    #[tokio::test]
    async fn data_exists_at_key_maps_head_errors() {
        const KEY: &str = "PUB/PublicKey/some-object";

        // An `S3Storage` whose only mocked operation is `head_object`, served by `rule`.
        fn storage_for(rule: &Rule) -> S3Storage {
            let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, [rule], |c| c
                .force_path_style(true));
            S3Storage::new(client, MOCK_BUCKET.to_string(), StorageType::PUB, None).unwrap()
        }

        // Object present: `head_object` succeeds ⇒ `true`.
        let ok = mock!(aws_sdk_s3::Client::head_object)
            .then_output(|| HeadObjectOutput::builder().build());
        assert!(storage_for(&ok).data_exists_at_key(KEY).await.unwrap());

        // Genuine "not found" ⇒ `false`.
        let not_found = mock!(aws_sdk_s3::Client::head_object)
            .then_error(|| HeadObjectError::NotFound(NotFound::builder().build()));
        assert!(
            !storage_for(&not_found)
                .data_exists_at_key(KEY)
                .await
                .unwrap()
        );

        // Any other service error must propagate rather than read as "absent". Cover a 403-style
        // access error and a 503-style throttling error, both non-`NotFound` variants.
        for code in ["AccessDenied", "SlowDown"] {
            let err = mock!(aws_sdk_s3::Client::head_object).then_error(move || {
                HeadObjectError::generic(ErrorMetadata::builder().code(code).build())
            });
            assert!(
                storage_for(&err).data_exists_at_key(KEY).await.is_err(),
                "head_object {code} error should propagate, not map to Ok(false)"
            );
        }
    }

    /// Reading a key that does not exist surfaces the `get_object` error as an `Err` rather than
    /// silently succeeding.
    #[tokio::test]
    async fn read_missing_data_errors() {
        let storage = create_s3_storage(StorageType::PUB, "read_missing").await;
        assert!(
            storage
                .load_bytes(&RequestId::default(), "PublicKey")
                .await
                .is_err()
        );
    }

    /// `list_all` follows `ListObjectsV2` continuation tokens and merges every page (the stateful
    /// mock returns a single page, so this uses explicit multi-page rules).
    #[tokio::test]
    async fn list_all_follows_continuation_tokens() {
        let mut rng = rand::thread_rng();
        let id_a = RequestId::new_random(&mut rng);
        let id_b = RequestId::new_random(&mut rng);
        let key_a = format!("PUB/PublicKey/{id_a}");
        let key_b = format!("PUB/PublicKey/{id_b}");

        // First page: truncated, hands back a continuation token.
        let page1 = mock!(aws_sdk_s3::Client::list_objects_v2)
            .match_requests(|i| i.continuation_token().is_none())
            .then_output(move || {
                ListObjectsV2Output::builder()
                    .contents(Object::builder().key(key_a.clone()).build())
                    .is_truncated(true)
                    .next_continuation_token("page-2")
                    .build()
            });
        // Second page: final page for that token.
        let page2 = mock!(aws_sdk_s3::Client::list_objects_v2)
            .match_requests(|i| i.continuation_token() == Some("page-2"))
            .then_output(move || {
                ListObjectsV2Output::builder()
                    .contents(Object::builder().key(key_b.clone()).build())
                    .is_truncated(false)
                    .build()
            });
        let client = mock_client!(aws_sdk_s3, RuleMode::MatchAny, [&page1, &page2], |c| c
            .force_path_style(true));
        let storage =
            S3Storage::new(client, MOCK_BUCKET.to_string(), StorageType::PUB, None).unwrap();

        let ids = storage.all_data_ids("PublicKey").await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id_a));
        assert!(ids.contains(&id_b));
    }
}

/// This is a trait to abstract over getting different ReadOnlyS3Storage implementations,
/// It is mostly needed for mocking the read only s3 storage in tests.
///
/// Calling [Self::get_storage] on the real implementation simply constructs a new ReadOnlyS3Storage,
/// only one getter is needed to construct different ReadOnlyS3Storage objects.
pub(crate) trait ReadOnlyS3StorageGetter<R> {
    fn get_storage(
        &self,
        s3_client: S3Client,
        bucket: String,
        storage_type: StorageType,
        storage_prefix: Option<&str>,
    ) -> anyhow::Result<R>;
}

pub(crate) struct RealReadOnlyS3StorageGetter;

impl ReadOnlyS3StorageGetter<ReadOnlyS3Storage> for RealReadOnlyS3StorageGetter {
    fn get_storage(
        &self,
        s3_client: S3Client,
        bucket: String,
        storage_type: StorageType,
        storage_prefix: Option<&str>,
    ) -> anyhow::Result<ReadOnlyS3Storage> {
        ReadOnlyS3Storage::new(s3_client, bucket, storage_type, storage_prefix)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DummyReadOnlyS3StorageGetter {
    // A counter that's incremented each time get_storage is called
    // it also selects which ram storage to return, i.e., the nth call to get_storage
    // returns the nth ram storage in the ram_storages vector
    pub(crate) counter: RefCell<usize>,
    pub(crate) ram_storages: Vec<crate::vault::storage::ram::RamStorage>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct DummyReadOnlyS3Storage {
    pub(crate) ram_storage: crate::vault::storage::ram::RamStorage,
}

#[cfg(test)]
impl ReadOnlyS3StorageGetter<DummyReadOnlyS3Storage> for DummyReadOnlyS3StorageGetter {
    fn get_storage(
        &self,
        _s3_client: S3Client,
        _bucket: String,
        _storage_type: StorageType,
        _prefix: Option<&str>,
    ) -> anyhow::Result<DummyReadOnlyS3Storage> {
        let val = { *self.counter.borrow() };
        let out = DummyReadOnlyS3Storage {
            ram_storage: self.ram_storages[val].clone(),
        };
        self.counter.replace(val + 1);
        Ok(out)
    }
}

#[cfg(test)]
impl StorageReader for DummyReadOnlyS3Storage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        self.ram_storage.data_exists(data_id, data_type).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.ram_storage.read_data(data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.ram_storage.load_bytes(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        self.ram_storage.all_data_ids(data_type).await
    }

    async fn all_data_types(&self) -> anyhow::Result<RootEntries> {
        self.ram_storage.all_data_types().await
    }

    fn info(&self) -> String {
        self.ram_storage.info()
    }
}

#[test]
fn test_find_region() {
    let url = "https://zama-zws-dev-tkms-b6q87.s3.eu-west-1.amazonaws.com/".to_string();
    let region = find_region_from_s3_url(&url).unwrap();
    assert_eq!(region.as_str(), "eu-west-1");

    let url = "https://s3.us-west-1.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string();
    let region = find_region_from_s3_url(&url).unwrap();
    assert_eq!(region.as_str(), "us-west-1");

    let url = "https://s3.amazonaws.com/zama-zws-dev-tkms-b6q87/".to_string();
    let region = find_region_from_s3_url(&url).unwrap();
    assert_eq!(region.as_str(), "us-east-1");

    let url = "http://dev-s3-mock:9000".to_string();
    let region = find_region_from_s3_url(&url).unwrap();
    assert_eq!(region.as_str(), "us-east-1");
}
