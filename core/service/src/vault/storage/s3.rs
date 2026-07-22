use super::{Storage, StorageReader, StorageType, StoreWriteOutcome};
use crate::vault::storage::{StorageExt, StorageReaderExt, all_data_ids_from_all_epochs_impl};
use crate::{anyhow_error_and_log, consts::SAFE_SER_SIZE_LIMIT, vault::storage_prefix_safety};
use aws_config::{self, Region, SdkConfig};
use aws_sdk_s3::{
    Client as S3Client,
    error::ProvideErrorMetadata,
    primitives::ByteStream,
    types::{ChecksumAlgorithm, CompletedMultipartUpload, CompletedPart},
};
use kms_grpc::{RequestId, identifiers::EpochId};
use serde::{Serialize, de::DeserializeOwned};
#[cfg(test)]
use std::cell::RefCell;
use std::{collections::HashSet, str::FromStr, sync::mpsc};
use tfhe::{
    Unversionize, Versionize,
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
};
use tokio::{io::AsyncReadExt, sync::oneshot};
use url::Url;

const PREALLOCATED_BLOB_SIZE: usize = 32768;

/// Serialized bytes buffered per multipart part. 16 MiB keeps peak memory at
/// O(part size) while a maximal 2 GiB (`SAFE_SER_SIZE_LIMIT`) object still
/// yields only 128 parts, far below the S3 limit of 10,000.
pub(crate) const S3_MULTIPART_PART_SIZE: usize = 16 * 1024 * 1024;

/// S3's minimum size for every multipart part except the last.
pub(crate) const S3_MULTIPART_MIN_PART_SIZE: usize = 5 * 1024 * 1024;

const _: () = assert!(S3_MULTIPART_PART_SIZE >= S3_MULTIPART_MIN_PART_SIZE);

// A maximal `SAFE_SER_SIZE_LIMIT` payload must fit within S3's 10,000-part cap
// at this part size. Guards the production config (128 parts today) at compile
// time so a future bump to the size limit or drop in part size fails the build
// instead of surfacing only at `CompleteMultipartUpload`, after the whole
// object has been uploaded.
const _: () = assert!(SAFE_SER_SIZE_LIMIT.div_ceil(S3_MULTIPART_PART_SIZE as u64) <= 10_000);

/// Queue depth between the serializing task and the uploader thread; peak
/// in-flight memory is roughly `(3 + capacity) * part_size`: the buffer being
/// filled, the one held by a blocking send, the queued one, and the one the
/// uploader is currently shipping.
const PART_CHANNEL_CAPACITY: usize = 1;

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

    /// Checks whether an object exists at the given key. Only a genuine 404
    /// maps to `Ok(false)`; any other failure (e.g. access denied) is returned
    /// as an error, so exists-guarded callers (overwrite checks, purge and
    /// destroy-epoch flows) never mistake a failed check for absent data.
    /// Note S3 answers `HeadObject` on a missing key with 403 instead of 404
    /// when the caller lacks `s3:ListBucket`, so that permission is required.
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
            Err(sdk_error) => match sdk_error.as_service_error().map(|e| e.is_not_found()) {
                Some(true) => Ok(false),
                Some(false) | None => Err(anyhow_error_and_log(format!(
                    "Could not check existence of object in bucket {} under key {}: {:?}",
                    self.bucket, key, sdk_error
                ))),
            },
        }
    }

    /// Stores the versioned serialization of `data` under `key`. Payloads that
    /// fit in one part buffer go out as a single PUT; larger ones are streamed
    /// as a multipart upload so the full blob never sits in memory (see
    /// [`s3_put_versioned`]).
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
        let size = s3_put_versioned(
            &self.s3_client,
            &self.bucket,
            key,
            data,
            S3_MULTIPART_PART_SIZE,
            SAFE_SER_SIZE_LIMIT,
        )
        .await?;

        // Record the persisted payload size, keyed by the element's type name (see `observe_size`).
        observability::metrics::METRICS.observe_size(<T as Named>::NAME, size as f64);

        Ok(())
    }

    /// Deletes the object at the given key. Deleting a non-existent key succeeds
    /// (S3 `DeleteObject` is idempotent), but genuine deletion failures are
    /// returned so callers never mistake a failed delete for a successful one
    /// (e.g. the destroy-epoch and purge flows must be able to retry).
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
            .map_err(|e| {
                anyhow_error_and_log(format!(
                    "Could not delete object in bucket {} under key {}: {:?}",
                    self.bucket, key, e
                ))
            })?;

        Ok(())
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
        let mut ids = HashSet::new();
        let result = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .delimiter("/")
            .prefix(format!("{}/{}/", self.prefix, data_type))
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
        let mut ids = HashSet::new();
        let result = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .delimiter("/")
            .prefix(format!("{}/{}/{}/", self.prefix, data_type, epoch_id))
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

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let mut ids = HashSet::new();
        let result = self
            .s3_client
            .list_objects_v2()
            .bucket(&self.bucket)
            .delimiter("/")
            .prefix(format!("{}/{}/", self.prefix, data_type))
            .send()
            .await?;
        // With delimiter="/", epoch_ids appear as "directories" in common_prefixes,
        // not as objects in contents()
        for cur_res in result.common_prefixes() {
            if let Some(key) = &cur_res.prefix {
                let trimmed_key = key.trim();
                // Ensure we only count "directories" by checking for the trailing "/"
                if trimmed_key.ends_with('/') {
                    // Remove the '/' at the end and take the last segment after splitting on "/" to get epoch_id
                    if let Some(cur_id) = trimmed_key.trim_end_matches('/').split('/').next_back() {
                        ids.insert(EpochId::from_str(cur_id)?);
                    }
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

/// Upload id (if the multipart upload was created) plus the uploaded parts or
/// the first upload error.
type MultipartUploadResult = (Option<String>, anyhow::Result<Vec<CompletedPart>>);

/// Channel ends connecting an [`S3PartWriter`] to its uploader thread.
struct MultipartPipeline {
    part_tx: mpsc::SyncSender<Vec<u8>>,
    result_rx: oneshot::Receiver<MultipartUploadResult>,
}

/// Outcome of a finished serialization stream: either the whole payload fit in
/// one buffer (store it with a single PUT) or the multipart pipeline ran.
enum PartWriterOutcome {
    Single(Vec<u8>),
    Multipart(oneshot::Receiver<MultipartUploadResult>),
}

/// `std::io::Write` sink that buffers serialized bytes into `part_size` chunks
/// and, once the payload outgrows the first chunk, streams them to S3 as a
/// multipart upload.
///
/// The serializer runs on the calling async task (it borrows the element, so
/// it cannot move into `spawn_blocking`) — under `block_in_place` on
/// multi-thread runtimes, inline otherwise (see [`s3_put_versioned`]) — while
/// a dedicated uploader thread drains the bounded part queue, so
/// serialization and upload overlap without unbounded buffering.
struct S3PartWriter {
    config: aws_sdk_s3::Config,
    bucket: String,
    key: String,
    part_size: usize,
    buf: Vec<u8>,
    total_written: u64,
    pipeline: Option<MultipartPipeline>,
}

impl S3PartWriter {
    fn new(config: aws_sdk_s3::Config, bucket: &str, key: &str, part_size: usize) -> Self {
        // Callers pass `S3_MULTIPART_PART_SIZE` or a test constant, so this
        // cannot fire in correct execution. Not a `debug_assert`: in release
        // S3 would only reject an undersized part at CompleteMultipartUpload,
        // once the whole object has already been uploaded.
        assert!(part_size >= S3_MULTIPART_MIN_PART_SIZE);
        Self {
            config,
            bucket: bucket.to_string(),
            key: key.to_string(),
            part_size,
            buf: Vec::new(),
            total_written: 0,
            pipeline: None,
        }
    }

    /// Ship the full buffer to the uploader thread, spawning it on first use.
    fn spill(&mut self) -> std::io::Result<()> {
        if self.pipeline.is_none() {
            let (part_tx, part_rx) = mpsc::sync_channel(PART_CHANNEL_CAPACITY);
            let (result_tx, result_rx) = oneshot::channel();
            let (config, bucket, key) =
                (self.config.clone(), self.bucket.clone(), self.key.clone());
            std::thread::Builder::new()
                .name("s3-multipart-upload".to_string())
                .spawn(move || run_multipart_uploader(config, bucket, key, part_rx, result_tx))
                .map_err(|e| {
                    std::io::Error::other(format!("failed to spawn the S3 uploader thread: {e}"))
                })?;
            tracing::info!(
                "Streaming multipart upload engaged for key {} ({} byte parts)",
                self.key,
                self.part_size
            );
            self.pipeline = Some(MultipartPipeline { part_tx, result_rx });
        }
        let part = std::mem::replace(&mut self.buf, Vec::with_capacity(self.part_size));
        let pipeline = self.pipeline.as_ref().expect("pipeline installed above");
        pipeline.part_tx.send(part).map_err(|_| {
            std::io::Error::other("S3 multipart uploader stopped; it reports the root cause")
        })
    }

    /// Finish the stream. The non-empty tail part is sent only when
    /// serialization succeeded; closing the channel lets the uploader exit.
    fn finish(mut self, serialization_ok: bool) -> PartWriterOutcome {
        match self.pipeline.take() {
            None => PartWriterOutcome::Single(self.buf),
            Some(pipeline) => {
                if serialization_ok && !self.buf.is_empty() {
                    // A send error means the uploader already failed; that
                    // error arrives through the result channel.
                    let _ = pipeline.part_tx.send(std::mem::take(&mut self.buf));
                }
                drop(pipeline.part_tx);
                PartWriterOutcome::Multipart(pipeline.result_rx)
            }
        }
    }
}

impl std::io::Write for S3PartWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        // Ship only when more bytes arrive after the buffer filled, so a
        // payload of exactly one part stays on the single-PUT fast path.
        if self.buf.len() == self.part_size {
            self.spill()?;
        }
        let n = std::cmp::min(self.part_size - self.buf.len(), data.len());
        self.buf.extend_from_slice(&data[..n]);
        self.total_written += n as u64;
        Ok(n)
    }

    // Never flush a partial buffer: every part but the last must be at least
    // `S3_MULTIPART_MIN_PART_SIZE`, and only `finish` knows which is last.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Uploads parts received over `part_rx` to a new multipart upload of
/// `bucket`/`key`, reporting the outcome over `result_tx`.
///
/// Runs on a dedicated OS thread with its own single-threaded runtime and its
/// own S3 client so uploads progress while the caller's runtime thread is
/// blocked inside the serializer (see [`S3PartWriter`]). Dropping `part_rx` on
/// error unblocks the serializing side with a send error.
fn run_multipart_uploader(
    config: aws_sdk_s3::Config,
    bucket: String,
    key: String,
    part_rx: mpsc::Receiver<Vec<u8>>,
    result_tx: oneshot::Sender<MultipartUploadResult>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = result_tx.send((
                None,
                Err(anyhow::anyhow!("failed to build S3 uploader runtime: {e}")),
            ));
            return;
        }
    };
    // Sharing the caller's HTTP client could hand out pooled connections that
    // are driven by the caller's runtime, which can sit blocked in the
    // serializer while this upload runs; force a fresh pool instead.
    let mut config = config.to_builder();
    config.set_http_client(None);
    // Same for the identity cache: the caller's lazy cache single-flights
    // credential refreshes, so waiting here on a refresh started by a task on
    // the caller's (blocked) runtime would deadlock the pipeline. The
    // credentials provider behind the fresh cache is still shared.
    config.set_identity_cache(aws_sdk_s3::config::IdentityCache::lazy().build());
    // Bound each attempt so a black-holed connection cannot pin the uploader
    // — and the serializer blocked in `send` — forever. 600 s still clears a
    // 16 MiB part at ~28 KiB/s.
    config.set_timeout_config(Some(
        aws_sdk_s3::config::timeout::TimeoutConfig::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .operation_attempt_timeout(std::time::Duration::from_secs(600))
            .build(),
    ));
    // Pin checksum calculation so an ambient `when_required` setting (env or
    // profile) cannot strip the per-part CRC32 that the declared algorithm
    // below obliges every part to carry.
    config.set_request_checksum_calculation(Some(
        aws_sdk_s3::config::RequestChecksumCalculation::WhenSupported,
    ));
    let client = S3Client::from_conf(config.build());

    // The SDK adds a CRC32 checksum to every part under `WhenSupported`;
    // declaring the algorithm up front keeps create/upload/complete consistent.
    let created = rt.block_on(
        client
            .create_multipart_upload()
            .bucket(&bucket)
            .key(&key)
            .checksum_algorithm(ChecksumAlgorithm::Crc32)
            .send(),
    );
    let upload_id = match created {
        Ok(out) => match out.upload_id {
            Some(id) => id,
            None => {
                let _ = result_tx.send((
                    None,
                    Err(anyhow::anyhow!("S3 returned no upload id for key {key}")),
                ));
                return;
            }
        },
        Err(err) => {
            tracing::error!("{:?} {:?}", err.meta(), err.code());
            let _ = result_tx.send((
                None,
                Err(anyhow::anyhow!(
                    "AWS error creating multipart upload for key {key}: {err}"
                )),
            ));
            return;
        }
    };

    let mut parts = Vec::new();
    // Parts are numbered from 1; the serialized-size limit caps the count far
    // below S3's maximum of 10,000.
    while let Ok(part_buf) = part_rx.recv() {
        let part_number = parts.len() as i32 + 1;
        match rt.block_on(
            client
                .upload_part()
                .bucket(&bucket)
                .key(&key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(ByteStream::from(part_buf))
                .send(),
        ) {
            Ok(out) => parts.push(
                CompletedPart::builder()
                    .part_number(part_number)
                    .set_e_tag(out.e_tag)
                    .set_checksum_crc32(out.checksum_crc32)
                    .build(),
            ),
            Err(err) => {
                tracing::error!("{:?} {:?}", err.meta(), err.code());
                // Returning drops `part_rx`, which fails the serializer's next
                // send and unwinds the store operation.
                let _ = result_tx.send((
                    Some(upload_id),
                    Err(anyhow::anyhow!(
                        "AWS error uploading part {part_number} for key {key}: {err}"
                    )),
                ));
                return;
            }
        }
    }
    let _ = result_tx.send((Some(upload_id), Ok(parts)));
}

/// Best-effort abort of a multipart upload; failures are only logged, leaving
/// the orphaned parts for a bucket `AbortIncompleteMultipartUpload` lifecycle
/// rule (if configured) to reclaim.
async fn abort_multipart_upload_best_effort(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    upload_id: &str,
) {
    tracing::warn!("Aborting multipart upload {upload_id} for key {key}");
    if let Err(err) = s3_client
        .abort_multipart_upload()
        .bucket(bucket)
        .key(key)
        .upload_id(upload_id)
        .send()
        .await
    {
        tracing::error!(
            "Failed to abort multipart upload {upload_id} for key {key}: {:?} {:?}",
            err.meta(),
            err.code()
        );
    }
}

/// Safe-serializes `data` (versioned) and stores it under `key` in `bucket`,
/// returning the total number of serialized bytes.
///
/// Payloads that fit in one `part_size` buffer are stored with a single
/// `PutObject`; larger ones are streamed as an S3 multipart upload so the full
/// serialized blob never exists in memory. Visibility is all-or-nothing: the
/// object appears only once `CompleteMultipartUpload` succeeds. Reported
/// failures abort the upload best-effort; a panic or a cancelled future can
/// still leave an incomplete upload behind for a bucket lifecycle rule
/// (if configured) to reclaim.
pub(crate) async fn s3_put_versioned<T: Serialize + Versionize + Named>(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    data: &T,
    part_size: usize,
    size_limit: u64,
) -> anyhow::Result<u64> {
    let mut writer = S3PartWriter::new(s3_client.config().clone(), bucket, key, part_size);
    // The serializer borrows `data`, so it cannot move into `spawn_blocking`;
    // it runs on this task, blocking in `spill` at upload pace once the
    // payload exceeds one part (see [`run_blocking`]).
    let ser_result = run_blocking(|| safe_serialize(data, &mut writer, size_limit)).map_err(|e| {
        anyhow::anyhow!(
            "failed to serialize {} for key {key}: {e}",
            <T as Named>::NAME
        )
    });
    s3_finish_put(s3_client, bucket, key, writer, ser_result).await
}

/// Run blocking pipeline work off the async scheduler: under `block_in_place`
/// on multi-thread runtimes so the worker's other tasks keep running;
/// `block_in_place` panics on current-thread runtimes (tests), where the work
/// simply runs inline and blocks the runtime while the uploader thread makes
/// progress on its own.
fn run_blocking<R>(f: impl FnOnce() -> R) -> R {
    if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

/// Complete the store fed through an [`S3PartWriter`]: a single PUT for
/// payloads that never spilled, otherwise complete or abort the multipart
/// upload depending on `ser_result` and the uploader outcome. Returns the
/// total number of bytes written to `writer`.
async fn s3_finish_put(
    s3_client: &S3Client,
    bucket: &str,
    key: &str,
    writer: S3PartWriter,
    ser_result: anyhow::Result<()>,
) -> anyhow::Result<u64> {
    let total_written = writer.total_written;
    let serialization_ok = ser_result.is_ok();
    // Once the pipeline is engaged, the tail-part send in `finish` blocks on
    // the bounded channel just like `spill`, so it needs the same
    // off-scheduler treatment as the serializer; the single-PUT path cannot
    // block and skips that overhead.
    let outcome = if writer.pipeline.is_some() {
        run_blocking(move || writer.finish(serialization_ok))
    } else {
        writer.finish(serialization_ok)
    };
    match outcome {
        PartWriterOutcome::Single(buf) => {
            ser_result?;
            s3_put_blob(s3_client, bucket, key, buf).await?;
        }
        PartWriterOutcome::Multipart(result_rx) => {
            let (upload_id, upload_result) = result_rx.await.map_err(|_| {
                anyhow::anyhow!(
                    "S3 multipart uploader thread died for key {key}; an incomplete \
                     multipart upload may linger unless a bucket lifecycle rule reaps it"
                )
            })?;
            let parts = match (upload_result, ser_result) {
                (Ok(parts), Ok(())) => parts,
                // The uploader error is the root cause: its failure closes the
                // part channel, which the serializer then sees as a write error.
                (Err(upload_err), _) => {
                    if let Some(id) = &upload_id {
                        abort_multipart_upload_best_effort(s3_client, bucket, key, id).await;
                    }
                    return Err(upload_err);
                }
                (Ok(_), Err(ser_err)) => {
                    if let Some(id) = &upload_id {
                        abort_multipart_upload_best_effort(s3_client, bucket, key, id).await;
                    }
                    return Err(ser_err);
                }
            };
            // The uploader only reports Ok after the channel closed, i.e. once
            // every part (including the tail sent by `finish`) was uploaded.
            let upload_id = upload_id.expect("upload id accompanies uploaded parts");
            let part_count = parts.len();
            let completed = CompletedMultipartUpload::builder()
                .set_parts(Some(parts))
                .build();
            if let Err(err) = s3_client
                .complete_multipart_upload()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .multipart_upload(completed)
                .send()
                .await
            {
                tracing::error!("{:?} {:?}", err.meta(), err.code());
                abort_multipart_upload_best_effort(s3_client, bucket, key, &upload_id).await;
                return Err(anyhow::anyhow!(
                    "AWS error completing multipart upload for key {key}: {err}"
                ));
            }
            tracing::info!(
                "Completed multipart upload of {total_written} bytes in {part_count} parts for key {key}"
            );
        }
    }
    Ok(total_written)
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

cfg_if::cfg_if! {
    if #[cfg(feature = "s3_tests")]{
        pub const BUCKET_NAME: &str = "ci-kms-key-test";
        pub const AWS_REGION: &str = "eu-north-1";
        // this points to a locally running Minio
        pub const AWS_S3_ENDPOINT: &str = "http://127.0.0.1:9000";
    }
}

#[cfg(all(feature = "s3_tests", any(test, feature = "testing")))]
pub async fn create_s3_storage(storage_type: StorageType, prefix: &str) -> S3Storage {
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
        .await
        .unwrap();
    S3Storage::new(
        s3_client,
        BUCKET_NAME.to_string(),
        storage_type,
        Some(prefix),
    )
    .unwrap()
}

// Observe that certain tests require an S3 instance setup.
// There are run with the extra argument `-F s3_tests`.
// Note that we pay for each of these tests, in the order of single digit cents per tests.
//
// To setup the testing environment locally with Minio, proceed as follows:
// 1. Install and run Minio in Docker
//    a. Simplest way is to just run `docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml up` as this ensure Minio is configured and started correctly.
// 2. Setup the bucket. Within the `dev-s3-mock-1` container in Docker execute the following commands:
//   a. First open Docker desktop and navigate to `Volumes` and find `zama-core-threshold_minio_secrets` and copy the content of `access_key` and the content of `secret_key`.
//   b. Run `mc alias set testminio http://127.0.0.1:9000 <access_key> <secret_key>` (and replace `<access_key>` respectively `<secret_key>` with the values copied above and assuming no change to [`AWS_S3_ENDPOINT`])
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
//    b. In the top right corner of the page there will be your AWS account name. Click on it, and in the drop-down menu go to "security credentials".
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
    use crate::vault::storage::tests::{
        test_batch_helper_methods, test_epoch_methods, test_storage_read_store_methods,
        test_store_bytes_does_not_overwrite_existing_bytes,
        test_store_data_does_not_overwrite_existing_data, test_store_data_records_payload_size,
    };

    async fn create_s3_storage(storage_type: StorageType, prefix: &str) -> S3Storage {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
            .await
            .unwrap();
        S3Storage::new(
            s3_client,
            BUCKET_NAME.to_string(),
            storage_type,
            Some(prefix),
        )
        .unwrap()
    }

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

    #[tokio::test]
    async fn test_s3_anon() {
        let prefix = std::stringify!(test_s3_anon);
        let mut storage = create_s3_storage(StorageType::PUB, prefix).await;
        storage
            .store_bytes(b"fake-pk", &RequestId::default(), "PublicKey")
            .await
            .unwrap();

        // Build an anonymous client pointing at local MinIO
        let s3_client = build_anonymous_s3_client(AWS_S3_ENDPOINT, AWS_REGION.to_string())
            .await
            .unwrap();

        let pub_storage = ReadOnlyS3Storage::new(
            s3_client,
            BUCKET_NAME.to_string(),
            StorageType::PUB,
            Some(prefix),
        )
        .unwrap();

        let public_key_ids = pub_storage.all_data_ids("PublicKey").await.unwrap();
        assert!(!public_key_ids.is_empty());
    }

    /// Deleting a key that was never stored must succeed: S3 `DeleteObject` is
    /// idempotent, so deletes of absent objects stay non-fatal.
    #[tokio::test]
    async fn test_delete_missing_key_is_ok_s3() {
        let prefix = std::stringify!(test_delete_missing_key_is_ok_s3);
        let mut storage = create_s3_storage(StorageType::PUB, prefix).await;
        storage
            .delete_data(&RequestId::default(), "PublicKey")
            .await
            .unwrap();
    }

    /// A delete that genuinely fails (here: the bucket does not exist) must
    /// surface an error, so purge/destroy flows never mistake a failed delete
    /// for a successful one.
    #[tokio::test]
    async fn test_delete_failure_propagates_s3() {
        let prefix = std::stringify!(test_delete_failure_propagates_s3);
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
            .await
            .unwrap();
        let bucket = "no-such-bucket-delete-test";
        let mut storage = S3Storage::new(
            s3_client,
            bucket.to_string(),
            StorageType::PUB,
            Some(prefix),
        )
        .unwrap();
        let err = storage
            .delete_data(&RequestId::default(), "PublicKey")
            .await
            .expect_err("delete against a missing bucket must fail");
        assert!(
            err.to_string().contains(bucket),
            "error must carry the bucket context, got: {err}"
        );
    }

    /// An existence check that fails with a non-404 service error (here:
    /// credentials the server rejects) must surface an error rather than
    /// "data absent", so exists-guarded flows (overwrite checks, purge and
    /// destroy-epoch) never skip work because of e.g. broken credentials.
    #[tokio::test]
    async fn test_exists_failure_propagates_s3() {
        let prefix = std::stringify!(test_exists_failure_propagates_s3);
        let credentials = aws_sdk_s3::config::Credentials::new(
            "invalid-access-key",
            "invalid-secret-key",
            None,
            None,
            "s3-exists-negative-test",
        );
        let config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(Region::new(AWS_REGION))
            .credentials_provider(credentials)
            .endpoint_url(AWS_S3_ENDPOINT)
            .force_path_style(true)
            .build();
        let storage = S3Storage::new(
            S3Client::from_conf(config),
            BUCKET_NAME.to_string(),
            StorageType::PUB,
            Some(prefix),
        )
        .unwrap();
        let err = storage
            .data_exists(&RequestId::default(), "PublicKey")
            .await
            .expect_err("existence check with rejected credentials must fail");
        assert!(
            err.to_string().contains(BUCKET_NAME),
            "error must carry the bucket context, got: {err}"
        );
    }

    mod multipart {
        use super::*;
        use crate::engine::base::derive_request_id;
        use serde::Deserialize;
        use tfhe_versionable::VersionsDispatch;

        #[derive(Serialize, Deserialize, PartialEq, Debug, VersionsDispatch)]
        pub enum TestBigTypeVersions {
            V0(TestBigType),
        }

        impl Named for TestBigType {
            const NAME: &'static str = "TestBigType";
        }

        /// Payload large enough to span several multipart parts.
        #[derive(Serialize, Deserialize, PartialEq, Debug, Versionize)]
        #[versionize(TestBigTypeVersions)]
        pub struct TestBigType {
            pub data: Vec<u8>,
        }

        fn big_payload(len: usize) -> TestBigType {
            TestBigType {
                data: (0..len).map(|i| (i % 251) as u8).collect(),
            }
        }

        #[tokio::test]
        async fn s3_multipart_store_and_read() {
            let prefix = std::stringify!(s3_multipart_store_and_read);
            let mut storage = create_s3_storage(StorageType::PUB, prefix).await;
            // Three parts at the minimal part size: 5 + 5 + ~1 MiB.
            let data = big_payload(11 * 1024 * 1024);
            let req_id = derive_request_id(prefix).unwrap();
            let key = storage.item_key(&req_id, TestBigType::NAME);

            let size = s3_put_versioned(
                &storage.s3_client,
                BUCKET_NAME,
                &key,
                &data,
                S3_MULTIPART_MIN_PART_SIZE,
                SAFE_SER_SIZE_LIMIT,
            )
            .await
            .unwrap();

            let stored = storage
                .load_bytes(&req_id, TestBigType::NAME)
                .await
                .unwrap();
            assert_eq!(stored.len() as u64, size);
            // A multipart ETag ends in "-<part count>"; this proves the
            // pipeline actually engaged instead of falling back to one PUT.
            let head = storage
                .s3_client
                .head_object()
                .bucket(BUCKET_NAME)
                .key(&key)
                .send()
                .await
                .unwrap();
            let etag = head.e_tag.unwrap();
            assert!(
                etag.trim_matches('"').ends_with("-3"),
                "expected a 3-part multipart ETag, got {etag}"
            );
            let read_back: TestBigType =
                storage.read_data(&req_id, TestBigType::NAME).await.unwrap();
            assert_eq!(read_back, data);
            storage
                .delete_data(&req_id, TestBigType::NAME)
                .await
                .unwrap();
        }

        /// A payload whose serialized size is exactly one part must stay on
        /// the single-PUT fast path (a multipart ETag would end in "-<parts>").
        #[tokio::test]
        async fn s3_exact_part_size_stays_single_put() {
            let prefix = std::stringify!(s3_exact_part_size_stays_single_put);
            let mut storage = create_s3_storage(StorageType::PUB, prefix).await;
            // Serialization overhead (header + vec length) is constant, so an
            // empty payload measures it exactly.
            let mut empty = Vec::new();
            safe_serialize(&big_payload(0), &mut empty, SAFE_SER_SIZE_LIMIT).unwrap();
            let data = big_payload(S3_MULTIPART_MIN_PART_SIZE - empty.len());
            let req_id = derive_request_id(prefix).unwrap();
            let key = storage.item_key(&req_id, TestBigType::NAME);

            let size = s3_put_versioned(
                &storage.s3_client,
                BUCKET_NAME,
                &key,
                &data,
                S3_MULTIPART_MIN_PART_SIZE,
                SAFE_SER_SIZE_LIMIT,
            )
            .await
            .unwrap();
            assert_eq!(size as usize, S3_MULTIPART_MIN_PART_SIZE);

            let head = storage
                .s3_client
                .head_object()
                .bucket(BUCKET_NAME)
                .key(&key)
                .send()
                .await
                .unwrap();
            let etag = head.e_tag.unwrap();
            assert!(
                !etag.trim_matches('"').contains('-'),
                "expected a single-PUT ETag, got multipart {etag}"
            );
            let read_back: TestBigType =
                storage.read_data(&req_id, TestBigType::NAME).await.unwrap();
            assert_eq!(read_back, data);
            storage
                .delete_data(&req_id, TestBigType::NAME)
                .await
                .unwrap();
        }

        // Coverage note: the serialization-error abort arm is exercised below,
        // and the create-failure arm by `s3_multipart_uploader_failure_propagates`.
        // The remaining two abort arms in `s3_finish_put` — a mid-stream
        // `upload_part` failure and a `CompleteMultipartUpload` failure — cannot
        // be triggered against a real MinIO without a fault-injection seam: the
        // writer only ever emits valid, adequately sized parts, so neither an
        // undersized-part reject nor a mid-stream part error occurs on the happy
        // path. Both arms are correct by construction (abort iff an `upload_id`
        // was obtained) and share the abort helper the tested arms use.
        #[tokio::test]
        async fn s3_multipart_abort_on_error() {
            use std::io::Write;

            let prefix = std::stringify!(s3_multipart_abort_on_error);
            let storage = create_s3_storage(StorageType::PUB, prefix).await;
            let req_id = derive_request_id(prefix).unwrap();
            let key = storage.item_key(&req_id, TestBigType::NAME);

            // Drive the writer past one part so the pipeline engages (the
            // multipart upload is created and part 1 ships), then finish with
            // an injected serialization failure to exercise the abort path.
            let mut writer = S3PartWriter::new(
                storage.s3_client.config().clone(),
                BUCKET_NAME,
                &key,
                S3_MULTIPART_MIN_PART_SIZE,
            );
            writer
                .write_all(&vec![7u8; S3_MULTIPART_MIN_PART_SIZE + 1024 * 1024])
                .unwrap();
            let res = s3_finish_put(
                &storage.s3_client,
                BUCKET_NAME,
                &key,
                writer,
                Err(anyhow::anyhow!("injected serialization failure")),
            )
            .await;
            let err = res.expect_err("injected failure must propagate");
            assert!(err.to_string().contains("injected serialization failure"));

            // All-or-nothing: no object and no lingering multipart upload.
            assert!(
                !storage
                    .data_exists(&req_id, TestBigType::NAME)
                    .await
                    .unwrap()
            );
            let pending = storage
                .s3_client
                .list_multipart_uploads()
                .bucket(BUCKET_NAME)
                .prefix(&key)
                .send()
                .await
                .unwrap();
            assert!(
                pending.uploads().is_empty(),
                "multipart upload was not aborted: {:?}",
                pending.uploads()
            );
        }

        #[tokio::test]
        async fn s3_oversized_payload_stores_nothing() {
            let prefix = std::stringify!(s3_oversized_payload_stores_nothing);
            let storage = create_s3_storage(StorageType::PUB, prefix).await;
            let data = big_payload(11 * 1024 * 1024);
            let req_id = derive_request_id(prefix).unwrap();
            let key = storage.item_key(&req_id, TestBigType::NAME);

            // Only the small header reaches the writer before bincode's
            // size-limit pre-pass rejects the body, so no part ever spills and
            // the failed serialization keeps the single PUT from happening.
            let res = s3_put_versioned(
                &storage.s3_client,
                BUCKET_NAME,
                &key,
                &data,
                S3_MULTIPART_MIN_PART_SIZE,
                6 * 1024 * 1024,
            )
            .await;
            assert!(res.is_err(), "serialization over the size limit must fail");
            assert!(
                !storage
                    .data_exists(&req_id, TestBigType::NAME)
                    .await
                    .unwrap()
            );
            let pending = storage
                .s3_client
                .list_multipart_uploads()
                .bucket(BUCKET_NAME)
                .prefix(&key)
                .send()
                .await
                .unwrap();
            assert!(
                pending.uploads().is_empty(),
                "no multipart upload should ever be created: {:?}",
                pending.uploads()
            );
        }

        // Multi-thread flavor so the store exercises the `block_in_place`
        // serialization branch that production (multi-thread) runtimes take.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn s3_multipart_via_store_data() {
            let prefix = std::stringify!(s3_multipart_via_store_data);
            let mut storage = create_s3_storage(StorageType::PUB, prefix).await;
            // 1 MiB more than a production part, so the pipeline engages.
            let data = big_payload(S3_MULTIPART_PART_SIZE + 1024 * 1024);
            let req_id = derive_request_id(prefix).unwrap();

            // Ensure no old data is present: a leftover object from a failed
            // previous run (persistent buckets) would make the store a no-op.
            storage
                .delete_data(&req_id, TestBigType::NAME)
                .await
                .unwrap();
            let before =
                observability::metrics::METRICS.payload_size_sample_count(TestBigType::NAME);
            let outcome = storage
                .store_data(&data, &req_id, TestBigType::NAME)
                .await
                .unwrap();
            assert!(matches!(outcome, StoreWriteOutcome::Created));

            let read_back: TestBigType =
                storage.read_data(&req_id, TestBigType::NAME).await.unwrap();
            assert_eq!(read_back, data);
            let after =
                observability::metrics::METRICS.payload_size_sample_count(TestBigType::NAME);
            assert!(
                after > before,
                "storing data must record a payload-size sample (before={before}, after={after})"
            );
            storage
                .delete_data(&req_id, TestBigType::NAME)
                .await
                .unwrap();
        }

        /// An uploader-side S3 failure (here: the bucket does not exist, so
        /// `CreateMultipartUpload` fails on the uploader thread) must close the
        /// part channel, unwind the serializing side, and surface the uploader
        /// error as the root cause.
        #[tokio::test]
        async fn s3_multipart_uploader_failure_propagates() {
            use std::io::Write;

            let prefix = std::stringify!(s3_multipart_uploader_failure_propagates);
            let storage = create_s3_storage(StorageType::PUB, prefix).await;
            let req_id = derive_request_id(prefix).unwrap();
            let key = storage.item_key(&req_id, TestBigType::NAME);
            let bucket = "no-such-bucket-multipart-test";

            let mut writer = S3PartWriter::new(
                storage.s3_client.config().clone(),
                bucket,
                &key,
                S3_MULTIPART_MIN_PART_SIZE,
            );
            // Two spills, so a send blocks on the capacity-1 channel and
            // observes the uploader dropping its receiver on failure. Whether
            // the write itself errors depends on how fast the uploader dies;
            // the uploader error must win either way.
            let write_res =
                writer.write_all(&vec![7u8; 2 * S3_MULTIPART_MIN_PART_SIZE + 1024 * 1024]);
            let ser_result = write_res.map_err(|e| anyhow::anyhow!(e));
            let res = s3_finish_put(&storage.s3_client, bucket, &key, writer, ser_result).await;
            let err = res.expect_err("uploader failure must propagate");
            assert!(
                err.to_string().contains("creating multipart upload"),
                "expected the uploader's create error as root cause, got: {err}"
            );
        }
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

/// Unit tests for [`S3PartWriter`]'s buffering that need no S3/MinIO (so they
/// run in ordinary CI, unlike the `s3_tests`-gated suite above). They assert on
/// the writer's local state only; the single-PUT paths never spill, and the one
/// spilling test points the (spawned, retry-disabled) uploader at a refused
/// local port and never awaits it.
#[cfg(test)]
mod part_writer_tests {
    use super::*;
    use std::io::Write;

    fn refused_config() -> aws_sdk_s3::Config {
        aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test",
                "test",
                None,
                None,
                "part-writer-test",
            ))
            // Nothing listens here, so a spilled part's upload fails at once.
            .endpoint_url("http://127.0.0.1:1")
            .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
            .force_path_style(true)
            .build()
    }

    fn writer(part_size: usize) -> S3PartWriter {
        S3PartWriter::new(refused_config(), "bucket", "key", part_size)
    }

    /// A single write fills the buffer up to `part_size` but never spills: a
    /// spill fires only when more bytes arrive after the buffer is full, and a
    /// write caps at the remaining capacity so the buffer never overflows.
    #[test]
    fn write_fills_to_part_size_without_spilling() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        let n = w.write(&vec![0u8; part_size + 100]).unwrap();
        assert_eq!(n, part_size, "a write caps at the remaining part capacity");
        assert_eq!(w.buf.len(), part_size);
        assert!(w.pipeline.is_none(), "filling the buffer must not spill");
        assert_eq!(w.total_written, part_size as u64);
    }

    /// A payload that fits in one buffer finishes on the single-PUT fast path.
    #[test]
    fn sub_part_payload_finishes_single() {
        let mut w = writer(S3_MULTIPART_MIN_PART_SIZE);
        w.write_all(&[0u8; 1024]).unwrap();
        assert!(w.pipeline.is_none());
        assert_eq!(w.total_written, 1024);
        match w.finish(true) {
            PartWriterOutcome::Single(buf) => assert_eq!(buf.len(), 1024),
            PartWriterOutcome::Multipart(_) => panic!("small payload must stay single-PUT"),
        }
    }

    /// A payload of exactly one part also stays single-PUT: serialization ends
    /// before any further write can trigger the spill-on-next-write rule.
    #[test]
    fn exact_part_payload_finishes_single() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        w.write_all(&vec![0u8; part_size]).unwrap();
        assert!(w.pipeline.is_none());
        match w.finish(true) {
            PartWriterOutcome::Single(buf) => assert_eq!(buf.len(), part_size),
            PartWriterOutcome::Multipart(_) => panic!("exact-part payload must stay single-PUT"),
        }
    }

    /// One byte past a full buffer spills the full `part_size` part and engages
    /// the pipeline, leaving only the overflow buffered. `finish` is
    /// intentionally not called: with the pipeline engaged its tail send would
    /// block on the (dead) uploader; dropping the writer closes the channel and
    /// lets the uploader thread exit.
    #[test]
    fn crossing_part_boundary_engages_pipeline() {
        let part_size = S3_MULTIPART_MIN_PART_SIZE;
        let mut w = writer(part_size);
        w.write_all(&vec![0u8; part_size]).unwrap();
        assert!(
            w.pipeline.is_none(),
            "a full-but-not-exceeded buffer has not spilled yet"
        );
        w.write_all(&[7u8; 1]).unwrap();
        assert!(
            w.pipeline.is_some(),
            "exceeding one part must engage the multipart pipeline"
        );
        assert_eq!(w.buf.len(), 1, "only the overflow byte stays buffered");
        assert_eq!(w.total_written, part_size as u64 + 1);
    }
}
