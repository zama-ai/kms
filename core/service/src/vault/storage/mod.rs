use crate::{anyhow_error_and_log, some_or_err};
use anyhow::anyhow;
use aws_sdk_s3::Client as S3Client;
use kms_grpc::kms::v1::RequestId;
use kms_grpc::rpc_types::{
    PrivDataType, PubDataType, PublicKeyType, WrappedPublicKey, WrappedPublicKeyOwned,
};
use ordermap::OrderMap;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use std::fmt::{self};
use strum::{EnumIter, IntoEnumIterator};
use tfhe::{named::Named, Unversionize, Versionize};
use tracing;
use url::Url;

pub mod crypto_material;
pub mod file;
pub mod ram;
pub mod s3;

// TODO add a wrapper struct for both public and private storage.

/// Trait for public KMS storage reading
#[tonic::async_trait]
pub trait StorageReader {
    /// Validate if data exists at a given `url`.
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool>;

    /// Read some data from a given `url`.
    /// On return, the data is unversioned.
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T>;

    /// Compute an URL for some specific data given its `data_id` and of a given `data_type`.
    /// Depending on how the underlying functionality is realized one of these parameters might not
    /// be used.
    ///
    /// The implementation should prefix the URL with the storage backend type. For example,
    /// file-based storage should start with file://, S3 based storage should start with s3://, etc.
    /// Further, in the URL, the type should come before the ID, i.e., file://<metadata>/<type>/<id>.
    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url>;

    /// Return all URLs stored of a specific data type
    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>>;

    /// Output some information on the storage instance.
    fn info(&self) -> String;
}

// Trait for KMS public storage reading and writing
// Warning: There is no compiler validation that the data being stored are of a versioned type!
#[tonic::async_trait]
pub trait Storage: StorageReader {
    /// Store the given `data` at the given `url`
    /// Under the hood, the versioned data is stored.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()>;

    /// Delete the given `data` stored at `url`.
    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()>;
}

#[tonic::async_trait]
pub trait StorageForText: Storage {
    /// Store the given `text` at the given `url`
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()>;
}

/// Store some data at a location defined by `request_id` and `data_type`.
/// Under the hood, the versioned data will be stored.
pub async fn store_versioned_at_request_id<
    'a,
    S: Storage,
    T: Serialize + Versionize + Named + Send + Sync,
>(
    storage: &mut S,
    request_id: &RequestId,
    data: &'a T,
    data_type: &str,
) -> anyhow::Result<()>
where
    <T as Versionize>::Versioned<'a>: Send + Sync,
{
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.store_data(data, &url).await.map_err(|e| {
        anyhow_error_and_log(format!(
            "Could not store data with ID {} and type {}: {}",
            request_id, data_type, e
        ))
    })
}

// Helper method for storing text under a request ID.
// An error will be returned if the data already exists.
pub async fn store_text_at_request_id<S: StorageForText>(
    storage: &mut S,
    request_id: &RequestId,
    data: &str,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.store_text(data, &url).await.map_err(|e| {
        anyhow_error_and_log(format!(
            "Could not store data with ID {} and type {}: {}",
            request_id, data_type, e
        ))
    })
}

/// Delete ALL data under a given `request_id`.
/// Observe that this method does not produce any error regardless of any whether data is deleted or not.
pub async fn delete_all_at_request_id<S: Storage>(storage: &mut S, request_id: &RequestId) {
    for cur_type in PrivDataType::iter() {
        // Ignore an error as it is likely because the data does not exist
        let _ = delete_at_request_id(storage, request_id, &cur_type.to_string()).await;
    }
    for cur_type in PubDataType::iter() {
        // Ignore an error as it is likely because the data does not exist
        let _ = delete_at_request_id(storage, request_id, &cur_type.to_string()).await;
    }
}

// Helper method to remove data based on a data type and request ID.
// An error will be returned if the data could not be deleted.
// In case the data does not exist, a warning is logged but no error returned.
pub async fn delete_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    if storage.data_exists(&url).await? {
        storage.delete_data(&url).await.map_err(|e| {
            anyhow::anyhow!(format!(
                "Could not delete data with ID {} and type {}: {}",
                request_id, data_type, e
            ))
        })
    } else {
        tracing::warn!(
            "Data with ID {} and type {} does not exist",
            request_id,
            data_type
        );
        Ok(())
    }
}

// Helper method to remove data based on a data type and request ID.
pub async fn delete_pk_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
) -> anyhow::Result<()> {
    let _ = delete_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string()).await;
    let _ = delete_at_request_id(
        storage,
        request_id,
        &PubDataType::PublicKeyMetadata.to_string(),
    )
    .await;
    // Don't report errors
    Ok(())
}

/// Read some data stored in a location defined by `request_id` and `data_type`.
/// The returned result is automatically unversioned.
pub async fn read_versioned_at_request_id<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<T>
where
    <T as tfhe_versionable::VersionizeOwned>::VersionedOwned: Send,
{
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.read_data(&url).await
}

/// This function will perform verionize on the type.
pub async fn store_pk_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    pk: WrappedPublicKey<'_>,
) -> anyhow::Result<()> {
    tracing::info!("Storing public key");
    match pk {
        WrappedPublicKey::Compact(inner_pk) => {
            store_versioned_at_request_id(
                storage,
                request_id,
                inner_pk,
                &PubDataType::PublicKey.to_string(),
            )
            .await?;
            store_versioned_at_request_id(
                storage,
                request_id,
                &PublicKeyType::Compact,
                &PubDataType::PublicKeyMetadata.to_string(),
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn read_pk_at_request_id<S: Storage>(
    storage: &S,
    request_id: &RequestId,
) -> anyhow::Result<WrappedPublicKeyOwned> {
    let pk_type: PublicKeyType = read_versioned_at_request_id(
        storage,
        request_id,
        &PubDataType::PublicKeyMetadata.to_string(),
    )
    .await?;

    let out = match pk_type {
        PublicKeyType::Compact => WrappedPublicKeyOwned::Compact(
            read_versioned_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string())
                .await?,
        ),
    };

    Ok(out)
}

/// Helper method for reading all data of a specific type.
pub async fn read_all_data_versioned<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    data_type: &str,
) -> anyhow::Result<HashMap<RequestId, T>> {
    let url_map = storage.all_urls(data_type).await?;
    let mut res = HashMap::with_capacity(url_map.len());
    for (data_ptr, url) in url_map.iter() {
        let data: T = storage
            .read_data(url)
            .await
            .map_err(|e| anyhow!("reading failed on url {url}: {e}"))?;
        let req_id: RequestId = data_ptr.to_owned().try_into()?;
        if !req_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "Request ID {} is not valid",
                data_ptr
            )));
        }
        res.insert(req_id, data);
    }
    Ok(res)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum StorageType {
    PUB,
    PRIV,
    CLIENT,
    BACKUP,
}
impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[allow(dead_code)]
pub enum StorageVersion {
    Dev,
    Ram,
}

/// Represents all storage types as variants of one concrete type. This
/// monstrosity is required to work around the Rust's inability to create trait
/// objects if the trait has methods with generic parameters. Without it, the
/// code in `main()` that creates storage objects and passes them to the server
/// startup functions will blow up quadratically in the number of available
/// storage backends, as one would have to create both public and private
/// storage object at the same time as passing them to the server startup
/// function.
#[cfg(feature = "non-wasm")]
#[allow(clippy::large_enum_variant)]
pub enum StorageProxy {
    File(file::FileStorage),
    #[allow(dead_code)]
    Ram(ram::RamStorage),
    S3(s3::S3Storage),
}

/// Neither `delegate` nor `ambassador` crates can work with
/// `tonic::async_trait` because Rust doesn't support eager macro instantiation,
/// or something. So, more monstrosity.
#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl StorageReader for StorageProxy {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        match &self {
            StorageProxy::File(s) => s.data_exists(url).await,
            StorageProxy::Ram(s) => s.data_exists(url).await,
            StorageProxy::S3(s) => s.data_exists(url).await,
        }
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        match &self {
            StorageProxy::File(s) => s.read_data(url).await,
            StorageProxy::Ram(s) => s.read_data(url).await,
            StorageProxy::S3(s) => s.read_data(url).await,
        }
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        match &self {
            StorageProxy::File(s) => s.compute_url(data_id, data_type),
            StorageProxy::Ram(s) => s.compute_url(data_id, data_type),
            StorageProxy::S3(s) => s.compute_url(data_id, data_type),
        }
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        match &self {
            StorageProxy::File(s) => s.all_urls(data_type).await,
            StorageProxy::Ram(s) => s.all_urls(data_type).await,
            StorageProxy::S3(s) => s.all_urls(data_type).await,
        }
    }

    fn info(&self) -> String {
        match &self {
            StorageProxy::File(s) => s.info(),
            StorageProxy::Ram(s) => s.info(),
            StorageProxy::S3(s) => s.info(),
        }
    }
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl Storage for StorageProxy {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        match &mut self {
            StorageProxy::File(s) => s.store_data(data, url).await,
            StorageProxy::Ram(s) => s.store_data(data, url).await,
            StorageProxy::S3(s) => s.store_data(data, url).await,
        }
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        match &mut self {
            StorageProxy::File(s) => s.delete_data(url).await,
            StorageProxy::Ram(s) => s.delete_data(url).await,
            StorageProxy::S3(s) => s.delete_data(url).await,
        }
    }
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl StorageForText for StorageProxy {
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        match &mut self {
            StorageProxy::File(s) => s.store_text(text, url).await,
            StorageProxy::Ram(s) => s.store_text(text, url).await,
            StorageProxy::S3(s) => s.store_text(text, url).await,
        }
    }
}

pub fn make_storage(
    storage: Option<Url>,
    storage_type: StorageType,
    party_id: Option<usize>,
    storage_cache: Option<StorageCache>,
    s3_client: Option<S3Client>,
) -> anyhow::Result<StorageProxy> {
    let storage = match storage {
        Some(storage_url) => match storage_url.scheme() {
            "s3" => {
                let s3_client = s3_client.expect("AWS S3 client must be configured");
                StorageProxy::S3(s3::S3Storage::new(
                    s3_client,
                    some_or_err(storage_url.host_str(), "No host in url {url}".to_string())?
                        .to_string(),
                    Some(storage_url.path().to_string()),
                    storage_type,
                    party_id,
                    storage_cache,
                )?)
            }
            "file" => StorageProxy::File(file::FileStorage::new(
                Some(file::url_to_pathbuf(&storage_url).as_path()),
                storage_type,
                party_id,
            )?),
            _ => panic!("Unknown storage type"),
        },
        None => StorageProxy::File(file::FileStorage::new(None, storage_type, party_id)?),
    };
    Ok(storage)
}

pub struct StorageCache {
    cache: OrderMap<(String, String), Vec<u8>>,
    max_cache_size: usize,
}

impl StorageCache {
    pub fn new(max_cache_size: usize) -> anyhow::Result<Self> {
        if max_cache_size != 0 {
            Ok(Self {
                cache: OrderMap::new(),
                max_cache_size,
            })
        } else {
            anyhow::bail!("storage cache size should not be zero");
        }
    }

    pub(crate) fn insert(&mut self, key: &str, subkey: &str, data: &[u8]) -> Option<Vec<u8>> {
        let out = self
            .cache
            .insert((key.to_string(), subkey.to_string()), data.to_vec());

        if self.cache.len() > self.max_cache_size {
            _ = self.cache.remove_index(0);
        }

        out
    }

    pub(crate) fn get(&self, key: &str, subkey: &str) -> Option<&Vec<u8>> {
        // do we have to use to_string()?
        self.cache.get(&(key.to_string(), subkey.to_string()))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use kms_grpc::rpc_types::PubDataType;
    use serde::{Deserialize, Serialize};
    use tfhe_versionable::VersionsDispatch;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, VersionsDispatch)]
    pub enum TestTypeVersioned {
        V0(TestType),
    }

    impl Named for TestType {
        const NAME: &'static str = "TestType";
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(TestTypeVersioned)]
    pub struct TestType {
        pub i: u32,
    }

    pub async fn test_storage_read_store_methods<S: Storage>(storage: &mut S) {
        let data = TestType { i: 42 };
        let data_type = "TestType";
        let req_id = RequestId::derive("123").unwrap();

        // Ensure no old data is present
        let _ = delete_at_request_id(storage, &req_id, data_type).await;
        assert!(
            store_versioned_at_request_id(storage, &req_id, &data, data_type)
                .await
                .is_ok()
        );
        let retrieved_store: TestType = read_versioned_at_request_id(storage, &req_id, data_type)
            .await
            .unwrap();
        assert_eq!(data, retrieved_store);
        assert!(delete_at_request_id(storage, &req_id, data_type)
            .await
            .is_ok());
        let reretrieved_store: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id, data_type).await;
        assert!(reretrieved_store.is_err());
    }

    pub async fn test_batch_helper_methods<S: Storage>(storage: &mut S) {
        // Setup data
        let req_id_1 = RequestId::derive("1").unwrap();
        let data_1_pk = TestType { i: 1 };
        let data_1_vk = TestType { i: 2 };
        let req_id_2 = RequestId::derive("2").unwrap();
        let data_2_pk = TestType { i: 3 };
        let url_1_pk = storage
            .compute_url(&req_id_1.to_string(), &PubDataType::PublicKey.to_string())
            .unwrap();
        let url_1_vk = storage
            .compute_url(&req_id_1.to_string(), &PubDataType::VerfKey.to_string())
            .unwrap();
        let url_2_pk = storage
            .compute_url(&req_id_2.to_string(), &PubDataType::PublicKey.to_string())
            .unwrap();

        // Ensure no old test data is present
        println!("deleting..");
        delete_all_at_request_id(storage, &req_id_1).await;
        delete_all_at_request_id(storage, &req_id_2).await;

        // Store data
        println!("storing..");
        storage.store_data(&data_1_pk, &url_1_pk).await.unwrap();
        storage.store_data(&data_1_vk, &url_1_vk).await.unwrap();
        storage.store_data(&data_2_pk, &url_2_pk).await.unwrap();

        // Check data retrieval
        println!("retrieving.. {}", storage.info());
        let req_id_1_pk: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id_1, &PubDataType::PublicKey.to_string())
                .await;
        assert_eq!(&req_id_1_pk.unwrap(), &data_1_pk);
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert_eq!(pks.len(), 2);
        assert_eq!(pks.get(&req_id_1).unwrap(), &data_1_pk);
        assert_eq!(pks.get(&req_id_2).unwrap(), &data_2_pk);
        let verfs: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::VerfKey.to_string())
                .await
                .unwrap();
        assert_eq!(verfs.len(), 1);
        assert_eq!(verfs.get(&req_id_1).unwrap(), &data_1_vk);

        // Delete data
        delete_all_at_request_id(storage, &req_id_1).await;

        // Check data retrieval again
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert_eq!(pks.len(), 1);
        assert_eq!(pks.get(&req_id_2).unwrap(), &data_2_pk);
        let req_id_1_pk: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id_1, &PubDataType::PublicKey.to_string())
                .await;
        // Check there is no longer a pk for req_id_1
        assert!(req_id_1_pk.is_err());

        let verfs: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::VerfKey.to_string())
                .await
                .unwrap();
        assert!(verfs.is_empty());

        // Delete last data
        delete_all_at_request_id(storage, &req_id_2).await;

        // Check data retrieval again
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert!(pks.is_empty());
    }

    #[test]
    fn ordered_map() {
        let mut om = StorageCache::new(2).unwrap();
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
