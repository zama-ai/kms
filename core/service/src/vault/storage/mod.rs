use crate::{
    anyhow_error_and_log,
    conf::{FileStorage, RamStorage, S3Storage, Storage as StorageConf},
    engine::context,
};
use anyhow::anyhow;
use aws_sdk_s3::Client as S3Client;
use enum_dispatch::enum_dispatch;
use kms_grpc::{
    rpc_types::{
        PrivDataType, PubDataType, PublicKeyType, WrappedPublicKey, WrappedPublicKeyOwned,
    },
    RequestId,
};
use ordermap::OrderMap;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self};
use strum::{EnumIter, IntoEnumIterator};
use tfhe::{named::Named, Unversionize, Versionize};
use threshold_fhe::execution::runtime::party::Role;
use tracing;

pub mod crypto_material;
pub mod file;
pub mod ram;
pub mod s3;

// TODO add a wrapper struct for both public and private storage.

/// Trait for public KMS storage reading
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait StorageReader {
    /// Validate if data exists at a given `url`.
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool>;

    /// Read some data with the given `data_id` and of the given `data_type`.
    /// On return, the data is unversioned.
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T>;

    /// Return all URLs stored of a specific data type
    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>>;

    /// Output some information on the storage instance.
    fn info(&self) -> String;
}

// Trait for KMS public storage reading and writing
// Warning: There is no compiler validation that the data being stored are of a versioned type!
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait Storage: StorageReader {
    /// Store the given `data` with the given `data_id` of the given `data_type`
    /// Under the hood, the versioned data is stored.
    /// If the object with `data_id` and `data_type` already exists, it will not be overwritten and
    /// instead a warning is logged, but the call will succeed.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()>;

    /// Delete the given `data_id` with the given `data_type`.
    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()>;
}

/// Sometimes we want to store bytes directly, without the need for versioning
/// and serialization. This trait was created initially to work with ASCII text,
/// such as Ethereum addresses and PEM-formatted X.509 certificates but we also
/// have to work with raw bytes, for example, cryptographic commitments.
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait StorageForBytes: Storage {
    /// Store the given `bytes` with the given `data_id` and `data_type`.
    /// If the object with `data_id` and `data_type` already exists, it will not be overwritten and
    /// instead a warning is logged, nut the call will succeed.
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()>;
    /// Load some bytes from the given `data_id` and `data_type`.
    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>>;
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
    storage
        .store_data(data, request_id, data_type)
        .await
        .map_err(|e| {
            anyhow_error_and_log(format!(
                "Could not store data with ID {request_id} and type {data_type}: {e}"
            ))
        })
}

// Helper method for storing text under a request ID.
// An error will be returned if the data already exists.
pub async fn store_text_at_request_id<S: StorageForBytes>(
    storage: &mut S,
    request_id: &RequestId,
    data: &str,
    data_type: &str,
) -> anyhow::Result<()> {
    storage
        .store_bytes(data.as_bytes(), request_id, data_type)
        .await
        .map_err(|e| {
            anyhow_error_and_log(format!(
                "Could not store data with ID {request_id} and type {data_type}: {e}"
            ))
        })
}

// Helper method for reading text under a request ID.
// An error will be returned if the data already exists.
pub async fn read_text_at_request_id<S: StorageForBytes>(
    storage: &S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<String> {
    String::from_utf8(
        storage
            .load_bytes(request_id, data_type)
            .await
            .map_err(|e| {
                anyhow_error_and_log(format!(
                    "Could not read data with ID {request_id} and type {data_type}: {e}"
                ))
            })?,
    )
    .map_err(|e| anyhow_error_and_log(e.utf8_error().to_string()))
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
// An error will be returned if the data exists but could not be deleted.
// In case the data does not exist, an info log is made but no error returned.
pub async fn delete_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<()> {
    if storage.data_exists(request_id, data_type).await? {
        storage
            .delete_data(request_id, data_type)
            .await
            .map_err(|e| {
                anyhow::anyhow!(format!(
                    "Could not delete data with ID {} and type {}: {}",
                    request_id, data_type, e
                ))
            })
    } else {
        tracing::info!(
            "Tried to delete data with ID {} and type {}, but did not exist",
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
    storage.read_data(request_id, data_type).await
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

pub async fn read_pk_at_request_id<S: StorageReader>(
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

/// Simple wrapper around [store_versioned_at_request_id]
/// for the Context PrivDataType.
pub async fn store_context_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    context_info: &context::ContextInfo,
) -> anyhow::Result<()> {
    store_versioned_at_request_id(
        storage,
        request_id,
        context_info,
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
}

/// Simple wrapper around [read_context_at_request_id]
/// for the Context PrivDataType.
pub async fn read_context_at_request_id<S: StorageReader>(
    storage: &S,
    request_id: &RequestId,
) -> anyhow::Result<context::ContextInfo> {
    read_versioned_at_request_id(storage, request_id, &PrivDataType::ContextInfo.to_string()).await
}

pub async fn delete_context_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
) -> anyhow::Result<()> {
    delete_at_request_id(storage, request_id, &PrivDataType::ContextInfo.to_string()).await
}

/// Helper method for reading all data of a specific type.
pub async fn read_all_data_versioned<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    data_type: &str,
) -> anyhow::Result<HashMap<RequestId, T>> {
    let id_set = storage.all_data_ids(data_type).await?;
    let mut res = HashMap::with_capacity(id_set.len());
    for data_id in id_set.iter() {
        if !data_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "Request ID {data_id} is not valid"
            )));
        }
        let data: T = storage
            .read_data(data_id, data_type)
            .await
            .map_err(|e| anyhow!("reading failed on data id {data_id}: {e}"))?;
        res.insert(*data_id, data);
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
        write!(f, "{self:?}")
    }
}

/// Represents all storage types as variants of one concrete type. This is
/// required to enable multiple dispatch on non-dyn compatible Storage* traits.
#[cfg(feature = "non-wasm")]
#[allow(clippy::large_enum_variant)]
#[enum_dispatch(StorageReader, Storage, StorageForBytes)]
#[derive(Debug, Clone)]
pub enum StorageProxy {
    File(file::FileStorage),
    #[allow(dead_code)]
    Ram(ram::RamStorage),
    S3(s3::S3Storage),
}

pub fn make_storage(
    storage_conf: Option<StorageConf>,
    storage_type: StorageType,
    party_role: Option<Role>,
    storage_cache: Option<StorageCache>,
    s3_client: Option<S3Client>,
) -> anyhow::Result<StorageProxy> {
    let storage =
        match storage_conf {
            Some(storage_conf) => match storage_conf {
                StorageConf::S3(S3Storage { bucket, prefix }) => {
                    let s3_client = s3_client.expect("AWS S3 client must be configured");
                    StorageProxy::from(s3::S3Storage::new(
                        s3_client,
                        bucket,
                        prefix,
                        storage_type,
                        party_role,
                        storage_cache,
                    )?)
                }
                StorageConf::File(FileStorage { path }) => StorageProxy::from(
                    file::FileStorage::new(Some(&path), storage_type, party_role)?,
                ),
                StorageConf::Ram(RamStorage {}) => StorageProxy::from(ram::RamStorage::new()),
            },
            None => StorageProxy::from(file::FileStorage::new(None, storage_type, party_role)?),
        };
    Ok(storage)
}

#[derive(Debug, Clone)]
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

    pub(crate) fn remove(&mut self, key: &str, subkey: &str) -> Option<Vec<u8>> {
        self.cache.remove(&(key.to_string(), subkey.to_string()))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::engine::base::derive_request_id;

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
        let req_id = derive_request_id("123").unwrap();

        // Ensure no old data is present
        let _ = delete_at_request_id(storage, &req_id, data_type).await;
        store_versioned_at_request_id(storage, &req_id, &data, data_type)
            .await
            .unwrap();
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
        let req_id_1 = derive_request_id("1").unwrap();
        let data_1_pk = TestType { i: 1 };
        let data_1_vk = TestType { i: 2 };
        let req_id_2 = derive_request_id("2").unwrap();
        let data_2_pk = TestType { i: 3 };

        // Ensure no old test data is present
        println!("deleting..");
        delete_all_at_request_id(storage, &req_id_1).await;
        delete_all_at_request_id(storage, &req_id_2).await;

        // Store data
        println!("storing..");
        storage
            .store_data(&data_1_pk, &req_id_1, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();
        storage
            .store_data(&data_1_vk, &req_id_1, &PubDataType::VerfKey.to_string())
            .await
            .unwrap();
        storage
            .store_data(&data_2_pk, &req_id_2, &PubDataType::PublicKey.to_string())
            .await
            .unwrap();

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

    pub(crate) async fn test_store_bytes_does_not_overwrite_existing_bytes<
        S: Storage + StorageForBytes,
    >(
        storage: &mut S,
    ) {
        let data_id = derive_request_id("BYTES_OVERWRITE").unwrap();
        let data_type = PubDataType::CRS.to_string();

        // First bytes to store
        let original_bytes = vec![1, 2, 3, 4, 5];
        storage
            .store_bytes(&original_bytes, &data_id, &data_type)
            .await
            .unwrap();

        // Attempt to overwrite with different bytes
        let new_bytes = vec![9, 8, 7, 6, 5];
        storage
            .store_bytes(&new_bytes, &data_id, &data_type)
            .await
            .unwrap();

        // Read back and verify it is still the original bytes
        let loaded = storage.load_bytes(&data_id, &data_type).await.unwrap();
        assert_eq!(loaded, original_bytes, "Bytes should not be overwritten");
    }

    pub(crate) async fn test_store_data_does_not_overwrite_existing_data<S: Storage>(
        storage: &mut S,
    ) {
        let data_id = derive_request_id("ID_OVERWRITE").unwrap();
        let data_type = PubDataType::CRS.to_string();

        // First data to store
        let original_data = TestType { i: 42 };
        storage
            .store_data(&original_data, &data_id, &data_type)
            .await
            .unwrap();

        // Attempt to overwrite with different data
        let new_data = TestType { i: 99 };
        storage
            .store_data(&new_data, &data_id, &data_type)
            .await
            .unwrap();

        // Read back and verify it is still the original data
        let loaded: TestType = storage.read_data(&data_id, &data_type).await.unwrap();
        assert_eq!(loaded.i, original_data.i, "Data should not be overwritten");
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
