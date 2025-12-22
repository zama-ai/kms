use crate::{
    anyhow_error_and_log,
    conf::{FileStorage, RamStorage, S3Storage, Storage as StorageConf},
    engine::context,
    vault::Vault,
};
use anyhow::anyhow;
use aws_sdk_s3::Client as S3Client;
use enum_dispatch::enum_dispatch;
use kms_grpc::{
    identifiers::{ContextId, EpochId},
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
use tracing;

pub mod crypto_material;
pub mod file;
pub mod ram;
pub mod s3;

/// Trait for KMS storage reading.
///
/// This reader does not consider data that are stored under epochs.
/// In most cases, attempting to read data that are only available under certain epochs
/// will fail as they will not exist when using this trait to read.
/// In general, we do not guarantee its behaviour when attempting to read data that's under epochs.
/// For that scenario, use StorageReaderExt.
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait StorageReader {
    // TODO(#2829) types should be changed to strong types instead of strings
    /// Validate if data exists at a given `url`.
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool>;

    /// Read some data with the given `data_id` and of the given `data_type`.
    /// On return, the data is unversioned.
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T>;

    /// Load raw bytes from storage without deserializing.
    /// This is useful when you need to verify a digest of the original serialized bytes
    /// before deserializing, to avoid issues with version upgrades changing the serialized form.
    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>>;

    /// Return all URLs stored of a specific data type
    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>>;

    /// Output some information on the storage instance.
    fn info(&self) -> String;
}

/// Return all URLs stored of a specific data type
pub(crate) async fn all_data_ids_from_all_epochs_impl(
    storage: &impl StorageReaderExt,
    data_type: &str,
) -> anyhow::Result<HashSet<RequestId>> {
    // First, get IDs from non-epoch path using StorageReader's implementation
    let ids_from_non_epoch_storage = storage.all_data_ids(data_type).await?;

    // Also check for data stored under epochs
    let mut ids_from_epoch_storage = HashSet::new();
    let epoch_ids = storage.all_epoch_ids_for_data(data_type).await?;
    for epoch_id in epoch_ids {
        let epoch_data_ids = storage.all_data_ids_at_epoch(&epoch_id, data_type).await?;
        ids_from_epoch_storage.extend(epoch_data_ids);
    }

    if ids_from_non_epoch_storage.is_empty() && ids_from_epoch_storage.is_empty() {
        // Both are empty, return empty set
        Ok(HashSet::new())
    } else if ids_from_non_epoch_storage.is_empty() && !ids_from_epoch_storage.is_empty() {
        Ok(ids_from_epoch_storage)
    } else if !ids_from_non_epoch_storage.is_empty() && ids_from_epoch_storage.is_empty() {
        Ok(ids_from_non_epoch_storage)
    } else {
        // when both are non empty, then we have some inconsistency
        // there is no correct set to return and returning the union is also problematic
        let msg = format!("inconsistent storage, ids_from_non_epoch_storage.len()={}, ids_from_epoch_storage.len()={}",
                ids_from_non_epoch_storage.len(),ids_from_epoch_storage.len());
        tracing::error!(msg);
        Err(anyhow::anyhow!(msg))
    }
}

/// Extended storage reader trait for epoch-aware data access.
///
/// This trait extends [`StorageReader`] with methods that support reading data
/// organized by epoch IDs. Epochs represent distinct time periods or versions
/// of the private key material, which is created during resharing.
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait StorageReaderExt: StorageReader {
    /// Returns all data IDs stored under the given epoch and data type.
    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>>;

    /// Returns all epoch IDs that contain data of the given type.
    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>>;

    /// Checks whether data exists for the given data ID, epoch ID, and data type.
    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool>;

    /// Reads and deserializes data stored at the given data ID, epoch ID, and data type.
    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T>;

    /// Return all URLs stored of a specific data type
    // In theory only a default implementation is needed,
    // but we cannot implement it easily due to this issue
    // https://github.com/rust-lang/impl-trait-utils/issues/17
    // so all implementers must implement this function by calling
    // [all_data_ids_from_all_epochs_impl]
    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>>;

    /// Load raw bytes from storage at the given epoch without deserializing.
    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>>;
}

/// Trait for KMS storage reading and writing.
///
/// See the documentation for [StorageReader] for behaviour related to epochs.
/// To write data under specific epochs, use [StorageExt].
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

    /// Store raw bytes directly without versioning or serialization.
    /// This is useful for storing ASCII text (e.g., Ethereum addresses, PEM certificates)
    /// or raw bytes like cryptographic commitments.
    /// If the object with `data_id` and `data_type` already exists, it will not be overwritten and
    /// instead a warning is logged, but the call will succeed.
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()>;

    /// Delete the given `data_id` with the given `data_type`.
    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()>;
}

/// Extended storage trait for epoch-aware data storage and deletion.
///
/// This trait combines [`StorageReaderExt`] and [`Storage`] with additional methods
/// for storing and deleting data organized by epoch IDs. Use this trait when you need
/// to manage private key material that may belong to a specific epoch.
#[enum_dispatch]
#[trait_variant::make(Send)]
pub trait StorageExt: StorageReaderExt + Storage {
    /// Stores the given data at the specified data ID, epoch ID, and data type.
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()>;

    /// Store raw bytes at the specified epoch without versioning or serialization.
    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()>;

    /// Deletes data at the specified data ID, epoch ID, and data type.
    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()>;
}

/// Store some data at a location defined by `request_id` and `data_type`.
/// Under the hood, the versioned data will be stored.
/// If the object with `data_id` and `data_type` already exists, it will not be overwritten and
/// instead a warning is logged, but the call will succeed.
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

/// Store some data at a location defined by `request_id` and `data_type`.
/// Under the hood, the versioned data will be stored.
pub async fn store_versioned_at_request_and_epoch_id<
    'a,
    S: StorageExt,
    T: Serialize + Versionize + Named + Send + Sync,
>(
    storage: &mut S,
    request_id: &RequestId,
    epoch_id: &EpochId,
    data: &'a T,
    data_type: &str,
) -> anyhow::Result<()>
where
    <T as Versionize>::Versioned<'a>: Send + Sync,
{
    storage
        .store_data_at_epoch(data, request_id, epoch_id, data_type)
        .await
        .map_err(|e| {
            anyhow_error_and_log(format!(
                "Could not store data with ID {request_id}, epoch ID {epoch_id} and type {data_type}: {e}"
            ))
        })
}

// Helper method for storing text under a request ID.
// An error will be returned if the data already exists.
pub async fn store_text_at_request_id<S: Storage>(
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
pub async fn read_text_at_request_id<S: StorageReader>(
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
pub async fn delete_all_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
) -> anyhow::Result<()> {
    for cur_type in PrivDataType::iter() {
        match cur_type {
            PrivDataType::FhePrivateKey | PrivDataType::FheKeyInfo => {
                // These types might have epoch-specific data
                continue;
            }
            _ => {
                delete_at_request_id(storage, request_id, &cur_type.to_string()).await?;
            }
        }
    }
    for cur_type in PubDataType::iter() {
        delete_at_request_id(storage, request_id, &cur_type.to_string()).await?;
    }
    Ok(())
}

/// Helper method to remove data based on a data type and request ID.
/// An error will be returned if the data exists but could not be deleted.
/// In case the data does not exist, an info log is made but no error returned.
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

/// Helper method to remove data based on a data type, request ID and epoch ID.
/// An error will be returned if the data exists but could not be deleted.
/// In case the data does not exist, an info log is made but no error returned.
pub async fn delete_at_request_and_epoch_id<S: StorageExt>(
    storage: &mut S,
    request_id: &RequestId,
    epoch_id: &EpochId,
    data_type: &str,
) -> anyhow::Result<()> {
    if storage
        .data_exists_at_epoch(request_id, epoch_id, data_type)
        .await?
    {
        storage
            .delete_data_at_epoch(request_id, epoch_id, data_type)
            .await
            .map_err(|e| {
                anyhow::anyhow!(format!(
                    "Could not delete data with ID {} and epoch {} and type {}: {}",
                    request_id, epoch_id, data_type, e
                ))
            })
    } else {
        tracing::info!(
            "Tried to delete data with ID {} and epoch {} and type {}, but did not exist",
            request_id,
            epoch_id,
            data_type
        );
        Ok(())
    }
}

/// Helper method to remove data based on a data type and request ID.
pub async fn delete_pk_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
) -> anyhow::Result<()> {
    delete_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string()).await?;
    delete_at_request_id(
        storage,
        request_id,
        &PubDataType::PublicKeyMetadata.to_string(),
    )
    .await?;
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

/// Read some data stored in a location defined by `request_id`, `epoch_id`, and `data_type`.
/// The returned result is automatically unversioned.
pub async fn read_versioned_at_request_and_epoch_id<
    S: StorageReaderExt,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    request_id: &RequestId,
    epoch_id: &EpochId,
    data_type: &str,
) -> anyhow::Result<T>
where
    <T as tfhe_versionable::VersionizeOwned>::VersionedOwned: Send,
{
    storage
        .read_data_at_epoch(request_id, epoch_id, data_type)
        .await
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
pub async fn store_context_at_id<S: Storage>(
    storage: &mut S,
    context_id: &ContextId,
    context_info: &context::ContextInfo,
) -> anyhow::Result<()> {
    store_versioned_at_request_id(
        storage,
        &(*context_id).into(),
        context_info,
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
}

/// Simple wrapper around [read_versioned_at_request_id]
/// for the Context PrivDataType.
pub async fn read_context_at_id<S: StorageReader>(
    storage: &S,
    context_id: &ContextId,
) -> anyhow::Result<context::ContextInfo> {
    read_versioned_at_request_id(
        storage,
        &(*context_id).into(),
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
}

pub async fn delete_context_at_id<S: Storage>(
    storage: &mut S,
    request_id: &ContextId,
) -> anyhow::Result<()> {
    delete_at_request_id(
        storage,
        &(*request_id).into(),
        &PrivDataType::ContextInfo.to_string(),
    )
    .await
}

pub async fn delete_custodian_context_at_id<PubS: Storage>(
    pub_storage: &mut PubS,
    backup_storage: &mut Vault,
    backup_id: &RequestId, // TODO(#2830) should be changed to a BackupId
) -> anyhow::Result<()> {
    // Delete everything that is backed up in relation to a specific request ID
    // Note that this method will fail if backup_id is the current backup id
    backup_storage.remove_old_backup(backup_id).await?;

    // If the vault allows the backup deletion, then also delete the public data
    delete_at_request_id(
        pub_storage,
        backup_id,
        &PubDataType::RecoveryMaterial.to_string(),
    )
    .await
}
/// Helper method for reading all data of a specific type.
pub async fn read_all_data_from_all_epochs_versioned<
    S: StorageReaderExt,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    data_type: &str,
) -> anyhow::Result<HashMap<(RequestId, EpochId), T>> {
    // first read all the PRSS data
    let epochs = storage
        .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
        .await?;

    // then we know all the epochs, and we can read the data stored under each epoch
    let mut res = HashMap::new();
    for epoch in epochs {
        let epoch_id: EpochId = epoch.into();
        let id_set = storage.all_data_ids_at_epoch(&epoch_id, data_type).await?;
        for data_id in id_set.iter() {
            if !data_id.is_valid() {
                return Err(anyhow_error_and_log(format!(
                    "Request ID {data_id} is not valid"
                )));
            }
            let data: T = storage
                .read_data_at_epoch(data_id, &epoch_id, data_type)
                .await
                .map_err(|e| anyhow!("reading failed for {data_type} with id {data_id} and epoch id {epoch_id}: {e}"))?;
            res.insert((*data_id, epoch_id), data);
        }
    }

    Ok(res)
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
            .map_err(|e| anyhow!("reading failed for {data_type} with id {data_id}: {e}"))?;
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
#[enum_dispatch(StorageReader, Storage, StorageReaderExt, StorageExt)]
#[derive(Debug, Clone)]
pub enum StorageProxy {
    File(file::FileStorage),
    #[allow(dead_code)]
    Ram(ram::RamStorage),
    S3(s3::S3Storage),
}

// If storage_conf is None, then we default to file storage at the default path and prefix.
pub fn make_storage(
    storage_conf: Option<StorageConf>,
    storage_type: StorageType,
    storage_cache: Option<StorageCache>,
    s3_client: Option<S3Client>,
) -> anyhow::Result<StorageProxy> {
    let storage = match storage_conf {
        Some(storage_conf) => match storage_conf {
            StorageConf::S3(S3Storage { bucket, prefix }) => {
                let s3_client = s3_client.expect("AWS S3 client must be configured");
                StorageProxy::from(s3::S3Storage::new(
                    s3_client,
                    bucket,
                    storage_type,
                    prefix.as_deref(),
                    storage_cache,
                )?)
            }
            StorageConf::File(FileStorage { path, prefix }) => StorageProxy::from(
                file::FileStorage::new(Some(&path), storage_type, prefix.as_deref())?,
            ),
            StorageConf::Ram(RamStorage {}) => StorageProxy::from(ram::RamStorage::new()),
        },
        None => StorageProxy::from(file::FileStorage::new(None, storage_type, None)?),
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
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::PubDataType;
    use rand::SeedableRng;
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
        delete_at_request_id(storage, &req_id, data_type)
            .await
            .unwrap();
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

    pub async fn test_epoch_methods<S: StorageExt>(storage: &mut S) {
        // create two epochs and write two objects on each epoch
        let mut rng = AesRng::seed_from_u64(12121212);
        let epoch1 = EpochId::new_random(&mut rng);
        let epoch2 = EpochId::new_random(&mut rng);

        let data1 = TestType { i: 42 };
        let data2 = TestType { i: 43 };
        let data3 = TestType { i: 44 };
        let data4 = TestType { i: 45 };

        let id1 = derive_request_id("DATA1").unwrap();
        let id2 = derive_request_id("DATA2").unwrap();
        let id3 = derive_request_id("DATA3").unwrap();
        let id4 = derive_request_id("DATA4").unwrap();

        let data_type = PrivDataType::FheKeyInfo.to_string();
        storage
            .store_data_at_epoch(&data1, &id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data2, &id2, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data3, &id3, &epoch2, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data4, &id4, &epoch2, &data_type)
            .await
            .unwrap();

        // read all data in epoch1
        let ids_epoch1 = storage
            .all_data_ids_at_epoch(&epoch1, &data_type)
            .await
            .unwrap();
        assert_eq!(ids_epoch1.len(), 2);
        assert!(ids_epoch1.contains(&id1));
        assert!(ids_epoch1.contains(&id2));

        // read all data in epoch2
        let ids_epoch2 = storage
            .all_data_ids_at_epoch(&epoch2, &data_type)
            .await
            .unwrap();
        assert_eq!(ids_epoch2.len(), 2);
        assert!(ids_epoch2.contains(&id3));
        assert!(ids_epoch2.contains(&id4));

        // read all epochs for PrivDataType::FheKeyInfo
        let epochs = storage.all_epoch_ids_for_data(&data_type).await.unwrap();
        assert_eq!(epochs.len(), 2);
        assert!(epochs.contains(&epoch1));
        assert!(epochs.contains(&epoch2));
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
        delete_all_at_request_id(storage, &req_id_1).await.unwrap();
        delete_all_at_request_id(storage, &req_id_2).await.unwrap();

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
        delete_all_at_request_id(storage, &req_id_1).await.unwrap();

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
        delete_all_at_request_id(storage, &req_id_2).await.unwrap();

        // Check data retrieval again
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert!(pks.is_empty());
    }

    pub(crate) async fn test_store_bytes_does_not_overwrite_existing_bytes<S: Storage>(
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

    pub async fn test_all_data_ids_from_all_epochs<S: StorageExt>(storage: &mut S) {
        let mut rng = AesRng::seed_from_u64(98765);
        let epoch1 = EpochId::new_random(&mut rng);
        let epoch2 = EpochId::new_random(&mut rng);

        let data1 = TestType { i: 100 };
        let data2 = TestType { i: 101 };
        let data3 = TestType { i: 102 };

        let id1 = derive_request_id("ALL_EPOCHS_1").unwrap();
        let id2 = derive_request_id("ALL_EPOCHS_2").unwrap();
        let id3 = derive_request_id("ALL_EPOCHS_3").unwrap();

        let data_type = PrivDataType::FheKeyInfo.to_string();

        // Case 1: Data only in epoch storage
        storage
            .store_data_at_epoch(&data1, &id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data2, &id2, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data3, &id3, &epoch2, &data_type)
            .await
            .unwrap();

        let ids = storage
            .all_data_ids_from_all_epochs(&data_type)
            .await
            .unwrap();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert!(ids.contains(&id3));

        // Clean up epoch data
        storage
            .delete_data_at_epoch(&id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .delete_data_at_epoch(&id2, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .delete_data_at_epoch(&id3, &epoch2, &data_type)
            .await
            .unwrap();

        // Case 2: Data only in non-epoch storage
        let id4 = derive_request_id("ALL_EPOCHS_4").unwrap();
        let id5 = derive_request_id("ALL_EPOCHS_5").unwrap();
        let data4 = TestType { i: 200 };
        let data5 = TestType { i: 201 };

        storage.store_data(&data4, &id4, &data_type).await.unwrap();
        storage.store_data(&data5, &id5, &data_type).await.unwrap();

        let ids = storage
            .all_data_ids_from_all_epochs(&data_type)
            .await
            .unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id4));
        assert!(ids.contains(&id5));

        // Case 3: Data in both epoch and non-epoch storage (should error)
        storage
            .store_data_at_epoch(&data1, &id1, &epoch1, &data_type)
            .await
            .unwrap();

        let result = storage.all_data_ids_from_all_epochs(&data_type).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("inconsistent storage"));

        // Clean up
        storage
            .delete_data_at_epoch(&id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage.delete_data(&id4, &data_type).await.unwrap();
        storage.delete_data(&id5, &data_type).await.unwrap();
    }

    pub async fn test_store_load_bytes_at_epoch<S: StorageExt>(storage: &mut S) {
        let mut rng = AesRng::seed_from_u64(54321);
        let epoch1 = EpochId::new_random(&mut rng);
        let epoch2 = EpochId::new_random(&mut rng);

        let bytes1 = vec![1, 2, 3, 4, 5];
        let bytes2 = vec![10, 20, 30];
        let bytes3 = vec![100, 200];

        let id1 = derive_request_id("BYTES_EPOCH_1").unwrap();
        let id2 = derive_request_id("BYTES_EPOCH_2").unwrap();

        let data_type = PrivDataType::FheKeyInfo.to_string();

        // Store bytes at different epochs
        storage
            .store_bytes_at_epoch(&bytes1, &id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&bytes2, &id1, &epoch2, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&bytes3, &id2, &epoch1, &data_type)
            .await
            .unwrap();

        // Load bytes and verify
        let loaded1 = storage
            .load_bytes_at_epoch(&id1, &epoch1, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded1, bytes1);

        let loaded2 = storage
            .load_bytes_at_epoch(&id1, &epoch2, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded2, bytes2);

        let loaded3 = storage
            .load_bytes_at_epoch(&id2, &epoch1, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded3, bytes3);

        // Verify loading non-existent data fails
        let result = storage.load_bytes_at_epoch(&id2, &epoch2, &data_type).await;
        assert!(result.is_err());

        // Clean up
        storage
            .delete_data_at_epoch(&id1, &epoch1, &data_type)
            .await
            .unwrap();
        storage
            .delete_data_at_epoch(&id1, &epoch2, &data_type)
            .await
            .unwrap();
        storage
            .delete_data_at_epoch(&id2, &epoch1, &data_type)
            .await
            .unwrap();
    }

    pub async fn test_store_bytes_at_epoch_does_not_overwrite<S: StorageExt>(storage: &mut S) {
        let mut rng = AesRng::seed_from_u64(11111);
        let epoch = EpochId::new_random(&mut rng);

        let original_bytes = vec![1, 2, 3, 4, 5];
        let new_bytes = vec![9, 8, 7, 6, 5];

        let data_id = derive_request_id("BYTES_EPOCH_OVERWRITE").unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        // Store original bytes
        storage
            .store_bytes_at_epoch(&original_bytes, &data_id, &epoch, &data_type)
            .await
            .unwrap();

        // Attempt to overwrite with different bytes
        storage
            .store_bytes_at_epoch(&new_bytes, &data_id, &epoch, &data_type)
            .await
            .unwrap();

        // Verify original bytes are preserved
        let loaded = storage
            .load_bytes_at_epoch(&data_id, &epoch, &data_type)
            .await
            .unwrap();
        assert_eq!(
            loaded, original_bytes,
            "Bytes at epoch should not be overwritten"
        );

        // Clean up
        storage
            .delete_data_at_epoch(&data_id, &epoch, &data_type)
            .await
            .unwrap();
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
