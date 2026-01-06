//! Core traits for cryptographic material storage

use crate::vault::storage::{StorageReader, StorageReaderExt};
use kms_grpc::{identifiers::EpochId, RequestId};

/// Trait for reading cryptographic material from storage
///
/// This trait defines a standard interface for reading different types of
/// cryptographic material from storage backends.
/// It will not work for materials that require epoch-based versioning.
#[tonic::async_trait]
pub trait CryptoMaterialReader {
    /// Read cryptographic material from storage
    ///
    /// # Type Parameters
    ///
    /// * `S` - Storage implementation type
    ///
    /// # Parameters
    ///
    /// * `storage` - Reference to the storage backend
    /// * `request_id` - Request ID used to identify the material
    ///
    /// # Returns
    ///
    /// The cryptographic material if found, or an error
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: StorageReader + Send + Sync + 'static,
        Self: Sized;
}

/// Trait for reading private cryptographic material from storage at a specific epoch.
///
/// It will only work for materials that require epoch-based versioning,
/// which are only private crypto materials.
#[tonic::async_trait]
pub trait PrivateCryptoMaterialReader {
    /// Read cryptographic material from storage at a specific epoch
    ///
    /// # Type Parameters
    ///
    /// * `S` - StorageExt implementation type
    ///
    /// # Parameters
    ///
    /// * `storage` - Reference to the storage backend
    /// * `request_id` - Request ID used to identify the material
    /// * `epoch_id` - Epoch ID to read the material at
    /// # Returns
    ///
    /// The cryptographic material if found, or an error
    async fn read_from_storage_at_epoch<S>(
        storage: &S,
        request_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<Self>
    where
        S: StorageReaderExt + Send + Sync + 'static,
        Self: Sized;
}
