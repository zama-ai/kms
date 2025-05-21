//! Core traits for cryptographic material storage

use crate::vault::storage::Storage;
use kms_grpc::RequestId;

/// Trait for reading cryptographic material from storage
///
/// This trait defines a standard interface for reading different types of
/// cryptographic material from storage backends.
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
        S: Storage + Send + Sync + 'static,
        Self: Sized;
}
