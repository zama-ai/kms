//! Implementation of CryptoMaterialReader for WrappedPublicKeyOwned
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the WrappedPublicKeyOwned type, enabling it to be read from storage.

use crate::vault::storage::{read_pk_at_request_id, StorageReader};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::rpc_types::WrappedPublicKeyOwned;
use kms_grpc::RequestId;

#[tonic::async_trait]
impl CryptoMaterialReader for WrappedPublicKeyOwned {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: StorageReader + Send + Sync + 'static,
    {
        read_pk_at_request_id(storage, request_id)
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read WrappedPublicKeyOwned from storage for request ID {request_id}: {e}"
                ))
            })
    }
}
