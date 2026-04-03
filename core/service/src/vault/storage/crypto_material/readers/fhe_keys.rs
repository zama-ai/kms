//! Implementation of CryptoMaterialReader for KmsFheKeyHandles
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the KmsFheKeyHandles type, enabling it to be read from storage.

use crate::anyhow_error_and_warn_log;
use crate::engine::base::KmsFheKeyHandles;
use crate::vault::storage::crypto_material::traits::PrivateCryptoMaterialReader;
use crate::vault::storage::{StorageReaderExt, read_versioned_at_request_and_epoch_id};
use kms_grpc::RequestId;
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::PrivDataType;

#[tonic::async_trait]
impl PrivateCryptoMaterialReader for KmsFheKeyHandles {
    async fn read_from_storage_at_epoch<S>(
        storage: &S,
        request_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<Self>
    where
        S: StorageReaderExt + Send + Sync + 'static,
    {
        read_versioned_at_request_and_epoch_id(
            storage,
            request_id,
            epoch_id,
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        .map_err(|e| {
            anyhow_error_and_warn_log(format!(
                "Failed to read KmsFheKeyHandles from storage for request ID {request_id}: {e}"
            ))
        })
    }
}
