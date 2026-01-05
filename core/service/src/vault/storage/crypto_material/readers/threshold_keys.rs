//! Implementation of CryptoMaterialReader for ThresholdFheKeys
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the ThresholdFheKeys type, enabling it to be read from storage.

use crate::anyhow_error_and_warn_log;
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::vault::storage::crypto_material::traits::PrivateCryptoMaterialReader;
use crate::vault::storage::{read_versioned_at_request_and_epoch_id, StorageReaderExt};
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;

#[tonic::async_trait]
impl PrivateCryptoMaterialReader for ThresholdFheKeys {
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
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .map_err(|e| {
            anyhow_error_and_warn_log(format!(
                "Failed to read ThresholdFheKeys from storage for request ID {request_id}: {e}"
            ))
        })
    }
}
