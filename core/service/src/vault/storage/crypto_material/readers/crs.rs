//! Implementation of CryptoMaterialReader for CompactPkeCrs
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the CompactPkeCrs type, enabling it to be read from storage.

use crate::engine::base::CrsGenMetadata;
use crate::vault::storage::crypto_material::PrivateCryptoMaterialReader;
use crate::vault::storage::{
    StorageReader, StorageReaderExt, read_versioned_at_request_and_epoch_id,
    read_versioned_at_request_id,
};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_grpc::{EpochId, RequestId};
use tfhe::zk::CompactPkeCrs;

#[tonic::async_trait]
impl CryptoMaterialReader for CompactPkeCrs {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: StorageReader + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PubDataType::CRS.to_string())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read CompactPkeCrs from storage for request ID {request_id}: {e}"
                ))
            })
    }
}

#[tonic::async_trait]
impl PrivateCryptoMaterialReader for CrsGenMetadata {
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
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .map_err(|e| {
            anyhow_error_and_warn_log(format!(
                "Failed to read CrsGenMetadata from storage for request ID {request_id}: {e}"
            ))
        })
    }
}
