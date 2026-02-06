//! Implementation of CryptoMaterialReader for CompactPublicKey
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the CompactPublicKey type, enabling it to be read from storage.

use crate::vault::storage::{read_versioned_at_request_id, StorageReader};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::RequestId;
use tfhe::CompactPublicKey;

#[tonic::async_trait]
impl CryptoMaterialReader for CompactPublicKey {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: StorageReader + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read CompactPublicKey from storage for request ID {request_id}: {e}"
                ))
            })
    }
}
