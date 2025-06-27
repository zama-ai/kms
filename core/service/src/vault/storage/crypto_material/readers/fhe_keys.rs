//! Implementation of CryptoMaterialReader for KmsFheKeyHandles
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the KmsFheKeyHandles type, enabling it to be read from storage.

use crate::engine::base::KmsFheKeyHandles;
use crate::vault::storage::{read_versioned_at_request_id, Storage};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;

#[tonic::async_trait]
impl CryptoMaterialReader for KmsFheKeyHandles {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PrivDataType::FheKeyInfo.to_string())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read KmsFheKeyHandles from storage for request ID {request_id}: {e}"
                ))
            })
    }
}
