//! Implementation of CryptoMaterialReader for CompactPkeCrs
//!
//! This module provides the implementation of the CryptoMaterialReader trait
//! for the CompactPkeCrs type, enabling it to be read from storage.

use crate::vault::storage::{read_versioned_at_request_id, Storage};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::RequestId;
use tfhe::zk::CompactPkeCrs;

#[tonic::async_trait]
impl CryptoMaterialReader for CompactPkeCrs {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PubDataType::CRS.to_string())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read CompactPkeCrs from storage for request ID {}: {}",
                    request_id, e
                ))
            })
    }
}
