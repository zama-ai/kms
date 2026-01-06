use crate::engine::context::ContextInfo;
use crate::vault::storage::{read_context_at_id, StorageReader};
use crate::{
    anyhow_error_and_warn_log, vault::storage::crypto_material::traits::CryptoMaterialReader,
};
use kms_grpc::RequestId;

#[tonic::async_trait]
impl CryptoMaterialReader for ContextInfo {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: StorageReader + Send + Sync + 'static,
    {
        read_context_at_id(storage, &(*request_id).into())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read ContextInfo from storage for context ID {request_id}: {e}"
                ))
            })
    }
}
