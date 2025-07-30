use crate::{
    anyhow_error_and_log,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        internal_crypto_types::PrivateSigKey,
    },
    engine::threshold::{service::ThresholdFheKeys, traits::BackupOperator},
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::ThresholdCryptoMaterialStorage, read_all_data_versioned,
            store_versioned_at_request_id, Storage, StorageReader,
        },
        Vault,
    },
};
use kms_grpc::{
    kms::v1::{Empty, OperatorPublicKey},
    rpc_types::{PrivDataType, SignedPubDataHandleInternal},
    utils::tonic_result::tonic_handle_potential_err,
    RequestId,
};
use std::collections::HashMap;
use tokio::sync::MutexGuard;
use tonic::{Code, Request, Response, Status};

pub struct RealBackupOperator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub security_module: Option<SecurityModuleProxy>,
}

#[tonic::async_trait]
impl<PubS, PrivS> BackupOperator for RealBackupOperator<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn get_operator_public_key(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OperatorPublicKey>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref v) => {
                let v = v.lock().await;
                match v.keychain {
                    Some(KeychainProxy::SecretSharing(ref k)) => {
                        let public_key = k.operator_public_key_bytes();
                        let attestation_document = match &self.security_module {
                            Some(sm) => sm.attest_pk_bytes(public_key.clone()).await.map_err(|e| Status::new(Code::Internal, format!("Could not issue attestation document for operator backup public key: {e}")))?,
                            None => vec![],
                        };
                        Ok(Response::new(OperatorPublicKey {
                            public_key,
                            attestation_document,
                        }))
                    }
                    _ => Err(Status::new(
                        tonic::Code::Unimplemented,
                        "Backup vault does not support operator public key retrieval",
                    )),
                }
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }

    async fn custodian_backup_restore(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let mut private_storage = private_storage.lock().await;
                let backup_vault: tokio::sync::MutexGuard<'_, Vault> = backup_vault.lock().await;
                tonic_handle_potential_err(
                    restore_data(&backup_vault, &mut private_storage).await,
                    "Failed to restore".to_string(),
                )?;
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }
}

async fn restore_data<PrivS>(
    backup_vault: &MutexGuard<'_, Vault>,
    priv_storage: &mut MutexGuard<'_, PrivS>,
) -> anyhow::Result<()>
where
    PrivS: Storage + Sync + Send + 'static,
{
    // TODO do as macro
    // Restore FHE keys
    let versioned_data: HashMap<RequestId, ThresholdFheKeys> =
        read_all_data_versioned(&**backup_vault, &PrivDataType::FheKeyInfo.to_string()).await?;
    for (request_id, data) in versioned_data.iter() {
        if priv_storage
            .data_exists(request_id, &PrivDataType::FheKeyInfo.to_string())
            .await?
        {
            return Err(anyhow_error_and_log(format!("Data for {:?} with request ID {request_id} already exists. Cancelling restore to avoid overwriting existing data.", PrivDataType::FheKeyInfo)));
        }
        store_versioned_at_request_id(
            &mut **priv_storage,
            request_id,
            data,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;
    }

    // Restore Signing key
    let versioned_data: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(&**backup_vault, &PrivDataType::SigningKey.to_string()).await?;
    for (request_id, data) in versioned_data.iter() {
        if priv_storage
            .data_exists(request_id, &PrivDataType::SigningKey.to_string())
            .await?
        {
            return Err(anyhow_error_and_log(format!("Data for {:?} with request ID {request_id} already exists. Cancelling restore to avoid overwriting existing data.", PrivDataType::SigningKey)));
        }
        store_versioned_at_request_id(
            &mut **priv_storage,
            request_id,
            data,
            &PrivDataType::SigningKey.to_string(),
        )
        .await?;
    }
    // Restore CRS info
    let versioned_data: HashMap<RequestId, SignedPubDataHandleInternal> =
        read_all_data_versioned(&**backup_vault, &PrivDataType::CrsInfo.to_string()).await?;
    for (request_id, data) in versioned_data.iter() {
        if priv_storage
            .data_exists(request_id, &PrivDataType::CrsInfo.to_string())
            .await?
        {
            return Err(anyhow_error_and_log(format!("Data for {:?} with request ID {request_id} already exists. Cancelling restore to avoid overwriting existing data.", PrivDataType::CrsInfo)));
        }
        store_versioned_at_request_id(
            &mut **priv_storage,
            request_id,
            data,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await?;
    }
    Ok(())
}

impl<PubS, PrivS> RealBackupOperator<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    pub async fn update_backup_vault(&self) -> anyhow::Result<()> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let private_storage = private_storage.lock().await;
                let mut backup_vault: tokio::sync::MutexGuard<'_, Vault> =
                    backup_vault.lock().await;
                // For each data type in the private storage check if the data is in the backup vault.
                // If not, restore it.
                let versioned_data: HashMap<RequestId, ThresholdFheKeys> = read_all_data_versioned(
                    &*private_storage,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await?;
                for (request_id, data) in versioned_data.iter() {
                    if !backup_vault
                        .data_exists(request_id, &PrivDataType::FheKeyInfo.to_string())
                        .await?
                    {
                        store_versioned_at_request_id(
                            &mut *backup_vault,
                            request_id,
                            data,
                            &PrivDataType::FheKeyInfo.to_string(),
                        )
                        .await?;
                    }
                }
                let versioned_data: HashMap<RequestId, PrivateSigKey> = read_all_data_versioned(
                    &*private_storage,
                    &PrivDataType::SigningKey.to_string(),
                )
                .await?;
                for (request_id, data) in versioned_data.iter() {
                    if !backup_vault
                        .data_exists(request_id, &PrivDataType::SigningKey.to_string())
                        .await?
                    {
                        store_versioned_at_request_id(
                            &mut *backup_vault,
                            request_id,
                            data,
                            &PrivDataType::SigningKey.to_string(),
                        )
                        .await?;
                    }
                }
                let versioned_data: HashMap<RequestId, SignedPubDataHandleInternal> =
                    read_all_data_versioned(&*private_storage, &PrivDataType::CrsInfo.to_string())
                        .await?;
                for (request_id, data) in versioned_data.iter() {
                    if !backup_vault
                        .data_exists(request_id, &PrivDataType::CrsInfo.to_string())
                        .await?
                    {
                        store_versioned_at_request_id(
                            &mut *backup_vault,
                            request_id,
                            data,
                            &PrivDataType::CrsInfo.to_string(),
                        )
                        .await?;
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
