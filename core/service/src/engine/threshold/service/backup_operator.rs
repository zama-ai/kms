use crate::{
    backup::custodian::InternalCustodianContext,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        internal_crypto_types::PrivateSigKey,
    },
    engine::threshold::{service::ThresholdFheKeys, traits::BackupOperator},
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::ThresholdCryptoMaterialStorage, store_versioned_at_request_id,
            Storage, StorageReader,
        },
        Vault,
    },
};
use kms_grpc::rpc_types::BackupDataType;
use kms_grpc::{
    kms::v1::{Empty, OperatorPublicKey},
    rpc_types::{PrivDataType, SignedPubDataHandleInternal},
    utils::tonic_result::tonic_handle_potential_err,
};
use strum::IntoEnumIterator;
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
macro_rules! restore_data_type {
    ($priv_storage:expr, $backup_vault:expr, $data_type_enum:expr, $data_type:ty) => {{
        let req_ids = $backup_vault
            .all_data_ids(&$data_type_enum.to_string().to_string())
            .await?;
        for request_id in req_ids.iter() {
            if $priv_storage
                .data_exists(request_id, &$data_type_enum.to_string())
                .await?
            {
                tracing::warn!(
                    "Data for {:?} with request ID {request_id} already exists. I am NOT overwriting it!", $data_type_enum);
                    continue;
            }
            let cur_data_type = BackupDataType::PrivData($data_type_enum).to_string();
            let cur_data: $data_type = $backup_vault
                .read_data(request_id, &cur_data_type.to_string())
                .await?;
            store_versioned_at_request_id(
                &mut **$priv_storage,
                request_id,
                &cur_data,
                &cur_data_type.to_string(),
            )
            .await?;
        }
    }};
}

async fn restore_data<PrivS>(
    backup_vault: &MutexGuard<'_, Vault>,
    priv_storage: &mut MutexGuard<'_, PrivS>,
) -> anyhow::Result<()>
where
    PrivS: Storage + Sync + Send + 'static,
{
    for cur_type in PrivDataType::iter() {
        match cur_type {
            PrivDataType::FheKeyInfo => {
                restore_data_type!(
                    priv_storage,
                    backup_vault,
                    PrivDataType::FheKeyInfo,
                    ThresholdFheKeys
                );
            }
            PrivDataType::SigningKey => {
                restore_data_type!(
                    priv_storage,
                    backup_vault,
                    PrivDataType::SigningKey,
                    PrivateSigKey
                );
            }
            PrivDataType::CrsInfo => {
                restore_data_type!(
                    priv_storage,
                    backup_vault,
                    PrivDataType::CrsInfo,
                    SignedPubDataHandleInternal
                );
            }
            PrivDataType::FhePrivateKey => {
                tracing::warn!(
                    "FhePrivateKey backup in the centralized case is not implemented yet. Skipping for now."
                );
            }
            PrivDataType::PrssSetup => {
                tracing::info!("PRSS setup data is not backed up currently. Skipping for now.");
            }
            PrivDataType::CustodianInfo => {
                restore_data_type!(
                    priv_storage,
                    backup_vault,
                    PrivDataType::CustodianInfo,
                    InternalCustodianContext
                );
            }
            PrivDataType::ContextInfo => {
                tracing::warn!(
                    "FhePrivateKey backup in the centralized case is not implemented yet. Skipping for now."
                );
            }
        }
    }
    Ok(())
}

macro_rules! update_specific_backup_vault {
    ($priv_storage:expr, $backup_vault:expr, $data_type_enum:expr, $serialized_data_type:ty) => {{
        let req_ids = $priv_storage
            .all_data_ids(&$data_type_enum.to_string().to_string())
            .await?;
        for request_id in req_ids.iter() {
            let cur_data_type = BackupDataType::PrivData($data_type_enum).to_string();
            if !$backup_vault
                .data_exists(request_id, &cur_data_type.to_string())
                .await?
            {
                let cur_data: $serialized_data_type = $priv_storage
                    .read_data(request_id, &$data_type_enum.to_string())
                    .await?;
                store_versioned_at_request_id(
                    &mut *$backup_vault,
                    request_id,
                    &cur_data,
                    &cur_data_type.to_string(),
                )
                .await?;
            }
        }
    }};
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
                for cur_type in PrivDataType::iter() {
                    match cur_type {
                        PrivDataType::SigningKey => {
                            update_specific_backup_vault!(
                                *private_storage,
                                backup_vault,
                                PrivDataType::SigningKey,
                                PrivateSigKey
                            );
                        }
                        PrivDataType::FheKeyInfo => {
                            update_specific_backup_vault!(
                                *private_storage,
                                backup_vault,
                                PrivDataType::FheKeyInfo,
                                ThresholdFheKeys
                            );
                        }
                        PrivDataType::CrsInfo => {
                            update_specific_backup_vault!(
                                *private_storage,
                                backup_vault,
                                PrivDataType::CrsInfo,
                                SignedPubDataHandleInternal
                            );
                        }
                        PrivDataType::FhePrivateKey => {
                            tracing::warn!(
                                "FhePrivateKey backup in the centralized case is not implemented yet. Skipping for now."
                            );
                        }
                        PrivDataType::PrssSetup => {
                            tracing::info!(
                                "PRSS setup data is not backed up currently. Skipping for now."
                            );
                        }
                        PrivDataType::CustodianInfo => {
                            update_specific_backup_vault!(
                                *private_storage,
                                backup_vault,
                                PrivDataType::CustodianInfo,
                                InternalCustodianContext
                            );
                        }
                        PrivDataType::ContextInfo => {
                            tracing::warn!(
                                "FhePrivateKey backup in the centralized case is not implemented yet. Skipping for now."
                            );
                        }
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
