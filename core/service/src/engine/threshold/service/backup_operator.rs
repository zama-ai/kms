use crate::{
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
use kms_grpc::{
    kms::v1::{Empty, OperatorPublicKey},
    rpc_types::{PrivDataType, SignedPubDataHandleInternal},
    utils::tonic_result::tonic_handle_potential_err,
};
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
            let cur_data: $data_type = $backup_vault
                .read_data(request_id, &$data_type_enum.to_string())
                .await?;
            store_versioned_at_request_id(
                &mut **$priv_storage,
                request_id,
                &cur_data,
                &$data_type_enum.to_string(),
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
    restore_data_type!(
        priv_storage,
        backup_vault,
        PrivDataType::FheKeyInfo,
        ThresholdFheKeys
    );
    restore_data_type!(
        priv_storage,
        backup_vault,
        PrivDataType::SigningKey,
        PrivateSigKey
    );
    restore_data_type!(
        priv_storage,
        backup_vault,
        PrivDataType::CrsInfo,
        SignedPubDataHandleInternal
    );
    Ok(())
}

macro_rules! update_specific_backup_vault {
    ($priv_storage:expr, $backup_vault:expr, $data_type_enum:expr, $serialized_data_type:ty) => {{
        let req_ids = $priv_storage
            .all_data_ids(&$data_type_enum.to_string().to_string())
            .await?;
        for request_id in req_ids.iter() {
            if !$backup_vault
                .data_exists(request_id, &$data_type_enum.to_string())
                .await?
            {
                let cur_data: $serialized_data_type = $priv_storage
                    .read_data(request_id, &$data_type_enum.to_string())
                    .await?;
                store_versioned_at_request_id(
                    &mut *$backup_vault,
                    request_id,
                    &cur_data,
                    &$data_type_enum.to_string(),
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

                update_specific_backup_vault!(
                    *private_storage,
                    backup_vault,
                    PrivDataType::FheKeyInfo,
                    ThresholdFheKeys
                );
                update_specific_backup_vault!(
                    *private_storage,
                    backup_vault,
                    PrivDataType::SigningKey,
                    PrivateSigKey
                );
                update_specific_backup_vault!(
                    *private_storage,
                    backup_vault,
                    PrivDataType::CrsInfo,
                    SignedPubDataHandleInternal
                );
                Ok(())
            }
            None => Ok(()),
        }
    }
}
