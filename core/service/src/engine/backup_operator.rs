use crate::{
    backup::custodian::InternalCustodianContext,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        internal_crypto_types::PrivateSigKey,
    },
    engine::{context::ContextInfo, threshold::service::ThresholdFheKeys, traits::BackupOperator},
    util::key_setup::FhePrivateKey,
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::CryptoMaterialStorage, store_versioned_at_request_id, Storage,
            StorageReader,
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
    pub crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
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
        match self.crypto_storage.backup_vault {
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
        match self.crypto_storage.backup_vault {
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

async fn restore_data_type<
    S1: Storage + Sync + Send + 'static,
    T: serde::de::DeserializeOwned
        + tfhe::Unversionize
        + tfhe::named::Named
        + Send
        + serde::ser::Serialize
        + tfhe::Versionize
        + Sync
        + 'static,
>(
    priv_storage: &mut S1,
    backup_vault: &Vault,
    data_type_enum: PrivDataType,
) -> anyhow::Result<()>
where
    for<'a> <T as tfhe::Versionize>::Versioned<'a>: Send + Sync,
{
    let backup_data_type = BackupDataType::PrivData(data_type_enum).to_string();
    let req_ids = backup_vault.all_data_ids(&backup_data_type).await?;
    for request_id in req_ids.iter() {
        if priv_storage
            .data_exists(request_id, &data_type_enum.to_string())
            .await?
        {
            tracing::warn!(
                "Data for {:?} with request ID {request_id} already exists. I am NOT overwriting it!",
                data_type_enum
            );
            continue;
        }
        let cur_data: T = backup_vault
            .read_data(request_id, &backup_data_type)
            .await?;
        store_versioned_at_request_id(
            priv_storage,
            request_id,
            &cur_data,
            &data_type_enum.to_string(),
        )
        .await?;
    }
    Ok(())
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
                restore_data_type::<PrivS, ThresholdFheKeys>(priv_storage, backup_vault, cur_type)
                    .await?;
            }
            PrivDataType::SigningKey => {
                restore_data_type::<PrivS, PrivateSigKey>(priv_storage, backup_vault, cur_type)
                    .await?;
            }
            PrivDataType::CrsInfo => {
                restore_data_type::<PrivS, SignedPubDataHandleInternal>(
                    priv_storage,
                    backup_vault,
                    cur_type,
                )
                .await?;
            }
            PrivDataType::FhePrivateKey => {
                restore_data_type::<PrivS, FhePrivateKey>(priv_storage, backup_vault, cur_type)
                    .await?;
            }
            PrivDataType::PrssSetup => {
                tracing::info!("PRSS setup data is not backed up currently. Skipping for now.");
            }
            PrivDataType::CustodianInfo => {
                restore_data_type::<PrivS, InternalCustodianContext>(
                    priv_storage,
                    backup_vault,
                    cur_type,
                )
                .await?;
            }
            PrivDataType::ContextInfo => {
                restore_data_type::<PrivS, ContextInfo>(priv_storage, backup_vault, cur_type)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn update_specific_backup_vault<
    S1: Storage + Sync + Send + 'static,
    T: serde::de::DeserializeOwned
        + tfhe::Unversionize
        + tfhe::named::Named
        + Send
        + serde::ser::Serialize
        + tfhe::Versionize
        + Sync
        + 'static,
>(
    priv_storage: &S1,
    backup_vault: &mut Vault,
    data_type_enum: PrivDataType,
) -> anyhow::Result<()>
where
    for<'a> <T as tfhe::Versionize>::Versioned<'a>: Send + Sync,
{
    let req_ids = priv_storage
        .all_data_ids(&data_type_enum.to_string())
        .await?;
    let backup_data_type = BackupDataType::PrivData(data_type_enum).to_string();
    for request_id in req_ids.iter() {
        if !backup_vault
            .data_exists(request_id, &backup_data_type.to_string())
            .await?
        {
            let cur_data: T = priv_storage
                .read_data(request_id, &data_type_enum.to_string())
                .await?;
            store_versioned_at_request_id(
                backup_vault,
                request_id,
                &cur_data,
                &backup_data_type.to_string(),
            )
            .await?;
        }
    }
    Ok(())
}

impl<PubS, PrivS> RealBackupOperator<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    pub async fn update_backup_vault(&self) -> anyhow::Result<()> {
        match self.crypto_storage.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let private_storage = private_storage.lock().await;
                let mut backup_vault: tokio::sync::MutexGuard<'_, Vault> =
                    backup_vault.lock().await;
                for cur_type in PrivDataType::iter() {
                    match cur_type {
                        PrivDataType::SigningKey => {
                            update_specific_backup_vault::<PrivS, PrivateSigKey>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                        PrivDataType::FheKeyInfo => {
                            update_specific_backup_vault::<PrivS, ThresholdFheKeys>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                        PrivDataType::CrsInfo => {
                            update_specific_backup_vault::<PrivS, SignedPubDataHandleInternal>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                        PrivDataType::FhePrivateKey => {
                            update_specific_backup_vault::<PrivS, FhePrivateKey>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                        PrivDataType::PrssSetup => {
                            tracing::info!(
                                "PRSS setup data is not backed up currently. Skipping for now."
                            );
                        }
                        PrivDataType::CustodianInfo => {
                            update_specific_backup_vault::<PrivS, InternalCustodianContext>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                        PrivDataType::ContextInfo => {
                            update_specific_backup_vault::<PrivS, ContextInfo>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                            )
                            .await?;
                        }
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}
