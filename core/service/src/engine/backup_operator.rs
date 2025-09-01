use crate::{
    backup::custodian::InternalCustodianContext,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        internal_crypto_types::PrivateSigKey,
    },
    engine::{
        base::CrsGenMetadata,
        context::ContextInfo,
        threshold::{service::ThresholdFheKeys, traits::BackupOperator},
    },
    util::key_setup::FhePrivateKey,
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::ThresholdCryptoMaterialStorage, store_versioned_at_request_id,
            Storage, StorageReader,
        },
        Vault,
    },
};
use kms_grpc::{kms::v1::BackupRecoveryRequest, rpc_types::BackupDataType};
use kms_grpc::{
    kms::v1::{Empty, KeyMaterialAvailabilityResponse, OperatorPublicKey},
    rpc_types::PrivDataType,
    utils::tonic_result::ok_or_tonic_abort,
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

    /// Recover the backup master decryption key previously secret shared with the custodians.
    /// That is, the method can only be used if custodian based backup is used and the backup recovery has
    /// been initialized on the KMS using `custodian_recovery_init`.
    ///
    /// Observe that the decryption key is NOT persisted on disc and in fact removed immediately after a call to `backup_restore`
    /// in order to minimize the possibility of leakage.
    async fn custodian_backup_recovery(
        &self,
        _request: Request<BackupRecoveryRequest>,
    ) -> Result<Response<Empty>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => {
                let backup_vault: tokio::sync::MutexGuard<'_, Vault> = backup_vault.lock().await;
                match backup_vault.keychain {
                    Some(KeychainProxy::SecretSharing(ref _keychain)) => {
                        // TODO need to call verify_and_recover and store the key temporarely
                        // let private_storage = self.crypto_storage.get_private_storage().clone();
                        // let mut private_storage = private_storage.lock().await;
                        // let custodian_recovery_output =
                        //     request.into_inner().custodian_recovery_output;
                        // ok_or_tonic_abort(
                        //     keychain
                        //         .custodian_backup_recovery(
                        //             &mut private_storage,
                        //             custodian_recovery_output,
                        //         )
                        //         .await,
                        //     "Failed to restore".to_string(),
                        // )?;
                        todo!()
                    }
                    _ => Err(Status::new(
                        tonic::Code::Unavailable,
                        "Backup vault is not setup with a keychain for custodian-based backup recovery",
                    )),
                }
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }

    /// Restores the private data from the backup vault.
    /// More specifically data in the backup vault will be used to fill the private storage.
    /// In case data elements already exists in the private storage a warning will be logged,
    /// and the function will continue to recover any other data elements not already in the private storage.
    /// Thus in case of corruption of the data already in the private store, these elements needs to be
    /// deleted before running the restore.
    ///
    /// Observe that if secret sharing is used for backup (i.e. with a master key being shared with a set of custodians)
    /// then [`custodian_recovery`] _must_ be called first in order to ensure that the master key is restored,
    /// which is needed to allow decryption of the backup data.
    async fn backup_restore(&self, _request: Request<Empty>) -> Result<Response<Empty>, Status> {
        match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let mut private_storage = private_storage.lock().await;
                let backup_vault: tokio::sync::MutexGuard<'_, Vault> = backup_vault.lock().await;
                ok_or_tonic_abort(
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

    async fn get_key_material_availability(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<KeyMaterialAvailabilityResponse>, Status> {
        use crate::engine::utils::query_key_material_availability;

        let priv_storage = self.crypto_storage.get_private_storage();
        let priv_guard = priv_storage.lock().await;

        // Note: Preprocessing IDs are retrieved and added at the endpoint level
        // from the preprocessor service which has access to the metastore
        let response = query_key_material_availability(
            &*priv_guard,
            "Threshold KMS",
            Vec::new(), // Will be populated by the endpoint from preprocessor
        )
        .await?;

        Ok(Response::new(response))
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
                restore_data_type::<PrivS, CrsGenMetadata>(priv_storage, backup_vault, cur_type)
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
        match self.crypto_storage.inner.backup_vault {
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
                            update_specific_backup_vault::<PrivS, CrsGenMetadata>(
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
