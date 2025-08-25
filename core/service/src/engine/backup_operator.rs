use std::{collections::HashMap, sync::Arc};

use crate::{
    anyhow_error_and_log,
    backup::{
        custodian::InternalCustodianContext,
        operator::{BackupCommitments, InnerRecoveryRequest, Operator, DSEP_BACKUP_CIPHER},
    },
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        backup_pke::{self, BackupPrivateKey},
        internal_crypto_types::{PrivateSigKey, PublicSigKey, Signature},
        signcryption::internal_verify_sig,
    },
    engine::{
        base::BaseKmsStruct, context::ContextInfo, threshold::service::ThresholdFheKeys,
        traits::BackupOperator,
    },
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
use itertools::Itertools;
use kms_grpc::{
    kms::v1::{BackupRecoveryRequest, RecoveryRequest},
    rpc_types::{BackupDataType, PubDataType},
    RequestId,
};
use kms_grpc::{
    kms::v1::{Empty, OperatorPublicKey},
    rpc_types::{PrivDataType, SignedPubDataHandleInternal},
};
use strum::IntoEnumIterator;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::{Mutex, MutexGuard};
use tonic::{Code, Request, Response, Status};

pub struct RealBackupOperator<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    my_role: Role,
    base_kms: BaseKmsStruct,
    crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    security_module: Option<SecurityModuleProxy>,
    // Ephemeral decryption key only set and used during custodian based backup recovery
    ephemeral_dec_key: Arc<Mutex<Option<BackupPrivateKey>>>,
}

impl<PubS, PrivS> RealBackupOperator<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    pub fn new(
        my_role: Role,
        base_kms: BaseKmsStruct,
        crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
        security_module: Option<SecurityModuleProxy>,
    ) -> Self {
        Self {
            my_role,
            base_kms,
            crypto_storage,
            security_module,
            ephemeral_dec_key: Arc::new(Mutex::new(None)),
        }
    }

    /// Generate a recovery request to return to the custodians
    /// based on the already stored [`InternalCustodianContext`]
    async fn gen_outer_recovery_request(
        &self,
        backup_id: RequestId,
        recovery_request: InnerRecoveryRequest,
    ) -> anyhow::Result<(RecoveryRequest, BackupPrivateKey)> {
        let mut rng = self.base_kms.new_rng().await;
        // Generate asymmetric ephemeral keys for the operator to use to encrypt the backup
        let (backup_pub_key, backup_priv_key) = backup_pke::keygen(&mut rng)?;
        let verification_key: PublicSigKey = (*self.base_kms.sig_key).clone().into();
        let mut cts = HashMap::new();
        for (cur_cus_role, cur_cus_ct) in recovery_request.cts {
            let signature = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_cus_ct.signature)?,
            };
            internal_verify_sig(
                &DSEP_BACKUP_CIPHER,
                &cur_cus_ct.ciphertext,
                &signature,
                &verification_key,
            )?;
            cts.insert(cur_cus_role.one_based() as u64, cur_cus_ct.into());
        }
        let mut serialized_priv_key = Vec::new();
        safe_serialize(
            &backup_priv_key,
            &mut serialized_priv_key,
            SAFE_SER_SIZE_LIMIT,
        )?;
        let mut serialized_pub_key = Vec::new();
        safe_serialize(
            &backup_pub_key,
            &mut serialized_pub_key,
            SAFE_SER_SIZE_LIMIT,
        )?;
        let recovery_request = RecoveryRequest {
            enc_key: serialized_pub_key,
            cts,
            backup_id: Some(backup_id.into()),
            operator_role: self.my_role.one_based() as u64,
        };

        tracing::info!(
            "Generated outer recovery request for backup_id/context_id={}",
            backup_id
        );
        Ok((recovery_request, backup_priv_key))
    }
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

    async fn custodian_recovery_init(
        &self,
        _request: Request<Empty>, // todo could be opt to allow restore of old backups
    ) -> Result<Response<RecoveryRequest>, Status> {
        // Lock the ephemeral key for the entire duration of the method
        let mut guarded_priv_key = self.ephemeral_dec_key.lock().await;
        if guarded_priv_key.is_some() {
            return Err(Status::new(
                tonic::Code::FailedPrecondition,
                "Ephemeral decryption key already exists. Cannot initialize recovery again before previous recovery is completed.",
            ));
        }
        let backup_id = get_latest_backup_id(&self.crypto_storage.private_storage)
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to get latest backup id: {e}"),
                )
            })?;
        // let custodian_contexts: InternalCustodianContext = {
        //     let priv_storage = self.crypto_storage.get_private_storage();
        //     let guarded_priv_storage = priv_storage.lock().await;
        //     guarded_priv_storage
        //         .read_data(&backup_id, &PrivDataType::CustodianInfo.to_string())
        //         .await
        //         .map_err(|e| {
        //             Status::new(
        //                 tonic::Code::Internal,
        //                 format!("Failed to read custodian context: {e}"),
        //             )
        //         })?
        // };
        let inner_recovery_request: InnerRecoveryRequest = {
            let pub_storage = self.crypto_storage.get_public_storage();
            let guarded_pub_storage = pub_storage.lock().await;
            guarded_pub_storage
                .read_data(&backup_id, &PubDataType::RecoveryRequest.to_string())
                .await
                .map_err(|e| {
                    Status::new(
                        tonic::Code::Internal,
                        format!("Failed to read inner recovery request: {e}"),
                    )
                })?
        };
        let (recovery_request, backup_priv_key) = self
            .gen_outer_recovery_request(backup_id, inner_recovery_request)
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to generate recovery request: {e}"),
                )
            })?;
        // We already ensured that no key is previously set, so ignore the result
        let _ = guarded_priv_key.replace(backup_priv_key);
        Ok(Response::new(recovery_request))
    }

    /// Recover the backup master decryption key previously secret shared with the custodians.
    /// That is, the method can only be used if custodian based backup is used and the backup recovery has
    /// been initialized on the KMS using `custodian_recovery_init`.
    ///
    /// Observe that the decryption key is NOT persisted on disc and in fact removed immediately after a call to `backup_restore`
    /// in order to minimize the possibility of leakage.
    async fn custodian_backup_recovery(
        &self,
        request: Request<BackupRecoveryRequest>,
    ) -> Result<Response<Empty>, Status> {
        let ephemeral_dec_key = {
            let guarded_dec_key = self.ephemeral_dec_key.lock().await;
            match guarded_dec_key.clone() {
                Some(key) => key,
                None => {
                    return Err(Status::new(
                        tonic::Code::FailedPrecondition,
                        "Ephemeral decryption key has not been generated",
                    ));
                }
            }
        };
        //todo validate request constraints and remove unwraps
        let inner = request.into_inner();
        let context_id = inner.custodian_context_id.unwrap().try_into().unwrap();
        let commitments: BackupCommitments = {
            let guarded_pub_storage = self.crypto_storage.public_storage.lock().await;
            guarded_pub_storage
                .read_data(&context_id, &PubDataType::Commitments.to_string())
                .await
                .map_err(|e| {
                    Status::new(
                        tonic::Code::Internal,
                        format!("Failed to read backup commitments: {e}"),
                    )
                })?
        };
        let custodian_data: InternalCustodianContext = {
            let guarded_priv_storage = self.crypto_storage.private_storage.lock().await;
            guarded_priv_storage
                .read_data(&context_id, &PrivDataType::CustodianInfo.to_string())
                .await
                .map_err(|e| {
                    Status::new(
                        tonic::Code::Internal,
                        format!("Failed to read custodian info: {e}"),
                    )
                })?
        };
        match self.crypto_storage.backup_vault {
            Some(ref backup_vault) => {
                let mut backup_vault: tokio::sync::MutexGuard<'_, Vault> =
                    backup_vault.lock().await;
                match backup_vault.keychain {
                    Some(KeychainProxy::SecretSharing(ref mut keychain)) => {
                        let operator = Operator::new(
                            self.my_role,
                            custodian_data.custodian_nodes.values().cloned().collect_vec(),
                            self.base_kms.sig_key.as_ref().clone(),
                            custodian_data.threshold as usize,
                        ).unwrap();
                        let parsed_custodian_rec = inner.custodian_recovery_outputs.iter().map(|ct| ct.clone().try_into().unwrap()).collect_vec();
                        let serialized_dec_key = operator.verify_and_recover(&parsed_custodian_rec, &commitments, context_id, &ephemeral_dec_key).unwrap();
                        let backup_dec_key: BackupPrivateKey = safe_deserialize(std::io::Cursor::new(&serialized_dec_key), SAFE_SER_SIZE_LIMIT).unwrap();
                        keychain.set_dec_key(Some(backup_dec_key));
                        // todo unset key after recovery , fix unwraps
                        Ok(Response::new(Empty {}))
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
        match self.crypto_storage.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.crypto_storage.get_private_storage().clone();
                let mut private_storage = private_storage.lock().await;
                let backup_vault: tokio::sync::MutexGuard<'_, Vault> = backup_vault.lock().await;
                restore_data(&backup_vault, &mut private_storage)
                    .await
                    .map_err(|e| {
                        Status::new(
                            tonic::Code::Internal,
                            format!("Failed to restore backup data: {e}"),
                        )
                    })?;
                Ok(Response::new(Empty {}))
            }
            None => Err(Status::new(
                tonic::Code::Unavailable,
                "Backup vault is not configured",
            )),
        }
    }
}

async fn get_latest_backup_id<PrivS>(priv_storage: &Arc<Mutex<PrivS>>) -> anyhow::Result<RequestId>
where
    PrivS: Storage + Sync + Send + 'static,
{
    let guarded_priv_storage = priv_storage.lock().await;
    let all_custodian_ids = guarded_priv_storage
        .all_data_ids(&PrivDataType::CustodianInfo.to_string())
        .await?;
    match all_custodian_ids.iter().sorted().last() {
        Some(latest_context_id) => Ok(*latest_context_id),
        None => Err(anyhow_error_and_log(
            "No custodian setup available in the vault",
        )),
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
    // todo this should be limited to the correct backup id otherwise things will fail
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
