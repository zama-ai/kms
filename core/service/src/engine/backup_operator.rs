use crate::backup::custodian::InternalCustodianRecoveryOutput;
use crate::backup::operator::DSEP_BACKUP_RECOVERY;
use crate::engine::utils::query_key_material_availability;
use crate::{
    anyhow_error_and_log,
    backup::operator::{InnerOperatorBackupOutput, Operator, RecoveryValidationMaterial},
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        attestation::{SecurityModule, SecurityModuleProxy},
        encryption::{
            Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
        },
        signatures::{PrivateSigKey, PublicSigKey},
        signcryption::{UnifiedUnsigncryptionKey, Unsigncrypt},
    },
    engine::{
        base::{BaseKmsStruct, CrsGenMetadata, KmsFheKeyHandles},
        context::ContextInfo,
        threshold::service::ThresholdFheKeys,
        traits::BackupOperator,
        validation::{parse_optional_proto_request_id, RequestIdParsingErr},
    },
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
use kms_grpc::kms::v1::{CustodianRecoveryInitRequest, CustodianRecoveryOutput};
use kms_grpc::{
    kms::v1::{CustodianRecoveryRequest, RecoveryRequest},
    rpc_types::PubDataType,
    RequestId,
};
use kms_grpc::{
    kms::v1::{Empty, KeyMaterialAvailabilityResponse, OperatorPublicKey},
    rpc_types::PrivDataType,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
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
    security_module: Option<Arc<SecurityModuleProxy>>,
    // Ephemeral en/decryption keys only set and used during custodian based backup recovery
    ephemeral_keys: Arc<Mutex<Option<(UnifiedPrivateEncKey, UnifiedPublicEncKey)>>>,
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
        security_module: Option<Arc<SecurityModuleProxy>>,
    ) -> Self {
        Self {
            my_role,
            base_kms,
            crypto_storage,
            security_module: security_module.as_ref().map(Arc::clone),
            ephemeral_keys: Arc::new(Mutex::new(None)),
        }
    }

    /// Generate a recovery request to return to the custodians
    /// based on the already stored [`InternalCustodianContext`]
    /// More specifically using the `cts` containing the signcryptions of the operator's share of the private backup decryption key
    async fn gen_outer_recovery_request(
        &self,
        backup_id: RequestId,
        cts: BTreeMap<Role, InnerOperatorBackupOutput>,
    ) -> anyhow::Result<(RecoveryRequest, UnifiedPrivateEncKey, UnifiedPublicEncKey)> {
        let mut rng = self.base_kms.new_rng().await;
        // Generate asymmetric ephemeral keys for the operator to use to encrypt the backup
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (ephem_operator_priv_key, ephem_operator_pub_key) = enc
            .keygen()
            .map_err(|e| anyhow::anyhow!("Failure in ephemeral key generation for backup: {e}"))?;
        let mut grpc_cts = HashMap::new();
        for (cur_cus_role, cur_cus_ct) in cts {
            grpc_cts.insert(cur_cus_role.one_based() as u64, cur_cus_ct.try_into()?);
        }
        let mut serialized_priv_key = Vec::new();
        safe_serialize(
            &ephem_operator_priv_key,
            &mut serialized_priv_key,
            SAFE_SER_SIZE_LIMIT,
        )?;
        let mut serialized_pub_key = Vec::new();
        safe_serialize(
            &ephem_operator_pub_key,
            &mut serialized_pub_key,
            SAFE_SER_SIZE_LIMIT,
        )?;
        let recovery_request = RecoveryRequest {
            ephem_op_enc_key: serialized_pub_key,
            cts: grpc_cts,
            backup_id: Some(backup_id.into()),
            operator_role: self.my_role.one_based() as u64,
        };
        tracing::info!(
            "Generated outer recovery request for backup_id/context_id={}",
            backup_id
        );
        Ok((
            recovery_request,
            ephem_operator_priv_key,
            ephem_operator_pub_key,
        ))
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
                        let public_key = k.operator_public_key_bytes().map_err(|e| {
                            Status::new(
                                tonic::Code::Internal,
                                format!("Could not get operator public key: {e}"),
                            )
                        })?;
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

    /// Restores the most recent custodian based backup.
    async fn custodian_recovery_init(
        &self,
        request: Request<CustodianRecoveryInitRequest>,
    ) -> Result<Response<RecoveryRequest>, Status> {
        // Lock the ephemeral key for the entire duration of the method
        let mut guarded_priv_key = self.ephemeral_keys.lock().await;
        if guarded_priv_key.is_some() {
            match request.into_inner().overwrite_ephemeral_key {
                true => {
                    tracing::warn!("Ephemeral decryption key already exists. OVERWRITING the old ephemeral key, thus invalidating any previous recovery initialization!");
                }
                false => {
                    return Err(Status::new(
                        tonic::Code::AlreadyExists,
                        "Ephemeral decryption key already exists. Use the `overwrite_ephemeral_key` flag to overwrite it, thus invalidating any previous recovery initialization!",
                    ));
                }
            }
        }
        let backup_id = get_latest_backup_id(&self.crypto_storage.backup_vault)
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to get latest backup id: {e}"),
                )
            })?;
        let recovery_material: RecoveryValidationMaterial = {
            let pub_storage = self.crypto_storage.get_public_storage();
            let guarded_pub_storage = pub_storage.lock().await;
            guarded_pub_storage
                .read_data(&backup_id, &PubDataType::RecoveryMaterial.to_string())
                .await
                .map_err(|e| {
                    Status::new(
                        tonic::Code::Internal,
                        format!("Failed to read inner recovery request: {e}"),
                    )
                })?
        };
        let (recovery_request, ephem_op_dec_key, ephem_op_enc_key) = self
            .gen_outer_recovery_request(backup_id, recovery_material.payload.cts)
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to generate recovery request: {e}"),
                )
            })?;
        // We already ensured that no key is previously set, so ignore the result
        let _ = guarded_priv_key.replace((ephem_op_dec_key, ephem_op_enc_key));
        Ok(Response::new(recovery_request))
    }

    /// Recover the backup master decryption key previously secret shared with the custodians.
    /// That is, the method can only be used if custodian based backup is used and the backup recovery has
    /// been initialized on the KMS using `custodian_recovery_init`.
    ///
    /// Observe that the decryption key is NOT persisted on disc and in fact removed immediately after a call to `restore_from_backup`
    /// in order to minimize the possibility of leakage.
    async fn custodian_backup_recovery(
        &self,
        request: Request<CustodianRecoveryRequest>,
    ) -> Result<Response<Empty>, Status> {
        let (ephemeral_dec_key, ephemeral_enc_key) = {
            let guarded_ephemeral_keys = self.ephemeral_keys.lock().await;
            match guarded_ephemeral_keys.clone() {
                Some((ephemeral_dec_key, ephemeral_enc_key)) => {
                    (ephemeral_dec_key, ephemeral_enc_key)
                }
                None => {
                    return Err(Status::new(
                        tonic::Code::FailedPrecondition,
                        "Ephemeral decryption key has not been generated",
                    ));
                }
            }
        };
        let inner = request.into_inner();
        let context_id: RequestId = parse_optional_proto_request_id(
            &inner.custodian_context_id,
            RequestIdParsingErr::BackupRecovery,
        )?;
        let my_verf_key = PublicSigKey::from_sk(&self.base_kms.sig_key);
        let recovery_material = {
            load_recovery_validation_material(
                &self.crypto_storage.get_public_storage(),
                &context_id,
                &my_verf_key,
            )
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to load recovery validation material: {e}"),
                )
            })?
        };
        let parsed_custodian_rec = {
            filter_custodian_data(
                inner.custodian_recovery_outputs,
                &recovery_material,
                self.my_role,
                &my_verf_key,
                &ephemeral_dec_key,
                &ephemeral_enc_key,
            )
            .await
            .map_err(|e| {
                Status::new(
                    tonic::Code::Internal,
                    format!("Failed to prune custodian recovery outputs: {e}"),
                )
            })?
        };
        // Check that we have enough valid recovery outputs
        if parsed_custodian_rec.len()
            < (recovery_material.custodian_context().threshold as usize) + 1
        {
            return Err(Status::new(
                    tonic::Code::InvalidArgument,
                    format!(
                        "Only received {} valid recovery outputs, but threshold is {}. Cannot recover the backup decryption key.",
                        parsed_custodian_rec.len(),
                        recovery_material.custodian_context().threshold
                    ),
                ));
        }
        match self.crypto_storage.backup_vault {
            Some(ref backup_vault) => {
                let mut backup_vault: tokio::sync::MutexGuard<'_, Vault> =
                    backup_vault.lock().await;
                match backup_vault.keychain {
                    Some(KeychainProxy::SecretSharing(ref mut keychain)) => {
                        // Amount of custodians get defined during context creation
                        let amount_custodians = recovery_material.payload.custodian_context.custodian_nodes.len();
                        let operator = Operator::new(
                            self.my_role,
                            recovery_material.custodian_context().custodian_nodes.values().cloned().collect_vec(),
                            self.base_kms.sig_key.as_ref().clone(),
                            recovery_material.custodian_context().threshold as usize,
                            amount_custodians,
                            // Don't validate the timestamp since it is expired at this point in time, and we only cared about the timestamp during custodian context setup
                            false,
                        ).map_err(|e| {
                            Status::new(
                                tonic::Code::Internal,
                                format!("Failed to create operator for secret sharing based decryption: {e}"),
                            )
                        })?;
                        let custodian_outputs: Vec<InternalCustodianRecoveryOutput> = parsed_custodian_rec.values().cloned().collect();
                        let serialized_dec_key = operator.verify_and_recover(&custodian_outputs, &recovery_material, context_id, &ephemeral_dec_key, &ephemeral_enc_key).map_err(|e| {
                            Status::new(
                                tonic::Code::Unauthenticated,
                                format!("Failed to verify the backup decryption request: {e}"),
                            )
                        })?;
                        let backup_dec_key: UnifiedPrivateEncKey = safe_deserialize(std::io::Cursor::new(&serialized_dec_key), SAFE_SER_SIZE_LIMIT).map_err(|e| {
                            Status::new(
                                tonic::Code::Internal,
                                format!("Failed to deserialize backup decryption key: {e}"),
                            )
                        })?;
                        keychain.set_dec_key(Some(backup_dec_key));
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
    async fn restore_from_backup(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<Empty>, Status> {
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

                let mut ephemeral_keys = self.ephemeral_keys.lock().await;
                // Remove any decryption key (if it is there) now that restoration is done.
                *ephemeral_keys = None;
                tracing::info!("Successfully restored private data from backup vault");
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
        let priv_storage = self.crypto_storage.get_private_storage();
        let priv_guard = priv_storage.lock().await;

        // Note: Preprocessing IDs are retrieved and added at the endpoint level
        // from the preprocessor service which has access to the metastore
        let response = query_key_material_availability(
            &*priv_guard,
            self.base_kms.kms_type,
            Vec::new(), // Will be populated by the endpoint from preprocessor
        )
        .await?;

        Ok(Response::new(response))
    }
}
/// Load and validate the recovery validation material associated with the provided context ID
async fn load_recovery_validation_material<S>(
    public_storage: &Mutex<S>,
    context_id: &RequestId,
    verf_key: &PublicSigKey,
) -> anyhow::Result<RecoveryValidationMaterial>
where
    S: StorageReader + Send,
{
    let public_storage_guard = public_storage.lock().await;
    let recovery_material: RecoveryValidationMaterial = public_storage_guard
        .read_data(context_id, &PubDataType::RecoveryMaterial.to_string())
        .await?;
    if &recovery_material.custodian_context().context_id != context_id {
        anyhow::bail!("The custodian context associated with the provided context ID is invalid",);
    }
    if !recovery_material.validate(verf_key) {
        anyhow::bail!("Could not verify the signature on the recovery material",);
    }
    Ok(recovery_material)
}

/// Filter and validate the custodian recovery outputs, returning a map from custodian role to recovery output
/// Each output is verified to be correctly signed by the custodian and to be intended for the current operator role.
async fn filter_custodian_data(
    custodian_recovery_outputs: Vec<CustodianRecoveryOutput>,
    recovery_material: &RecoveryValidationMaterial,
    my_role: Role,
    my_verf_key: &PublicSigKey,
    ephemeral_dec_key: &UnifiedPrivateEncKey,
    ephemeral_enc_key: &UnifiedPublicEncKey,
) -> anyhow::Result<HashMap<Role, InternalCustodianRecoveryOutput>> {
    let mut parsed_custodian_rec: HashMap<Role, InternalCustodianRecoveryOutput> = HashMap::new();
    for cur_recovery_output in &custodian_recovery_outputs {
        let cur_op_role = Role::indexed_from_one(cur_recovery_output.operator_role as usize);
        if cur_op_role != my_role {
            tracing::warn!(
                    "Received recovery output for operator role {}, but current server's role is {}. The output will be ignored.",
                    cur_recovery_output.operator_role,
                    my_role.one_based()
                );
            continue;
        }
        if cur_recovery_output.custodian_role == 0
            || cur_recovery_output.custodian_role > custodian_recovery_outputs.len() as u64
        {
            tracing::warn!(
                    "Received recovery output with invalid custodian role {}. The output will be ignored.",
                    cur_recovery_output.custodian_role,
                );
            continue;
        }
        let cur_verf = match recovery_material.custodian_context().custodian_nodes.get(
            &Role::indexed_from_one(cur_recovery_output.custodian_role as usize),
        ) {
            Some(custodian_setup_msg) => &custodian_setup_msg.public_verf_key,
            None => {
                tracing::warn!(
                    "Could not find verification key for custodian role {}",
                    cur_recovery_output.custodian_role
                );
                continue;
            }
        };

        let verf_key_id = my_verf_key.verf_key_id();
        let unsign_key = UnifiedUnsigncryptionKey::new(
            ephemeral_dec_key,
            ephemeral_enc_key,
            cur_verf,
            &verf_key_id,
        );
        let cur_signcryption = match &cur_recovery_output.backup_output {
            Some(cur_op_out) => cur_op_out.try_into()?,
            None => {
                tracing::warn!(
                    "Could not find signcryption for custodian role {}",
                    cur_recovery_output.custodian_role
                );
                continue;
            }
        };
        if unsign_key
            .validate_signcryption(&DSEP_BACKUP_RECOVERY, &cur_signcryption)
            .is_err()
        {
            tracing::warn!(
                "Could not validate signcryption for custodian role {}",
                cur_recovery_output.custodian_role
            );
            continue;
        }
        match <InternalCustodianRecoveryOutput as TryFrom<_>>::try_from(
            cur_recovery_output.to_owned(),
        ) {
            Ok(output) => {
                if let Some(old_val) = parsed_custodian_rec.insert(output.custodian_role, output) {
                    tracing::warn!(
                                "Received multiple recovery outputs for custodian role {}. Only the first one will be used.",
                                cur_op_role,
                            );
                    parsed_custodian_rec.insert(cur_op_role, old_val);
                }
            }
            Err(e) => {
                tracing::warn!(
                            "Failed to parse custodian recovery output for operator role {}: {e}. The output will be ignored.",
                            cur_op_role,
                        );
                continue;
            }
        }
    }
    if parsed_custodian_rec.len() < 1 + recovery_material.custodian_context().threshold as usize {
        return Err(anyhow_error_and_log(format!(
                "Only received {} valid recovery outputs, but threshold is {}. Cannot recover the backup decryption key.",
                parsed_custodian_rec.len(),
                recovery_material.custodian_context().threshold)
            ));
    }
    Ok(parsed_custodian_rec)
}

async fn get_latest_backup_id(
    backup_vault: &Option<Arc<Mutex<Vault>>>,
) -> anyhow::Result<RequestId> {
    match backup_vault {
        None => Err(anyhow_error_and_log(
            "Backup vault is not configured".to_string(),
        )),
        Some(backup_vault) => {
            let guarded_vault_storage = backup_vault.lock().await;
            if let Some(KeychainProxy::SecretSharing(ssk)) = guarded_vault_storage.keychain.as_ref()
            {
                ssk.get_current_backup_id()
            } else {
                anyhow::bail!(
                    "Backup vault is not setup with a keychain for custodian-based backup recovery"
                );
            }
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
    let req_ids = backup_vault
        .all_data_ids(&data_type_enum.to_string())
        .await?;
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
            .read_data(request_id, &data_type_enum.to_string())
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
                restore_data_type::<PrivS, KmsFheKeyHandles>(priv_storage, backup_vault, cur_type)
                    .await?;
            }
            PrivDataType::PrssSetup => {
                tracing::info!("PRSS setup data is not backed up currently. Skipping for now.");
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
    for request_id in req_ids.iter() {
        if !backup_vault
            .data_exists(request_id, &data_type_enum.to_string())
            .await?
        {
            let cur_data: T = priv_storage
                .read_data(request_id, &data_type_enum.to_string())
                .await?;
            store_versioned_at_request_id(
                backup_vault,
                request_id,
                &cur_data,
                &data_type_enum.to_string(),
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
                if !keychain_initialized(&backup_vault).await {
                    tracing::warn!("Secret sharing keychain in the backup vault has not been initialized yet. Skipping backup update.");
                    return Ok(());
                }
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
                            update_specific_backup_vault::<PrivS, KmsFheKeyHandles>(
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

async fn keychain_initialized(backup_vault_guard: &tokio::sync::MutexGuard<'_, Vault>) -> bool {
    if let Some(KeychainProxy::SecretSharing(ssk)) = &backup_vault_guard.keychain {
        // If the backup key is not there, then it is not initialized
        if ssk.get_backup_enc_key().is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::custodian::{CustodianSetupMessagePayload, InternalCustodianContext, HEADER},
        cryptography::{
            signatures::{gen_sig_keys, SigningSchemeType},
            signcryption::UnifiedSigncryption,
        },
        engine::base::derive_request_id,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{CustodianContext, CustodianSetupMessage, OperatorBackupOutput};
    use rand::SeedableRng;
    use std::{
        collections::BTreeMap,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn dummy_recovery_material(
        threshold: u32,
    ) -> (
        RecoveryValidationMaterial,
        PublicSigKey,
        UnifiedPrivateEncKey,
        UnifiedPublicEncKey,
    ) {
        let mut rng = AesRng::seed_from_u64(0);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (dec_key, enc_key) = enc.keygen().unwrap();
        let backup_id = derive_request_id("test").unwrap();
        let mut commitments = BTreeMap::new();
        commitments.insert(Role::indexed_from_one(1), vec![1_u8; 32]);
        commitments.insert(Role::indexed_from_one(2), vec![2_u8; 32]);
        commitments.insert(Role::indexed_from_one(3), vec![3_u8; 32]);
        // Dummy payload; but needs to be a properly serialized payload
        let payload = CustodianSetupMessagePayload {
            header: HEADER.to_string(),
            random_value: [4_u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            public_enc_key: enc_key.clone(),
            verification_key: verf_key.clone(),
        };
        let mut payload_serial = Vec::new();
        safe_serialize(&payload, &mut payload_serial, SAFE_SER_SIZE_LIMIT).unwrap();
        let setup_msg1 = CustodianSetupMessage {
            custodian_role: 1,
            name: "Custodian-1".to_string(),
            payload: payload_serial.clone(),
        };
        let setup_msg2 = CustodianSetupMessage {
            custodian_role: 2,
            name: "Custodian-2".to_string(),
            payload: payload_serial.clone(),
        };
        let setup_msg3 = CustodianSetupMessage {
            custodian_role: 3,
            name: "Custodian-3".to_string(),
            payload: payload_serial.clone(),
        };
        let custodian_context = CustodianContext {
            custodian_nodes: vec![setup_msg1, setup_msg2, setup_msg3],
            context_id: Some(backup_id.into()),
            threshold,
        };
        let internal_custodian_context =
            InternalCustodianContext::new(custodian_context, enc_key.clone()).unwrap();
        let mut cts = BTreeMap::new();
        let cts_out = InnerOperatorBackupOutput {
            signcryption: UnifiedSigncryption {
                payload: vec![1, 2, 3],
                pke_type: PkeSchemeType::MlKem512,
                signing_type: SigningSchemeType::Ecdsa256k1,
            },
        };
        cts.insert(Role::indexed_from_one(1), cts_out.clone());
        cts.insert(Role::indexed_from_one(2), cts_out.clone());
        cts.insert(Role::indexed_from_one(3), cts_out.clone());
        let rec_material =
            RecoveryValidationMaterial::new(cts, commitments, internal_custodian_context, &sig_key)
                .unwrap();
        (rec_material, verf_key, dec_key, enc_key)
    }

    fn dummy_output_for_role(custodian_role: u64, operator_role: u64) -> CustodianRecoveryOutput {
        CustodianRecoveryOutput {
            custodian_role,
            operator_role,
            backup_output: Some(OperatorBackupOutput {
                signcryption: vec![1, 2, 3],
                pke_type: 0,
                signing_type: 0,
            }),
        }
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_filter_custodian_missing_cus_output() {
        let (recovery_material, verf_key, dec_key, enc_key) = dummy_recovery_material(1);
        let my_role = Role::indexed_from_one(1);
        let mut outputs = vec![dummy_output_for_role(1, 1)];
        let cus_2 = CustodianRecoveryOutput {
            custodian_role: 2,
            operator_role: 1,
            backup_output: None, // Missing backup output for custodian role 2
        };
        outputs.push(cus_2);
        let result = filter_custodian_data(
            outputs,
            &recovery_material,
            my_role,
            &verf_key,
            &dec_key,
            &enc_key,
        )
        .await;
        assert!(logs_contain(
            "Could not find signcryption for custodian role"
        ));
        assert!(result.is_err());
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_filter_custodian_data_invalid_operator_role() {
        let (recovery_material, verf_key, dec_key, enc_key) = dummy_recovery_material(1);
        let my_role = Role::indexed_from_one(1);
        let outputs = vec![
            dummy_output_for_role(1, 2), // operator_role does not match my_role
        ];
        let result = filter_custodian_data(
            outputs,
            &recovery_material,
            my_role,
            &verf_key,
            &dec_key,
            &enc_key,
        )
        .await;
        assert!(result.is_err());
        assert!(logs_contain("Received recovery output for operator role"));
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_filter_custodian_data_invalid_custodian_role() {
        let (recovery_material, verf_key, dec_key, enc_key) = dummy_recovery_material(1);
        let my_role = Role::indexed_from_one(1);
        let outputs = vec![
            dummy_output_for_role(0, 1),  // custodian_role == 0
            dummy_output_for_role(99, 1), // custodian_role out of bounds
        ];
        let result = filter_custodian_data(
            outputs,
            &recovery_material,
            my_role,
            &verf_key,
            &dec_key,
            &enc_key,
        )
        .await;
        assert!(result.is_err());
        assert!(logs_contain(
            "Received recovery output with invalid custodian role"
        ));
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_filter_custodian_data_invalid_signature() {
        // Note there is no node information in the dummy material
        let (recovery_material, verf_key, dec_key, enc_key) = dummy_recovery_material(1);
        let my_role = Role::indexed_from_one(1);
        let outputs = vec![
            dummy_output_for_role(1, 1),
            dummy_output_for_role(2, 1),
            dummy_output_for_role(3, 1),
        ];
        let result = filter_custodian_data(
            outputs,
            &recovery_material,
            my_role,
            &verf_key,
            &dec_key,
            &enc_key,
        )
        .await;
        assert!(result.is_err());
        assert!(logs_contain(
            "Could not validate signcryption for custodian"
        ));
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Only received 0 valid recovery outputs")); // Signatures are wrong so no valid outputs
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_filter_custodian_data_missing_verification_key() {
        // Note there is no node information in the dummy material
        let (mut recovery_material, verf_key, dec_key, enc_key) = dummy_recovery_material(1);
        recovery_material
            .payload
            .custodian_context
            .custodian_nodes
            .remove(&Role::indexed_from_one(2));
        let my_role = Role::indexed_from_one(1);
        let outputs = vec![dummy_output_for_role(1, 1), dummy_output_for_role(2, 1)];
        let result = filter_custodian_data(
            outputs,
            &recovery_material,
            my_role,
            &verf_key,
            &dec_key,
            &enc_key,
        )
        .await;
        assert!(result.is_err());
        assert!(logs_contain(
            "Could not find verification key for custodian role"
        ));
    }
}
