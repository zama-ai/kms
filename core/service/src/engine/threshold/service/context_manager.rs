use crate::backup::custodian::{InternalCustodianContext, InternalCustodianSetupMessage};
use crate::backup::operator::{BackupCommitments, Operator, RecoveryRequest};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::backup_pke::{self, BackupCiphertext};
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::{
    engine::{
        base::BaseKmsStruct, threshold::traits::ContextManager, validation::validate_request_id,
    },
    grpc::metastore_status_service::CustodianMetaStore,
    vault::storage::{crypto_material::ThresholdCryptoMaterialStorage, Storage},
};
use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::kms::v1::CustodianContext;
use kms_grpc::rpc_types::{BackupDataType, PrivDataType, SignedPubDataHandleInternal};
use kms_grpc::RequestId;
use kms_grpc::{kms::v1::Empty, utils::tonic_result::tonic_handle_potential_err};
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc};
use strum::IntoEnumIterator;
use tfhe::safe_serialization::safe_serialize;
use tfhe::ClientKey;
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::RwLock;
use tokio_util::task::TaskTracker;
use tonic::Response;

pub struct RealContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: ThresholdCryptoMaterialStorage<PubS, PrivS>,
    pub custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
    pub my_role: Role,
    pub tracker: Arc<TaskTracker>,
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for RealContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn new_kms_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }

    async fn destroy_kms_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }

    async fn new_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let inner = request.into_inner().new_context.ok_or_else(|| {
            tonic::Status::invalid_argument("new_context is required in NewCustodianContextRequest")
        })?;
        tracing::info!(
            "Custodian context addition starting with context_id={:?}, threshold={}, previous_context_id={:?}, from {} custodians",
            inner.context_id,
            inner.threshold,
            inner.previous_context_id,
            inner.custodian_nodes.len()
        );
        tonic_handle_potential_err(
            self.inner_new_custodian_context(inner).await,
            "Could not create new custodian context".to_string(),
        )?;

        //Always answer with Empty
        Ok(Response::new(Empty {}))
    }

    async fn destroy_custodian_context(
        &self,
        _request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        todo!()
    }
}

macro_rules! backup_priv_data {
    ($rng:expr, $guarded_priv_storage:expr, $guarded_backup_vault:expr, $cur_type:expr, $data_type:ty, $pub_enc_key:expr) => {
        let data_ids = $guarded_priv_storage
            .all_data_ids(&$cur_type.to_string())
            .await?;
        for data_id in data_ids {
            let data: $data_type = $guarded_priv_storage
                .read_data(&data_id, &$cur_type.to_string())
                .await?;
            let mut serialized_data = Vec::new();
            safe_serialize(&data, &mut serialized_data, SAFE_SER_SIZE_LIMIT)?;
            let encrypted_data = $pub_enc_key.encrypt($rng, &serialized_data)?;
            let enc_ct = BackupCiphertext {
                ciphertext: encrypted_data,
                priv_data_type: $cur_type,
            };

            // Delete the old backup data
            // Observe that no backups from previous contexts are deleted, only current context.
            $guarded_backup_vault
                .delete_data(&data_id, &$cur_type.to_string())
                .await?;
            $guarded_backup_vault
                .store_data(
                    &enc_ct,
                    &data_id,
                    &BackupDataType::PrivData($cur_type).to_string(),
                )
                .await?;
        }
    };
}

impl<PubS, PrivS> RealContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn inner_new_custodian_context(&self, context: CustodianContext) -> anyhow::Result<()> {
        let context_id: RequestId = match context.context_id {
            Some(id) => id.into(),
            None => {
                return Err(anyhow::anyhow!(
                    "Context ID is required in NewCustodianContextRequest"
                ))
            }
        };
        validate_request_id(&context_id)?;
        let backup_vault = match self.crypto_storage.inner.backup_vault {
            Some(ref backup_vault) => backup_vault,
            None => return Err(anyhow::anyhow!("Backup vault is not configured")),
        };

        // Generate new backup keys and recovery request
        let mut node_map = HashMap::new();
        for setup_message in context.custodian_nodes.iter() {
            let internal_msg: InternalCustodianSetupMessage =
                setup_message.to_owned().try_into()?;
            node_map.insert(
                Role::indexed_from_one(setup_message.custodian_role as usize),
                internal_msg,
            );
        }
        let mut rng = &mut self.base_kms.new_rng().await;
        // Generate asymmetric keys for the operator to use to encrypt the backup
        let (backup_enc_key, backup_priv_key) = backup_pke::keygen(&mut rng)?;
        let custodian_context = InternalCustodianContext {
            context_id,
            threshold: context.threshold,
            previous_context_id: context.previous_context_id.map(Into::into),
            custodian_nodes: node_map,
            backup_enc_key: backup_enc_key.clone(),
        };
        let (recovery_request, commitments) = self
            .gen_recovery_request(
                rng,
                &custodian_context,
                self.my_role,
                context_id,
                backup_enc_key.clone(),
                backup_priv_key,
            )
            .await?;

        // Reencrypt everything
        // Basically we want to ensure the recovery request contains the decryption key and everything else is encrypted using the public encryption key
        let (lock_acquired_time, total_lock_time) = {
            let lock_start = std::time::Instant::now();
            let lock_acquired_time = lock_start.elapsed();
            let guarded_priv_storage = self.crypto_storage.inner.private_storage.lock().await;
            let mut guarded_backup_vault = backup_vault.lock().await;
            for cur_type in PrivDataType::iter() {
                // We need to match on each type to manually specify the data type and to ensure that we do not forget anything in case the enum is extended
                match cur_type {
                    PrivDataType::SigningKey => {
                        backup_priv_data!(
                            &mut rng,
                            guarded_priv_storage,
                            guarded_backup_vault,
                            cur_type,
                            PrivateSigKey,
                            backup_enc_key
                        );
                    }
                    PrivDataType::FheKeyInfo => {
                        backup_priv_data!(
                            &mut rng,
                            guarded_priv_storage,
                            guarded_backup_vault,
                            cur_type,
                            ThresholdFheKeys,
                            backup_enc_key
                        );
                    }
                    PrivDataType::CrsInfo => {
                        backup_priv_data!(
                            &mut rng,
                            guarded_priv_storage,
                            guarded_backup_vault,
                            cur_type,
                            SignedPubDataHandleInternal,
                            backup_enc_key
                        );
                    }
                    PrivDataType::FhePrivateKey => {
                        backup_priv_data!(
                            &mut rng,
                            guarded_priv_storage,
                            guarded_backup_vault,
                            cur_type,
                            ClientKey,
                            backup_enc_key
                        );
                    }
                    PrivDataType::PrssSetup => {
                        // We will not back up PRSS setup data
                        continue;
                    }
                    PrivDataType::CustodianInfo => {
                        // TODO Types for custodians are not finalized yet
                        tracing::warn!(
                            "CustodianInfo type is not backed up, please implement it if needed"
                        );
                        continue;
                    }
                    PrivDataType::ContextInfo => {
                        tracing::warn!("Types for context are not finalized yet, skipping backup");
                        continue;
                    }
                }
            }
            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };
        tracing::info!(
            "New context storage - context_id={}, lock_acquired_in={:?}, total_lock_held={:?}",
            context_id,
            lock_acquired_time,
            total_lock_time
        );

        // Then store the results
        self.crypto_storage
            .write_backup_keys_with_meta_store(
                &context_id,
                backup_enc_key,
                recovery_request,
                custodian_context,
                commitments,
                Arc::clone(&self.custodian_meta_store),
            )
            .await;

        // TODO I am unsure what should be stored in the backup vault and what should be in the public storage.
        // Basically everything can be released publicly and have build in ways of protecting against tampering.
        // Hence for now I store everything in the public storage since the backup vault is now used for export
        // Log after lock is released

        Ok(())
    }

    /// Generate a recovery request to the backup vault.
    async fn gen_recovery_request(
        &self,
        rng: &mut AesRng,
        custodian_context: &InternalCustodianContext,
        my_role: Role,
        backup_id: RequestId,
        pub_enc_key: backup_pke::BackupPublicKey,
        priv_key: backup_pke::BackupPrivateKey,
    ) -> anyhow::Result<(RecoveryRequest, BackupCommitments)> {
        let verification_key = (*self.base_kms.sig_key).clone().into();
        let operator = Operator::new(
            my_role,
            custodian_context
                .custodian_nodes
                .values()
                .cloned()
                .collect_vec(),
            (*self.base_kms.sig_key).clone(),
            verification_key,
            priv_key.clone(),
            pub_enc_key,
            custodian_context.threshold.try_into().unwrap(),
        )?;
        // TODO should commitments be moved into secret_share_and_encrypt? Since this should basically just be used to share the private key
        let mut serialized_priv_key = Vec::new();
        safe_serialize(&priv_key, &mut serialized_priv_key, SAFE_SER_SIZE_LIMIT)?;
        let (ct_map, commitments) = operator
            .secret_share_and_encrypt(rng, &serialized_priv_key, backup_id)
            .unwrap();
        let mut ciphertexts = BTreeMap::new();
        for custodian_index in 1..=custodian_context.custodian_nodes.keys().len() {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct = ct_map.get(&custodian_role).unwrap();
            ciphertexts.insert(custodian_role, ct.to_owned());
        }
        let recovery_request = RecoveryRequest::new(
            operator.public_key().to_owned(),
            &self.base_kms.sig_key,
            ciphertexts,
            backup_id,
            my_role,
        )?;

        tracing::info!(
            "Generated recovery request for backup_id/context_id={}",
            backup_id
        );
        Ok((recovery_request, commitments))
    }
}
