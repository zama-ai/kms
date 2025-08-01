use crate::backup::custodian::{InternalCustodianContext, InternalCustodianSetupMessage};
use crate::backup::operator::{BackupCommitments, Operator, RecoveryRequest};
use crate::cryptography::backup_pke;
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
use kms_grpc::rpc_types::{BackupDataType, PrivDataType};
use kms_grpc::RequestId;
use kms_grpc::{kms::v1::Empty, utils::tonic_result::tonic_handle_potential_err};
use std::collections::BTreeMap;
use std::{collections::HashMap, sync::Arc};
use strum::IntoEnumIterator;
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
        let mut backup_vault = match self.crypto_storage.inner.backup_vault {
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
        let custodian_context = InternalCustodianContext {
            context_id,
            threshold: context.threshold,
            previous_context_id: context.previous_context_id.map(Into::into),
            custodian_nodes: node_map,
        };
        let mut rng = &mut self.base_kms.new_rng().await;
        // Generate asymmetric keys for the operator to use to encrypt the backup
        let (pub_enc_key, priv_key) = backup_pke::keygen(&mut rng)?;
        let (recovery_request, commitments) = self
            .gen_backup_keys(
                rng,
                &custodian_context,
                self.my_role,
                context_id,
                pub_enc_key.clone(),
                priv_key,
            )
            .await?;

        // Reencrypt everything
        // Basically we want to ensure the recovery request contains the decryption key and everything else is encrypted using the public encryption key
        {
            let mut guarded_priv_storage = self.crypto_storage.inner.private_storage.lock().await;
            let mut guarded_backup_vault = backup_vault.lock().await;
            for cur_type in PrivDataType::iter() {
                let data_ids = guarded_priv_storage
                    .all_data_ids(&cur_type.to_string())
                    .await?;
                for data_id in data_ids {
                    // TODO make macro to avoid code duplication and go through all types
                    let data: ThresholdFheKeys = guarded_priv_storage
                        .read_data(&data_id, &cur_type.to_string())
                        .await?;
                    // Observe that the vault automatically encrypts or secret shares the data as long as a keychain is configured
                    guarded_backup_vault
                        .store_data(&data, &data_id, &BackupDataType::Ciphertext.to_string())
                        .await;
                }
            }
        }
        // Then store the results

        // let mut guarded_priv_storage = self.crypto_storage.inner.private_storage.lock().await;
        // // let mut guarded_backup_storage = backup_vault.lock().await;
        // let mut guarded_pub_storage = self.crypto_storage.inner.public_storage.lock().await;

        // TODO I am unsure what should be stored in the backup vault and what should be in the public storage.
        // Basically everything can be released publicly and have build in ways of protecting against tampering.
        // Hence for now I store everything in the public storage since the backup vault is now used for export

        // Store public backup encryption key in the private storage
        // as it is crucial that it cannot be maliciously replaced and
        // no-one besides the operator needs to be able to read it.
        // let priv_storage_future = async move {
        //     let store_result = store_versioned_at_request_id(
        //         &mut (*guarded_priv_storage),
        //         &context_id,
        //         &pub_enc_key,
        //         &PrivDataType::PubBackupKey.to_string(),
        //     )
        //     .await;
        //     if let Err(e) = &store_result {
        //         tracing::error!(
        //             "Failed to store public backup encryption key to private storage for request {}: {}",
        //             context_id,
        //             e
        //         );
        //     }
        //     store_result.is_ok()
        // };

        // let pub_storage_future = async move {
        //     let recovery_store_result = store_versioned_at_request_id(
        //         &mut (*guarded_pub_storage),
        //         &context_id,
        //         &recovery_request,
        //         &PubDataType::RecoveryRequest.to_string(),
        //     )
        //     .await;
        //     if let Err(e) = &recovery_store_result {
        //         tracing::error!(
        //             "Failed to store recovery request to the public storage for request {}: {}",
        //             context_id,
        //             e
        //         );
        //     }
        //     let commit_store_result = store_versioned_at_request_id(
        //         &mut (*guarded_pub_storage),
        //         &context_id,
        //         &commitments,
        //         &PubDataType::Commitments.to_string(),
        //     )
        //     .await;
        //     if let Err(e) = &recovery_store_result {
        //         tracing::error!(
        //             "Failed to store commitments to the public storage for request {}: {}",
        //             context_id,
        //             e
        //         );
        //     }
        //     recovery_store_result.is_ok() && commit_store_result.is_ok()
        // };

        // TODO reencrypt everything if context new

        // todo should be done externally
        // Below we write to the meta-store.
        // After writing, the the meta-store on this [req_id] will be in the "Started" state
        // So we need to update it everytime something bad happens,
        // or put all the code that may error before the first write to the meta-store,
        // otherwise it'll be in the "Started" state forever.
        // Optimize lock hold time by minimizing operations under lock
        let (lock_acquired_time, total_lock_time) = {
            let lock_start = std::time::Instant::now();
            // let mut custodian_meta_store = self.custodian_meta_store.write().await;
            let lock_acquired_time = lock_start.elapsed();
            // tonic_handle_potential_err(
            //     custodian_meta_store.insert(&context_id),
            //     format!("Could not insert new custodian context {context_id} into meta store"),
            // )?;

            // // We don't need to check the result of this write, since insert above fails if an element already exists
            // custodian_meta_store.update(&context_id, Ok(custodian_context))?;

            // if custodian_meta_store.get_current_count() > 0 {
            //     // First time we make a context
            // } else {
            //     // A context already exists
            // }

            let total_lock_time = lock_start.elapsed();
            (lock_acquired_time, total_lock_time)
        };
        // Log after lock is released
        tracing::info!(
            "MetaStore INITIAL insert for custodian context - context_id={}, lock_acquired_in={:?}, total_lock_held={:?}",
            context_id, lock_acquired_time, total_lock_time
        );
        Ok(())
    }

    /// Generate a recovery request to the backup vault.
    async fn gen_backup_keys(
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
            Arc::clone(&self.base_kms.sig_key),
            verification_key,
            priv_key.clone(),
            pub_enc_key,
            custodian_context.threshold.try_into().unwrap(),
        )?;
        // TODO should commitments be moved into secret_share_and_encrypt?
        let ct_map = operator
            .secret_share_and_encrypt(rng, &bc2wrap::serialize(&priv_key)?, backup_id)
            .unwrap();
        let mut commitments = Vec::new();
        let mut ciphertexts = BTreeMap::new();
        for custodian_index in 1..=custodian_context.custodian_nodes.keys().len() {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct = ct_map.get(&custodian_role).unwrap();
            commitments.push(ct.commitment.clone());
            ciphertexts.insert(custodian_role, ct.to_owned());
        }
        let recovery_request = RecoveryRequest::new(
            operator.public_key().to_owned(),
            operator.verification_key().to_owned(),
            ciphertexts,
            backup_id,
            my_role,
        )?;

        tracing::info!(
            "Generated recovery request for backup_id/context_id={}",
            backup_id
        );
        Ok((
            recovery_request,
            BackupCommitments {
                commitments,
                signature: todo!(),
            },
        ))
    }

    #[allow(dead_code)]
    async fn rewrite_private_data(
        &self,
        _context_id: RequestId,
        _custodian_context: InternalCustodianContext,
    ) -> anyhow::Result<()> {
        // todo update backuped data with new custodian context
        Ok(())
    }
}
