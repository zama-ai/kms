use crate::backup::custodian::{InternalCustodianContext, InternalCustodianSetupMessage};
use crate::backup::operator::{BackupCommitments, Operator, RecoveryRequest};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::backup_pke::{self, BackupCiphertext};
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::engine::context::ContextInfo;
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::engine::traits::ContextManager;
use crate::vault::storage::crypto_material::CryptoMaterialStorage;
use crate::vault::storage::delete_context_at_request_id;
use crate::vault::Vault;
use crate::{
    engine::{base::BaseKmsStruct, validation::validate_request_id},
    grpc::metastore_status_service::CustodianMetaStore,
    vault::storage::Storage,
};
use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::kms::v1::{CustodianContext, NewKmsContextRequest};
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
use tonic::{Response, Status};

pub struct RealContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    pub base_kms: BaseKmsStruct,
    pub crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    pub custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
    pub my_role: Role,
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for RealContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn new_kms_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        // first verify that the context is valid
        let NewKmsContextRequest {
            active_context,
            new_context,
        } = request.into_inner();

        let new_context =
            new_context.ok_or_else(|| Status::invalid_argument("new_context is required"))?;
        let new_context = ContextInfo::try_from(new_context)
            .map_err(|e| Status::invalid_argument(format!("Invalid context info: {e}")))?;

        // verify new context
        {
            let storage_ref = self.crypto_storage.private_storage.clone();
            let guarded_priv_storage = storage_ref.lock().await;
            // my_id is always 1 in the centralized case
            new_context
                .verify(
                    1,
                    &(*guarded_priv_storage),
                    active_context
                        .and_then(|c| ContextInfo::try_from(c).ok())
                        .as_ref(),
                )
                .await
                .map_err(|e| {
                    Status::invalid_argument(format!("Failed to verify new context: {e}"))
                })?;
        }

        // store the new context
        let res = self
            .crypto_storage
            .write_context_info(new_context.context_id(), &new_context, false)
            .await;

        tonic_handle_potential_err(
            res,
            format!(
                "Failed to write new KMS context for ID {}",
                new_context.context_id()
            ),
        )?;

        Ok(Response::new(Empty {}))
    }

    async fn destroy_kms_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyKmsContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let context_id = request
            .into_inner()
            .context_id
            .ok_or_else(|| Status::invalid_argument("context_id is required"))?;
        let storage_ref = self.crypto_storage.private_storage.clone();
        let mut guarded_priv_storage = storage_ref.lock().await;

        let kms_context_id = context_id.into();
        delete_context_at_request_id(&mut *guarded_priv_storage, &kms_context_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete context: {e}")))?;
        Ok(Response::new(Empty {}))
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

async fn backup_priv_data<
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
    rng: &mut AesRng,
    priv_storage: &S1,
    backup_vault: &mut Vault,
    data_type_enum: PrivDataType,
    pub_enc_key: &backup_pke::BackupPublicKey,
) -> anyhow::Result<()>
where
    for<'a> <T as tfhe::Versionize>::Versioned<'a>: Send + Sync,
{
    let data_ids = priv_storage
        .all_data_ids(&data_type_enum.to_string())
        .await?;
    for data_id in data_ids.iter() {
        let data: T = priv_storage
            .read_data(&data_id, &data_type_enum.to_string())
            .await?;
        let mut serialized_data = Vec::new();
        safe_serialize(&data, &mut serialized_data, SAFE_SER_SIZE_LIMIT)?;
        let encrypted_data = pub_enc_key.encrypt(rng, &serialized_data)?;
        let enc_ct = BackupCiphertext {
            ciphertext: encrypted_data,
            priv_data_type: data_type_enum,
        };
        // Delete the old backup data
        // Observe that no backups from previous contexts are deleted, only backups for current custodian context in case they exist.
        backup_vault
            .delete_data(&data_id, &data_type_enum.to_string())
            .await?;
        backup_vault
            .store_data(
                &enc_ct,
                &data_id,
                &BackupDataType::PrivData(data_type_enum).to_string(),
            )
            .await?;
    }
    Ok(())
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
        let backup_vault = match self.crypto_storage.backup_vault {
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
        let mut rng = self.base_kms.new_rng().await;
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
                &mut rng,
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
            let guarded_priv_storage = self.crypto_storage.private_storage.lock().await;
            let mut guarded_backup_vault = backup_vault.lock().await;
            for cur_type in PrivDataType::iter() {
                // We need to match on each type to manually specify the data type and to ensure that we do not forget anything in case the enum is extended
                match cur_type {
                    PrivDataType::SigningKey => {
                        backup_priv_data::<PrivS, PrivateSigKey>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
                    }
                    PrivDataType::FheKeyInfo => {
                        backup_priv_data::<PrivS, ThresholdFheKeys>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
                    }
                    PrivDataType::CrsInfo => {
                        backup_priv_data::<PrivS, SignedPubDataHandleInternal>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
                    }
                    PrivDataType::FhePrivateKey => {
                        backup_priv_data::<PrivS, ClientKey>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
                    }
                    PrivDataType::PrssSetup => {
                        // We will not back up PRSS setup data
                        continue;
                    }
                    PrivDataType::CustodianInfo => {
                        backup_priv_data::<PrivS, InternalCustodianContext>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
                    }
                    PrivDataType::ContextInfo => {
                        backup_priv_data::<PrivS, ContextInfo>(
                            &mut rng,
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                            &backup_enc_key,
                        )
                        .await?;
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
        tracing::info!(
            "New custodian context created with context_id={}, threshold={} from {} custodians",
            context_id,
            context.threshold,
            context.custodian_nodes.len()
        );
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
            custodian_context.threshold as usize,
        )?;
        let mut serialized_priv_key = Vec::new();
        safe_serialize(&priv_key, &mut serialized_priv_key, SAFE_SER_SIZE_LIMIT)?;
        let (ct_map, commitments) =
            operator.secret_share_and_encrypt(rng, &serialized_priv_key, backup_id)?;
        let mut ciphertexts = BTreeMap::new();
        for custodian_role in custodian_context.custodian_nodes.keys() {
            let ct = ct_map.get(custodian_role).unwrap_or_else(|| {
                panic!("Missing operator backup output for role {custodian_role}")
            });
            ciphertexts.insert(*custodian_role, ct.to_owned());
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cryptography::{
            internal_crypto_types::{gen_sig_keys, PublicSigKey},
            signcryption::ephemeral_encryption_key_generation,
        },
        engine::context::{NodeInfo, SoftwareVersion},
        util::meta_store::MetaStore,
        vault::storage::{
            crypto_material::get_core_signing_key, ram::RamStorage, read_context_at_request_id,
            store_versioned_at_request_id,
        },
    };
    use kms_grpc::{kms::v1::DestroyKmsContextRequest, rpc_types::PrivDataType, RequestId};
    use rand::rngs::OsRng;
    use tokio::sync::Mutex;
    use tonic::Request;

    const DUMMY_SIGNING_KEY_REQ_ID: [u8; 32] = [1u8; 32];

    async fn setup_crypto_storage() -> (
        PublicSigKey,
        PrivateSigKey,
        CryptoMaterialStorage<RamStorage, RamStorage>,
    ) {
        let priv_storage = Arc::new(Mutex::new(RamStorage::new()));
        let pub_storage = Arc::new(Mutex::new(RamStorage::new()));

        let crypto_storage =
            CryptoMaterialStorage::<_, _>::new(priv_storage, pub_storage, None, None);

        // store private signing key
        let (pk, sk) = gen_sig_keys(&mut OsRng);

        let req_id = RequestId::from_bytes(DUMMY_SIGNING_KEY_REQ_ID);
        {
            let mut guarded_priv_storage = crypto_storage.private_storage.lock().await;
            store_versioned_at_request_id(
                &mut *guarded_priv_storage,
                &req_id,
                &sk,
                &PrivDataType::SigningKey.to_string(),
            )
            .await
            .unwrap();

            // check that the signing key exists
            let _ = get_core_signing_key(&*guarded_priv_storage).await.unwrap();
        }

        (pk, sk, crypto_storage)
    }

    #[tokio::test]
    async fn test_kms_context() {
        let (backup_encryption_public_key, _) = ephemeral_encryption_key_generation(&mut OsRng);
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(sig_key).unwrap();
        let req_id = RequestId::from_bytes([4u8; 32]);
        let new_context = ContextInfo {
            kms_nodes: vec![NodeInfo {
                name: "Node1".to_string(),
                party_id: 1,
                verification_key: verification_key.clone(),
                backup_encryption_public_key: backup_encryption_public_key.clone(),
                external_url: "localhost:12345".to_string(),
                tls_cert: vec![],
                public_storage_url: "http://storage".to_string(),
                extra_verification_keys: vec![],
            }],
            context_id: req_id,
            previous_context_id: None,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
        };

        let request = Request::new(NewKmsContextRequest {
            active_context: None,
            new_context: Some(new_context.try_into().unwrap()),
        });
        let context_manager = RealContextManager {
            base_kms,
            crypto_storage: crypto_storage.clone(),
            custodian_meta_store: Arc::new(RwLock::new(MetaStore::new(100, 10))),
            my_role: Role::indexed_from_one(1),
        };

        let response = context_manager.new_kms_context(request).await;
        response.unwrap();

        // check that the context is stored
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let stored_context = read_context_at_request_id(&*guarded_priv_storage, &req_id)
                .await
                .unwrap();

            assert_eq!(*stored_context.context_id(), req_id);
            assert_eq!(stored_context.kms_nodes.len(), 1);
            assert_eq!(stored_context.kms_nodes[0].party_id, 1);
            assert_eq!(
                stored_context.kms_nodes[0].verification_key,
                verification_key
            );
        }

        // now that it is stored, we try to delete it
        let request = Request::new(DestroyKmsContextRequest {
            context_id: Some(req_id.into()),
        });

        let response = context_manager.destroy_kms_context(request).await;
        response.unwrap();

        // check that the context is deleted
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let _ = read_context_at_request_id(&*guarded_priv_storage, &req_id)
                .await
                .unwrap_err();
        }
    }
}
