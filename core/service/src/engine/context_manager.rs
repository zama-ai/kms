use crate::anyhow_error_and_log;
use crate::backup::custodian::InternalCustodianContext;
use crate::backup::operator::{Operator, RecoveryValidationMaterial};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey};
use crate::cryptography::signatures::PrivateSigKey;
use crate::engine::base::{CrsGenMetadata, KmsFheKeyHandles};
use crate::engine::context::ContextInfo;
use crate::engine::threshold::service::session::SessionMaker;
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::engine::traits::ContextManager;
use crate::engine::validation::{parse_proto_context_id, RequestIdParsingErr};
use crate::vault::keychain::KeychainProxy;
use crate::vault::storage::crypto_material::CryptoMaterialStorage;
use crate::vault::storage::{
    delete_at_request_id, delete_context_at_id, store_versioned_at_request_id,
};
use crate::vault::Vault;
use crate::{
    engine::base::BaseKmsStruct, grpc::metastore_status_service::CustodianMetaStore,
    vault::storage::Storage,
};
use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::identifiers::ContextId;
use kms_grpc::kms::v1::CustodianContext;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::{kms::v1::Empty, utils::tonic_result::ok_or_tonic_abort};
use std::sync::Arc;
use strum::IntoEnumIterator;
use tfhe::safe_serialization::safe_serialize;
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::RwLock;
use tonic::{Response, Status};

/// This is a shared data structure for both centralized and threshold context managers.
struct SharedContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
    my_role: Role,
}

impl<PubS, PrivS> SharedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn verify_and_extract_new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<(Role, ContextInfo), tonic::Status> {
        // first verify that the context is valid
        let kms_grpc::kms::v1::NewMpcContextRequest { new_context } = request.into_inner();

        let new_context =
            new_context.ok_or_else(|| Status::invalid_argument("new_context is required"))?;
        let new_context = ContextInfo::try_from(new_context)
            .map_err(|e| Status::invalid_argument(format!("Invalid context info: {e}")))?;

        // verify new context
        let my_role = {
            let storage_ref = self.crypto_storage.private_storage.clone();
            let guarded_priv_storage = storage_ref.lock().await;
            new_context
                .verify(&(*guarded_priv_storage))
                .await
                .map_err(|e| {
                    Status::invalid_argument(format!("Failed to verify new context: {e}"))
                })?
        };

        Ok((my_role, new_context))
    }

    async fn mpc_context_exists(&self, context_id: &ContextId) -> anyhow::Result<bool> {
        let contexts = self
            .crypto_storage
            .read_all_context_info()
            .await
            .inspect_err(|e| tracing::error!("Failed to load all contexts from storage: {}", e))?;
        for context in contexts {
            if context.context_id() == context_id {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn parse_mpc_context_for_destruction(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyMpcContextRequest>,
    ) -> Result<ContextId, tonic::Status> {
        let proto_context_id = request
            .into_inner()
            .context_id
            .ok_or_else(|| Status::invalid_argument("context_id is required"))?;
        let context_id =
            parse_proto_context_id(&proto_context_id, RequestIdParsingErr::CustodianContext)?;

        Ok(context_id)
    }

    async fn new_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let inner = request.into_inner().new_context.ok_or_else(|| {
            tonic::Status::invalid_argument("new_context is required in NewCustodianContextRequest")
        })?;
        tracing::info!(
            "Custodian context addition starting with context_id={:?}, threshold={} from {} custodians",
            inner.context_id,
            inner.threshold,
            inner.custodian_nodes.len()
        );
        ok_or_tonic_abort(
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

    /// Observe that in case a custodian is missing or something bad is detected in the data then the function will fail
    async fn inner_new_custodian_context(&self, context: CustodianContext) -> anyhow::Result<()> {
        let backup_vault = match self.crypto_storage.backup_vault {
            Some(ref backup_vault) => backup_vault,
            None => return Err(anyhow::anyhow!("Backup vault is not configured")),
        };

        let mut rng = self.base_kms.new_rng().await;
        // Generate asymmetric keys for the operator to use to encrypt the backup
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (backup_dec_key, backup_enc_key) = enc.keygen()?;
        let inner_context: InternalCustodianContext =
            InternalCustodianContext::new(context, backup_enc_key.clone())?;
        let recovery_validation = gen_recovery_validation(
            &mut rng,
            self.base_kms.sig_key()?.as_ref(),
            backup_dec_key,
            &inner_context,
            self.my_role,
        )
        .await?;

        // Reencrypt everything
        // Basically we want to ensure the recovery request contains the decryption key and everything else is encrypted using the public encryption key
        let (lock_acquired_time, total_lock_time) = {
            let lock_start = std::time::Instant::now();
            let lock_acquired_time = lock_start.elapsed();
            let guarded_priv_storage = self.crypto_storage.private_storage.lock().await;
            let mut guarded_backup_vault = backup_vault.lock().await;
            // First update the backup vault's context ID
            if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) =
                guarded_backup_vault.keychain.as_mut()
            {
                secret_share_keychain
                    .set_backup_enc_key(inner_context.context_id, backup_enc_key.clone());
            } else {
                return Err(anyhow_error_and_log("A secret sharing keychain is not configured! It is not possible to use custodian contexts"));
            }
            for cur_type in PrivDataType::iter() {
                // We need to match on each type to manually specify the data type and to ensure that we do not forget anything in case the enum is extended
                match cur_type {
                    PrivDataType::SigningKey => {
                        backup_priv_data::<PrivS, PrivateSigKey>(
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                        )
                        .await?;
                    }
                    PrivDataType::FheKeyInfo => {
                        backup_priv_data::<PrivS, ThresholdFheKeys>(
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                        )
                        .await?;
                    }
                    PrivDataType::CrsInfo => {
                        backup_priv_data::<PrivS, CrsGenMetadata>(
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                        )
                        .await?;
                    }
                    PrivDataType::FhePrivateKey => {
                        backup_priv_data::<PrivS, KmsFheKeyHandles>(
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
                        )
                        .await?;
                    }
                    #[expect(deprecated)]
                    PrivDataType::PrssSetup => {
                        // We will not back up PRSS setup data
                        continue;
                    }
                    PrivDataType::PrssSetupCombined => {
                        // We will not back up Combined PRSS setup data
                        continue;
                    }
                    PrivDataType::ContextInfo => {
                        backup_priv_data::<PrivS, ContextInfo>(
                            &guarded_priv_storage,
                            &mut guarded_backup_vault,
                            cur_type,
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
            inner_context.context_id,
            lock_acquired_time,
            total_lock_time
        );
        // Then store the results
        self.crypto_storage
            .write_backup_keys_with_meta_store(
                &recovery_validation,
                Arc::clone(&self.custodian_meta_store),
            )
            .await;
        tracing::info!(
            "New custodian context created with context_id={}, threshold={} from {} custodians",
            inner_context.context_id,
            inner_context.threshold,
            inner_context.custodian_nodes.len()
        );
        Ok(())
    }
}

pub struct CentralizedContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    inner: SharedContextManager<PubS, PrivS>,
}

impl<PubS, PrivS> CentralizedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    pub(crate) fn new(
        base_kms: BaseKmsStruct,
        crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
        custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
        my_role: Role,
    ) -> Self {
        Self {
            inner: SharedContextManager {
                base_kms,
                crypto_storage,
                custodian_meta_store,
                my_role,
            },
        }
    }
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for CentralizedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let (_my_role, new_context) = self
            .inner
            .verify_and_extract_new_mpc_context(request)
            .await?;

        // store the new context
        let res = self
            .inner
            .crypto_storage
            .write_context_info(new_context.context_id(), &new_context)
            .await;

        // TODO(zama-ai/kms-internal/issues/2814)
        // in addition to storing the context in storage
        // we need to make sure it's also loaded in memory so that the centralized KMS
        // can check whether context changes are valid

        ok_or_tonic_abort(
            res,
            format!(
                "Failed to write new KMS context for ID {}",
                new_context.context_id()
            ),
        )?;

        Ok(Response::new(Empty {}))
    }

    async fn destroy_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyMpcContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let context_id = self
            .inner
            .parse_mpc_context_for_destruction(request)
            .await?;

        let storage_ref = self.inner.crypto_storage.private_storage.clone();
        let mut guarded_priv_storage = storage_ref.lock().await;

        delete_context_at_id(&mut *guarded_priv_storage, &context_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete context: {e}")))?;

        // TODO(zama-ai/kms-internal/issues/2814)
        // in addition to deleting the context from storage
        // we need to make sure it's also deleted from memory so that the centralized KMS
        // can check whether context changes are valid

        Ok(Response::new(Empty {}))
    }

    async fn new_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        self.inner.new_custodian_context(request).await
    }

    async fn destroy_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        self.inner.destroy_custodian_context(request).await
    }

    async fn mpc_context_exists(&self, context_id: &ContextId) -> Result<bool, Status> {
        Ok(ok_or_tonic_abort(
            self.inner.mpc_context_exists(context_id).await,
            "Failed to check if context exists".to_string(),
        )?)
    }
}

pub struct ThresholdContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
> {
    inner: SharedContextManager<PubS, PrivS>,
    session_maker: SessionMaker,
}

impl<PubS, PrivS> ThresholdContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    pub(crate) fn new(
        base_kms: BaseKmsStruct,
        crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
        custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
        my_role: Role,
        session_maker: SessionMaker,
    ) -> Self {
        Self {
            inner: SharedContextManager {
                base_kms,
                crypto_storage,
                custodian_meta_store,
                my_role,
            },
            session_maker,
        }
    }

    pub(crate) async fn load_mpc_context_from_storage(&self) -> anyhow::Result<()> {
        let contexts = self
            .inner
            .crypto_storage
            .read_all_context_info()
            .await
            .inspect_err(|e| tracing::error!("Failed to load all contexts from storage: {}", e))?;
        let my_role = self.inner.my_role;
        for context in contexts {
            self.session_maker
                .add_context_info(my_role, &context)
                .await
                .inspect_err(|e| {
                    tracing::error!(
                        "Failed to add context {} into session maker: {}",
                        context.context_id(),
                        e
                    )
                })?;
        }
        Ok(())
    }
}

/// Atomically update both the storage and the session maker with the new context info.
/// If any of the two operations fail, rollback to the original state.
///
/// This function should only be used in the threshold setting since SessionMaker does not exist in centralized mode.
async fn atomic_update_context<
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
>(
    session_maker: &SessionMaker,
    crypto_storage: &CryptoMaterialStorage<PubS, PrivS>,
    my_role: Role,
    new_context: &ContextInfo,
) -> anyhow::Result<()> {
    let context_id = new_context.context_id();
    let res1 = crypto_storage
        .write_context_info(new_context.context_id(), new_context)
        .await;

    let res2 = session_maker.add_context_info(my_role, new_context).await;

    match (res1, res2) {
        (Ok(_), Ok(_)) => (),
        _ => {
            // Rollback if any operation failed
            // first delete the context from storage
            let storage_ref = crypto_storage.private_storage.clone();
            let mut guarded_priv_storage = storage_ref.lock().await;
            _ = delete_context_at_id(&mut *guarded_priv_storage, context_id).await;

            // next delete the context from session maker
            session_maker.remove_context(context_id).await;
            return Err(anyhow::anyhow!("Failed to atomically update context"));
        }
    }

    Ok(())
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for ThresholdContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: Storage + Sync + Send + 'static,
{
    async fn new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let (my_role, new_context) = self
            .inner
            .verify_and_extract_new_mpc_context(request)
            .await?;

        let res = atomic_update_context(
            &self.session_maker,
            &self.inner.crypto_storage,
            my_role,
            &new_context,
        )
        .await;
        ok_or_tonic_abort(
            res,
            format!(
                "Failed to write new KMS context for ID {}",
                new_context.context_id()
            ),
        )?;

        Ok(Response::new(Empty {}))
    }

    async fn destroy_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyMpcContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let context_id = self
            .inner
            .parse_mpc_context_for_destruction(request)
            .await?;

        let storage_ref = self.inner.crypto_storage.private_storage.clone();
        let mut guarded_priv_storage = storage_ref.lock().await;

        self.session_maker.remove_context(&context_id).await;

        // There is nothing we can do if deletion fails here.
        // Note that it cannot fail if the context does not exist.
        delete_context_at_id(&mut *guarded_priv_storage, &context_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to delete context: {e}")))?;
        Ok(Response::new(Empty {}))
    }

    async fn new_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        self.inner.new_custodian_context(request).await
    }

    async fn destroy_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        self.inner.destroy_custodian_context(request).await
    }

    async fn mpc_context_exists(&self, context_id: &ContextId) -> Result<bool, Status> {
        Ok(ok_or_tonic_abort(
            self.inner.mpc_context_exists(context_id).await,
            "Failed to check if context exists".to_string(),
        )?)
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
    priv_storage: &S1,
    backup_vault: &mut Vault,
    data_type_enum: PrivDataType,
) -> anyhow::Result<()>
where
    for<'a> <T as tfhe::Versionize>::Versioned<'a>: Send + Sync,
{
    let data_ids = priv_storage
        .all_data_ids(&data_type_enum.to_string())
        .await?;
    for data_id in data_ids.iter() {
        let data: T = priv_storage
            .read_data(data_id, &data_type_enum.to_string())
            .await?;
        // Delete the old backup data
        // Observe that no backups from previous contexts are deleted, only backups for current custodian context in case they exist.
        delete_at_request_id(backup_vault, data_id, &data_type_enum.to_string()).await?;
        store_versioned_at_request_id(backup_vault, data_id, &data, &data_type_enum.to_string())
            .await?;
    }
    Ok(())
}

/// Generate a recovery request to the backup vault.
async fn gen_recovery_validation(
    rng: &mut AesRng,
    sig_key: &PrivateSigKey,
    backup_priv_key: UnifiedPrivateEncKey,
    custodian_context: &InternalCustodianContext,
    my_role: Role,
) -> anyhow::Result<RecoveryValidationMaterial> {
    let operator = Operator::new_for_sharing(
        my_role,
        custodian_context
            .custodian_nodes
            .values()
            .cloned()
            .collect_vec(),
        (*sig_key).clone(),
        custodian_context.threshold as usize,
        // the amount of custodians are defined by the initial context
        custodian_context.custodian_nodes.len(),
    )?;
    let mut serialized_priv_key = Vec::new();
    safe_serialize(
        &backup_priv_key,
        &mut serialized_priv_key,
        SAFE_SER_SIZE_LIMIT,
    )?;
    let (ct_map, commitments) = operator.secret_share_and_signcrypt(
        rng,
        &serialized_priv_key,
        custodian_context.context_id,
    )?;
    let validation_material = RecoveryValidationMaterial::new(
        ct_map,
        commitments,
        custodian_context.to_owned(),
        sig_key,
    )?;
    tracing::info!(
        "Generated inner recovery request for backup_id/context_id={}",
        custodian_context.context_id
    );
    Ok(validation_material)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::{
            custodian::Custodian,
            operator::InternalRecoveryRequest,
            seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
        },
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{gen_sig_keys, PublicSigKey},
            signcryption::UnifiedUnsigncryptionKey,
        },
        engine::context::{NodeInfo, SoftwareVersion},
        util::meta_store::MetaStore,
        vault::storage::{
            crypto_material::get_core_signing_key, ram::RamStorage, read_context_at_id,
            store_versioned_at_request_id,
        },
    };
    use kms_grpc::{
        identifiers::ContextId,
        kms::v1::{DestroyMpcContextRequest, NewMpcContextRequest},
        rpc_types::{KMSType, PrivDataType},
        RequestId,
    };
    use rand::{rngs::OsRng, SeedableRng};
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
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sig_key).unwrap();
        let context_id = ContextId::from_bytes([4u8; 32]);
        let new_context = ContextInfo {
            mpc_nodes: vec![NodeInfo {
                mpc_identity: "Node1".to_string(),
                party_id: 1,
                verification_key: Some(verification_key.clone()),
                external_url: "http://localhost:12345".to_string(),
                ca_cert: None,
                public_storage_url: "http://storage".to_string(),
                extra_verification_keys: vec![],
            }],
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values: vec![],
        };

        let request = Request::new(NewMpcContextRequest {
            new_context: Some(new_context.try_into().unwrap()),
        });
        let session_maker =
            SessionMaker::four_party_dummy_session(None, None, base_kms.new_rng().await);
        let context_manager = ThresholdContextManager::new(
            base_kms,
            crypto_storage.clone(),
            Arc::new(RwLock::new(MetaStore::new(100, 10))),
            Role::indexed_from_one(1),
            session_maker,
        );

        let response = context_manager.new_mpc_context(request).await;
        response.unwrap();

        // check that the context is stored
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let stored_context = read_context_at_id(&*guarded_priv_storage, &context_id)
                .await
                .unwrap();

            assert_eq!(*stored_context.context_id(), context_id);
            assert_eq!(stored_context.mpc_nodes.len(), 1);
            assert_eq!(stored_context.mpc_nodes[0].party_id, 1);
            assert_eq!(
                stored_context.mpc_nodes[0].verification_key,
                Some(verification_key)
            );
        }

        // now that it is stored, we try to delete it
        let request = Request::new(DestroyMpcContextRequest {
            context_id: Some(context_id.into()),
        });

        let response = context_manager.destroy_mpc_context(request).await;
        response.unwrap();

        // check that the context is deleted
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let _ = read_context_at_id(&*guarded_priv_storage, &context_id)
                .await
                .unwrap_err();
        }
    }

    #[tokio::test]
    async fn test_kms_context_load_from_storage() {
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let context_id = ContextId::from_bytes([4u8; 32]);
        let new_context = ContextInfo {
            mpc_nodes: vec![NodeInfo {
                mpc_identity: "Node1".to_string(),
                party_id: 1,
                verification_key: Some(verification_key.clone()),
                external_url: "http://localhost:12345".to_string(),
                ca_cert: None,
                public_storage_url: "http://storage".to_string(),
                extra_verification_keys: vec![],
            }],
            context_id,
            software_version: SoftwareVersion {
                major: 0,
                minor: 1,
                patch: 0,
                tag: None,
            },
            threshold: 0,
            pcr_values: vec![],
        };

        let request = Request::new(NewMpcContextRequest {
            new_context: Some(new_context.try_into().unwrap()),
        });

        // create the context manager and store the new context
        {
            let base_kms = BaseKmsStruct::new(KMSType::Threshold, sig_key.clone()).unwrap();
            let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng().await);
            let context_manager = ThresholdContextManager::new(
                base_kms,
                crypto_storage.clone(),
                Arc::new(RwLock::new(MetaStore::new(100, 10))),
                Role::indexed_from_one(1),
                session_maker,
            );

            let response = context_manager.new_mpc_context(request).await;
            response.unwrap();

            assert_eq!(1, context_manager.session_maker.context_count().await);
        }

        // check that the context is stored
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let stored_context = read_context_at_id(&*guarded_priv_storage, &context_id)
                .await
                .unwrap();

            assert_eq!(*stored_context.context_id(), context_id);
            assert_eq!(stored_context.mpc_nodes.len(), 1);
            assert_eq!(stored_context.mpc_nodes[0].party_id, 1);
            assert_eq!(
                stored_context.mpc_nodes[0].verification_key,
                Some(verification_key)
            );
        }

        // recreate another new context manager that's initially empty
        // and then we should have nothing in the session maker.
        {
            let base_kms = BaseKmsStruct::new(KMSType::Threshold, sig_key.clone()).unwrap();
            let session_maker = SessionMaker::empty_dummy_session(base_kms.new_rng().await);
            let context_manager = ThresholdContextManager::new(
                base_kms,
                crypto_storage.clone(),
                Arc::new(RwLock::new(MetaStore::new(100, 10))),
                Role::indexed_from_one(1),
                session_maker,
            );

            // check that there are no contexts
            assert_eq!(0, context_manager.session_maker.context_count().await);

            // load the contexts from disk
            context_manager
                .load_mpc_context_from_storage()
                .await
                .unwrap();
            assert_eq!(1, context_manager.session_maker.context_count().await);
        }
    }

    /// Test to sanity check the overall flow of construction of material needed for backup
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_gen_recovery_request_payloads() {
        let mut rng = AesRng::seed_from_u64(40);
        let backup_id = RequestId::new_random(&mut rng);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (backup_dec_key, backup_enc_key) = enc.keygen().unwrap();
        let mnemonic = seed_phrase_from_rng(&mut rng).expect("Failed to generate seed phrase");
        let custodian1: Custodian =
            custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(1)).unwrap();
        let custodian2: Custodian =
            custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(2)).unwrap();
        let custodian3: Custodian =
            custodian_from_seed_phrase(&mnemonic, Role::indexed_from_one(3)).unwrap();
        let setup_msg_1 = custodian1
            .generate_setup_message(&mut rng, "Custodian-1".to_string())
            .unwrap();
        let setup_msg_2 = custodian2
            .generate_setup_message(&mut rng, "Custodian-2".to_string())
            .unwrap();
        let setup_msg_3 = custodian3
            .generate_setup_message(&mut rng, "Custodian-3".to_string())
            .unwrap();
        let context = CustodianContext {
            custodian_nodes: vec![
                setup_msg_1.try_into().unwrap(),
                setup_msg_2.try_into().unwrap(),
                setup_msg_3.try_into().unwrap(),
            ],
            context_id: Some(backup_id.into()),
            threshold: 1,
        };
        let internal_context =
            InternalCustodianContext::new(context, backup_enc_key.clone()).unwrap();
        let recovery_material = gen_recovery_validation(
            &mut rng,
            &server_sig_key,
            backup_dec_key.clone(),
            &internal_context,
            Role::indexed_from_one(1),
        )
        .await
        .unwrap();
        let internal_rec_req = InternalRecoveryRequest::new(
            recovery_material.payload.custodian_context.backup_enc_key,
            recovery_material.payload.cts,
            backup_id,
            Role::indexed_from_one(1),
        )
        .unwrap();
        let custodian_id = custodian1.verification_key().verf_key_id();
        let unsign_key = UnifiedUnsigncryptionKey::new(
            custodian1.public_dec_key(),
            custodian1.public_enc_key(),
            &server_verf_key,
            &custodian_id,
        );
        assert!(internal_rec_req
            .is_valid(Role::indexed_from_one(1), &unsign_key)
            .unwrap());
    }
}
