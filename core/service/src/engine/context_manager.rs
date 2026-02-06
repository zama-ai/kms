use crate::anyhow_error_and_log;
use crate::backup::custodian::InternalCustodianContext;
use crate::backup::operator::{Operator, RecoveryValidationMaterial};
use crate::conf::threshold::{ThresholdPartyConf, TlsConf};
use crate::consts::{DEFAULT_MPC_CONTEXT, SAFE_SER_SIZE_LIMIT};
use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey};
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
use crate::engine::base::{CrsGenMetadata, KmsFheKeyHandles};
use crate::engine::context::{ContextInfo, NodeInfo, SoftwareVersion};
use crate::engine::threshold::service::session::SessionMaker;
use crate::engine::threshold::service::ThresholdFheKeys;
use crate::engine::traits::ContextManager;
use crate::engine::validation::{
    parse_grpc_request_id, parse_optional_grpc_request_id, RequestIdParsingErr,
};
use crate::vault::keychain::KeychainProxy;
use crate::vault::storage::crypto_material::CryptoMaterialStorage;
use crate::vault::storage::{
    delete_at_request_id, delete_context_at_id, delete_custodian_context_at_id,
    store_context_at_id, store_versioned_at_request_id, StorageExt,
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
use std::collections::HashSet;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tfhe::safe_serialization::safe_serialize;
use threshold_fhe::execution::runtime::party::Role;
use tokio::sync::RwLock;
use tonic::{Response, Status};

const CENTRALIZED_MPC_IDENTITY: &str = "centralized-zama-kms";
const CENTRALIZED_PARTY_ID: u32 = 1;
const CENTRALIZED_EXTERNAL_URL: &str = "https://doesnotexist.zama.ai";

/// This is a shared data structure for both centralized and threshold context managers.
struct SharedContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
> {
    base_kms: BaseKmsStruct,
    crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
    custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
}

impl<PubS, PrivS> SharedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
{
    async fn verify_and_extract_new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<(Option<Role>, ContextInfo), tonic::Status> {
        // first verify that the context is valid
        let kms_grpc::kms::v1::NewMpcContextRequest { new_context } = request.into_inner();

        let new_context =
            new_context.ok_or_else(|| Status::invalid_argument("new_context is required"))?;
        let new_context = ContextInfo::try_from(new_context)
            .map_err(|e| Status::invalid_argument(format!("Invalid context info: {e}")))?;
        // verify new context
        let my_role = self.extract_my_role_from_context(&new_context).await?;

        Ok((my_role, new_context))
    }

    async fn extract_my_role_from_context(
        &self,
        context: &ContextInfo,
    ) -> Result<Option<Role>, tonic::Status> {
        let storage_ref = self.crypto_storage.private_storage.clone();
        let guarded_priv_storage = storage_ref.lock().await;
        context
            .verify(&(*guarded_priv_storage))
            .await
            .map_err(|e| Status::invalid_argument(format!("Failed to verify new context: {e}")))
    }

    async fn mpc_context_exists_in_storage(&self, context_id: &ContextId) -> anyhow::Result<bool> {
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
            parse_grpc_request_id(&proto_context_id, RequestIdParsingErr::CustodianContext)?;

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

    /// Removes a custodian context from disk storage and RAM (the meta-store).
    async fn destroy_custodian_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::DestroyCustodianContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let context_id = parse_optional_grpc_request_id(
            &request.into_inner().context_id,
            RequestIdParsingErr::CustodianContextDestruction,
        )?;

        // Note that care must be taken in the order of getting locks here
        // Use meta store as sync point
        let mut cus_meta_store = self.custodian_meta_store.write().await;
        match cus_meta_store.delete(&context_id) {
            Some(cell) => {
                if cell.get().await.as_ref().is_err() {
                    return Err(Status::internal(format!(
                        "Custodian context with id {:?} could not be removed from meta store",
                        context_id
                    )));
                }
            }
            None => {
                // It might already have been automatically removed from the RAM, so we just log this and continue
                tracing::warn!(
                    "Custodian context with id {:?} does not exist in meta store",
                    context_id
                );
            }
        }

        let mut guarded_pub_storage = self.crypto_storage.public_storage.lock().await;
        let guarded_backup_storage_ref =
            self.crypto_storage.backup_vault.as_ref().ok_or_else(|| {
                Status::new(
                    tonic::Code::FailedPrecondition,
                    "Backup vault is not configured",
                )
            })?;
        let mut guarded_backup_storage = guarded_backup_storage_ref.lock().await;

        // There is nothing we can do if deletion fails here.
        // Note that it cannot fail if the context does not exist.
        delete_custodian_context_at_id(
            &mut *guarded_pub_storage,
            &mut guarded_backup_storage,
            &context_id,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to delete context: {e}")))?;
        Ok(Response::new(Empty {}))
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
                if let Ok(cur_backup_id) = secret_share_keychain.get_current_backup_id() {
                    if cur_backup_id == inner_context.context_id {
                        anyhow::bail!("A custodian context with the same context ID already exists in the backup vault!");
                    }
                }
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
                        // TODO needs fixing
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

pub async fn create_default_centralized_context_in_storage<
    PrivS: StorageExt + Sync + Send + 'static,
>(
    priv_storage: &mut PrivS,
    sk: &PrivateSigKey,
) -> anyhow::Result<()> {
    // Create and store the default context for centralized mode testing
    let verification_key = PublicSigKey::from_sk(sk);
    let context_info = ContextInfo {
        mpc_nodes: vec![NodeInfo {
            mpc_identity: CENTRALIZED_MPC_IDENTITY.to_string(), // identity is not used in centralized KMS
            party_id: CENTRALIZED_PARTY_ID,                     // always 1
            verification_key: Some(verification_key),
            external_url: CENTRALIZED_EXTERNAL_URL.to_string(), // no external URL since there are no peers
            ca_cert: None, // there's no peer network, so no certificate is needed
            public_storage_url: "".to_string(),
            public_storage_prefix: None, // None will default to "PUB"
            extra_verification_keys: vec![],
        }],
        context_id: *DEFAULT_MPC_CONTEXT,
        software_version: SoftwareVersion::current(),
        threshold: 0,
        pcr_values: vec![],
    };
    store_context_at_id(priv_storage, &DEFAULT_MPC_CONTEXT, &context_info)
        .await
        .expect("Could not store default context");

    Ok(())
}

/// Create and store the default MPC context for threshold mode from peer configuration.
///
/// This function builds a `ContextInfo` from the peer list in `threshold_config` and stores it
/// in private storage under `DEFAULT_MPC_CONTEXT`. If a context already exists at that ID,
/// it is deleted first to ensure consistency with the latest peer list.
///
/// Returns `Ok(())` if peers are present and context was created, or if no peers are configured.
///
/// # Arguments
/// * `priv_storage` - The private storage to write the context to
/// * `threshold_config` - The threshold party configuration containing peers, threshold, etc.
/// * `verf_key` - The verification key of this party
pub async fn ensure_default_threshold_context_in_storage<
    PrivS: StorageExt + Sync + Send + 'static,
>(
    priv_storage: &mut PrivS,
    threshold_config: &ThresholdPartyConf,
    verf_key: &PublicSigKey,
) -> anyhow::Result<()> {
    let peers = match &threshold_config.peers {
        Some(peers) => peers,
        None => return Ok(()), // No peers configured, nothing to do
    };

    let context_id = *DEFAULT_MPC_CONTEXT;

    // Build NodeInfo for each peer
    let mpc_nodes = peers
        .iter()
        .map(|peer| {
            let (role, identity) = peer.into_role_identity();
            // URL format is only valid with a scheme, so we add it here
            let scheme = match peer.tls_cert {
                Some(_) => "https",
                None => "http",
            };
            match peer
                .tls_cert
                .as_ref()
                .map(|cert| cert.unchecked_cert_string())
                .transpose()
            {
                Ok(pem_string) => {
                    let verification_key = if let Some(my_id) = threshold_config.my_id {
                        if peer.party_id == my_id {
                            Some(PublicSigKey::clone(verf_key))
                        } else {
                            None
                        }
                    } else {
                        // If the MPC parties are started for the first time, they do not know about any context.
                        // Consequently, if we must use a default context, the default context cannot hold the
                        // verification key of other parties since they don't know about it at start up.
                        None
                    };
                    Ok(NodeInfo {
                        mpc_identity: identity.mpc_identity().to_string(),
                        party_id: role.one_based() as u32,
                        verification_key,
                        external_url: format!(
                            "{}://{}:{}",
                            scheme,
                            identity.hostname(),
                            identity.port()
                        ),
                        ca_cert: pem_string.map(|cert_pem| cert_pem.into_bytes()),
                        // We do not know the storage URLs in the default context
                        // since it does not have access to the configuration of other parties.
                        public_storage_url: "".to_string(),
                        public_storage_prefix: None,
                        extra_verification_keys: vec![],
                    })
                }
                Err(e) => Err(e),
            }
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Extract PCR values from TLS config if available
    let pcr_values = threshold_config.tls.as_ref().and_then(|tls| match tls {
        TlsConf::Manual { cert: _, key: _ } => None,
        TlsConf::Auto {
            eif_signing_cert: _,
            trusted_releases,
            ignore_aws_ca_chain: _,
            attest_private_vault_root_key: _,
            renew_slack_after_expiration: _,
            renew_fail_retry_timeout: _,
        } => Some(trusted_releases.clone()),
    });

    let context_info = ContextInfo {
        mpc_nodes,
        context_id,
        software_version: SoftwareVersion::current(),
        threshold: threshold_config.threshold as u32,
        pcr_values: pcr_values.unwrap_or_default(),
    };

    // Delete any existing context at DEFAULT_MPC_CONTEXT to ensure consistency
    // with the latest peer list. This is important because the peer list may have
    // changed since the last time the context was stored.
    delete_context_at_id(priv_storage, &context_id).await?;

    store_context_at_id(priv_storage, &context_id, &context_info).await?;

    Ok(())
}

pub struct CentralizedContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
> {
    inner: SharedContextManager<PubS, PrivS>,
    cache: Arc<RwLock<HashSet<ContextId>>>,
}

impl<PubS, PrivS> CentralizedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
{
    pub(crate) fn new(
        base_kms: BaseKmsStruct,
        crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
        custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
    ) -> Self {
        Self {
            inner: SharedContextManager {
                base_kms,
                crypto_storage,
                custodian_meta_store,
            },
            cache: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Load all MPC contexts from storage into the cache.
    /// This should be called once during initialization to populate the cache.
    pub(crate) async fn load_mpc_context_from_storage(&self) -> anyhow::Result<()> {
        let contexts = self
            .inner
            .crypto_storage
            .read_all_context_info()
            .await
            .inspect_err(|e| tracing::error!("Failed to load all contexts from storage: {}", e))?;

        let mut write_guard = self.cache.write().await;
        for context in contexts {
            let is_new_insert = (*write_guard).insert(*context.context_id());
            if !is_new_insert {
                tracing::warn!(
                    "loaded a centralized context with ID {} that was already present in cache",
                    context.context_id()
                )
            }
        }
        tracing::info!(
            "Loaded {} MPC contexts into centralized context cache",
            write_guard.len()
        );
        Ok(())
    }
}

#[tonic::async_trait]
impl<PubS, PrivS> ContextManager for CentralizedContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
{
    async fn new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let (_my_role, new_context) = self
            .inner
            .verify_and_extract_new_mpc_context(request)
            .await?;
        // Check if the context already exists
        if self
            .inner
            .crypto_storage
            .read_context_info(new_context.context_id())
            .await
            .is_ok()
        {
            return Err(Status::already_exists(format!(
                "Context with ID {} already exists",
                new_context.context_id()
            )));
        }

        // store the new context
        let res = self
            .inner
            .crypto_storage
            .write_context_info(new_context.context_id(), &new_context)
            .await;

        {
            let mut write_guard = self.cache.write().await;
            let is_new_insert = (*write_guard).insert(*new_context.context_id());
            if !is_new_insert {
                tracing::warn!(
                    "inserted a centralized context with ID {} that was already present",
                    new_context.context_id()
                )
            }
        }

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

        {
            let mut write_guard = self.cache.write().await;
            let was_present = (*write_guard).remove(&context_id);
            if !was_present {
                tracing::warn!(
                    "deleted a centralized context with ID {} that was not present",
                    context_id,
                )
            }
        }

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

    async fn mpc_context_exists_and_consistent(
        &self,
        context_id: &ContextId,
    ) -> Result<bool, Status> {
        let exists_in_cache = {
            let guard = self.cache.read().await;
            (*guard).contains(context_id)
        };
        let exists_in_storage = ok_or_tonic_abort(
            self.inner.mpc_context_exists_in_storage(context_id).await,
            "Failed to check if context exists".to_string(),
        )?;
        if exists_in_storage != exists_in_cache {
            Err(Status::internal(format!(
                "inconsistent context state for ID {context_id} while checking existance,
                exists_in_storage={exists_in_storage}, eexsits_in_cache={exists_in_cache}"
            )))
        } else {
            Ok(exists_in_cache && exists_in_storage)
        }
    }

    async fn mpc_context_exists_in_cache(&self, context_id: &ContextId) -> bool {
        let guard = self.cache.read().await;
        (*guard).contains(context_id)
    }
}

pub struct ThresholdContextManager<
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
> {
    inner: SharedContextManager<PubS, PrivS>,
    session_maker: SessionMaker,
}

impl<PubS, PrivS> ThresholdContextManager<PubS, PrivS>
where
    PubS: Storage + Sync + Send + 'static,
    PrivS: StorageExt + Sync + Send + 'static,
{
    pub(crate) fn new(
        base_kms: BaseKmsStruct,
        crypto_storage: CryptoMaterialStorage<PubS, PrivS>,
        custodian_meta_store: Arc<RwLock<CustodianMetaStore>>,
        session_maker: SessionMaker,
    ) -> Self {
        Self {
            inner: SharedContextManager {
                base_kms,
                crypto_storage,
                custodian_meta_store,
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

        for context in contexts {
            let my_role = self.inner.extract_my_role_from_context(&context).await?;
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
    PrivS: StorageExt + Sync + Send + 'static,
>(
    session_maker: &SessionMaker,
    crypto_storage: &CryptoMaterialStorage<PubS, PrivS>,
    my_role: Option<Role>,
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
    PrivS: StorageExt + Sync + Send + 'static,
{
    async fn new_mpc_context(
        &self,
        request: tonic::Request<kms_grpc::kms::v1::NewMpcContextRequest>,
    ) -> Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status> {
        let (my_role, new_context) = self
            .inner
            .verify_and_extract_new_mpc_context(request)
            .await?;

        // First check if the context already exists
        if self
            .inner
            .crypto_storage
            .read_context_info(new_context.context_id())
            .await
            .is_ok()
            || self
                .session_maker
                .context_exists(new_context.context_id())
                .await
        {
            return Err(Status::already_exists(format!(
                "Context with ID {} already exists",
                new_context.context_id()
            )));
        }
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

    async fn mpc_context_exists_and_consistent(
        &self,
        context_id: &ContextId,
    ) -> Result<bool, Status> {
        let exsits_in_session_maker = self.session_maker.context_exists(context_id).await;
        let exists_in_storage = ok_or_tonic_abort(
            self.inner.mpc_context_exists_in_storage(context_id).await,
            "Failed to check if context exists".to_string(),
        )?;
        if exists_in_storage != exsits_in_session_maker {
            Err(Status::internal(format!(
                "inconsistent context state for ID {context_id} while checking existance,
                exists_in_storage={exists_in_storage}, exsits_in_session_maker={exsits_in_session_maker}"
            )))
        } else {
            Ok(exsits_in_session_maker && exists_in_storage)
        }
    }

    async fn mpc_context_exists_in_cache(&self, context_id: &ContextId) -> bool {
        self.session_maker.context_exists(context_id).await
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
) -> anyhow::Result<RecoveryValidationMaterial> {
    let operator = Operator::new_for_sharing(
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::{
        backup::{
            custodian::{Custodian, InternalCustodianSetupMessage, HEADER},
            operator::InternalRecoveryRequest,
            seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
        },
        consts::DEFAULT_EPOCH_ID,
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{gen_sig_keys, PublicSigKey},
            signcryption::UnifiedUnsigncryptionKey,
        },
        engine::context::{NodeInfo, SoftwareVersion},
        util::meta_store::MetaStore,
        vault::{
            keychain::secretsharing,
            storage::{
                crypto_material::get_core_signing_key,
                ram::{self, RamStorage},
                read_context_at_id, read_versioned_at_request_id, store_versioned_at_request_id,
                StorageProxy,
            },
        },
    };
    use kms_grpc::{
        identifiers::ContextId,
        kms::v1::{
            DestroyCustodianContextRequest, DestroyMpcContextRequest, NewCustodianContextRequest,
            NewMpcContextRequest,
        },
        rpc_types::{KMSType, PrivDataType, PubDataType},
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
        let guarded_pub_storage = pub_storage.lock().await;
        let backup_proxy = StorageProxy::from(ram::RamStorage::new());
        let ssk = secretsharing::SecretShareKeychain::new(
            AesRng::seed_from_u64(1244),
            Some(&*guarded_pub_storage),
        )
        .await
        .unwrap();
        let keychain_proxy = KeychainProxy::from(ssk);
        let backup_vault = Arc::new(Mutex::new(Vault {
            storage: backup_proxy,
            keychain: Some(keychain_proxy),
        }));
        drop(guarded_pub_storage);

        let crypto_storage =
            CryptoMaterialStorage::<_, _>::new(priv_storage, pub_storage, Some(backup_vault));

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
                public_storage_prefix: None,
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
            new_context: Some(new_context.clone().try_into().unwrap()),
        });
        let epoch_id = *DEFAULT_EPOCH_ID;
        let session_maker =
            SessionMaker::four_party_dummy_session(None, None, &epoch_id, base_kms.new_rng().await);
        let context_manager = ThresholdContextManager::new(
            base_kms,
            crypto_storage.clone(),
            Arc::new(RwLock::new(MetaStore::new(100, 10))),
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
        // Try to make a context with the same context ID (should fail)
        {
            let request = Request::new(NewMpcContextRequest {
                new_context: Some(new_context.try_into().unwrap()),
            });
            let response = context_manager.new_mpc_context(request).await;
            // Should fail since the same ID is used
            assert!(response.is_err());
        }

        // now we try to delete the stored context
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
                public_storage_prefix: None,
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

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_custodian_context() {
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(KMSType::Threshold, sig_key).unwrap();
        // Generate custodian keys
        let threshold = 1;
        let amount_custodians = 2 * threshold + 1; // Minimum amount of custodians is 2 * threshold + 1
        let mut setup_msgs = Vec::new();
        let mut rng = AesRng::seed_from_u64(42);
        let epoch_id = *DEFAULT_EPOCH_ID;
        for custodian_index in 1..=amount_custodians {
            let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            let (_sk_dec_key, pk_enc_key) = enc.keygen().unwrap();
            let (verf_key, _sig_key) = gen_sig_keys(&mut rng);
            let cur_msg = InternalCustodianSetupMessage {
                header: HEADER.to_string(),
                custodian_role: Role::indexed_from_one(custodian_index),
                name: format!("Custodian-{}", custodian_index),
                random_value: [2u8; 32],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                public_enc_key: pk_enc_key,
                public_verf_key: verf_key,
            };
            setup_msgs.push(cur_msg.try_into().unwrap());
        }

        // Create a new custodian context
        let (context_manager, first_context_id) = {
            let first_context_id = RequestId::from_bytes([4u8; 32]);
            let first_context = CustodianContext {
                custodian_nodes: setup_msgs.clone(),
                context_id: Some(first_context_id.into()),
                threshold: threshold as u32,
            };
            let request = Request::new(NewCustodianContextRequest {
                new_context: Some(first_context),
            });
            let session_maker = SessionMaker::four_party_dummy_session(
                None,
                None,
                &epoch_id,
                base_kms.new_rng().await,
            );
            let context_manager = ThresholdContextManager::new(
                base_kms,
                crypto_storage.clone(),
                Arc::new(RwLock::new(MetaStore::new(100, 10))),
                session_maker,
            );

            let response = context_manager.new_custodian_context(request).await;
            assert!(response.is_ok());
            (context_manager, first_context_id)
        };

        // check that the context is stored
        {
            let pub_storage = Arc::clone(&crypto_storage.public_storage);
            let guarded_pub_storage = pub_storage.lock().await;
            let stored_context: RecoveryValidationMaterial = read_versioned_at_request_id(
                &*guarded_pub_storage,
                &first_context_id,
                &PubDataType::RecoveryMaterial.to_string(),
            )
            .await
            .unwrap();

            assert!(stored_context.validate(&verification_key));
            assert_eq!(
                stored_context.custodian_context().context_id,
                first_context_id
            );
            assert_eq!(
                stored_context.custodian_context().threshold,
                threshold as u32
            );
            assert_eq!(
                stored_context.custodian_context().custodian_nodes.len(),
                amount_custodians
            );
            for cur_cus_id in 0..amount_custodians {
                assert_eq!(
                    stored_context
                        .custodian_context()
                        .custodian_nodes
                        .get(&Role::indexed_from_zero(cur_cus_id))
                        .unwrap(),
                    &setup_msgs
                        .get(cur_cus_id)
                        .unwrap()
                        .clone()
                        .try_into()
                        .unwrap()
                );
            }
        }

        // now that it is stored, we try to delete it
        {
            let request = Request::new(DestroyCustodianContextRequest {
                context_id: Some(first_context_id.into()),
            });

            let response = context_manager.destroy_custodian_context(request).await;
            // This should fail since it is the current active context
            assert!(response.is_err());
        }

        // Make a new context so we can delete the old one
        {
            // First try to do it with the same context ID (should fail)
            let request = Request::new(NewCustodianContextRequest {
                new_context: Some(CustodianContext {
                    custodian_nodes: setup_msgs.clone(),
                    context_id: Some(first_context_id.into()),
                    threshold: threshold as u32,
                }),
            });
            let response = context_manager.new_custodian_context(request).await;
            // Should fail since the same ID is used
            assert!(response.is_err());

            // Now try with a different context ID (should succeed)
            let second_context_id = RequestId::from_bytes([42u8; 32]);
            let second_context = CustodianContext {
                custodian_nodes: setup_msgs.clone(),
                context_id: Some(second_context_id.into()),
                threshold: threshold as u32,
            };
            let request = Request::new(NewCustodianContextRequest {
                new_context: Some(second_context),
            });

            let response = context_manager.new_custodian_context(request).await;
            assert!(response.is_ok());
        }
        // now try again to delete the first context
        {
            let request = Request::new(DestroyCustodianContextRequest {
                context_id: Some(first_context_id.into()),
            });

            let response = context_manager.destroy_custodian_context(request).await;
            assert!(response.is_ok());
        }
        // check that the context is deleted
        {
            let pub_storage = Arc::clone(&crypto_storage.public_storage);
            let guarded_pub_storage = pub_storage.lock().await;
            assert!(
                read_versioned_at_request_id::<RamStorage, RecoveryValidationMaterial>(
                    &*guarded_pub_storage,
                    &first_context_id,
                    &PubDataType::RecoveryMaterial.to_string(),
                )
                .await
                .is_err(),
                "Custodian context was not deleted"
            );
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
        )
        .await
        .unwrap();
        let internal_rec_req = InternalRecoveryRequest::new(
            recovery_material.payload.custodian_context.backup_enc_key,
            recovery_material.payload.cts,
            backup_id,
            server_verf_key.clone(),
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

    #[tokio::test]
    async fn test_centralized_context_cache() {
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(KMSType::Centralized, sig_key).unwrap();
        let context_id = ContextId::from_bytes([5u8; 32]);
        let new_context = ContextInfo {
            mpc_nodes: vec![NodeInfo {
                mpc_identity: "Node1".to_string(),
                party_id: 1,
                verification_key: Some(verification_key.clone()),
                external_url: "http://localhost:12345".to_string(),
                ca_cert: None,
                public_storage_url: "http://storage".to_string(),
                public_storage_prefix: None,
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

        let context_manager = CentralizedContextManager::new(
            base_kms,
            crypto_storage.clone(),
            Arc::new(RwLock::new(MetaStore::new(100, 10))),
        );

        // Initially, the cache should be empty
        assert!(
            !context_manager
                .mpc_context_exists_in_cache(&context_id)
                .await
        );

        // Create a new context
        let request = Request::new(NewMpcContextRequest {
            new_context: Some(new_context.clone().try_into().unwrap()),
        });
        let response = context_manager.new_mpc_context(request).await;
        response.unwrap();

        // Now the context should exist in cache
        assert!(
            context_manager
                .mpc_context_exists_in_cache(&context_id)
                .await
        );

        // Verify context is stored in storage
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let stored_context = read_context_at_id(&*guarded_priv_storage, &context_id)
                .await
                .unwrap();
            assert_eq!(*stored_context.context_id(), context_id);
        }

        // Try to create the same context with the same context ID which is not allowed (should fail)
        let request = Request::new(NewMpcContextRequest {
            new_context: Some(new_context.try_into().unwrap()),
        });
        let response = context_manager.new_mpc_context(request).await;
        assert!(response.is_err());

        // Destroy the context
        let request = Request::new(DestroyMpcContextRequest {
            context_id: Some(context_id.into()),
        });
        let response = context_manager.destroy_mpc_context(request).await;
        response.unwrap();

        // Cache should no longer have the context
        assert!(
            !context_manager
                .mpc_context_exists_in_cache(&context_id)
                .await
        );

        // Storage should no longer have the context
        {
            let storage_ref = Arc::clone(&crypto_storage.private_storage);
            let guarded_priv_storage = storage_ref.lock().await;
            let result = read_context_at_id(&*guarded_priv_storage, &context_id).await;
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn test_centralized_context_exists_and_consistent() {
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(KMSType::Centralized, sig_key).unwrap();
        let context_id = ContextId::from_bytes([6u8; 32]);
        let new_context = ContextInfo {
            mpc_nodes: vec![NodeInfo {
                mpc_identity: "Node1".to_string(),
                party_id: 1,
                verification_key: Some(verification_key.clone()),
                external_url: "http://localhost:12345".to_string(),
                ca_cert: None,
                public_storage_url: "http://storage".to_string(),
                public_storage_prefix: None,
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

        let context_manager = CentralizedContextManager::new(
            base_kms,
            crypto_storage.clone(),
            Arc::new(RwLock::new(MetaStore::new(100, 10))),
        );

        // Initially, context should not exist
        let non_existent_id = ContextId::from_bytes([99u8; 32]);
        let result = context_manager
            .mpc_context_exists_and_consistent(&non_existent_id)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Create a new context
        let request = Request::new(NewMpcContextRequest {
            new_context: Some(new_context.try_into().unwrap()),
        });
        context_manager.new_mpc_context(request).await.unwrap();

        // Now mpc_context_exists_and_consistent should return true
        let result = context_manager
            .mpc_context_exists_and_consistent(&context_id)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Destroy the context
        let request = Request::new(DestroyMpcContextRequest {
            context_id: Some(context_id.into()),
        });
        context_manager.destroy_mpc_context(request).await.unwrap();

        // After destruction, context should not exist
        let result = context_manager
            .mpc_context_exists_and_consistent(&context_id)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_centralized_multiple_contexts() {
        let (verification_key, sig_key, crypto_storage) = setup_crypto_storage().await;
        let base_kms = BaseKmsStruct::new(KMSType::Centralized, sig_key).unwrap();

        let context_manager = CentralizedContextManager::new(
            base_kms,
            crypto_storage.clone(),
            Arc::new(RwLock::new(MetaStore::new(100, 10))),
        );

        // Create multiple contexts
        let context_ids: Vec<ContextId> = (0..3)
            .map(|i| ContextId::from_bytes([i + 10; 32]))
            .collect();

        for context_id in &context_ids {
            let new_context = ContextInfo {
                mpc_nodes: vec![NodeInfo {
                    mpc_identity: "Node1".to_string(),
                    party_id: 1,
                    verification_key: Some(verification_key.clone()),
                    external_url: "http://localhost:12345".to_string(),
                    ca_cert: None,
                    public_storage_url: "http://storage".to_string(),
                    public_storage_prefix: None,
                    extra_verification_keys: vec![],
                }],
                context_id: *context_id,
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
            context_manager.new_mpc_context(request).await.unwrap();
        }

        // All contexts should exist in cache
        for context_id in &context_ids {
            assert!(
                context_manager
                    .mpc_context_exists_in_cache(context_id)
                    .await
            );
            assert!(context_manager
                .mpc_context_exists_and_consistent(context_id)
                .await
                .unwrap());
        }

        // Destroy the middle context
        let request = Request::new(DestroyMpcContextRequest {
            context_id: Some(context_ids[1].into()),
        });
        context_manager.destroy_mpc_context(request).await.unwrap();

        // First and third should still exist, second should not
        assert!(
            context_manager
                .mpc_context_exists_in_cache(&context_ids[0])
                .await
        );
        assert!(
            !context_manager
                .mpc_context_exists_in_cache(&context_ids[1])
                .await
        );
        assert!(
            context_manager
                .mpc_context_exists_in_cache(&context_ids[2])
                .await
        );
    }
}
