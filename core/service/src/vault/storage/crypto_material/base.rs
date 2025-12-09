//! Base implementation of cryptographic material storage
//!
//! This module provides the foundational storage implementation used by
//! both centralized and threshold KMS variants.
use super::{check_data_exists, log_storage_success, CryptoMaterialReader};
use crate::{
    anyhow_error_and_warn_log,
    backup::operator::RecoveryValidationMaterial,
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata},
        context::ContextInfo,
        threshold::service::ThresholdFheKeys,
    },
    grpc::metastore_status_service::CustodianMetaStore,
    util::meta_store::MetaStore,
    vault::{
        keychain::KeychainProxy,
        storage::{
            crypto_material::log_storage_success_optional_variant, delete_all_at_request_id,
            delete_at_request_id, delete_pk_at_request_id, read_all_data_versioned,
            read_context_at_id, store_context_at_id, store_pk_at_request_id,
            store_versioned_at_request_id, Storage,
        },
        Vault,
    },
};
use kms_grpc::{
    identifiers::ContextId,
    rpc_types::{KMSType, PrivDataType, PubDataType, WrappedPublicKey, WrappedPublicKeyOwned},
    RequestId,
};
use std::{collections::HashMap, sync::Arc};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

/// A cached generic storage entity for the common data structures
/// used by both the centralized and the threshold KMS.
///
/// This struct provides thread-safe access to public, private, and optional backup storage,
/// along with a cache for generated public keys. Cloning is cheap due to internal Arc usage.
pub struct CryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    /// Storage for publicly readable data (may be susceptible to malicious modifications)
    /// Warning: In relation to concurrency where multiple locks are needed always lock public_storage first, then private_storage second, backup_vault third and finally pk_cache last.
    pub(crate) public_storage: Arc<Mutex<PubS>>,

    /// Storage for private data (only accessible by owner, modifications are detectable)
    /// Warning: In relation to concurrency where multiple locks are needed always lock public_storage first, then private_storage second, backup_vault third and finally pk_cache last.
    pub(crate) private_storage: Arc<Mutex<PrivS>>,

    /// Optional backup vault for recovery purposes
    /// Warning: In relation to concurrency where multiple locks are needed always lock public_storage first, then private_storage second, backup_vault third and finally pk_cache last.
    pub(crate) backup_vault: Option<Arc<Mutex<Vault>>>,

    /// Cache for already generated public keys
    /// Warning: In relation to concurrency where multiple locks are needed always lock public_storage first, then private_storage second, backup_vault third and finally pk_cache last.
    pub(crate) pk_cache: Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>,
    // Cache for current backup key (if it is set)
    // Observe that the `Option` is inside the lock since it may be added during runtime through a new custodian context.
    // pub(crate) current_backup_key: Arc<RwLock<Option<BackupPublicKey>>>,
}

impl<PubS, PrivS> CryptoMaterialStorage<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
{
    // =========================
    // Initializers
    // =========================

    /// Creates a new CryptoMaterialStorage with pre-wrapped storages.
    ///
    /// Use this when you already have Arc<Mutex<_>> wrapped storages.
    pub fn new(
        public_storage: Arc<Mutex<PubS>>,
        private_storage: Arc<Mutex<PrivS>>,
        backup_vault: Option<Arc<Mutex<Vault>>>,
        pk_cache: Option<Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>>,
    ) -> Self {
        Self {
            public_storage,
            private_storage,
            backup_vault,
            pk_cache: pk_cache.unwrap_or_else(|| Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Creates a CryptoMaterialStorage by wrapping the provided storages.
    pub fn from(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        pk_cache: Option<Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>>,
    ) -> Self {
        Self::new(
            Arc::new(Mutex::new(public_storage)),
            Arc::new(Mutex::new(private_storage)),
            backup_vault.map(|s| Arc::new(Mutex::new(s))),
            pk_cache,
        )
    }

    /// Getter for public_storage
    pub fn get_public_storage(&self) -> Arc<Mutex<PubS>> {
        Arc::clone(&self.public_storage)
    }

    /// Getter for private_storage
    pub fn get_private_storage(&self) -> Arc<Mutex<PrivS>> {
        Arc::clone(&self.private_storage)
    }

    /// Getter for backup_storage (if present)
    pub fn get_backup_vault(&self) -> Option<Arc<Mutex<Vault>>> {
        self.backup_vault.as_ref().map(Arc::clone)
    }

    // =========================
    // Existence Check Methods
    // =========================

    /// Check if data exists in both public and private storage
    pub async fn data_exists(
        &self,
        req_id: &RequestId,
        pub_data_type: &str,
        priv_data_type: &str,
    ) -> anyhow::Result<bool> {
        // First locking public storage, then private storage as per concurrency rules
        let pub_storage = self.public_storage.lock().await;
        let priv_storage = self.private_storage.lock().await;

        check_data_exists(
            &*pub_storage,
            &*priv_storage,
            req_id,
            pub_data_type,
            priv_data_type,
        )
        .await
    }

    /// Check if signing keys exist in the storage.
    ///
    /// This method checks if signing keys exist in the private storage.
    ///
    /// # Returns
    /// `Ok(true)` if signing keys exist, `Ok(false)` if they don't, or an error if the check fails.
    pub async fn private_signing_keys_exist(&self) -> anyhow::Result<bool> {
        let priv_storage = self.private_storage.lock().await;
        let keys: HashMap<RequestId, PrivateSigKey> =
            read_all_data_versioned(&*priv_storage, &PrivDataType::SigningKey.to_string())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read signing key data: {}", e))?;

        Ok(!keys.is_empty())
    }

    /// Check if FHE keys exist (for central server)
    pub async fn fhe_keys_exist(&self, key_id: &RequestId) -> anyhow::Result<bool> {
        self.data_exists(
            key_id,
            &PubDataType::PublicKey.to_string(),
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
    }

    /// Check if threshold FHE keys exist
    pub async fn threshold_fhe_keys_exist(&self, key_id: &RequestId) -> anyhow::Result<bool> {
        self.data_exists(
            key_id,
            &PubDataType::PublicKey.to_string(),
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
    }

    /// Check if CRS exists
    pub async fn crs_exists(&self, crs_handle: &RequestId) -> anyhow::Result<bool> {
        self.data_exists(
            crs_handle,
            &PubDataType::CRS.to_string(),
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
    }

    /// Get signing key from private storage
    pub async fn get_signing_key(&self) -> anyhow::Result<PrivateSigKey> {
        let priv_storage = self.private_storage.lock().await;
        super::utils::get_core_signing_key(&*priv_storage).await
    }

    /// Store threshold public key
    pub async fn store_threshold_public_key(
        &self,
        key_id: &RequestId,
        public_key: WrappedPublicKey<'_>,
    ) -> anyhow::Result<()> {
        let mut pub_storage = self.public_storage.lock().await;
        store_pk_at_request_id(&mut *pub_storage, key_id, public_key).await
    }

    /// Store threshold public server key
    pub async fn store_threshold_public_server_key(
        &self,
        key_id: &RequestId,
        server_key: &tfhe::ServerKey,
    ) -> anyhow::Result<()> {
        let mut pub_storage = self.public_storage.lock().await;
        store_versioned_at_request_id(
            &mut *pub_storage,
            key_id,
            server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
    }

    /// Store threshold private FHE key info
    pub async fn store_threshold_private_fhe_key_info(
        &self,
        key_id: &RequestId,
        threshold_fhe_keys: &ThresholdFheKeys,
    ) -> anyhow::Result<()> {
        let mut priv_storage = self.private_storage.lock().await;
        store_versioned_at_request_id(
            &mut *priv_storage,
            key_id,
            threshold_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
    }

    // =========================
    // Ensure_xxx_existence Methods
    // =========================

    /// Tries to delete all the types of key material related to a specific [RequestId].
    /// WARNING: This also deletes the BACKUP of the keys. Hence the method should should only be used as cleanup after a failed DKG.
    pub async fn purge_key_material(
        &self,
        req_id: &RequestId,
        kms_type: KMSType,
        mut guarded_meta_store: RwLockWriteGuard<'_, MetaStore<KeyGenMetadata>>,
    ) {
        // Lock all stores here as storing will be executed concurrently and hence we can otherwise not enforce the locking order
        let mut pub_storage = self.public_storage.lock().await;
        let mut priv_storage = self.private_storage.lock().await;
        let back_vault = match self.backup_vault {
            Some(ref x) => Some(x.lock().await),
            None => None,
        };

        let f1 = async {
            let pk_result = delete_pk_at_request_id(&mut (*pub_storage), req_id).await;
            if let Err(e) = &pk_result {
                tracing::warn!("Failed to delete public key for request {}: {}", req_id, e);
            }
            let server_key_result = delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::ServerKey.to_string(),
            )
            .await;
            if let Err(e) = &server_key_result {
                tracing::warn!("Failed to delete server key for request {}: {}", req_id, e);
            }
            pk_result.is_err() || server_key_result.is_err()
        };
        let f2 = async {
            let result = match kms_type {
                KMSType::Centralized => {
                    // In centralized KMS there is no FHE key info to delete, instead delete the FhePrivateKey
                    delete_at_request_id(
                        &mut (*priv_storage),
                        req_id,
                        &PrivDataType::FhePrivateKey.to_string(),
                    )
                    .await
                }
                KMSType::Threshold => {
                    // In threshold KMS we need to delete the FHE key info
                    delete_at_request_id(
                        &mut (*priv_storage),
                        req_id,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await
                }
            };
            if let Err(e) = &result {
                tracing::warn!(
                    "Failed to delete FHE key info from private storage for request {}: {}",
                    req_id,
                    e
                );
            }
            result.is_err()
        };
        let f3 = async {
            match back_vault {
                Some(mut guarded_backup_vault) => {
                    let result = delete_at_request_id(
                        &mut (*guarded_backup_vault),
                        req_id,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await;
                    if let Err(e) = &result {
                        tracing::warn!(
                            "Failed to delete FHE key info from backup storage for request {}: {}",
                            req_id,
                            e
                        );
                    }
                    result.is_err()
                }
                None => false,
            }
        };
        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        if r1 || r2 || r3 {
            tracing::error!("Failed to delete key material for request {}", req_id);
        } else {
            tracing::info!("Deleted all key material for request {}", req_id);
        }
        let meta_update_result =
            guarded_meta_store.update(req_id, Err("DKG failed during storage".to_string()));
        if meta_update_result.is_err() {
            tracing::error!(
                "Failed to remove key data from  meta store for request {} while purging key material",
                req_id
            );
        } else {
            tracing::info!(
                "Removed key data from meta store for request {} while purging key material",
                req_id
            );
        }
    }

    /// Write the CRS to the storage backend as well as the cache,
    /// and update the [meta_store] to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub async fn write_crs_with_meta_store(
        &self,
        req_id: &RequestId,
        pp: CompactPkeCrs,
        crs_info: CrsGenMetadata,
        meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        let (r1, r2, r3) = {
            // Enforce locking order for internal types
            let mut pub_storage = self.public_storage.lock().await;
            let mut priv_storage = self.private_storage.lock().await;
            let back_vault = match self.backup_vault {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };

            let f1 = async {
                let result = store_versioned_at_request_id(
                    &mut (*priv_storage),
                    req_id,
                    &crs_info,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await;
                if let Err(e) = &result {
                    tracing::error!(
                        "Failed to store CRS info to private storage for request {}: {}",
                        req_id,
                        e
                    );
                }
                result.is_ok()
            };
            let f2 = async {
                let result = store_versioned_at_request_id(
                    &mut (*pub_storage),
                    req_id,
                    &pp,
                    &PubDataType::CRS.to_string(),
                )
                .await;
                if let Err(e) = &result {
                    tracing::error!(
                        "Failed to store CRS to public storage for request {}: {}",
                        req_id,
                        e
                    );
                }
                result.is_ok()
            };
            let f3 = async {
                match back_vault {
                    Some(mut guarded_backup_vault) => {
                        let backup_result = store_versioned_at_request_id(
                            &mut (*guarded_backup_vault),
                            req_id,
                            &crs_info,
                            &PrivDataType::CrsInfo.to_string(),
                        )
                        .await;

                        if let Err(e) = &backup_result {
                            tracing::error!("Failed to store encrypted crs info to backup storage for request {req_id}: {e}");
                        }
                        backup_result.is_ok()
                    }
                    None => {
                        tracing::warn!("No backup vault configured. Skipping backup of CRS material for request {req_id}");
                        true
                    }
                }
            };
            tokio::join!(f1, f2, f3)
        };

        if r1
            && r2
            && r3
            && guarded_meta_store
                .update(req_id, Ok(crs_info))
                .inspect_err(|e| {
                    tracing::error!("Error ({e}) while updating CRS meta store for {}", req_id)
                })
                .is_ok()
        {
            // everything is ok, there's no cache to update
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might
            // be because the data did not get created
            // In any case, we can't do much.
            self.purge_crs_material(req_id, guarded_meta_store).await;
        }
    }

    /// Tries to delete all the types of CRS material related to a specific [RequestId].
    /// WARNING: This also deletes the BACKUP of the CRS data. Hence the method should should only be used as cleanup after a failed CRS generation.
    pub async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<'_, MetaStore<CrsGenMetadata>>,
    ) {
        // Enforce locking order for internal types
        let mut pub_storage = self.public_storage.lock().await;
        let mut priv_storage = self.private_storage.lock().await;
        let back_vault = match self.backup_vault {
            Some(ref x) => Some(x.lock().await),
            None => None,
        };

        let f1 = async {
            let result =
                delete_at_request_id(&mut (*pub_storage), req_id, &PubDataType::CRS.to_string())
                    .await;
            if let Err(e) = &result {
                tracing::warn!(
                    "Failed to delete CRS from public storage for request {}: {}",
                    req_id,
                    e
                );
            }
            result.is_err()
        };
        let f2 = async {
            let priv_result = delete_at_request_id(
                &mut (*priv_storage),
                req_id,
                &PrivDataType::CrsInfo.to_string(),
            )
            .await;
            if let Err(e) = &priv_result {
                tracing::warn!(
                    "Failed to delete CRS info from private storage for request {}: {}",
                    req_id,
                    e
                );
            }

            priv_result.is_err()
        };
        let f3 = async {
            match back_vault {
                Some(mut back_vault) => {
                    let vault_result = delete_at_request_id(
                        &mut (*back_vault),
                        req_id,
                        &PrivDataType::CrsInfo.to_string(),
                    )
                    .await;
                    if let Err(e) = &vault_result {
                        tracing::warn!(
                            "Failed to delete CRS info from backup storage for request {}: {}",
                            req_id,
                            e
                        );
                    }
                    vault_result.is_err()
                }
                None => false, // No backup vault, so no error
            }
        };
        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        if r1 || r2 || r3 {
            tracing::error!("Failed to delete crs material for request {}", req_id);
        } else {
            tracing::info!("Deleted all crs material for request {}", req_id);
        }
        // We cannot do much if updating the meta store fails at this point,
        // so just log an error.
        let meta_update_result = guarded_meta_store.update(
            req_id,
            Err(format!(
                "Failed to store CRS data to public storage for ID {req_id}"
            )),
        );
        let r3 = if let Err(e) = &meta_update_result {
            tracing::error!("Removing CRS from meta store failed with error: {}", e);
            true
        } else {
            false
        };

        // We cannot do much if updating CRS cache fails at this point,
        // so just log an error.
        if r3 {
            tracing::error!("Failed to remove crs cached data for request {}", req_id);
        } else {
            tracing::info!("Removed all crs cached data for request {}", req_id);
        }
    }

    /// Write the backup keys to the storage and update the meta store.
    /// This methods writes all the material associated with backups to storage,
    /// and updates the meta store accordingly.
    ///
    /// This means that the public encryption key for backup is written to the public storage.
    /// The same goes for the commitments to the custodian shares and the recovery request.
    /// Finally the custodian context, with the information about the custodian nodes, is also written to public storage.
    /// The private key for decrypting backups is written to the private storage.
    #[allow(clippy::too_many_arguments)]
    pub async fn write_backup_keys_with_meta_store(
        &self,
        recovery_material: &RecoveryValidationMaterial,
        meta_store: Arc<RwLock<CustodianMetaStore>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;
        let req_id = recovery_material.custodian_context().context_id;
        let pub_res = {
            // Lock the storage needed in correct order to avoid deadlocks.
            let mut public_storage_guard = self.public_storage.lock().await;

            let pub_storage_future = async {
                let store_result = store_versioned_at_request_id(
                    &mut (*public_storage_guard),
                    &req_id,
                    recovery_material,
                    &PubDataType::RecoveryMaterial.to_string(),
                )
                .await;
                if let Err(e) = &store_result {
                    tracing::error!(
                        "Failed to store commitments to the public storage for request {}: {}",
                        req_id,
                        e
                    );
                } else {
                    log_storage_success(
                        req_id,
                        public_storage_guard.info(),
                        &PubDataType::RecoveryMaterial.to_string(),
                        true,
                        true,
                    );
                }
                store_result.is_ok()
            };
            tokio::join!(pub_storage_future).0
        };
        {
            // Update meta store
            // First we insert the request ID
            // Whether things fail or not we can't do much
            match guarded_meta_store.insert(&req_id) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Failed to insert request ID {req_id} into meta store: {e}",);
                    self.purge_backup_material(&req_id, guarded_meta_store)
                        .await;
                    return;
                }
            };
            // If everything is ok, we update the meta store with a success
            if pub_res {
                if let Err(e) = guarded_meta_store.update(&req_id, Ok(recovery_material.clone())) {
                    tracing::error!("Failed to update meta store for request {req_id}: {e}");
                    self.purge_backup_material(&req_id, guarded_meta_store)
                        .await;
                }
            } else {
                self.purge_backup_material(&req_id, guarded_meta_store)
                    .await;
                tracing::error!(
                    "Failed to store backup keys for request {}: pub_res: {}",
                    req_id,
                    pub_res,
                );
            }
        }
        // Finally update the current backup key in the storage
        {
            match self.backup_vault {
                Some(ref vault) => {
                    let mut guarded_backup_vault = vault.lock().await;
                    match &mut guarded_backup_vault.keychain {
                        Some(keychain) => {
                            if let KeychainProxy::SecretSharing(sharing_chain) = keychain {
                                // Store the public key in the secret sharing keychain
                                sharing_chain.set_backup_enc_key(req_id, recovery_material.custodian_context().backup_enc_key.clone());
                            }
                        },
                        None => {
                            tracing::info!(
                                "No keychain in backup vault, skipping setting backup encryption key for request {req_id}"
                            );
                        },
                    }
                },
                None => tracing::warn!(
                    "No backup vault configured, skipping setting backup encryption key for request {req_id}"
                ),
            }
        }
    }

    /// Tries to delete all the data related to a custodian context (used for backup) for a specific context id [RequestId].
    /// WARNING: This also deletes ALL backups of a given context. Hence the method should only be used to clean up.
    pub async fn purge_backup_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<'_, CustodianMetaStore>,
    ) {
        // Enforce locking order for internal types
        let mut pub_storage = self.public_storage.lock().await;
        let back_vault = match self.backup_vault {
            Some(ref x) => Some(x.lock().await),
            None => None,
        };

        let pub_purge = async {
            let res = delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::RecoveryMaterial.to_string(),
            )
            .await;
            if let Err(e) = &res {
                tracing::warn!(
                    "Failed to delete commitment material for request {}: {}",
                    req_id,
                    e
                );
            }
            res.is_err()
        };
        let vault_purge = async {
            match back_vault {
                Some(mut back_vault) => delete_all_at_request_id(&mut (*back_vault), req_id)
                    .await
                    .is_err(),
                None => false, // No backup vault, so no error
            }
        };
        let (pub_purge_res, vault_purge_res) = tokio::join!(pub_purge, vault_purge);
        if pub_purge_res || vault_purge_res {
            tracing::error!("Failed to delete backup material for request {}", req_id);
        } else {
            tracing::info!("Deleted all backup material for request {}", req_id);
        }
        // We cannot do much if updating the meta store fails at this point,
        // so just log an error.
        let meta_update_result = guarded_meta_store.update(
            req_id,
            Err(format!("Failed to store backup data for ID {req_id}")),
        );
        let meta_res = if let Err(e) = &meta_update_result {
            tracing::error!("Removing backup from meta store failed with error: {}", e);
            true
        } else {
            false
        };

        // We cannot do much if updating the cache fails at this point,
        // so just log an error.
        if meta_res {
            tracing::error!("Failed to remove backup meta data for request {}", req_id);
        } else {
            tracing::info!(
                "Removed all orphaned backup meta data for request {}",
                req_id
            );
        }
    }

    /// Note that we're not storing a shortint decompression key
    pub async fn write_decompression_key_with_meta_store(
        &self,
        req_id: &RequestId,
        decompression_key: DecompressionKey,
        info: KeyGenMetadata,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
            let result = store_versioned_at_request_id(
                &mut (*pub_storage),
                req_id,
                &decompression_key,
                &PubDataType::DecompressionKey.to_string(),
            )
            .await;
            if let Err(e) = &result {
                tracing::error!(
                    "Failed to store decompression key to public storage for request {}: {}",
                    req_id,
                    e
                );
            }
            result.is_ok()
        };
        if f1.await
            && guarded_meta_store
                .update(req_id, Ok(info))
                .inspect_err(|e| {
                    tracing::error!(
                        "Error ({e}) while updating decompression key meta store for {}",
                        req_id
                    )
                })
                .is_ok()
        {
            // there is no cache to update
        } else {
            // delete the decompression key, we can't do much if there's an error
            let mut pub_storage = self.public_storage.lock().await;
            let delete_result = delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::DecompressionKey.to_string(),
            )
            .await;
            if let Err(e) = delete_result {
                tracing::error!(
                    "Error ({}) while deleting decompression key from storage for {}",
                    e,
                    req_id
                );
            }
        }
    }

    /// Read the public key from a cache, if it does not exist,
    /// attempt to read it from the public storage backend.
    pub(crate) async fn read_cloned_pk(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<WrappedPublicKeyOwned> {
        Self::read_cloned_crypto_material::<WrappedPublicKeyOwned, _>(
            self.pk_cache.clone(),
            req_id,
            self.public_storage.clone(),
        )
        .await
    }

    /// Read the server key
    /// from the public storage backend.
    pub(crate) async fn read_cloned_server_key(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<tfhe::ServerKey> {
        Self::read_cloned_crypto_material::<tfhe::ServerKey, _>(
            Arc::new(RwLock::new(HashMap::new())),
            req_id,
            self.public_storage.clone(),
        )
        .await
    }

    pub(crate) async fn read_cloned_crypto_material<T, S>(
        cache: Arc<RwLock<HashMap<RequestId, T>>>,
        req_id: &RequestId,
        storage: Arc<Mutex<S>>,
    ) -> anyhow::Result<T>
    where
        T: CryptoMaterialReader + Clone,
        S: Storage + Send + Sync + 'static,
    {
        let pub_storage = storage.lock().await;
        let out = {
            let cache_guard = cache.read().await;
            cache_guard.get(req_id).cloned()
        };

        match out {
            Some(pk) => Ok(pk),
            None => {
                let pk = T::read_from_storage(&(*pub_storage), req_id)
                    .await
                    .inspect_err(|e| {
                        tracing::error!(
                            "Failed to read public material with the handle {} ({e})",
                            req_id
                        );
                    })?;

                let mut write_cache_guard = cache.write().await;
                write_cache_guard.insert(*req_id, pk.clone());
                Ok(pk)
            }
        }
    }

    // TODO should be changed to KeyId
    pub async fn read_guarded_crypto_material_from_cache<T: Clone + std::fmt::Debug>(
        req_id: &RequestId,
        fhe_keys: Arc<RwLock<HashMap<RequestId, T>>>,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<RequestId, T>, T>> {
        // Returning a OwnedRwLockReadGuard just saves some data-copying
        // if the value is already in the cache.
        let fhe_keys = fhe_keys.clone();
        let guard = fhe_keys.read_owned().await;
        OwnedRwLockReadGuard::try_map(guard, |m| m.get(req_id)).map_err(|_| {
            anyhow_error_and_warn_log(format!(
                "Failed to find crypto material in cache for request ID {req_id}"
            ))
        })
    }

    pub async fn read_cloned_crypto_material_from_cache<T: Clone>(
        cache: Arc<RwLock<HashMap<RequestId, T>>>,
        req_id: &RequestId,
    ) -> anyhow::Result<T> {
        let out = {
            let guard = cache.read().await;
            guard.get(req_id).cloned()
        };
        out.ok_or_else(|| {
            anyhow_error_and_warn_log(format!("Key handles are not in the cache for ID {req_id}"))
        })
    }

    pub async fn refresh_crypto_material<T, S>(
        cache: Arc<RwLock<HashMap<RequestId, T>>>,
        req_id: &RequestId,
        storage: Arc<Mutex<S>>,
    ) -> anyhow::Result<()>
    where
        S: Storage + Send + Sync + 'static,
        T: CryptoMaterialReader,
    {
        // This function does not need to be atomic, so we take a read lock
        // on the cache first and check for existance, then release it.
        // We do this because we want to avoid write locks unless necessary.
        let exists = {
            let guarded_fhe_keys = cache.read().await;
            guarded_fhe_keys.contains_key(req_id)
        };

        if !exists {
            let storage = storage.lock().await;
            match T::read_from_storage(&(*storage), req_id).await {
                Ok(new_fhe_keys) => {
                    let mut guarded_fhe_keys = cache.write().await;
                    guarded_fhe_keys.insert(*req_id, new_fhe_keys);
                }
                Err(e) => {
                    return Err(anyhow_error_and_warn_log(format!(
                        "Failed to refresh crypto material from storage for request ID {req_id}: {e}"
                    )));
                }
            }
        }

        Ok(())
    }

    pub async fn write_context_info(
        &self,
        context_id: &ContextId,
        context_info: &ContextInfo,
    ) -> anyhow::Result<()> {
        let mut priv_storage = self.private_storage.lock().await;
        store_context_at_id(&mut *priv_storage, context_id, context_info).await?;
        log_storage_success_optional_variant(
            context_id,
            priv_storage.info(),
            "context info",
            false,
            None,
        );
        Ok(())
    }

    pub async fn read_context_info(&self, context_id: &ContextId) -> anyhow::Result<ContextInfo> {
        let priv_storage = self.private_storage.lock().await;
        let res = read_context_at_id(&*priv_storage, context_id).await?;
        log_storage_success_optional_variant(
            context_id,
            priv_storage.info(),
            "context info",
            false,
            None,
        );
        Ok(res)
    }

    /// Read all context info entries from storage.
    pub async fn read_all_context_info(&self) -> anyhow::Result<Vec<ContextInfo>> {
        let priv_storage = self.private_storage.lock().await;

        let context_map: HashMap<_, ContextInfo> =
            read_all_data_versioned(&*priv_storage, &PrivDataType::ContextInfo.to_string())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read context info: {}", e))?;
        Ok(context_map.into_values().collect())
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static> Clone
    for CryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            public_storage: Arc::clone(&self.public_storage),
            private_storage: Arc::clone(&self.private_storage),
            backup_vault: self.backup_vault.as_ref().map(Arc::clone),
            pk_cache: Arc::clone(&self.pk_cache),
        }
    }
}
