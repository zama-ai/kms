//! Threshold cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the threshold KMS variant.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use kms_grpc::{
    rpc_types::{
        BackupDataType, PrivDataType, PubDataType, SignedPubDataHandleInternal, WrappedPublicKey,
        WrappedPublicKeyOwned,
    },
    RequestId,
};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use threshold_fhe::execution::endpoints::keygen::FhePubKeySet;

use crate::{
    backup::{
        custodian::InternalCustodianContext,
        operator::{BackupCommitments, RecoveryRequest},
    },
    cryptography::backup_pke::BackupPublicKey,
    engine::threshold::service::ThresholdFheKeys,
    grpc::metastore_status_service::CustodianMetaStore,
    util::meta_store::MetaStore,
    vault::{
        keychain::KeychainProxy,
        storage::{store_pk_at_request_id, store_versioned_at_request_id, Storage},
        Vault,
    },
};

use super::base::CryptoMaterialStorage;

/// A cached generic storage entity for the threshold KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub struct ThresholdCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    pub(crate) inner: CryptoMaterialStorage<PubS, PrivS>,
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
    ThresholdCryptoMaterialStorage<PubS, PrivS>
{
    /// Create a new cached storage device for threshold KMS.
    pub fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        // current_backup_key: Option<BackupPublicKey>,
        pk_cache: HashMap<RequestId, WrappedPublicKeyOwned>,
        fhe_keys: HashMap<RequestId, ThresholdFheKeys>,
    ) -> Self {
        Self {
            inner: CryptoMaterialStorage {
                public_storage: Arc::new(Mutex::new(public_storage)),
                private_storage: Arc::new(Mutex::new(private_storage)),
                backup_vault: backup_vault.map(|x| Arc::new(Mutex::new(x))),
                pk_cache: Arc::new(RwLock::new(pk_cache)),
                // current_backup_key: Arc::new(RwLock::new(current_backup_key)),
            },
            fhe_keys: Arc::new(RwLock::new(fhe_keys)),
        }
    }

    /// Get an Arc of the private storage device.
    pub fn get_private_storage(&self) -> Arc<Mutex<PrivS>> {
        Arc::clone(&self.inner.private_storage)
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
        crs_info: SignedPubDataHandleInternal,
        meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    ) {
        self.inner
            .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
            .await
    }

    /// Write the key materials (result of a keygen) to storage and cache
    /// for the threshold KMS.
    /// The [meta_store] is updated to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub async fn write_threshold_keys_with_meta_store(
        &self,
        key_id: &RequestId,
        threshold_fhe_keys: ThresholdFheKeys,
        fhe_key_set: FhePubKeySet,
        info: HashMap<PubDataType, SignedPubDataHandleInternal>,
        meta_store: Arc<RwLock<MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_storage = meta_store.write().await;

        let f1 = async {
            let mut priv_storage = self.inner.private_storage.lock().await;
            // can't map() because async closures aren't stable in Rust
            // let back_vault = match self.inner.backup_vault {
            //     Some(ref x) => Some(x.lock().await),
            //     None => None,
            // };

            let store_result = store_versioned_at_request_id(
                &mut (*priv_storage),
                key_id,
                &threshold_fhe_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await;

            if let Err(e) = &store_result {
                tracing::error!(
                    "Failed to store threshold FHE keys to private storage for request {}: {}",
                    key_id,
                    e
                );
            }
            store_result.is_ok()

            // let backup_is_ok = match back_vault {
            //     Some(mut x) => {
            //         let backup_result = store_versioned_at_request_id(
            //             &mut (*x),
            //             key_id,
            //             &threshold_fhe_keys,
            //             &PrivDataType::FheKeyInfo.to_string(),
            //         )
            //         .await;

            //         if let Err(e) = &backup_result {
            //             tracing::error!("Failed to store threshold FHE keys to backup storage for request {}: {}", key_id, e);
            //         }
            //         backup_result.is_ok()
            //     }
            //     None => true,
            // };

            // store_is_ok && backup_is_ok
        };
        let f2 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            let result = store_pk_at_request_id(
                &mut (*pub_storage),
                key_id,
                WrappedPublicKey::Compact(&fhe_key_set.public_key),
            )
            .await;

            if let Err(e) = &result {
                tracing::error!("Failed to store public key for request {}: {}", key_id, e);
            }
            result.is_ok()
        };
        let f3 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            let result = store_versioned_at_request_id(
                &mut (*pub_storage),
                key_id,
                &fhe_key_set.server_key,
                &PubDataType::ServerKey.to_string(),
            )
            .await;

            if let Err(e) = &result {
                tracing::error!("Failed to store server key for request {}: {}", key_id, e);
            }
            result.is_ok()
        };
        let threshold_key_clone = threshold_fhe_keys.clone();
        let f4 = async move {
            // TODO this should happen in the backup vault storage, i.e. it should have the public encryption key
            // Construct a backup of the key material
            // let backup_key_guard = self.inner.current_backup_key.read().await;
            // let backup_key = match &*backup_key_guard {
            //     Some(backup_key) => backup_key.clone(),
            //     None => {
            //         tracing::warn!("No backup vault configured, skipping backup key material storage for request {key_id}");
            //         return true;
            //     }
            // };
            // drop(backup_key_guard);
            // // TODO ciphertext should be versioned
            // let mut serialized_keys = Vec::new();
            // safe_serialize(
            //     &threshold_fhe_keys,
            //     &mut serialized_keys,
            //     SAFE_SER_SIZE_LIMIT,
            // )
            // .is_err_and(|e| {
            //     tracing::error!(
            //         "Failed to serialize threshold FHE keys for request {key_id}: {e:?}",
            //     );
            //     return false;
            // });
            // let enc_key = match backup_key.encrypt(rng, &serialized_keys) {
            //     Ok(encrypted_key) => encrypted_key,
            //     Err(e) => {
            //         tracing::error!(
            //             "Failed to encrypt threshold FHE keys for request {key_id}: {e:?}",
            //         );
            //         return false;
            //     }
            // };
            // let ct_key = BackupCiphertext {
            //     ciphertext: enc_key,
            //     priv_data_type: PrivDataType::FheKeyInfo,
            // };
            match self.inner.backup_vault {
                Some(ref back_vault) => {
                    let mut guarded_backup_vault = back_vault.lock().await;
                    let backup_result = store_versioned_at_request_id(
                        &mut (*guarded_backup_vault),
                        key_id,
                        &threshold_key_clone,
                        &BackupDataType::PrivData(PrivDataType::FheKeyInfo).to_string(),
                    )
                    .await;

                    if let Err(e) = &backup_result {
                        tracing::error!("Failed to store encrypted threshold FHE keys to backup storage for request {key_id}: {e}");
                    }
                    backup_result.is_ok()
                }
                None => {
                    tracing::error!("No backup vault configured despite a current backup key being set! This should never happen! Skipping backup key material storage for request {key_id}");
                    false
                }
            }
        };

        // TODO since each thread is locking a storage component and they are run concurrently in a single thread
        // don't we risk deadlocks with parallel executions since we have no guaranteed on the lock order?
        let (r1, r2, r3, r4) = tokio::join!(f1, f2, f3, f4);

        // Try to store the new data
        tracing::info!("Storing DKG objects for key ID {}", key_id);

        let meta_update_result = guarded_meta_storage.update(key_id, Ok(info));
        if let Err(e) = &meta_update_result {
            tracing::error!(
                "Error ({}) while updating KeyGen meta store for {}",
                e,
                key_id
            );
        }

        if r1 && r2 && r3 && r4 && meta_update_result.is_ok() {
            // updating the cache is not critical to system functionality,
            // so we do not consider it as an error
            {
                let mut guarded_pk_cache = self.inner.pk_cache.write().await;
                let previous = guarded_pk_cache.insert(
                    *key_id,
                    WrappedPublicKeyOwned::Compact(fhe_key_set.public_key.clone()),
                );
                if previous.is_some() {
                    tracing::warn!("PK already exists in pk_cache for {}, overwriting", key_id);
                } else {
                    tracing::debug!("Added new PK to pk_cache for {}", key_id);
                }
            }
            {
                let mut guarded_fhe_keys = self.fhe_keys.write().await;
                let previous = guarded_fhe_keys.insert(*key_id, threshold_fhe_keys);
                if previous.is_some() {
                    tracing::warn!(
                        "Threshold FHE keys already exist in cache for {}, overwriting",
                        key_id
                    );
                } else {
                    tracing::debug!("Added new threshold FHE keys to cache for {}", key_id);
                }
            }
            tracing::info!("Finished DKG for Request Id {key_id}.");
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might be
            // because the data did not get created
            // In any case, we can't do much.
            tracing::warn!(
                "Failed to ensure existence of threshold key material for request with ID: {}",
                key_id
            );
            self.purge_key_material(key_id, guarded_meta_storage).await;
        }
    }

    /// Read the key materials for decryption in the threshold case.
    /// The object [ThresholdFheKeys] is big so
    /// we return a lock guard instead of the whole object to avoid copying.
    ///
    /// This function only uses the cache. If there's a chance that
    /// the key is not in the cache, consider calling [refresh_threshold_fhe_keys] first.
    pub async fn read_guarded_threshold_fhe_keys_from_cache(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>>
    {
        CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
            req_id,
            self.fhe_keys.clone(),
        )
        .await
    }

    /// Refresh the key materials for decryption in the threshold case.
    /// That is, if the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    /// The object [ThresholdFheKeys] is big so
    /// we return a lock guard instead of the whole object.
    ///
    /// Developers: try not to interleave calls to [refresh_threshold_fhe_keys]
    /// with calls to [read_threshold_fhe_keys] on the same tokio task
    /// since it's easy to deadlock, it's a consequence of RwLocks.
    /// see https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html#method.read_owned
    pub async fn refresh_threshold_fhe_keys(&self, req_id: &RequestId) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS>::refresh_crypto_material::<ThresholdFheKeys, _>(
            self.fhe_keys.clone(),
            req_id,
            self.inner.private_storage.clone(),
        )
        .await
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
        req_id: &RequestId,
        pub_key: BackupPublicKey,
        recovery_request: RecoveryRequest,
        custodian_context: InternalCustodianContext,
        commitments: BackupCommitments,
        meta_store: Arc<RwLock<CustodianMetaStore>>,
    ) {
        // Lock the storage needed in correct order to avoid deadlocks.
        let mut private_storage_guard = self.inner.private_storage.lock().await;
        let mut public_storage_guard = self.inner.public_storage.lock().await;

        let priv_storage_future = async {
            let custodian_context_store_res = store_versioned_at_request_id(
                &mut (*private_storage_guard),
                req_id,
                &custodian_context,
                &PrivDataType::CustodianInfo.to_string(),
            )
            .await;
            if let Err(e) = &custodian_context_store_res {
                tracing::error!(
                    "Failed to store custodian context to private storage for request {}: {}",
                    req_id,
                    e
                );
            }
            custodian_context_store_res.is_ok()
        };
        let pub_storage_future = async {
            let recovery_store_result = store_versioned_at_request_id(
                &mut (*public_storage_guard),
                req_id,
                &recovery_request,
                &PubDataType::RecoveryRequest.to_string(),
            )
            .await;
            if let Err(e) = &recovery_store_result {
                tracing::error!(
                    "Failed to store recovery request to the public storage for request {}: {}",
                    req_id,
                    e
                );
            }
            let commit_store_result = store_versioned_at_request_id(
                &mut (*public_storage_guard),
                req_id,
                &commitments,
                &PubDataType::Commitments.to_string(),
            )
            .await;
            if let Err(e) = &recovery_store_result {
                tracing::error!(
                    "Failed to store commitments to the public storage for request {}: {}",
                    req_id,
                    e
                );
            }
            recovery_store_result.is_ok() && commit_store_result.is_ok()
        };
        let (priv_res, pub_res) = tokio::join!(priv_storage_future, pub_storage_future);
        {
            // Update meta store
            // First we insert the request ID
            let mut guarded_meta_store = meta_store.write().await;
            // Whether things fail or not we can't do much
            match guarded_meta_store.insert(req_id) {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("Failed to insert request ID {req_id} into meta store: {e}",);
                    self.purge_backup_material(req_id, guarded_meta_store).await;
                    return;
                }
            };
            // If everything is ok, we update the meta store with a success
            if priv_res && pub_res {
                if let Err(e) = guarded_meta_store.update(req_id, Ok(custodian_context)) {
                    tracing::error!("Failed to update meta store for request {req_id}: {e}");
                    self.purge_backup_material(req_id, guarded_meta_store).await;
                }
            } else {
                self.purge_backup_material(req_id, guarded_meta_store).await;
                tracing::error!(
                    "Failed to store backup keys for request {}: priv_res: {}, pub_res: {}",
                    req_id,
                    priv_res,
                    pub_res,
                );
            }
        }
        // Finally update the current backup key in the storage
        {
            match self.inner.backup_vault {
                Some(ref vault) => {
                    let mut guarded_backup_vault = vault.lock().await;
                    match &mut guarded_backup_vault.keychain {
                        Some(keychain) => {
                            if let KeychainProxy::SecretSharing(sharing_chain) = keychain {
                                // Store the public key in the secret sharing keychain
                                sharing_chain.set_backup_enc_key(pub_key);
                            }
                        },
                        None => todo!(),
                    }
                },
                None => tracing::warn!(
                    "No backup vault configured, skipping setting backup encryption key for request {req_id}"
                ),
            }
        }
    }

    pub async fn purge_backup_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<'_, CustodianMetaStore>,
    ) {
        self.inner
            .purge_backup_material(req_id, guarded_meta_store)
            .await
    }

    pub async fn purge_key_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<
            '_,
            MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>,
        >,
    ) {
        self.inner
            .purge_key_material(req_id, guarded_meta_store)
            .await
    }

    pub async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<SignedPubDataHandleInternal>>,
    ) {
        self.inner
            .purge_crs_material(req_id, guarded_meta_store)
            .await
    }

    /// Note that we're not storing a shortint decompression key
    pub async fn write_decompression_key_with_meta_store(
        &self,
        req_id: &RequestId,
        decompression_key: DecompressionKey,
        info: HashMap<PubDataType, SignedPubDataHandleInternal>,
        meta_store: Arc<RwLock<MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>>>,
    ) {
        self.inner
            .write_decompression_key_with_meta_store(req_id, decompression_key, info, meta_store)
            .await
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static> Clone
    for ThresholdCryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
    From<&ThresholdCryptoMaterialStorage<PubS, PrivS>> for CryptoMaterialStorage<PubS, PrivS>
{
    fn from(value: &ThresholdCryptoMaterialStorage<PubS, PrivS>) -> Self {
        value.inner.clone()
    }
}
