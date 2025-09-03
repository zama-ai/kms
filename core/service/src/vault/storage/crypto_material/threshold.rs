//! Threshold cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the threshold KMS variant.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use kms_grpc::{
    rpc_types::{PrivDataType, PubDataType, WrappedPublicKey, WrappedPublicKeyOwned},
    RequestId,
};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet;

use crate::{
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata},
        threshold::service::ThresholdFheKeys,
    },
    util::meta_store::MetaStore,
    vault::{
        storage::{
            crypto_material::log_storage_success, store_pk_at_request_id,
            store_versioned_at_request_id, Storage, StorageReader,
        },
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
    /// Note that `fhe_keys` should be locked after any locking of elements in `inner`.
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
        pk_cache: HashMap<RequestId, WrappedPublicKeyOwned>,
        fhe_keys: HashMap<RequestId, ThresholdFheKeys>,
    ) -> Self {
        Self {
            inner: CryptoMaterialStorage {
                public_storage: Arc::new(Mutex::new(public_storage)),
                private_storage: Arc::new(Mutex::new(private_storage)),
                backup_vault: backup_vault.map(|x| Arc::new(Mutex::new(x))),
                pk_cache: Arc::new(RwLock::new(pk_cache)),
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
        crs_info: CrsGenMetadata,
        meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
    ) {
        self.inner
            .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
            .await
    }

    /// Check if the CRS under [req_id] exists in the storage.
    pub async fn crs_exists(&self, req_id: &RequestId) -> anyhow::Result<bool> {
        CryptoMaterialStorage::<PubS, PrivS>::crs_exists(&self.inner, req_id).await
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
        info: KeyGenMetadata,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_storage = meta_store.write().await;

        let (r1, r2, r3) = {
            // Lock the storage components in the correct order to avoid deadlocks.
            let mut pub_storage = self.inner.public_storage.lock().await;
            let mut priv_storage = self.inner.private_storage.lock().await;
            let back_vault = match self.inner.backup_vault {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };

            let f1 = async {
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
                } else {
                    log_storage_success(
                        key_id,
                        priv_storage.info(),
                        &PrivDataType::FheKeyInfo.to_string(),
                        false,
                        true,
                    );
                }
                store_result.is_ok()
            };
            let f2 = async {
                let pk_result = store_pk_at_request_id(
                    &mut (*pub_storage),
                    key_id,
                    WrappedPublicKey::Compact(&fhe_key_set.public_key),
                )
                .await;
                if let Err(e) = &pk_result {
                    tracing::error!("Failed to store public key for request {}: {}", key_id, e);
                } else {
                    log_storage_success(
                        key_id,
                        pub_storage.info(),
                        &PubDataType::PublicKey.to_string(),
                        true,
                        true,
                    );
                }
                let server_result = store_versioned_at_request_id(
                    &mut (*pub_storage),
                    key_id,
                    &fhe_key_set.server_key,
                    &PubDataType::ServerKey.to_string(),
                )
                .await;

                if let Err(e) = &server_result {
                    tracing::error!("Failed to store server key for request {}: {}", key_id, e);
                } else {
                    log_storage_success(
                        key_id,
                        pub_storage.info(),
                        &PubDataType::ServerKey.to_string(),
                        true,
                        true,
                    );
                }
                pk_result.is_ok() && server_result.is_ok()
            };
            let threshold_key_clone = threshold_fhe_keys.clone();
            let f3 = async move {
                match back_vault {
                    Some(mut guarded_backup_vault) => {
                        let backup_result = store_versioned_at_request_id(
                            &mut (*guarded_backup_vault),
                            key_id,
                            &threshold_key_clone,
                            &PrivDataType::FheKeyInfo.to_string(),
                        )
                        .await;

                        if let Err(e) = &backup_result {
                            tracing::error!("Failed to store encrypted threshold FHE keys to backup storage for request {key_id}: {e}");
                        } else {
                            log_storage_success(
                                key_id,
                                guarded_backup_vault.info(),
                                &PrivDataType::FheKeyInfo.to_string(),
                                false,
                                true,
                            );
                        }
                        backup_result.is_ok()
                    }
                    None => {
                        tracing::warn!("No backup vault configured. Skipping backup of key material for request {key_id}");
                        true
                    }
                }
            };
            tokio::join!(f1, f2, f3)
        };
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
        if r1 && r2 && r3 && meta_update_result.is_ok() {
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

    /// Check if the threshold FHE keys exist in the storage.
    pub async fn threshold_fhe_keys_exists(&self, req_id: &RequestId) -> anyhow::Result<bool> {
        CryptoMaterialStorage::<PubS, PrivS>::threshold_fhe_keys_exist(&self.inner, req_id).await
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

    /// Tries to delete all the types of key material related to a specific [RequestId].
    /// WARNING: This also deletes the BACKUP of the keys. Hence the method should should only be used as cleanup after a failed DKG.
    pub async fn purge_key_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<KeyGenMetadata>>,
    ) {
        self.inner
            .purge_key_material(req_id, guarded_meta_store)
            .await
    }

    /// Tries to delete all the types of CRS material related to a specific [RequestId].
    /// WARNING: This also deletes the BACKUP of the CRS data. Hence the method should should only be used as cleanup after a failed CRS generation.
    pub async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<CrsGenMetadata>>,
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
        info: KeyGenMetadata,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
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
