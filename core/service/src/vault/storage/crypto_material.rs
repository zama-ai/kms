//! This module has storage implementation for cryptographic material used in the KMS.
//! Usually there is only one flavour of function for writing into the storage,
//! e.g., write_XXX_with_meta_store. But there are multiple flavours of reading operations
//! read_cloned_XXX_from_cache, read_guarded_XXX_from_cache and read_cloned_XXX.
//! When using read_XXX_from_cache or read_guarded_XXX_from_cache,
//! the persistent storage backend is not used, to ensure the cache is fresh,
//! please use refresh_XXX. read_cloned_XXX will first try to read from the cache
//! and if it does not exist, it will try to read from the persistent storage.
//! Not all functions are implemented for all operations, they're implemented as needed
//! but not difficult to add.
use super::{
    read_pk_at_request_id, read_versioned_at_request_id, store_pk_at_request_id,
    store_versioned_at_request_id, Storage,
};
use crate::{
    anyhow_error_and_warn_log,
    engine::{base::KmsFheKeyHandles, threshold::service_real::ThresholdFheKeys},
    util::meta_store::MetaStore,
    vault::storage::{delete_at_request_id, delete_pk_at_request_id},
};
use kms_grpc::kms::v1::RequestId;
use kms_grpc::rpc_types::{
    PrivDataType, PubDataType, SignedPubDataHandleInternal, WrappedPublicKey, WrappedPublicKeyOwned,
};
use std::{collections::HashMap, sync::Arc};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use threshold_fhe::execution::endpoints::keygen::FhePubKeySet;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

#[tonic::async_trait]
trait CryptoMaterialReader {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
        Self: Sized;
}

#[tonic::async_trait]
impl CryptoMaterialReader for ThresholdFheKeys {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PrivDataType::FheKeyInfo.to_string())
            .await
    }
}

#[tonic::async_trait]
impl CryptoMaterialReader for WrappedPublicKeyOwned {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_pk_at_request_id(storage, request_id).await
    }
}

#[tonic::async_trait]
impl CryptoMaterialReader for KmsFheKeyHandles {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PrivDataType::FheKeyInfo.to_string())
            .await
    }
}

#[tonic::async_trait]
impl CryptoMaterialReader for CompactPkeCrs {
    async fn read_from_storage<S>(storage: &S, request_id: &RequestId) -> anyhow::Result<Self>
    where
        S: Storage + Send + Sync + 'static,
    {
        read_versioned_at_request_id(storage, request_id, &PubDataType::CRS.to_string()).await
    }
}

/// A cached generic storage entity for the threshold KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub(crate) struct ThresholdCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    inner: CryptoMaterialStorage<PubS, PrivS, BackS>,
    fhe_keys: Arc<RwLock<HashMap<RequestId, ThresholdFheKeys>>>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>
{
    /// Create a new cached storage device for threshold KMS.
    pub(crate) fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_storage: Option<BackS>,
        pk_cache: HashMap<RequestId, WrappedPublicKeyOwned>,
        fhe_keys: HashMap<RequestId, ThresholdFheKeys>,
    ) -> Self {
        Self {
            inner: CryptoMaterialStorage {
                public_storage: Arc::new(Mutex::new(public_storage)),
                private_storage: Arc::new(Mutex::new(private_storage)),
                backup_storage: backup_storage.map(|x| Arc::new(Mutex::new(x))),
                pk_cache: Arc::new(RwLock::new(pk_cache)),
            },
            fhe_keys: Arc::new(RwLock::new(fhe_keys)),
        }
    }

    /// Get an Arc of the private storage device.
    pub(crate) fn get_private_storage(&self) -> Arc<Mutex<PrivS>> {
        Arc::clone(&self.inner.private_storage)
    }

    /// Write the CRS to the storage backend as well as the cahce,
    /// and update the [meta_store] to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub(crate) async fn write_crs_with_meta_store(
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
    pub(crate) async fn write_threshold_keys_with_meta_store(
        &self,
        req_id: &RequestId,
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
            let mut back_storage = match self.inner.backup_storage {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };
            let store_is_ok = store_versioned_at_request_id(
                &mut (*priv_storage),
                req_id,
                &threshold_fhe_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_ok();
            let backup_is_ok = match back_storage {
                Some(ref mut x) => Some(
                    store_versioned_at_request_id(
                        &mut (**x),
                        req_id,
                        &threshold_fhe_keys,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await
                    .is_ok(),
                ),
                None => None,
            }
            .unwrap_or(true);
            store_is_ok && backup_is_ok
        };
        let f2 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            store_pk_at_request_id(
                &mut (*pub_storage),
                req_id,
                WrappedPublicKey::Compact(&fhe_key_set.public_key),
            )
            .await
            .is_ok()
        };
        let f3 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            store_versioned_at_request_id(
                &mut (*pub_storage),
                req_id,
                &fhe_key_set.server_key,
                &PubDataType::ServerKey.to_string(),
            )
            .await
            .is_ok()
        };

        let (r1, r2, r3) = tokio::join!(f1, f2, f3);

        //Try to store the new data
        tracing::info!("Storing DKG objects for request {}", req_id);
        if r1
            && r2
            && r3
            && guarded_meta_storage
                .update(req_id, Ok(info))
                .inspect_err(|e| {
                    tracing::error!(
                        "Error ({e}) while updating KeyGen meta store for {}",
                        req_id
                    )
                })
                .is_ok()
        {
            // updating the cache is not critical to system functionality,
            // so we do not consider it as an error
            {
                let mut guarded_pk_cache = self.inner.pk_cache.write().await;
                if guarded_pk_cache
                    .insert(
                        req_id.clone(),
                        WrappedPublicKeyOwned::Compact(fhe_key_set.public_key.clone()),
                    )
                    .is_some()
                {
                    tracing::warn!("PK already exists in pk_cache for {}", req_id)
                }
            }
            {
                let mut guarded_fhe_keys = self.fhe_keys.write().await;
                guarded_fhe_keys.insert(req_id.clone(), threshold_fhe_keys);
            }
            tracing::info!("Finished DKG for Request Id {req_id}.");
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might be
            // because the data did not get created
            // In any case, we can't do much.
            tracing::warn!(
                "Failed to ensure existance of threshold key material for request with ID: {}",
                req_id
            );
            self.purge_key_material(req_id, guarded_meta_storage).await;
        }
    }

    /// Read the key materials for decryption in the threshold case.
    /// The object [ThresholdFheKeys] is big so
    /// we return a lock guard instead of the whole object.
    /// This function only uses the cache, if there's a chance that
    /// the key is not in the cache, then consider calling [refresh_threshold_fhe_keys].
    pub(crate) async fn read_guarded_threshold_fhe_keys_from_cache(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<RequestId, ThresholdFheKeys>, ThresholdFheKeys>>
    {
        CryptoMaterialStorage::<PubS, PrivS, BackS>::read_guarded_crypto_material_from_cache(
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
    pub(crate) async fn refresh_threshold_fhe_keys(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS, BackS>::refresh_crypto_material::<ThresholdFheKeys, _>(
            self.fhe_keys.clone(),
            req_id,
            self.inner.private_storage.clone(),
        )
        .await
    }

    pub(crate) async fn purge_key_material(
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

    pub(crate) async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<SignedPubDataHandleInternal>>,
    ) {
        self.inner
            .purge_crs_material(req_id, guarded_meta_store)
            .await
    }

    /// Note that we're not storing a shortint decompression key
    pub(crate) async fn write_decompression_key_with_meta_store(
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

/// A cached generic storage entity for the centralized KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub(crate) struct CentralizedCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    inner: CryptoMaterialStorage<PubS, PrivS, BackS>,
    fhe_keys: Arc<RwLock<HashMap<RequestId, KmsFheKeyHandles>>>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>
{
    /// Create a new cached storage device for threshold KMS.
    pub(crate) fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_storage: Option<BackS>,
        pk_cache: HashMap<RequestId, WrappedPublicKeyOwned>,
        fhe_keys: HashMap<RequestId, KmsFheKeyHandles>,
    ) -> Self {
        Self {
            inner: CryptoMaterialStorage {
                public_storage: Arc::new(Mutex::new(public_storage)),
                private_storage: Arc::new(Mutex::new(private_storage)),
                backup_storage: backup_storage.map(|x| Arc::new(Mutex::new(x))),
                pk_cache: Arc::new(RwLock::new(pk_cache)),
            },
            fhe_keys: Arc::new(RwLock::new(fhe_keys)),
        }
    }

    /// Write the CRS to the storage backend as well as the cahce,
    /// and update the [meta_store] to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub(crate) async fn write_crs_with_meta_store(
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

    pub(crate) async fn write_decompression_key_with_meta_store(
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

    /// Write the key materials (result of a keygen) to storage and cache
    /// for the centralized KMS.
    /// The [meta_store] is updated to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub(crate) async fn write_centralized_keys_with_meta_store(
        &self,
        req_id: &RequestId,
        key_info: KmsFheKeyHandles,
        fhe_key_set: FhePubKeySet,
        meta_store: Arc<RwLock<MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        // Try to store the new data
        tracing::info!(
            "Attempting to store centralized keygen material for request {}",
            req_id
        );

        let f1 = async {
            let mut priv_storage = self.inner.private_storage.lock().await;
            // can't map() because async closures aren't stable in Rust
            let mut back_storage = match self.inner.backup_storage {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };
            let store_is_ok = store_versioned_at_request_id(
                &mut (*priv_storage),
                req_id,
                &key_info,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_ok();
            let backup_is_ok = match back_storage {
                Some(ref mut x) => Some(
                    store_versioned_at_request_id(
                        &mut (**x),
                        req_id,
                        &key_info,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await
                    .is_ok(),
                ),
                None => None,
            }
            .unwrap_or(true);
            store_is_ok && backup_is_ok
        };
        let f2 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            store_pk_at_request_id(
                &mut (*pub_storage),
                req_id,
                WrappedPublicKey::Compact(&fhe_key_set.public_key),
            )
            .await
            .is_ok()
        };
        let f3 = async {
            let mut pub_storage = self.inner.public_storage.lock().await;
            store_versioned_at_request_id(
                &mut (*pub_storage),
                req_id,
                &fhe_key_set.server_key,
                &PubDataType::ServerKey.to_string(),
            )
            .await
            .is_ok()
        };
        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        if r1
            && r2
            && r3
            && guarded_meta_store
                .update(req_id, Ok(key_info.public_key_info.to_owned()))
                .inspect_err(|e| {
                    tracing::error!("Error ({e}) while updating PK meta store for {}", req_id)
                })
                .is_ok()
        {
            // updating the cache is not critical to system functionality,
            // so we do not consider it as an error
            {
                let mut guarded_pk_cache = self.inner.pk_cache.write().await;
                if guarded_pk_cache
                    .insert(
                        req_id.clone(),
                        WrappedPublicKeyOwned::Compact(fhe_key_set.public_key.clone()),
                    )
                    .is_some()
                {
                    tracing::warn!("PK already exists in pk_cache for {}", req_id)
                }
            }
            {
                let mut guarded_fhe_keys = self.fhe_keys.write().await;
                guarded_fhe_keys.insert(req_id.clone(), key_info);
                tracing::info!(
                    "Successfully stored centralized keygen material for request {}",
                    req_id
                );
            }
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since
            // it might be because the data did not get created
            // In any case, we can't do much.
            self.inner
                .purge_key_material(req_id, guarded_meta_store)
                .await;
        }
    }

    /// Read the key materials for decryption in the centralized case.
    pub(crate) async fn read_cloned_centralized_fhe_keys_from_cache(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<KmsFheKeyHandles> {
        CryptoMaterialStorage::<PubS, PrivS, BackS>::read_cloned_crypto_material_from_cache(
            self.fhe_keys.clone(),
            req_id,
        )
        .await
    }

    /// Refresh the key materials for decryption in the centralized case.
    /// That is, if the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    ///
    /// Developers: try not to interleave calls to [refresh_centralized_fhe_keys]
    /// with calls to [read_centralized_fhe_keys] on the same tokio task
    /// since it's easy to deadlock, it's a consequence of RwLocks.
    /// see https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html#method.read_owned
    pub(crate) async fn refresh_centralized_fhe_keys(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS, BackS>::refresh_crypto_material::<KmsFheKeyHandles, _>(
            self.fhe_keys.clone(),
            req_id,
            self.inner.private_storage.clone(),
        )
        .await
    }

    #[cfg(test)]
    pub(crate) async fn set_wrong_cached_client_key(
        &self,
        key_handle: &RequestId,
        wrong_client_key: tfhe::ClientKey,
    ) -> anyhow::Result<()> {
        let mut key_info = self.fhe_keys.write().await;
        let x: &mut KmsFheKeyHandles = key_info.get_mut(key_handle).unwrap();
        let wrong_handles = KmsFheKeyHandles {
            client_key: wrong_client_key,
            decompression_key: x.decompression_key.clone(),
            public_key_info: x.public_key_info.clone(),
        };
        *x = wrong_handles;
        Ok(())
    }
}

/// A cached generic storage entity for the common data strcutures
/// used by both the centralized and the threshold KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub(crate) struct CryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    // Storage for data that is supposed to be readable by anyone on the internet,
    // but _may_ be suseptible to malicious modifications.
    public_storage: Arc<Mutex<PubS>>,
    // Storage for data that is supposed to only be readable, writable and modifiable by the entity
    // owner and where any modification will be detected.
    private_storage: Arc<Mutex<PrivS>>,
    // Optional second private storage for backup and recovery
    backup_storage: Option<Arc<Mutex<BackS>>>,
    // Map storing the already generated public keys.
    pk_cache: Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > CryptoMaterialStorage<PubS, PrivS, BackS>
{
    /// Tries to delete all the types of key material related to a specific [RequestId].
    pub(crate) async fn purge_key_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<
            '_,
            MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>,
        >,
    ) {
        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
            delete_pk_at_request_id(&mut (*pub_storage), req_id)
                .await
                .is_err()
        };
        let f2 = async {
            let mut pub_storage = self.public_storage.lock().await;

            delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::ServerKey.to_string(),
            )
            .await
            .is_err()
        };
        let f3 = async {
            let mut priv_storage = self.private_storage.lock().await;
            // can't map() because async closures aren't stable in Rust
            let back_storage = match self.backup_storage {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };
            let del_err_1 = delete_at_request_id(
                &mut (*priv_storage),
                req_id,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await
            .is_err();
            let del_err_2 = match back_storage {
                Some(mut x) => {
                    delete_at_request_id(&mut (*x), req_id, &PrivDataType::FheKeyInfo.to_string())
                        .await
                        .is_err()
                }
                None => false,
            };
            del_err_1 || del_err_2
        };
        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        if r1 || r2 || r3 {
            tracing::error!("Failed to delete key material for request {}", req_id);
        } else {
            tracing::info!("Deleted all key material for request {}", req_id);
        }
        if guarded_meta_store
            .update(req_id, Err("DKG failed during storage".to_string()))
            .is_err()
        {
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
    pub(crate) async fn write_crs_with_meta_store(
        &self,
        req_id: &RequestId,
        pp: CompactPkeCrs,
        crs_info: SignedPubDataHandleInternal,
        meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        let f1 = async {
            // let private_storage = self.private_storage.clone();
            let mut priv_storage = self.private_storage.lock().await;
            store_versioned_at_request_id(
                &mut (*priv_storage),
                req_id,
                &crs_info,
                &PrivDataType::CrsInfo.to_string(),
            )
            .await
            .is_ok()
        };
        let f2 = async {
            let mut pub_storage = self.public_storage.lock().await;
            store_versioned_at_request_id(
                &mut (*pub_storage),
                req_id,
                &pp,
                &PubDataType::CRS.to_string(),
            )
            .await
            .is_ok()
        };
        let (r1, r2) = tokio::join!(f1, f2);

        if r1
            && r2
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

    pub(crate) async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<'_, MetaStore<SignedPubDataHandleInternal>>,
    ) {
        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
            delete_at_request_id(&mut (*pub_storage), req_id, &PubDataType::CRS.to_string())
                .await
                .is_err()
        };
        let f2 = async {
            let mut priv_storage = self.private_storage.lock().await;
            delete_at_request_id(
                &mut (*priv_storage),
                req_id,
                &PrivDataType::CrsInfo.to_string(),
            )
            .await
            .is_err()
        };
        let (r1, r2) = tokio::join!(f1, f2);
        if r1 || r2 {
            tracing::error!("Failed to delete crs material for request {}", req_id);
        } else {
            tracing::info!("Deleted all crs material for request {}", req_id);
        }
        // We cannot do much if updating the meta store fails at this point,
        // so just log an error.
        let r3 = guarded_meta_store
            .update(
                req_id,
                Err(format!(
                    "Failed to store CRS data to public storage for ID {}",
                    req_id
                )),
            )
            .inspect(|e| tracing::error!("Removing CRS from meta stored failed with error {:?}", e))
            .is_err();

        // We cannot do much if updating CRS cache fails at this point,
        // so just log an error.
        if r3 {
            tracing::error!("Failed to remove crs cached data for request {}", req_id);
        } else {
            tracing::info!("Removed all crs cached data for request {}", req_id);
        }
    }

    pub(crate) async fn write_decompression_key_with_meta_store(
        &self,
        req_id: &RequestId,
        decompression_key: DecompressionKey,
        info: HashMap<PubDataType, SignedPubDataHandleInternal>,
        meta_store: Arc<RwLock<MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
            store_versioned_at_request_id(
                &mut (*pub_storage),
                req_id,
                &decompression_key,
                &PubDataType::DecompressionKey.to_string(),
            )
            .await
            .is_ok()
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
            let _ = delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::DecompressionKey.to_string(),
            )
            .await
            .inspect_err(|e| {
                tracing::error!(
                    "Error ({e}) while deletingdecompression key meta store for {}",
                    req_id
                )
            });
        }
    }

    /// Read the public key from a cache, if it does not exist,
    /// attempt to read it from the public storage backend.
    #[cfg(test)]
    async fn read_cloned_pk(&self, req_id: &RequestId) -> anyhow::Result<WrappedPublicKeyOwned> {
        Self::read_cloned_crypto_material::<WrappedPublicKeyOwned, _>(
            self.pk_cache.clone(),
            req_id,
            self.public_storage.clone(),
        )
        .await
    }

    #[cfg(test)]
    async fn read_cloned_crypto_material<T, S>(
        cache: Arc<RwLock<HashMap<RequestId, T>>>,
        req_id: &RequestId,
        storage: Arc<Mutex<S>>,
    ) -> anyhow::Result<T>
    where
        T: CryptoMaterialReader + Clone,
        S: Storage + Send + Sync + 'static,
    {
        let out = {
            let cache_guard = cache.read().await;
            cache_guard.get(req_id).cloned()
        };

        match out {
            Some(pk) => Ok(pk),
            None => {
                let pub_storage = storage.lock().await;
                let pk = T::read_from_storage(&(*pub_storage), req_id)
                    .await
                    .inspect_err(|e| {
                        tracing::error!("Failed to read CRS with the handle {} ({e})", req_id);
                    })?;

                let mut write_cache_guard = cache.write().await;
                write_cache_guard.insert(req_id.clone(), pk.clone());
                Ok(pk)
            }
        }
    }

    async fn read_guarded_crypto_material_from_cache<T: Clone + std::fmt::Debug>(
        req_id: &RequestId,
        fhe_keys: Arc<RwLock<HashMap<RequestId, T>>>,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<RequestId, T>, T>> {
        // Returning a OwnedRwLockReadGuard just saves some data-copying
        // if the value is already in the cache.
        let fhe_keys = fhe_keys.clone();
        let guard = fhe_keys.read_owned().await;
        OwnedRwLockReadGuard::try_map(guard, |m| m.get(req_id))
            .map_err(|e| anyhow::anyhow!("OwnedRwLockReadGuard::try_map failed with error {e:?}"))
    }

    async fn read_cloned_crypto_material_from_cache<T: Clone>(
        cache: Arc<RwLock<HashMap<RequestId, T>>>,
        req_id: &RequestId,
    ) -> anyhow::Result<T> {
        let out = {
            let guard = cache.read().await;
            guard.get(req_id).cloned()
        };
        out.ok_or(anyhow_error_and_warn_log(format!(
            "Key handles are not in the cache for ID {}",
            req_id
        )))
    }

    async fn refresh_crypto_material<T, S>(
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
            let new_fhe_keys = T::read_from_storage(&(*storage), req_id).await?;
            let mut guarded_fhe_keys = cache.write().await;
            guarded_fhe_keys.insert(req_id.clone(), new_fhe_keys);
        }

        Ok(())
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > Clone for CryptoMaterialStorage<PubS, PrivS, BackS>
{
    fn clone(&self) -> Self {
        Self {
            public_storage: Arc::clone(&self.public_storage),
            private_storage: Arc::clone(&self.private_storage),
            backup_storage: self.backup_storage.as_ref().map(Arc::clone),
            pk_cache: Arc::clone(&self.pk_cache),
        }
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > Clone for CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > Clone for ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > From<&CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>>
    for CryptoMaterialStorage<PubS, PrivS, BackS>
{
    fn from(value: &CentralizedCryptoMaterialStorage<PubS, PrivS, BackS>) -> Self {
        value.inner.clone()
    }
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > From<&ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>>
    for CryptoMaterialStorage<PubS, PrivS, BackS>
{
    fn from(value: &ThresholdCryptoMaterialStorage<PubS, PrivS, BackS>) -> Self {
        value.inner.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::base::derive_request_id;
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::WrappedPublicKey;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tfhe::{shortint::ClassicPBSParameters, CompactPublicKey, ConfigBuilder, ServerKey};
    use threshold_fhe::execution::{
        endpoints::keygen::FhePubKeySet,
        tfhe_internals::{
            parameters::DKGParams,
            test_feature::{gen_key_set, keygen_all_party_shares},
        },
    };
    use tokio::sync::{Mutex, RwLock};

    use crate::{
        consts::TEST_PARAM,
        engine::{
            base::{gen_sig_keys, KmsFheKeyHandles},
            centralized::central_kms::async_generate_crs,
            threshold::service_real::ThresholdFheKeys,
        },
        util::meta_store::MetaStore,
        vault::storage::{
            crypto_material::{
                CentralizedCryptoMaterialStorage, CryptoMaterialStorage,
                ThresholdCryptoMaterialStorage,
            },
            ram::{FailingRamStorage, RamStorage},
            store_pk_at_request_id, StorageType,
        },
    };

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn write_crs() {
        // write the CRS, first try with storage that are functional
        // then try to write into a failing storage and expect an error
        let pub_storage = Arc::new(Mutex::new(FailingRamStorage::new(StorageType::PUB, 100)));
        let crypto_storage = CryptoMaterialStorage {
            public_storage: pub_storage.clone(),
            private_storage: Arc::new(Mutex::new(RamStorage::new(StorageType::PRIV))),
            backup_storage: None as Option<Arc<Mutex<RamStorage>>>,
            pk_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pp, crs_info) = async_generate_crs(&sig_sk, rng, TEST_PARAM, Some(1), None)
            .await
            .unwrap();
        let req_id = derive_request_id("write_crs").unwrap();

        let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

        // writing to an empty meta store should fail
        crypto_storage
            .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
            .await;

        // update the meta store and we should be ok
        {
            let meta_store = meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&req_id).unwrap();
        }
        crypto_storage
            .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
            .await;
        // writing the same thing should fail because the
        // meta store disallow updating a cell that is set
        crypto_storage
            .write_crs_with_meta_store(&req_id, pp.clone(), crs_info.clone(), meta_store.clone())
            .await;

        // writing on a failed storage device should fail
        {
            let mut storage_guard = pub_storage.lock().await;
            storage_guard.set_available_writes(0);
        }
        let new_req_id = derive_request_id("write_crs_2").unwrap();
        crypto_storage
            .write_crs_with_meta_store(&new_req_id, pp, crs_info, meta_store.clone())
            .await;
        assert!(logs_contain("storage failed!"));
        assert!(logs_contain("Deleted all crs material for request"));

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
            assert!(!guard.exists(&new_req_id));
        }
    }

    #[tokio::test]
    async fn read_public_key() {
        // it doens't matter if we use centralized or threshold
        // the public key reading logic is the same
        let crypto_storage = CentralizedCryptoMaterialStorage::new(
            FailingRamStorage::new(StorageType::PUB, 100),
            RamStorage::new(StorageType::PUB),
            None as Option<RamStorage>,
            HashMap::new(),
            HashMap::new(),
        );

        let pub_storage = crypto_storage.inner.public_storage.clone();
        let pk_cache = crypto_storage.inner.pk_cache.clone();

        let pbs_params: ClassicPBSParameters = TEST_PARAM
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let config = ConfigBuilder::with_custom_parameters(pbs_params);
        let client_key = tfhe::ClientKey::generate(config);
        let public_key = CompactPublicKey::new(&client_key);

        let req_id = derive_request_id("read_keys").unwrap();
        {
            let pub_storage = pub_storage.clone();
            let mut s = pub_storage.lock().await;
            store_pk_at_request_id(&mut (*s), &req_id, WrappedPublicKey::Compact(&public_key))
                .await
                .unwrap();
        }

        // reading the public key without cache should succeed
        let _pk = crypto_storage.inner.read_cloned_pk(&req_id).await.unwrap();

        // check that there's an item in the cache
        let guard = pk_cache.read().await;
        assert!(guard.contains_key(&req_id));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn write_central_keys() {
        let param = TEST_PARAM;
        let crypto_storage = CentralizedCryptoMaterialStorage::new(
            FailingRamStorage::new(StorageType::PUB, 100),
            RamStorage::new(StorageType::PUB),
            None as Option<RamStorage>,
            HashMap::new(),
            HashMap::new(),
        );
        let pub_storage = crypto_storage.inner.public_storage.clone();

        let req_id = derive_request_id("write_central_keys").unwrap();

        let pbs_params: ClassicPBSParameters =
            param.get_params_basics_handle().to_classic_pbs_parameters();
        let sns_params = match param {
            DKGParams::WithoutSnS(_) => panic!("expect sns"),
            DKGParams::WithSnS(dkgparams_sn_s) => dkgparams_sn_s.sns_params,
        };
        let config =
            ConfigBuilder::with_custom_parameters(pbs_params).enable_noise_squashing(sns_params);
        let client_key = tfhe::ClientKey::generate(config);
        let public_key = CompactPublicKey::new(&client_key);
        let server_key = ServerKey::new(&client_key);
        let key_info = KmsFheKeyHandles {
            client_key,
            decompression_key: None,
            public_key_info: HashMap::new(),
        };
        let fhe_key_set = FhePubKeySet {
            public_key,
            server_key,
        };

        let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));

        // write to an empty meta store should fail
        crypto_storage
            .write_centralized_keys_with_meta_store(
                &req_id,
                key_info.clone(),
                fhe_key_set.clone(),
                meta_store.clone(),
            )
            .await;
        assert!(!logs_contain("storage failed!"));
        assert!(logs_contain("Deleted all key material for request"));

        // update the meta store and the write should be ok
        {
            let meta_store = meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&req_id).unwrap();
        }
        crypto_storage
            .write_centralized_keys_with_meta_store(
                &req_id,
                key_info.clone(),
                fhe_key_set.clone(),
                meta_store.clone(),
            )
            .await;

        // writing the same thing should fail because the
        // meta store disallow updating a cell that is set
        crypto_storage
            .write_centralized_keys_with_meta_store(
                &req_id,
                key_info.clone(),
                fhe_key_set.clone(),
                meta_store.clone(),
            )
            .await;
        // Check that the approach fails with the expected error message
        assert!(logs_contain("while updating PK meta store for"));

        // write on a failed storage device should fail
        {
            let mut storage_guard = pub_storage.lock().await;
            storage_guard.set_available_writes(0);
        }
        let new_req_id = derive_request_id("write_central_keys_2").unwrap();
        crypto_storage
            .write_centralized_keys_with_meta_store(
                &new_req_id,
                key_info,
                fhe_key_set,
                meta_store.clone(),
            )
            .await;
        assert!(logs_contain("storage failed!"));
        assert!(logs_contain("Deleted all key material for request"));

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
            assert!(!guard.exists(&new_req_id));
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn write_threshold_empty_update() {
        let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
        let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
        let req_id = derive_request_id("write_threshold_empty_update").unwrap();

        // Check no errors happened
        assert!(!logs_contain(&format!(
            "while updating KeyGen meta store for {}",
            req_id
        )));
        assert!(!logs_contain(&format!(
            "PK already exists in pk_cache for {}",
            req_id
        )));
        assert!(!logs_contain(&format!(
            "Failed to ensure existance of threshold key material for {}.",
            req_id
        )));
        // write to an empty meta store should fail
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;
        // Check that the expected error happened
        assert!(logs_contain("while updating KeyGen meta store for"));

        // update the meta store and the write should be ok
        {
            let meta_store = meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&req_id).unwrap();
        }
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
        }
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn write_threshold_keys_meta_update() {
        let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
        let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
        let req_id = derive_request_id("write_threshold_keys_meta_update").unwrap();

        // update the meta store and the write should be ok
        {
            let meta_store = meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&req_id).unwrap();
        }
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;
        // Check that no errors were logged
        assert!(!logs_contain(&format!(
            "while updating KeyGen meta store for {}",
            req_id
        )));
        assert!(!logs_contain(&format!(
            "PK already exists in pk_cache for {}",
            req_id
        )));
        assert!(logs_contain(&format!(
            "Finished DKG for Request Id {}.",
            req_id
        )));

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
        }

        // writing the same thing should fail because the
        // meta store disallow updating a cell that is set
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;
        assert!(logs_contain("while updating KeyGen meta store for"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn write_threshold_keys_failed_storage() {
        let (crypto_storage, threshold_fhe_keys, fhe_key_set) = setup_threshold_store();
        let meta_store = Arc::new(RwLock::new(MetaStore::new_unlimited()));
        let pub_storage = crypto_storage.inner.public_storage.clone();
        let req_id = derive_request_id("write_threshold_keys_failed_storage").unwrap();

        // update the meta store and the write should be ok
        {
            let meta_store = meta_store.clone();
            let mut guard = meta_store.write().await;
            guard.insert(&req_id).unwrap();
        }
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;
        // Check that no errors were logged
        assert!(!logs_contain(&format!(
            "while updating KeyGen meta store for {}",
            req_id
        )));
        assert!(!logs_contain(&format!(
            "PK already exists in pk_cache for {}",
            req_id
        )));
        assert!(logs_contain(&format!(
            "Finished DKG for Request Id {}.",
            req_id
        )));

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
        }

        // write on a failed storage device should fail
        {
            let mut storage_guard = pub_storage.lock().await;
            storage_guard.set_available_writes(0);
        }
        let new_req_id = derive_request_id("write_threshold_keys_failed_storage_2").unwrap();
        crypto_storage
            .write_threshold_keys_with_meta_store(
                &new_req_id,
                threshold_fhe_keys.clone(),
                fhe_key_set.clone(),
                HashMap::new(),
                meta_store.clone(),
            )
            .await;
        // Check that no errors were logged
        assert!(!logs_contain(
            "while updating KeyGen meta store for {new_req_id}"
        ));

        // check the meta store is correct
        {
            let guard = meta_store.read().await;
            assert!(guard.exists(&req_id));
            assert!(!guard.exists(&new_req_id));
        }
    }

    fn setup_threshold_store() -> (
        ThresholdCryptoMaterialStorage<FailingRamStorage, RamStorage, RamStorage>,
        ThresholdFheKeys,
        FhePubKeySet,
    ) {
        let crypto_storage = ThresholdCryptoMaterialStorage::new(
            FailingRamStorage::new(StorageType::PUB, 100),
            RamStorage::new(StorageType::PUB),
            None as Option<RamStorage>,
            HashMap::new(),
            HashMap::new(),
        );

        let pbs_params: ClassicPBSParameters = TEST_PARAM
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let mut rng = AesRng::seed_from_u64(100);
        let key_set = gen_key_set(TEST_PARAM, &mut rng);
        let key_shares = keygen_all_party_shares(
            key_set.get_raw_lwe_client_key(),
            key_set.get_raw_glwe_client_key(),
            key_set.get_raw_glwe_client_sns_key_as_lwe().unwrap(),
            pbs_params,
            &mut rng,
            4,
            1,
        )
        .unwrap();

        let fhe_key_set = key_set.public_keys.clone();

        let (integer_server_key, _, _, _, sns_key, _) =
            key_set.public_keys.server_key.clone().into_raw_parts();

        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[0].to_owned(),
            integer_server_key,
            sns_key,
            decompression_key: None,
            pk_meta_data: HashMap::new(),
        };
        (crypto_storage, threshold_fhe_keys, fhe_key_set)
    }
}
