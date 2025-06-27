//! Base implementation of cryptographic material storage
//!
//! This module provides the foundational storage implementation used by
//! both centralized and threshold KMS variants.
use crate::{
    anyhow_error_and_warn_log,
    cryptography::internal_crypto_types::PrivateSigKey,
    engine::{base::KmsFheKeyHandles, context::ContextInfo, threshold::service::ThresholdFheKeys},
    util::meta_store::MetaStore,
    vault::storage::{
        delete_at_request_id, delete_pk_at_request_id, read_all_data_versioned,
        store_context_at_request_id, store_pk_at_request_id, store_versioned_at_request_id,
        Storage,
    },
};
use kms_grpc::{
    rpc_types::{
        PrivDataType, PubDataType, SignedPubDataHandleInternal, WrappedPublicKey,
        WrappedPublicKeyOwned,
    },
    RequestId,
};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use threshold_fhe::execution::endpoints::keygen::FhePubKeySet;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use super::{check_data_exists, log_storage_success, CryptoMaterialReader};

/// A cached generic storage entity for the common data structures
/// used by both the centralized and the threshold KMS.
///
/// This struct provides thread-safe access to public, private, and optional backup storage,
/// along with a cache for generated public keys. Cloning is cheap due to internal Arc usage.
pub struct CryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    /// Storage for publicly readable data (may be susceptible to malicious modifications)
    pub(crate) public_storage: Arc<Mutex<PubS>>,

    /// Storage for private data (only accessible by owner, modifications are detectable)
    pub(crate) private_storage: Arc<Mutex<PrivS>>,

    /// Optional backup storage for recovery purposes
    pub(crate) backup_storage: Option<Arc<Mutex<BackS>>>,

    /// Cache for already generated public keys
    pub(crate) pk_cache: Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>,
}

impl<PubS, PrivS, BackS> CryptoMaterialStorage<PubS, PrivS, BackS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
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
        backup_storage: Option<Arc<Mutex<BackS>>>,
        pk_cache: Option<Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>>,
    ) -> Self {
        Self {
            public_storage,
            private_storage,
            backup_storage,
            pk_cache: pk_cache.unwrap_or_else(|| Arc::new(RwLock::new(HashMap::new()))),
        }
    }

    /// Creates a CryptoMaterialStorage by wrapping the provided storages.
    pub fn from(
        public_storage: PubS,
        private_storage: PrivS,
        backup_storage: Option<BackS>,
        pk_cache: Option<Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>>,
    ) -> Self {
        Self::new(
            Arc::new(Mutex::new(public_storage)),
            Arc::new(Mutex::new(private_storage)),
            backup_storage.map(|s| Arc::new(Mutex::new(s))),
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
    pub fn get_backup_storage(&self) -> Option<Arc<Mutex<BackS>>> {
        self.backup_storage.as_ref().map(Arc::clone)
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
            &PrivDataType::FheKeyInfo.to_string(),
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
    // Storage Primitives
    // =========================

    // Simplified storage methods without metadata
    pub async fn store_private_serializable_data<T>(
        &self,
        req_id: &RequestId,
        data: &T,
        data_type: PrivDataType,
    ) -> anyhow::Result<()>
    where
        T: Serialize + tfhe::Versionize + tfhe::named::Named + Send + Sync,
        for<'a> <T as tfhe::Versionize>::Versioned<'a>: Serialize + Send + Sync,
    {
        let mut priv_storage = self.private_storage.lock().await;
        store_versioned_at_request_id(&mut *priv_storage, req_id, data, &data_type.to_string())
            .await?;

        tracing::info!(
            "Successfully stored private {} data for request ID {} in {}",
            data_type.to_string(),
            req_id,
            priv_storage.info()
        );
        Ok(())
    }

    pub async fn store_public_serializable_data<T>(
        &self,
        req_id: &RequestId,
        data: &T,
        data_type: PubDataType,
    ) -> anyhow::Result<()>
    where
        T: Serialize + tfhe::Versionize + tfhe::named::Named + Send + Sync,
        for<'a> <T as tfhe::Versionize>::Versioned<'a>: Serialize + Send + Sync,
    {
        let mut pub_storage = self.public_storage.lock().await;
        store_versioned_at_request_id(&mut *pub_storage, req_id, data, &data_type.to_string())
            .await?;

        tracing::info!(
            "Successfully stored public {} data for request ID {} in {}",
            data_type.to_string(),
            req_id,
            pub_storage.info()
        );
        Ok(())
    }

    // =========================
    // Convenience Storage Methods
    // =========================

    /// Store CRS (public parameters + private info)
    pub async fn store_crs(
        &self,
        crs_handle: &RequestId,
        public_params: &CompactPkeCrs,
        crs_info: &SignedPubDataHandleInternal,
        is_threshold: bool,
    ) -> anyhow::Result<()> {
        // Store private CRS info
        self.store_private_serializable_data(crs_handle, crs_info, PrivDataType::CrsInfo)
            .await?;
        log_storage_success(
            crs_handle,
            self.private_storage.lock().await.info(),
            "CRS data",
            false,
            is_threshold,
        );

        // Store public CRS
        self.store_public_serializable_data(crs_handle, public_params, PubDataType::CRS)
            .await?;
        log_storage_success(
            crs_handle,
            self.public_storage.lock().await.info(),
            "CRS data",
            true,
            is_threshold,
        );

        Ok(())
    }

    /// Store FHE keys (public key, server key, key info, optional private key)
    pub async fn store_fhe_keys(
        &self,
        req_id: &RequestId,
        public_keys: &FhePubKeySet,
        key_info: &KmsFheKeyHandles,
        is_threshold: bool,
        write_privkey: bool,
    ) -> anyhow::Result<()> {
        // Store key info
        self.store_private_serializable_data(req_id, key_info, PrivDataType::FheKeyInfo)
            .await?;
        log_storage_success(
            req_id,
            self.private_storage.lock().await.info(),
            "key data",
            false,
            is_threshold,
        );

        // Optionally store private key
        if write_privkey {
            self.store_private_serializable_data(
                req_id,
                &key_info.client_key,
                PrivDataType::FhePrivateKey,
            )
            .await?;
            log_storage_success(
                req_id,
                self.private_storage.lock().await.info(),
                "individual private key",
                false,
                is_threshold,
            );
        }

        // Store public key
        self.store_threshold_public_key(req_id, WrappedPublicKey::Compact(&public_keys.public_key))
            .await?;
        log_storage_success(
            req_id,
            self.public_storage.lock().await.info(),
            "key",
            true,
            is_threshold,
        );

        // Store server key
        self.store_public_serializable_data(
            req_id,
            &public_keys.server_key,
            PubDataType::ServerKey,
        )
        .await?;
        log_storage_success(
            req_id,
            self.public_storage.lock().await.info(),
            if is_threshold {
                "server key data"
            } else {
                "server signing key"
            },
            true,
            is_threshold,
        );

        Ok(())
    }

    /// Store threshold FHE keys
    pub async fn store_threshold_fhe_keys(
        &self,
        key_id: &RequestId,
        public_key: &tfhe::CompactPublicKey,
        server_key: &tfhe::ServerKey,
        threshold_fhe_keys: &ThresholdFheKeys,
    ) -> anyhow::Result<()> {
        // Store public key
        self.store_threshold_public_key(key_id, WrappedPublicKey::Compact(public_key))
            .await?;
        log_storage_success(
            key_id,
            self.public_storage.lock().await.info(),
            "key data",
            true,
            true,
        );

        // Store server key
        self.store_threshold_public_server_key(key_id, server_key)
            .await?;
        log_storage_success(
            key_id,
            self.public_storage.lock().await.info(),
            "server key data",
            true,
            true,
        );

        // Store private FHE key info
        self.store_threshold_private_fhe_key_info(key_id, threshold_fhe_keys)
            .await?;
        log_storage_success(
            key_id,
            self.private_storage.lock().await.info(),
            "key data",
            false,
            true,
        );

        Ok(())
    }

    // =========================
    // Ensure_xxx_existence Methods
    // =========================

    /// Tries to delete all the types of key material related to a specific [RequestId].
    pub async fn purge_key_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<
            '_,
            MetaStore<HashMap<PubDataType, SignedPubDataHandleInternal>>,
        >,
    ) {
        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
            let result = delete_pk_at_request_id(&mut (*pub_storage), req_id).await;
            if let Err(e) = &result {
                tracing::warn!("Failed to delete public key for request {}: {}", req_id, e);
            }
            result.is_err()
        };
        let f2 = async {
            let mut pub_storage = self.public_storage.lock().await;
            let result = delete_at_request_id(
                &mut (*pub_storage),
                req_id,
                &PubDataType::ServerKey.to_string(),
            )
            .await;
            if let Err(e) = &result {
                tracing::warn!("Failed to delete server key for request {}: {}", req_id, e);
            }
            result.is_err()
        };
        let f3 = async {
            let mut priv_storage = self.private_storage.lock().await;
            // can't map() because async closures aren't stable in Rust
            let back_storage = match self.backup_storage {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };
            let del_result_1 = delete_at_request_id(
                &mut (*priv_storage),
                req_id,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await;
            if let Err(e) = &del_result_1 {
                tracing::warn!(
                    "Failed to delete FHE key info from private storage for request {}: {}",
                    req_id,
                    e
                );
            }
            let del_err_1 = del_result_1.is_err();
            let del_err_2 = match back_storage {
                Some(mut x) => {
                    let result = delete_at_request_id(
                        &mut (*x),
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
            };
            del_err_1 || del_err_2
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
        crs_info: SignedPubDataHandleInternal,
        meta_store: Arc<RwLock<MetaStore<SignedPubDataHandleInternal>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        let f1 = async {
            let mut priv_storage = self.private_storage.lock().await;
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
            let mut pub_storage = self.public_storage.lock().await;
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

    pub async fn purge_crs_material(
        &self,
        req_id: &RequestId,
        mut guarded_meta_store: RwLockWriteGuard<'_, MetaStore<SignedPubDataHandleInternal>>,
    ) {
        let f1 = async {
            let mut pub_storage = self.public_storage.lock().await;
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
            let mut priv_storage = self.private_storage.lock().await;
            let result = delete_at_request_id(
                &mut (*priv_storage),
                req_id,
                &PrivDataType::CrsInfo.to_string(),
            )
            .await;
            if let Err(e) = &result {
                tracing::warn!(
                    "Failed to delete CRS info from private storage for request {}: {}",
                    req_id,
                    e
                );
            }
            result.is_err()
        };
        let (r1, r2) = tokio::join!(f1, f2);
        if r1 || r2 {
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

    pub async fn write_decompression_key_with_meta_store(
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
    #[cfg(test)]
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

    #[cfg(test)]
    pub(crate) async fn read_cloned_crypto_material<T, S>(
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
                write_cache_guard.insert(*req_id, pk.clone());
                Ok(pk)
            }
        }
    }

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
                        "Failed to read crypto material from storage for request ID {req_id}: {e}"
                    )));
                }
            }
        }

        Ok(())
    }

    pub async fn write_context_info(
        &self,
        req_id: &RequestId,
        context_info: &ContextInfo,
        is_threshold: bool,
    ) -> anyhow::Result<()> {
        let mut priv_storage = self.private_storage.lock().await;
        store_context_at_request_id(&mut *priv_storage, req_id, context_info).await?;
        log_storage_success(
            req_id,
            priv_storage.info(),
            "context info",
            false,
            is_threshold,
        );
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
