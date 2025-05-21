//! Base implementation of cryptographic material storage
//!
//! This module provides the foundational storage implementation used by
//! both centralized and threshold KMS variants.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use kms_grpc::{
    rpc_types::{PrivDataType, PubDataType, SignedPubDataHandleInternal, WrappedPublicKeyOwned},
    RequestId,
};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};

use crate::{
    anyhow_error_and_warn_log,
    util::meta_store::MetaStore,
    vault::storage::{
        delete_at_request_id, delete_pk_at_request_id, store_versioned_at_request_id, Storage,
    },
};

use super::CryptoMaterialReader;

/// A cached generic storage entity for the common data structures
/// used by both the centralized and the threshold KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub struct CryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
    BackS: Storage + Send + Sync + 'static,
> {
    // Storage for data that is supposed to be readable by anyone on the internet,
    // but _may_ be susceptible to malicious modifications.
    pub(crate) public_storage: Arc<Mutex<PubS>>,
    // Storage for data that is supposed to only be readable, writable and modifiable by the entity
    // owner and where any modification will be detected.
    pub(crate) private_storage: Arc<Mutex<PrivS>>,
    // Optional second private storage for backup and recovery
    pub(crate) backup_storage: Option<Arc<Mutex<BackS>>>,
    // Map storing the already generated public keys.
    pub(crate) pk_cache: Arc<RwLock<HashMap<RequestId, WrappedPublicKeyOwned>>>,
}

impl<
        PubS: Storage + Send + Sync + 'static,
        PrivS: Storage + Send + Sync + 'static,
        BackS: Storage + Send + Sync + 'static,
    > CryptoMaterialStorage<PubS, PrivS, BackS>
{
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
                "Failed to store CRS data to public storage for ID {}",
                req_id
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
                "Failed to find crypto material in cache for request ID {}",
                req_id
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
            anyhow_error_and_warn_log(format!(
                "Key handles are not in the cache for ID {}",
                req_id
            ))
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
                        "Failed to read crypto material from storage for request ID {}: {}",
                        req_id, e
                    )));
                }
            }
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
