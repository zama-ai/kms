//! Centralized cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the centralized KMS variant.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

use kms_grpc::{
    rpc_types::{PrivDataType, PubDataType, WrappedPublicKey, WrappedPublicKeyOwned},
    RequestId,
};
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet;

use crate::{
    engine::base::{CrsGenCallValues, KeyGenMetadata, KmsFheKeyHandles},
    util::meta_store::MetaStore,
    vault::{
        storage::{store_pk_at_request_id, store_versioned_at_request_id, Storage},
        Vault,
    },
};

use super::base::CryptoMaterialStorage;

/// A cached generic storage entity for the centralized KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub struct CentralizedCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: Storage + Send + Sync + 'static,
> {
    pub(crate) inner: CryptoMaterialStorage<PubS, PrivS>,
    fhe_keys: Arc<RwLock<HashMap<RequestId, KmsFheKeyHandles>>>,
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
    CentralizedCryptoMaterialStorage<PubS, PrivS>
{
    /// Create a new cached storage device for centralized KMS.
    pub fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        pk_cache: HashMap<RequestId, WrappedPublicKeyOwned>,
        fhe_keys: HashMap<RequestId, KmsFheKeyHandles>,
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

    /// Write the CRS to the storage backend as well as the cache,
    /// and update the [meta_store] to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub async fn write_crs_with_meta_store(
        &self,
        req_id: &RequestId,
        pp: CompactPkeCrs,
        crs_info: CrsGenCallValues,
        meta_store: Arc<RwLock<MetaStore<CrsGenCallValues>>>,
    ) {
        self.inner
            .write_crs_with_meta_store(req_id, pp, crs_info, meta_store)
            .await
    }

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

    /// Write the key materials (result of a keygen) to storage and cache
    /// for the centralized KMS.
    /// The [meta_store] is updated to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub async fn write_centralized_keys_with_meta_store(
        &self,
        key_id: &RequestId,
        key_info: KmsFheKeyHandles,
        fhe_key_set: FhePubKeySet,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let mut guarded_meta_store = meta_store.write().await;

        // Try to store the new data
        tracing::info!(
            "Attempting to store centralized keygen material for key ID {}",
            key_id
        );

        let f1 = async {
            let mut priv_storage = self.inner.private_storage.lock().await;
            // can't map() because async closures aren't stable in Rust
            let back_vault = match self.inner.backup_vault {
                Some(ref x) => Some(x.lock().await),
                None => None,
            };
            let store_result_1 = store_versioned_at_request_id(
                &mut (*priv_storage),
                key_id,
                &key_info,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await;
            if let Err(e) = &store_result_1 {
                tracing::error!(
                    "Failed to store FHE key info to private storage for request {}: {}",
                    key_id,
                    e
                );
            }
            let store_err_1 = store_result_1.is_err();

            let store_err_2 = match back_vault {
                Some(mut x) => {
                    let result = store_versioned_at_request_id(
                        &mut (*x),
                        key_id,
                        &key_info,
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await;
                    if let Err(e) = &result {
                        tracing::error!(
                            "Failed to store FHE key info to backup storage for request {}: {}",
                            key_id,
                            e
                        );
                    }
                    result.is_err()
                }
                None => false,
            };
            !(store_err_1 || store_err_2)
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

        let (r1, r2, r3) = tokio::join!(f1, f2, f3);
        if r1
            && r2
            && r3
            && guarded_meta_store
                .update(key_id, Ok(key_info.public_key_info.to_owned()))
                .inspect_err(|e| {
                    tracing::error!("Error ({e}) while updating PK meta store for {}", key_id)
                })
                .is_ok()
        {
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
                let previous = guarded_fhe_keys.insert(*key_id, key_info);
                if previous.is_some() {
                    tracing::warn!(
                        "FHE keys already exist in cache for {}, overwriting",
                        key_id
                    );
                }
                tracing::info!(
                    "Successfully stored centralized keygen material for request {}",
                    key_id
                );
            }
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since
            // it might be because the data did not get created
            // In any case, we can't do much.
            self.inner
                .purge_key_material(key_id, guarded_meta_store)
                .await;
        }
    }

    /// Read the key materials for decryption in the centralized case.
    pub async fn read_cloned_centralized_fhe_keys_from_cache(
        &self,
        req_id: &RequestId,
    ) -> anyhow::Result<KmsFheKeyHandles> {
        CryptoMaterialStorage::<PubS, PrivS>::read_cloned_crypto_material_from_cache(
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
    pub async fn refresh_centralized_fhe_keys(&self, req_id: &RequestId) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS>::refresh_crypto_material::<KmsFheKeyHandles, _>(
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
        use crate::anyhow_error_and_warn_log;

        let mut key_info = self.fhe_keys.write().await;
        let x = key_info.get_mut(key_handle).ok_or_else(|| {
            anyhow_error_and_warn_log(format!(
                "Cannot find key handle {key_handle} in cache to set wrong client key"
            ))
        })?;

        let wrong_handles = KmsFheKeyHandles {
            client_key: wrong_client_key,
            decompression_key: x.decompression_key.clone(),
            public_key_info: x.public_key_info.clone(),
        };
        *x = wrong_handles;
        Ok(())
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static> Clone
    for CentralizedCryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: Storage + Send + Sync + 'static>
    From<&CentralizedCryptoMaterialStorage<PubS, PrivS>> for CryptoMaterialStorage<PubS, PrivS>
{
    fn from(value: &CentralizedCryptoMaterialStorage<PubS, PrivS>) -> Self {
        value.inner.clone()
    }
}
