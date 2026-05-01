//! Centralized cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the centralized KMS variant.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};

use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{PrivDataType, PubDataType},
};

use crate::{
    engine::base::{KeyGenMetadata, KmsFheKeyHandles},
    util::meta_store::{MetaStore, ensure_meta_store_request_pending},
    vault::{
        Vault,
        storage::{
            Storage, StorageExt,
            crypto_material::{
                PublicKeySet,
                base::{StorageError, update_meta_store},
            },
        },
    },
};

use super::base::CryptoMaterialStorage;

/// A cached generic storage entity for the centralized KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub struct CentralizedCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
> {
    pub(crate) inner: CryptoMaterialStorage<PubS, PrivS>,
    fhe_keys: Arc<RwLock<HashMap<(RequestId, EpochId), KmsFheKeyHandles>>>,
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static>
    CentralizedCryptoMaterialStorage<PubS, PrivS>
{
    /// Create a new cached storage device for centralized KMS.
    pub fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        fhe_keys: HashMap<(RequestId, EpochId), KmsFheKeyHandles>,
    ) -> Self {
        Self {
            inner: CryptoMaterialStorage {
                public_storage: Arc::new(Mutex::new(public_storage)),
                private_storage: Arc::new(Mutex::new(private_storage)),
                backup_vault: backup_vault.map(|x| Arc::new(Mutex::new(x))),
            },
            fhe_keys: Arc::new(RwLock::new(fhe_keys)),
        }
    }

    pub(crate) async fn write_central_keys(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        central_fhe_keys: KmsFheKeyHandles,
        fhe_key_set: PublicKeySet,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        // First ensure that the meta store request is pending
        ensure_meta_store_request_pending(&meta_store, key_id)
            .await
            .map_err(|e| StorageError::MetaStoreError(e.to_string()))?;
        let meta_res = central_fhe_keys.public_key_info.clone();
        let res = self
            .inner
            .handle_fhe_keys(
                key_id,
                epoch_id,
                central_fhe_keys,
                PrivDataType::FhePrivateKey,
                fhe_key_set,
                Arc::clone(&self.fhe_keys),
                true,
                op_metric_tag,
            )
            .await;
        // Finally update meta store
        update_meta_store(res, key_id, meta_res, meta_store, op_metric_tag).await
    }

    pub(crate) async fn purge_centralized_key_material(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> bool {
        self.inner
            .purge_material(
                req_id,
                Some(epoch_id),
                &[
                    PubDataType::PublicKey,
                    PubDataType::ServerKey,
                    PubDataType::CompressedXofKeySet,
                ],
                &[PrivDataType::FhePrivateKey],
            )
            .await
    }

    /// Read the key materials for decryption in the centralized case.
    ///
    /// If the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    pub async fn read_centralized_fhe_keys(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<
        OwnedRwLockReadGuard<HashMap<(RequestId, EpochId), KmsFheKeyHandles>, KmsFheKeyHandles>,
    > {
        // First refresh. If the key is already in the cache then this is cheap
        self.inner
            .refresh_fhe_private_material::<KmsFheKeyHandles>(
                Arc::clone(&self.fhe_keys),
                req_id,
                epoch_id,
            )
            .await?;
        CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
            req_id,
            epoch_id,
            Arc::clone(&self.fhe_keys),
        )
        .await
    }

    /// Invalidate the cache entry for a given request and epoch ID.
    /// This is useful for testing scenarios where we want to force a re-read from storage.
    #[cfg(test)]
    pub async fn invalidate_fhe_keys_cache(&self, req_id: &RequestId, epoch_id: &EpochId) {
        let mut guarded_fhe_keys = self.fhe_keys.write().await;
        guarded_fhe_keys.remove(&(*req_id, *epoch_id));
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static> Clone
    for CentralizedCryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static>
    From<&CentralizedCryptoMaterialStorage<PubS, PrivS>> for CryptoMaterialStorage<PubS, PrivS>
{
    fn from(value: &CentralizedCryptoMaterialStorage<PubS, PrivS>) -> Self {
        value.inner.clone()
    }
}
