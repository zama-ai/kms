//! Centralized cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the centralized KMS variant.

use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, RwLock};

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
            .handle_central_key_storage(
                key_id,
                epoch_id,
                central_fhe_keys,
                fhe_key_set,
                op_metric_tag,
            )
            .await;
        // Finally update meta store
        update_meta_store(res, key_id, meta_res, meta_store, op_metric_tag).await
    }

    // TODO can we simplify this with the threshold methods with a macro since cache also needs to be updated, of format different in central comapred to threshold
    /// Helper function to write the central keys to storage, along with updating the cache if the storage operation was successful.
    pub(crate) async fn handle_central_key_storage(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        central_fhe_keys: KmsFheKeyHandles,
        fhe_key_set: PublicKeySet,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        // First try to store the special key
        let pk_to_store = match &fhe_key_set {
            PublicKeySet::Standard(keys) => {
                self.inner
                    .handle_all_storage::<tfhe::ServerKey, tfhe::ServerKey>(
                        key_id,
                        Some(epoch_id),
                        Some((&keys.server_key, PubDataType::ServerKey)),
                        None,
                        op_metric_tag,
                    )
                    .await?;
                &keys.public_key
            }
            PublicKeySet::Compressed {
                compact_public_key,
                compressed_keyset,
            } => {
                self.inner
                    .handle_all_storage::<tfhe::xof_key_set::CompressedXofKeySet, tfhe::xof_key_set::CompressedXofKeySet>(
                        key_id,
                        Some(epoch_id),
                        Some((&compressed_keyset, PubDataType::CompressedXofKeySet)),
                        None,
                        op_metric_tag,
                    )
                    .await?;
                &compact_public_key
            }
        };
        // If it goes well also store the public key and private state
        let res = self
            .inner
            .handle_all_storage(
                key_id,
                Some(epoch_id),
                Some((pk_to_store, PubDataType::PublicKey)),
                Some((&central_fhe_keys, PrivDataType::FheKeyInfo)),
                op_metric_tag,
            )
            .await;
        if res.is_ok() || res.as_ref().is_err_and(|e| e == &StorageError::BackupError) {
            // Update cache
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), central_fhe_keys);
            if previous.is_some() {
                tracing::warn!(
                    "Threshold FHE keys already exist in cache for {}, overwriting",
                    key_id
                );
            }
        }
        res
    }

    /// Read the key materials for decryption in the centralized case.
    ///
    /// If the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    pub async fn read_centralized_fhe_keys(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<KmsFheKeyHandles> {
        match CryptoMaterialStorage::<PubS, PrivS>::read_cloned_private_fhe_material_from_cache(
            self.fhe_keys.clone(),
            req_id,
            epoch_id,
        )
        .await
        {
            Ok(k) => Ok(k),
            Err(e) => {
                tracing::warn!("First attempt to read centralized fhe keys failed: {e}");
                // No keys in cache -- try to refresh from storage
                self.refresh_centralized_fhe_keys(req_id, epoch_id).await?;
                CryptoMaterialStorage::<PubS, PrivS>::read_cloned_private_fhe_material_from_cache(
                    self.fhe_keys.clone(),
                    req_id,
                    epoch_id,
                )
                .await
            }
        }
    }

    /// Refresh the key materials for decryption in the centralized case.
    /// That is, if the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    ///
    /// The `epoch_id` identifies the epoch that the secret FHE key belongs to.
    ///
    /// Developers: try not to interleave calls to [refresh_centralized_fhe_keys]
    /// with calls to [read_centralized_fhe_keys] on the same tokio task
    /// since it's easy to deadlock, it's a consequence of RwLocks.
    /// see https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html#method.read_owned
    pub async fn refresh_centralized_fhe_keys(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS>::refresh_fhe_private_material::<KmsFheKeyHandles, _>(
            self.fhe_keys.clone(),
            req_id,
            epoch_id,
            self.inner.private_storage.clone(),
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
