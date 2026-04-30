//! Threshold cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the threshold KMS variant.

use observability::metrics_names::OP_NEW_EPOCH;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};

use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{PrivDataType, PubDataType},
};
use tfhe::{xof_key_set::CompressedXofKeySet, zk::CompactPkeCrs};
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;

use crate::{
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata},
        threshold::service::{ThresholdFheKeys, session::PRSSSetupCombined},
    },
    util::meta_store::{MetaStore, ensure_meta_store_request_pending},
    vault::{
        Vault,
        storage::{
            Storage, StorageExt,
            crypto_material::base::{StorageError, update_meta_store},
            read_all_data_versioned,
        },
    },
};

use super::base::CryptoMaterialStorage;

pub enum PublicKeySet {
    Standard(FhePubKeySet),
    Compressed {
        compact_public_key: tfhe::CompactPublicKey,
        compressed_keyset: CompressedXofKeySet,
    },
}
/// A cached generic storage entity for the threshold KMS.
/// Cloning this object is cheap since it uses Arc internally.
pub struct ThresholdCryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
> {
    pub(crate) inner: CryptoMaterialStorage<PubS, PrivS>,
    /// Note that `fhe_keys` should be locked after any locking of elements in `inner`.
    fhe_keys: Arc<RwLock<HashMap<(RequestId, EpochId), ThresholdFheKeys>>>,
}

impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static>
    ThresholdCryptoMaterialStorage<PubS, PrivS>
{
    /// Create a new cached storage device for threshold KMS.
    pub fn new(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        fhe_keys: HashMap<(RequestId, EpochId), ThresholdFheKeys>,
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

    /// Get an Arc of the private storage device.
    pub fn get_private_storage(&self) -> Arc<Mutex<PrivS>> {
        Arc::clone(&self.inner.private_storage)
    }

    /// Write the PRSS info to the storage backend.
    /// No actions are taken on failure, but the error is returned to the caller for potential handling.
    pub async fn write_prss_info(
        &self,
        epoch_id: &EpochId,
        prss_info: &PRSSSetupCombined,
    ) -> anyhow::Result<()> {
        // No public data so we just use PRSSSetupCombined
        self.inner
            .handle_all_storage::<PRSSSetupCombined, PRSSSetupCombined>(
                &(*epoch_id).into(), // using epoch_id as req_id since PRSS info is stored under this directly
                None,
                None, // no public data for PRSS info
                Some((prss_info, PrivDataType::PrssSetupCombined)),
                OP_NEW_EPOCH,
            )
            .await
            .map_err(|e| anyhow::anyhow!("Storing PRSS failed with error: {e}"))
    }

    /// Read all PRSS info from storage
    pub async fn read_all_prss_info(
        &self,
    ) -> anyhow::Result<HashMap<RequestId, PRSSSetupCombined>> {
        let priv_storage = self.inner.private_storage.lock().await;
        read_all_data_versioned(&*priv_storage, &PrivDataType::PrssSetupCombined.to_string()).await
    }

    /// Write the CRS to the storage backend (for use in connection with resharing).
    /// Returns true if the write was successful, false otherwise.
    pub(crate) async fn resharing_crs_write(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        pp: CompactPkeCrs,
        crs_info: CrsGenMetadata,
    ) -> Result<(), StorageError> {
        self.inner
            .handle_all_storage(
                crs_id,
                Some(epoch_id),
                Some((&pp, PubDataType::CRS)),
                Some((&crs_info.clone(), PrivDataType::CrsInfo)),
                OP_NEW_EPOCH,
            )
            .await
    }

    /// Check if the CRS under [req_id, epoch_id] exists in the storage.
    pub async fn crs_exists(&self, req_id: &RequestId, epoch_id: &EpochId) -> anyhow::Result<bool> {
        CryptoMaterialStorage::<PubS, PrivS>::crs_exists(&self.inner, req_id, epoch_id).await
    }

    pub(crate) async fn write_threshold_keys(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
        fhe_key_set: PublicKeySet,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        // First ensure that the meta store request is pending
        ensure_meta_store_request_pending(&meta_store, key_id)
            .await
            .map_err(|e| StorageError::MetaStoreError(e.to_string()))?;
        let meta_res = threshold_fhe_keys.meta_data.clone();
        let res = self
            .handle_threshold_key_storage(
                key_id,
                epoch_id,
                threshold_fhe_keys,
                fhe_key_set,
                op_metric_tag,
            )
            .await;
        // Finally update meta store
        update_meta_store(res, key_id, meta_res, meta_store, op_metric_tag).await
    }

    /// Helper function to write the threshold keys to storage, along with updating the cache if the storage operation was successful.
    pub(crate) async fn handle_threshold_key_storage(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
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
                Some((&threshold_fhe_keys, PrivDataType::FheKeyInfo)),
                op_metric_tag,
            )
            .await;
        if res.is_ok() || res.as_ref().is_err_and(|e| e == &StorageError::BackupError) {
            // Update cache
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), threshold_fhe_keys);
            if previous.is_some() {
                tracing::warn!(
                    "Threshold FHE keys already exist in cache for {}, overwriting",
                    key_id
                );
            }
        }
        res
    }

    /// Read the key materials for decryption in the threshold case.
    /// The object [ThresholdFheKeys] is big so
    /// we return a lock guard instead of the whole object to avoid copying.
    ///
    /// This function ensures that the keys will be in the cache. If it is not already there it will be fetched first.
    pub async fn read_guarded_threshold_fhe_keys(
        &self,
        req_id: &RequestId, // TODO(#2849) change to keyid
        epoch_id: &EpochId,
    ) -> anyhow::Result<
        OwnedRwLockReadGuard<HashMap<(RequestId, EpochId), ThresholdFheKeys>, ThresholdFheKeys>,
    > {
        // First try to read from cache
        match CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
            req_id,
            epoch_id,
            self.fhe_keys.clone(),
        )
        .await
        {
            Ok(guarded_keys) => Ok(guarded_keys),
            Err(_) => {
                // Refresh the cache if the first read was an error
                self.refresh_threshold_fhe_keys(req_id, epoch_id).await?;
                // Retry reading after the refresh
                CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
                    req_id,
                    epoch_id,
                    self.fhe_keys.clone(),
                )
                .await
            }
        }
    }

    /// Refresh the key materials for decryption in the threshold case.
    /// That is, if the key material is not in the cache,
    /// an attempt is made to read from the storage to update the cache.
    /// The object [ThresholdFheKeys] is big so
    /// we return a lock guard instead of the whole object.
    ///
    /// The `epoch_id` identifies the epoch that the secret FHE key share belongs to.
    ///
    /// Developers: try not to interleave calls to [refresh_threshold_fhe_keys]
    /// with calls to [read_threshold_fhe_keys] on the same tokio task
    /// since it's easy to deadlock, it's a consequence of RwLocks.
    /// see https://docs.rs/tokio/latest/tokio/sync/struct.RwLock.html#method.read_owned
    pub async fn refresh_threshold_fhe_keys(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()> {
        CryptoMaterialStorage::<PubS, PrivS>::refresh_fhe_private_material::<ThresholdFheKeys, _>(
            self.fhe_keys.clone(),
            req_id,
            epoch_id,
            self.inner.private_storage.clone(),
        )
        .await
    }
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static> Clone
    for ThresholdCryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            fhe_keys: Arc::clone(&self.fhe_keys),
        }
    }
}
impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static>
    From<&ThresholdCryptoMaterialStorage<PubS, PrivS>> for CryptoMaterialStorage<PubS, PrivS>
{
    fn from(value: &ThresholdCryptoMaterialStorage<PubS, PrivS>) -> Self {
        value.inner.clone()
    }
}
