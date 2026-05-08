//! Threshold cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the threshold KMS variant.

use observability::metrics_names::OP_NEW_EPOCH;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};

use super::base::CryptoMaterialStorage;
use crate::{
    cryptography::signatures::{PrivateSigKey, compute_eip712_signature},
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata},
        threshold::service::{ThresholdFheKeys, session::PRSSSetupCombined},
        utils::verify_public_key_digest_from_bytes,
    },
    util::meta_store::{MetaStore, ensure_meta_store_request_pending},
    vault::{
        Vault,
        storage::{
            Storage, StorageExt,
            crypto_material::{
                PublicKeySet,
                base::{StorageError, update_meta_store},
            },
            delete_at_request_and_epoch_id, delete_at_request_id, read_all_data_versioned,
            read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
            store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
        },
    },
};
use kms_grpc::solidity_types::KeygenVerification;
use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{PrivDataType, PubDataType},
};
use tfhe::xof_key_set::CompressedXofKeySet;

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
            .write_all::<PRSSSetupCombined, PRSSSetupCombined>(
                &(*epoch_id).into(), // using epoch_id as req_id since PRSS info is stored under this directly
                None,
                None, // no public data for PRSS info
                Some((prss_info, PrivDataType::PrssSetupCombined)),
                true,
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
    /// Unlike the normal CRS writing this one does not update the meta store, nor the backup.
    pub(crate) async fn resharing_crs_write_no_backup(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        crs_info: CrsGenMetadata,
    ) -> Result<(), StorageError> {
        self.inner
            .write_all::<CrsGenMetadata, CrsGenMetadata>(
                crs_id,
                Some(epoch_id),
                None, // No public data is made when refreshing a CRS
                Some((&crs_info, PrivDataType::CrsInfo)),
                false,
                OP_NEW_EPOCH,
            )
            .await
    }

    /// Write the keys to the storage backend (for use in connection with resharing).
    /// Unlike the normal fhe writing this one does not update the meta store, nor the backup.
    pub(crate) async fn resharing_fhe_write_no_backup(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
    ) -> Result<(), StorageError> {
        let res = self
            .inner
            .write_all::<ThresholdFheKeys, ThresholdFheKeys>(
                key_id,
                Some(epoch_id),
                None, // No public data is made when refreshing keys
                Some((&threshold_fhe_keys, PrivDataType::FheKeyInfo)),
                false,
                OP_NEW_EPOCH,
            )
            .await;
        if res.is_ok() || res.as_ref().is_err_and(|e| e == &StorageError::Backup) {
            // Add the new data to the cache
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            let _ = guarded_fhe_keys.insert((*key_id, *epoch_id), threshold_fhe_keys);
        }
        res
    }

    /// Check if the threshold FHE keys exist for a given key and epoch ID.
    /// The check is agnostic to whether the keys are compressed or not.
    pub(crate) async fn threshold_fhe_keys_exists(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
    ) -> Result<bool, StorageError> {
        self.inner.fhe_keys_exists(key_id, epoch_id, true).await
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
            .map_err(|e| StorageError::MetaStore(e.to_string()))?;
        let meta_res = threshold_fhe_keys.meta_data.clone();
        let res = self
            .inner
            .handle_fhe_keys(
                key_id,
                epoch_id,
                threshold_fhe_keys,
                PrivDataType::FheKeyInfo,
                fhe_key_set,
                Arc::clone(&self.fhe_keys),
                true,
                op_metric_tag,
            )
            .await;
        let mut guarded_meta_store = meta_store.write().await;
        update_meta_store(
            res,
            key_id,
            meta_res,
            &mut guarded_meta_store,
            op_metric_tag,
        )
        .await
    }

    /// Purge threshold FHE key material from disk **and** from the in-memory
    /// cache.
    pub(crate) async fn purge_threshold_key_material(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> bool {
        let storage_ok = self
            .inner
            .purge_material(
                req_id,
                Some(epoch_id),
                &[
                    PubDataType::PublicKey,
                    PubDataType::ServerKey,
                    PubDataType::CompressedXofKeySet,
                ],
                &[PrivDataType::FheKeyInfo],
            )
            .await;
        // Lock-order: cache is acquired after pub/priv have been released.
        self.fhe_keys.write().await.remove(&(*req_id, *epoch_id));
        storage_ok
    }

    /// After a migration keygen (`UseExisting` + `CompressedKeyConfig::All`) stores the
    /// compressed keyset under `new_key_id`, this function copies it to `old_key_id`
    /// and replaces the `ThresholdFheKeys` at `(old_key_id, old_epoch_id)` with the
    /// migrated one, re-signed under `old_key_id`.
    ///
    /// The operation is split into validate-then-mutate phases: everything is read
    /// and checked before any backend is mutated, so a malformed migration input
    /// cannot leave pub and priv storage in inconsistent states. Once validation
    /// passes, pub storage, priv storage, backup vault, in-memory cache, and the
    /// keygen meta-store are all updated under the same held locks so a concurrent
    /// reader cannot observe a mixed pre/post state.
    ///
    /// The old `CompactPublicKey` and `ServerKey` files at `old_key_id` are
    /// preserved for compatibility. The migration keygen also stores the old
    /// `CompactPublicKey` at `new_key_id`, so the public key bytes remain
    /// identical under both IDs. `ServerKey` is retained even though compressed
    /// metadata does not advertise it, so legacy or direct-storage consumers can
    /// continue fetching it from the original key id while new flows prefer the
    /// signed compressed layout.
    #[expect(clippy::too_many_arguments)]
    pub async fn copy_compressed_key_to_original(
        &self,
        new_key_id: &RequestId,
        new_epoch_id: &EpochId,
        old_key_id: &RequestId,
        old_epoch_id: &EpochId,
        sk: &PrivateSigKey,
        eip712_domain: &alloy_sol_types::Eip712Domain,
        dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) -> anyhow::Result<()> {
        // Lock order: meta_store -> pub -> priv -> backup -> fhe_keys.
        let mut guarded_meta_store = dkg_pubinfo_meta_store.write().await;
        let mut pub_storage = self.inner.public_storage.lock().await;
        let mut priv_storage = self.inner.private_storage.lock().await;
        let mut back_vault = match self.inner.backup_vault {
            Some(ref x) => Some(x.lock().await),
            None => None,
        };

        // --- Phase A: validate everything before mutating anything. ---

        // Source of the migrated compressed keyset.
        let compressed_keyset: CompressedXofKeySet = read_versioned_at_request_id(
            &*pub_storage,
            new_key_id,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await?;

        // Source of the migrated ThresholdFheKeys (stored by the keygen at
        // (new_key_id, new_epoch_id); this may differ from old_epoch_id).
        let migrated_fhe_keys: ThresholdFheKeys = read_versioned_at_request_and_epoch_id(
            &*priv_storage,
            new_key_id,
            new_epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;

        // Validate that the original key exists before mutating any backend.
        let _: ThresholdFheKeys = read_versioned_at_request_and_epoch_id(
            &*priv_storage,
            old_key_id,
            old_epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "No existing ThresholdFheKeys at (old_key_id={old_key_id}, \
                 old_epoch_id={old_epoch_id:?}): {e}"
            )
        })?;

        // Reject LegacyV0 migrated metadata (we can't re-sign without the
        // structured digest map) and confirm the CompressedXofKeySet digest
        // is present.
        let migrated_inner = match &migrated_fhe_keys.meta_data {
            KeyGenMetadata::Current(inner) => inner,
            KeyGenMetadata::LegacyV0(_) => {
                anyhow::bail!(
                    "Cannot copy compressed key to original: \
                     migrated ThresholdFheKeys has LegacyV0 metadata"
                );
            }
        };
        let compressed_digest = migrated_inner
            .key_digest_map
            .get(&PubDataType::CompressedXofKeySet)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "Migrated ThresholdFheKeys metadata missing CompressedXofKeySet digest"
                )
            })?
            .clone();
        let public_key_digest = migrated_inner
            .key_digest_map
            .get(&PubDataType::PublicKey)
            .ok_or_else(|| {
                anyhow::anyhow!("Migrated ThresholdFheKeys metadata missing PublicKey digest")
            })?
            .clone();

        // The old PublicKey bytes are intentionally preserved in Phase B, so
        // verify now that they are present, readable, and match the digest
        // that will be signed into the migrated metadata.
        let old_public_key_bytes = pub_storage
            .load_bytes(old_key_id, &PubDataType::PublicKey.to_string())
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to load raw PublicKey bytes for old keyset {old_key_id}: {e}"
                )
            })?;
        verify_public_key_digest_from_bytes(&old_public_key_bytes, &public_key_digest).map_err(
            |e| {
                anyhow::anyhow!(
                    "PublicKey digest mismatch for old keyset {old_key_id}: {e}; \
                     expected={}, stored-bytes-hash={}",
                    hex::encode(&public_key_digest),
                    hex::encode(hashing::hash_element(
                        &crate::engine::base::DSEP_PUBDATA_KEY,
                        &old_public_key_bytes
                    )),
                )
            },
        )?;
        let _: tfhe::CompactPublicKey = read_versioned_at_request_id(
            &*pub_storage,
            old_key_id,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .map_err(|e| {
            anyhow::anyhow!("Failed to deserialize PublicKey for old keyset {old_key_id}: {e}")
        })?;

        // Re-sign the metadata under old_key_id, preserving the migrated
        // extra_data bytes when they exist.
        let extra_data = migrated_inner.extra_data.clone().unwrap_or_default();
        let sol_type = KeygenVerification::new_compressed(
            &migrated_inner.preprocessing_id,
            old_key_id,
            compressed_digest,
            public_key_digest,
            extra_data.clone(),
        );
        let new_signature = compute_eip712_signature(sk, &sol_type, eip712_domain)?;
        let new_metadata = KeyGenMetadata::new(
            *old_key_id,
            migrated_inner.preprocessing_id,
            migrated_inner.key_digest_map.clone(),
            new_signature,
            extra_data,
        );

        let updated_fhe_keys = ThresholdFheKeys::new(
            migrated_fhe_keys.private_keys.clone(),
            migrated_fhe_keys.public_material.clone(),
            new_metadata.clone(),
        );

        // --- Phase B: mutate all backends under the held locks. ---

        // Preserve the old PublicKey and ServerKey, and overwrite only the
        // compressed keyset at the original key ID.
        delete_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await?;
        store_versioned_at_request_id(
            &mut *pub_storage,
            old_key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await?;

        // Priv storage at (old_key_id, old_epoch_id): delete + re-store.
        delete_at_request_and_epoch_id(
            &mut *priv_storage,
            old_key_id,
            old_epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;
        store_versioned_at_request_and_epoch_id(
            &mut *priv_storage,
            old_key_id,
            old_epoch_id,
            &updated_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await?;

        // Backup vault (if configured): delete + re-store at the same location
        // so a restore brings back the migrated keys, not the pre-migration
        // uncompressed ones.
        if let Some(vault) = back_vault.as_deref_mut() {
            delete_at_request_and_epoch_id(
                vault,
                old_key_id,
                old_epoch_id,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await?;
            store_versioned_at_request_and_epoch_id(
                vault,
                old_key_id,
                old_epoch_id,
                &updated_fhe_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await?;
        } else {
            tracing::warn!(
                "No backup vault configured. Skipping backup update during \
                 copy_compressed_key_to_original for {old_key_id}"
            );
        }

        // --- Phase C: refresh dkg_pubinfo_meta_store for old_key_id. ---
        // `MetaStore::update` only accepts pending entries, so replace the
        // existing completed entry with delete + insert + update, all under
        // the meta_store write guard already held since the top of the function.
        let _ = guarded_meta_store.delete(old_key_id);
        guarded_meta_store.insert(old_key_id).map_err(|e| {
            anyhow::anyhow!("Failed to insert {old_key_id} into keygen meta-store: {e}")
        })?;
        guarded_meta_store
            .update(old_key_id, Ok(new_metadata))
            .map_err(|e| {
                anyhow::anyhow!("Failed to update {old_key_id} in keygen meta-store: {e}")
            })?;

        tracing::info!(
            "Copied compressed key from {new_key_id} to original {old_key_id} \
             and updated metadata"
        );

        // In-memory cache.
        {
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            guarded_fhe_keys.insert((*old_key_id, *old_epoch_id), updated_fhe_keys);
        }

        Ok(())
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
        // First refresh. If the key is already in the cache then this is cheap
        self.inner
            .refresh_fhe_private_material::<ThresholdFheKeys>(
                Arc::clone(&self.fhe_keys),
                req_id,
                epoch_id,
            )
            .await?;
        CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
            req_id,
            epoch_id,
            self.fhe_keys.clone(),
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
