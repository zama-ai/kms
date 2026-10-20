//! The FHE-key cache of [`CryptoMaterialStorage`].
//!
//! These methods write and read FHE keys and epoch data, keeping the cache in step with storage.

use observability::metrics_names::OP_NEW_EPOCH;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

use super::base::CryptoMaterialStorage;
use crate::{
    cryptography::signatures::{NodeSigningIdentity, SigningSchemeType},
    engine::{
        base::{
            CrsGenMetadata, CurrentPublicMaterialLayout, KeyGenMetadata,
            compute_info_keygen_from_digests,
        },
        material_integrity::verify_public_key_digest_from_bytes,
        service::{FheKeys, epoch_manager::EpochData},
    },
    util::meta_store::{MetaStore, MetaStorePermit, with_overwriting_claim},
    vault::{
        Vault,
        storage::{
            Storage, StorageExt,
            crypto_material::{
                PublicKeySet,
                base::{BackupPolicy, StorageError, update_meta_store},
            },
            delete_at_request_and_epoch_id, delete_at_request_id, read_all_data_versioned,
            read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
            store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
        },
    },
};
use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{PrivDataType, PubDataType},
};
use tfhe::xof_key_set::CompressedXofKeySet;

/// The FHE-key cache and the methods that keep it in step with storage.
impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static>
    CryptoMaterialStorage<PubS, PrivS>
{
    /// Wraps the provided storages, with the FHE-key cache seeded with `fhe_keys`.
    pub fn with_fhe_keys(
        public_storage: PubS,
        private_storage: PrivS,
        backup_vault: Option<Vault>,
        fhe_keys: HashMap<(RequestId, EpochId), FheKeys>,
    ) -> Self {
        let storage = Self::from(public_storage, private_storage, backup_vault);
        Self {
            fhe_keys: Arc::new(RwLock::new(fhe_keys)),
            ..storage
        }
    }

    /// Write the epoch data to the storage backend.
    /// No actions are taken on failure, but the error is returned to the caller for potential handling.
    pub async fn write_epoch_data(
        &self,
        epoch_id: &EpochId,
        epoch_data: &EpochData,
    ) -> anyhow::Result<()> {
        self.write_all::<EpochData, EpochData>(
            &epoch_id.into(), // using epoch_id as req_id since epoch data is stored under this directly
            None,
            None, // no public data for epoch info
            Some((epoch_data, PrivDataType::EpochData)),
            true,
            OP_NEW_EPOCH,
        )
        .await
        .map_err(|e| anyhow::anyhow!("Storing epoch data failed with error: {e}"))
    }

    /// Read all epoch data from the storage backend.
    /// The result is a map of epoch IDs to their corresponding epoch data.
    /// That is, epochs are flattened and NOT indexed by their associated context ID.
    pub async fn read_all_epoch_data(&self) -> anyhow::Result<HashMap<EpochId, EpochData>> {
        let priv_storage = self.private_storage.lock().await;
        let intermediate_res: HashMap<RequestId, EpochData> =
            read_all_data_versioned(&*priv_storage, &PrivDataType::EpochData.to_string()).await?;
        Ok(intermediate_res
            .into_iter()
            .map(|(epoch_id, epoch_data)| (epoch_id.into(), epoch_data))
            .collect())
    }

    /// Write the CRS to the storage backend (for use in connection with resharing).
    /// Unlike the normal CRS writing this one does not update the meta store, nor the backup.
    pub(crate) async fn resharing_crs_write_no_backup(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        crs_info: CrsGenMetadata,
    ) -> Result<(), StorageError> {
        self.write_all::<CrsGenMetadata, CrsGenMetadata>(
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
        keys: FheKeys,
    ) -> Result<(), StorageError> {
        let res = self
            .write_all::<FheKeys, FheKeys>(
                key_id,
                Some(epoch_id),
                None, // No public data is made when refreshing keys
                Some((&keys, PrivDataType::FheKeyInfo)),
                false,
                OP_NEW_EPOCH,
            )
            .await;
        if res.is_ok() || res.as_ref().is_err_and(|e| e == &StorageError::Backup) {
            // Add the new data to the cache
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            let _ = guarded_fhe_keys.insert((*key_id, *epoch_id), keys);
        }
        res
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn write_fhe_keys(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        keys: FheKeys,
        fhe_key_set: PublicKeySet,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
        permit: MetaStorePermit<KeyGenMetadata>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        let meta_res = keys.meta_data.clone();
        let res = self
            .handle_fhe_keys(
                key_id,
                epoch_id,
                keys,
                PrivDataType::FheKeyInfo,
                fhe_key_set,
                Arc::clone(&self.fhe_keys),
                true,
                op_metric_tag,
            )
            .await;
        update_meta_store(
            res,
            meta_res,
            &meta_store,
            permit,
            BackupPolicy::BackupIsBestEffort,
            op_metric_tag,
        )
        .await
    }

    /// Drop all cached FHE keys for the given epoch, returning the number of
    /// entries removed. Cache-only — deleting the on-disk material is the
    /// caller's job (see `destroy_epoch`).
    pub(crate) async fn purge_epoch_from_cache(&self, epoch_id: &EpochId) -> usize {
        let mut guarded_fhe_keys = self.fhe_keys.write().await;
        let before = guarded_fhe_keys.len();
        guarded_fhe_keys.retain(|(_, cached_epoch_id), _| cached_epoch_id != epoch_id);
        before.saturating_sub(guarded_fhe_keys.len())
    }

    /// Number of cached FHE key entries (feeds the `fhe_key_cache_size` gauge).
    /// Non-blocking: returns `None` when the lock is contended, so the metrics
    /// loop observes the cache without ever waiting on it.
    pub(crate) fn cached_fhe_key_count(&self) -> Option<usize> {
        self.fhe_keys.try_read().ok().map(|cache| cache.len())
    }

    /// After a migration keygen (`UseExisting` + `CompressedKeyConfig::All`) stores the
    /// compressed keyset under `new_key_id`, this function copies it to `old_key_id`
    /// and replaces the `FheKeys` at `(old_key_id, old_epoch_id)` with the
    /// migrated one, re-signed under `old_key_id`.
    ///
    /// The operation is split into validate-then-mutate phases: everything is read
    /// and checked before any backend is mutated, so a malformed migration input
    /// cannot leave pub and priv storage in inconsistent states.
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
        identity: &NodeSigningIdentity,
        schemes: &[SigningSchemeType],
        eip712_domain: &alloy_sol_types::Eip712Domain,
        dkg_pubinfo_meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) -> anyhow::Result<()> {
        // Hold a permit for `old_key_id` exclusively in the keygen meta-store for the whole
        // migration.
        let updated_fhe_keys =
            with_overwriting_claim(&dkg_pubinfo_meta_store, old_key_id, async || {
                // Lock order: pub -> priv -> backup.
                let mut pub_storage = self.public_storage.lock().await;
                let mut priv_storage = self.private_storage.lock().await;
                let mut back_vault = match self.backup_vault {
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

                // Source of the migrated FheKeys (stored by the keygen at
                // (new_key_id, new_epoch_id); this may differ from old_epoch_id).
                let migrated_fhe_keys: FheKeys = read_versioned_at_request_and_epoch_id(
                    &*priv_storage,
                    new_key_id,
                    new_epoch_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await?;

                // Validate that the original key exists before mutating any backend.
                let _: FheKeys = read_versioned_at_request_and_epoch_id(
                    &*priv_storage,
                    old_key_id,
                    old_epoch_id,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "No existing FheKeys at (old_key_id={old_key_id}, \
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
                     migrated FheKeys has LegacyV0 metadata"
                        );
                    }
                };
                if !migrated_inner
                    .key_digest_map
                    .contains_key(&PubDataType::CompressedXofKeySet)
                {
                    anyhow::bail!("Migrated FheKeys metadata missing CompressedXofKeySet digest");
                }
                let public_key_digest = migrated_inner
                    .key_digest_map
                    .get(&PubDataType::PublicKey)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Migrated FheKeys metadata missing PublicKey digest")
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
                verify_public_key_digest_from_bytes(&old_public_key_bytes, &public_key_digest)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "PublicKey digest mismatch for old keyset {old_key_id}: {e}; \
                     expected={}, stored-bytes-hash={}",
                            hex::encode(&public_key_digest),
                            hex::encode(hashing::hash_element(
                                &crate::engine::base::DSEP_PUBDATA_KEY,
                                &old_public_key_bytes
                            )),
                        )
                    })?;
                let _: tfhe::CompactPublicKey = read_versioned_at_request_id(
                    &*pub_storage,
                    old_key_id,
                    &PubDataType::PublicKey.to_string(),
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to deserialize PublicKey for old keyset {old_key_id}: {e}"
                    )
                })?;

                // Re-sign the metadata under old_key_id, preserving the migrated
                // extra_data bytes when they exist.
                //
                // Through the same builder a keygen uses, so the record comes out
                // signed under every scheme the request asked for.
                let extra_data = migrated_inner.extra_data.clone().unwrap_or_default();
                let new_metadata = compute_info_keygen_from_digests(
                    identity,
                    schemes,
                    CurrentPublicMaterialLayout::Compressed,
                    &migrated_inner.preprocessing_id,
                    old_key_id,
                    migrated_inner.key_digest_map.clone(),
                    eip712_domain,
                    extra_data,
                )?;

                let updated_fhe_keys = FheKeys::new(
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

                Ok((new_metadata, updated_fhe_keys))
            })
            .await?;

        tracing::info!(
            "Copied compressed key from {new_key_id} to original {old_key_id} \
             and updated metadata"
        );

        // In-memory cache (updated only after the commit above succeeds).
        {
            let mut guarded_fhe_keys = self.fhe_keys.write().await;
            guarded_fhe_keys.insert((*old_key_id, *old_epoch_id), updated_fhe_keys);
        }

        Ok(())
    }

    /// Read the key materials for decryption in the threshold case.
    /// The object [FheKeys] is big so
    /// we return a lock guard instead of the whole object to avoid copying.
    ///
    /// This function ensures that the keys will be in the cache. If it is not already there it will be fetched first.
    pub async fn read_guarded_fhe_keys(
        &self,
        req_id: &RequestId, // TODO(#2849) change to keyid
        epoch_id: &EpochId,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<(RequestId, EpochId), FheKeys>, FheKeys>> {
        // First refresh. If the key is already in the cache then this is cheap
        self.refresh_fhe_private_material::<FheKeys>(Arc::clone(&self.fhe_keys), req_id, epoch_id)
            .await?;
        CryptoMaterialStorage::<PubS, PrivS>::read_guarded_crypto_material_from_cache(
            req_id,
            epoch_id,
            self.fhe_keys.clone(),
        )
        .await
    }
}
