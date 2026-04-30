//! Threshold cryptographic material storage implementation
//!
//! This module provides the storage implementation for cryptographic material
//! used in the threshold KMS variant.

use observability::metrics_names::OP_NEW_EPOCH;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock, RwLockWriteGuard};

use kms_grpc::{
    RequestId,
    identifiers::EpochId,
    rpc_types::{KMSType, PrivDataType, PubDataType},
};
use tfhe::{
    integer::compression_keys::DecompressionKey, xof_key_set::CompressedXofKeySet,
    zk::CompactPkeCrs,
};
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;

use crate::{
    cryptography::signatures::{PrivateSigKey, compute_eip712_signature},
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata},
        threshold::service::{ThresholdFheKeys, session::PRSSSetupCombined},
        utils::verify_public_key_digest_from_bytes,
    },
    util::meta_store::update_err_req_in_meta_store,
    util::meta_store::{
        MetaStore, ensure_meta_store_request_pending, should_purge_after_meta_update_failure,
    },
    vault::{
        Vault,
        storage::{
            Storage, StorageExt, crypto_material::log_storage_success,
            delete_at_request_and_epoch_id, delete_at_request_id, read_all_data_versioned,
            read_versioned_at_request_and_epoch_id, read_versioned_at_request_id,
            store_versioned_at_request_and_epoch_id, store_versioned_at_request_id,
        },
    },
};

use kms_grpc::solidity_types::KeygenVerification;

use super::base::CryptoMaterialStorage;

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
        let mut priv_storage = self.inner.private_storage.lock().await;
        store_versioned_at_request_id(
            &mut *priv_storage,
            &(*epoch_id).into(),
            prss_info,
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;
        log_storage_success(
            epoch_id,
            priv_storage.info(),
            &PrivDataType::PrssSetupCombined.to_string(),
            false,
            true,
        );
        Ok(())
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
    ///
    /// On failure, the meta_store is used to purge dangling data.
    /// On success, the meta_store is NOT updated; the caller is responsible for that.
    pub(crate) async fn resharing_crs_write<T: Clone>(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        pp: CompactPkeCrs,
        crs_info: CrsGenMetadata,
        meta_store: Arc<RwLock<MetaStore<T>>>,
    ) -> bool {
        if self
            .inner
            .inner_write_crs(crs_id, epoch_id, pp, crs_info)
            .await
        {
            true
        } else {
            // Some store op failed, we need to purge any potentially
            // dangling data and update the meta store accordingly.
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might
            // be because the data did not get created
            // In any case, we can't do much.
            if self.inner.purge_crs_material(crs_id, epoch_id).await {
                // Successfully purged dangling data, now update meta store with error
                let mut guarded_meta_store = meta_store.write().await;
                let _ = update_err_req_in_meta_store(
                    &mut guarded_meta_store,
                    crs_id,
                    format!("Failed to write CRS to storage for epoch change to {epoch_id}"),
                    OP_NEW_EPOCH,
                );
            } else {
                // Failure in purging data
                let mut guarded_meta_store = meta_store.write().await;
                let _ = update_err_req_in_meta_store(
                    &mut guarded_meta_store,
                    crs_id,
                    format!(
                        "Failed to purge dangling data in connection with CRS update failure for epoch change to {epoch_id}"
                    ),
                    OP_NEW_EPOCH,
                );
            }
            false
        }
    }

    /// Check if the CRS under [req_id, epoch_id] exists in the storage.
    pub async fn crs_exists(&self, req_id: &RequestId, epoch_id: &EpochId) -> anyhow::Result<bool> {
        CryptoMaterialStorage::<PubS, PrivS>::crs_exists(&self.inner, req_id, epoch_id).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn inner_write_threshold_keys<T: Clone>(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
        fhe_key_set: FhePubKeySet,
        meta_store: Arc<RwLock<MetaStore<T>>>,
    ) -> bool {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let (r1, r2) = {
            // Lock the storage components in the correct order to avoid deadlocks.
            let mut pub_storage = self.inner.public_storage.lock().await;
            let mut priv_storage = self.inner.private_storage.lock().await;

            let f1 = async {
                let store_result = store_versioned_at_request_and_epoch_id(
                    &mut (*priv_storage),
                    key_id,
                    epoch_id,
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
                tracing::info!("Storing public key");
                let pk_result = store_versioned_at_request_id(
                    &mut (*pub_storage),
                    key_id,
                    &fhe_key_set.public_key,
                    &PubDataType::PublicKey.to_string(),
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
            tokio::join!(f1, f2)
        };
        // Try to store the new data
        tracing::info!("Storing Keys objects for key ID {}", key_id);

        if r1 && r2 {
            {
                let mut guarded_fhe_keys = self.fhe_keys.write().await;
                let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), threshold_fhe_keys);
                if previous.is_some() {
                    tracing::warn!(
                        "Threshold FHE keys already exist in cache for {}, overwriting",
                        key_id
                    );
                } else {
                    tracing::debug!("Added new threshold FHE keys to cache for {}", key_id);
                }
            }
            tracing::info!("Finished storing key for Key Id {key_id}.");
            true
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might be
            // because the data did not get created
            // In any case, we can't do much.
            tracing::warn!(
                "Failed to ensure existence of threshold key material for Key with ID: {}",
                key_id
            );
            let guarded_meta_storage = meta_store.write().await;
            self.purge_key_material(key_id, epoch_id, guarded_meta_storage)
                .await;
            false
        }
    }

    /// Write the key materials (result of a keygen) to storage and cache
    /// for the threshold KMS.
    /// The [meta_store] is updated to "Done" if the procedure is successful.
    ///
    /// When calling this function more than once, the same [meta_store]
    /// must be used, otherwise the storage state may become inconsistent.
    pub async fn write_threshold_keys_with_dkg_meta_store(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
        fhe_key_set: FhePubKeySet,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) -> anyhow::Result<()> {
        ensure_meta_store_request_pending(&meta_store, key_id).await?;

        let info = threshold_fhe_keys.meta_data.clone();
        let storage_ok = self
            .inner_write_threshold_keys(
                key_id,
                epoch_id,
                threshold_fhe_keys,
                fhe_key_set,
                Arc::clone(&meta_store),
            )
            .await;
        if !storage_ok {
            anyhow::bail!("Storage write failed for threshold key {key_id}");
        }
        let mut guarded_meta_store = meta_store.write().await;
        if let Err(e) = guarded_meta_store.update(key_id, Ok(info)) {
            self.handle_threshold_meta_update_failure(key_id, epoch_id, guarded_meta_store)
                .await;
            anyhow::bail!("Error while updating meta store for {key_id}: {e}");
        }
        Ok(())
    }

    /// Write the key materials (result of a compressed keygen) to storage and cache
    /// for the threshold KMS.
    /// The [meta_store] is updated to "Done" if the procedure is successful.
    ///
    /// This is similar to [write_threshold_keys_with_dkg_meta_store] but for compressed keys.
    #[allow(clippy::too_many_arguments)]
    pub async fn write_threshold_keys_with_dkg_meta_store_compressed(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
        compressed_keyset: &CompressedXofKeySet,
        compact_public_key: &tfhe::CompactPublicKey,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) -> anyhow::Result<()> {
        ensure_meta_store_request_pending(&meta_store, key_id).await?;

        let info = threshold_fhe_keys.meta_data.clone();
        let storage_ok = self
            .inner_write_threshold_keys_compressed(
                key_id,
                epoch_id,
                threshold_fhe_keys,
                compressed_keyset,
                compact_public_key,
                Arc::clone(&meta_store),
            )
            .await;
        if !storage_ok {
            anyhow::bail!("Storage write failed for compressed threshold key {key_id}");
        }
        let mut guarded_meta_store = meta_store.write().await;
        if let Err(e) = guarded_meta_store.update(key_id, Ok(info)) {
            self.handle_threshold_meta_update_failure(key_id, epoch_id, guarded_meta_store)
                .await;
            anyhow::bail!("Error while updating meta store for {key_id}: {e}");
        }
        Ok(())
    }

    async fn handle_threshold_meta_update_failure(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<KeyGenMetadata>>,
    ) {
        if should_purge_after_meta_update_failure(&guarded_meta_store, key_id) {
            self.purge_key_material(key_id, epoch_id, guarded_meta_store)
                .await;
        } else {
            drop(guarded_meta_store);
        }

        let mut guarded_fhe_keys = self.fhe_keys.write().await;
        guarded_fhe_keys.remove(&(*key_id, *epoch_id));
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn inner_write_threshold_keys_compressed<T: Clone>(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold_fhe_keys: ThresholdFheKeys,
        compressed_keyset: &CompressedXofKeySet,
        compact_public_key: &tfhe::CompactPublicKey,
        meta_store: Arc<RwLock<MetaStore<T>>>,
    ) -> bool {
        // use guarded_meta_store as the synchronization point
        // all other locks are taken as needed so that we don't lock up
        // other function calls too much
        let guarded_meta_storage = meta_store.write().await;
        let (r1, r2) = {
            // Lock the storage components in the correct order to avoid deadlocks.
            let mut pub_storage = self.inner.public_storage.lock().await;
            let mut priv_storage = self.inner.private_storage.lock().await;

            let f1 = async {
                let store_result = store_versioned_at_request_and_epoch_id(
                    &mut (*priv_storage),
                    key_id,
                    epoch_id,
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
                // Store compressed xof key set and the compact public key derived from it.
                let keyset_result = store_versioned_at_request_id(
                    &mut (*pub_storage),
                    key_id,
                    compressed_keyset,
                    &PubDataType::CompressedXofKeySet.to_string(),
                )
                .await;

                if let Err(e) = &keyset_result {
                    tracing::error!(
                        "Failed to store compressed server key for request {}: {}",
                        key_id,
                        e
                    );
                } else {
                    log_storage_success(
                        key_id,
                        pub_storage.info(),
                        &PubDataType::CompressedXofKeySet.to_string(),
                        true,
                        true,
                    );
                }

                let pk_result = store_versioned_at_request_id(
                    &mut (*pub_storage),
                    key_id,
                    compact_public_key,
                    &PubDataType::PublicKey.to_string(),
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

                keyset_result.is_ok() && pk_result.is_ok()
            };
            tokio::join!(f1, f2)
        };
        // Try to store the new data
        tracing::info!("Storing compressed keys objects for key ID {}", key_id);

        if r1 && r2 {
            {
                let mut guarded_fhe_keys = self.fhe_keys.write().await;
                let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), threshold_fhe_keys);
                if previous.is_some() {
                    tracing::warn!(
                        "Threshold FHE keys already exist in cache for {}, overwriting",
                        key_id
                    );
                } else {
                    tracing::debug!(
                        "Added new compressed threshold FHE keys to cache for {}",
                        key_id
                    );
                }
            }
            tracing::info!("Finished storing compressed key for Key Id {key_id}.");
            true
        } else {
            // Try to delete stored data to avoid anything dangling
            // Ignore any failure to delete something since it might be
            // because the data did not get created
            // In any case, we can't do much.
            tracing::warn!(
                "Failed to ensure existence of compressed threshold key material for Key with ID: {}",
                key_id
            );
            self.purge_key_material(key_id, epoch_id, guarded_meta_storage)
                .await;
            false
        }
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

    /// Tries to delete all the types of key material related to a specific [RequestId] and [EpochId].
    pub async fn purge_key_material<T: Clone>(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
        guarded_meta_store: RwLockWriteGuard<'_, MetaStore<T>>,
    ) {
        self.inner
            .purge_key_material(req_id, epoch_id, KMSType::Threshold, guarded_meta_store)
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
