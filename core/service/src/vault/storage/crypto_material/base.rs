//! Base implementation of cryptographic material storage
//!
//! This module provides the foundational storage implementation used by
//! both centralized and threshold KMS variants.
use crate::engine::threshold::service::session::PRSSSetupCombined;
use crate::util::meta_store::update_ok_req_in_meta_store;
use crate::util::meta_store::{ensure_meta_store_request_pending, update_err_req_in_meta_store};
use crate::vault::storage::crypto_material::check_data_exists;
use crate::vault::storage::store_versioned_at_request_and_epoch_id;
use crate::{
    anyhow_error_and_warn_log,
    backup::operator::RecoveryValidationMaterial,
    cryptography::signatures::PrivateSigKey,
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata, KmsFheKeyHandles},
        context::ContextInfo,
        threshold::service::ThresholdFheKeys,
    },
    grpc::metastore_status_service::CustodianMetaStore,
    util::meta_store::MetaStore,
    vault::{
        Vault,
        keychain::KeychainProxy,
        storage::{
            Storage, StorageExt,
            crypto_material::{
                check_data_exists_at_epoch, log_storage_success_optional_variant,
                traits::PrivateCryptoMaterialReader,
            },
            delete_all_at_request_id, delete_at_request_and_epoch_id, delete_at_request_id,
            read_all_data_versioned, read_context_at_id, store_versioned_at_request_id,
        },
    },
};
use kms_grpc::{
    RequestId,
    identifiers::{ContextId, EpochId},
    rpc_types::{PrivDataType, PubDataType},
};
use observability::metrics::METRICS;
use observability::metrics_names::{ERR_BACKUP, OP_DECOMPRESSION_KEYGEN, OP_NEW_CUSTODIAN_CONTEXT};
use serde::Serialize;
use std::{collections::HashMap, sync::Arc};
use strum::IntoEnumIterator;
use tfhe::Versionize;
use tfhe::named::Named;
use tfhe::xof_key_set::CompressedXofKeySet;
use tfhe::{integer::compression_keys::DecompressionKey, zk::CompactPkeCrs};
use thiserror::Error;
use threshold_execution::tfhe_internals::public_keysets::FhePubKeySet;
use tokio::sync::{Mutex, OwnedRwLockReadGuard, RwLock};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum StorageError {
    #[error("Trying to write content that already exists")]
    DuplicateError,
    #[error("Writing error")]
    WritingError,
    #[error("Reading error")]
    ReadingError,
    #[error("Purging error")]
    PurgingError,
    #[error("Backup vault purging error")]
    BackupVaultPurgingError,
    #[error("MetaStore error: {0}")]
    MetaStoreError(String),
    #[error("Error when backing up material")]
    BackupError,
    #[error("Other error: {0}")]
    Other(String),
}

/// Marker trait for private FHE materials.
/// This exists because FHE materials are stored by epochs, unlike other materials.
/// So we use this trait to differentiate FHE materials from others.
pub(crate) trait PrivateMaterialUnderEpoch {}

impl PrivateMaterialUnderEpoch for ThresholdFheKeys {}
impl PrivateMaterialUnderEpoch for KmsFheKeyHandles {}
impl PrivateMaterialUnderEpoch for CrsGenMetadata {}

/// The public-key payload produced by an FHE keygen and consumed by the
/// storage helpers.
///
/// Boxing the inner values keeps the enum cheap to move.
#[derive(Clone)]
pub enum PublicKeySet {
    Standard(Box<FhePubKeySet>),
    Compressed {
        compact_public_key: Box<tfhe::CompactPublicKey>,
        compressed_keyset: Box<CompressedXofKeySet>,
    },
}

/// A cached generic storage entity for the common data structures
/// used by both the centralized and the threshold KMS.
///
/// This struct provides thread-safe access to public, private, and optional backup storage,
/// along with a cache for generated public keys. Cloning is cheap due to internal Arc usage.
///
/// Warning: In relation to concurrency where multiple locks are needed always lock public_storage first, then private_storage second, backup_vault third and finally pk_cache last.
pub struct CryptoMaterialStorage<
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
> {
    /// Storage for publicly readable data (may be susceptible to malicious modifications)
    pub(crate) public_storage: Arc<Mutex<PubS>>,

    /// Storage for private data (only accessible by owner, modifications are detectable)
    pub(crate) private_storage: Arc<Mutex<PrivS>>,

    /// Optional backup vault for recovery purposes
    pub(crate) backup_vault: Option<Arc<Mutex<Vault>>>,
}

impl<PubS, PrivS> CryptoMaterialStorage<PubS, PrivS>
where
    PubS: Storage + Send + Sync + 'static,
    PrivS: StorageExt + Send + Sync + 'static,
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
        backup_vault: Option<Arc<Mutex<Vault>>>,
    ) -> Self {
        Self {
            public_storage,
            private_storage,
            backup_vault,
        }
    }

    /// Creates a CryptoMaterialStorage by wrapping the provided storages.
    pub fn from(public_storage: PubS, private_storage: PrivS, backup_vault: Option<Vault>) -> Self {
        Self::new(
            Arc::new(Mutex::new(public_storage)),
            Arc::new(Mutex::new(private_storage)),
            backup_vault.map(|s| Arc::new(Mutex::new(s))),
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
    pub fn get_backup_vault(&self) -> Option<Arc<Mutex<Vault>>> {
        self.backup_vault.as_ref().map(Arc::clone)
    }

    // =========================
    // Existence Check Methods
    // =========================

    /// Check if data exists in both public and private storage
    #[allow(dead_code)]
    pub(in crate::vault::storage::crypto_material) async fn data_exists(
        &self,
        req_id: &RequestId,
        pub_data_type: &str,
        priv_data_type: &str,
    ) -> anyhow::Result<bool> {
        // First locking public storage, then private storage as per concurrency rules
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

    /// Check if data exists in both public and private storage,
    /// where the private part is stored at a specific epoch.
    ///
    /// Returns `Ok(true)` if all entries are present, `Ok(false)` if any is
    /// missing, or `Err(StorageError)` if the storage backend fails the check.
    pub(in crate::vault::storage::crypto_material) async fn data_exists_at_epoch(
        &self,
        req_id: &RequestId,
        epoch_id: &EpochId,
        pub_data_type: &[String],
        priv_data_type: &[String],
    ) -> Result<bool, StorageError> {
        // First locking public storage, then private storage as per concurrency rules
        let pub_storage = self.public_storage.lock().await;
        let priv_storage = self.private_storage.lock().await;

        check_data_exists_at_epoch(
            &*pub_storage,
            &*priv_storage,
            req_id,
            epoch_id,
            pub_data_type,
            priv_data_type,
        )
        .await
    }

    /// Check if FHE keys exist.
    ///
    /// The `epoch_id` identifies the epoch that the secret key belongs to.
    /// This checks for both uncompressed keys (`CompactPublicKey` + `ServerKey`) and the current
    /// compressed layout (`CompressedXofKeySet` + `CompactPublicKey`).
    ///
    /// Returns `Ok(true)` if either layout is fully present, `Ok(false)` if
    /// neither is, or `Err(StorageError)` on a storage backend failure.
    pub async fn fhe_keys_exists(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
    ) -> Result<bool, StorageError> {
        let priv_types = vec![PrivDataType::FhePrivateKey.to_string()];
        // Try the uncompressed (standard) layout first.
        if self
            .data_exists_at_epoch(
                key_id,
                epoch_id,
                &[
                    PubDataType::PublicKey.to_string(),
                    PubDataType::ServerKey.to_string(),
                ],
                &priv_types,
            )
            .await?
        {
            return Ok(true);
        }
        // Fallback: check for the current compressed layout.
        self.data_exists_at_epoch(
            key_id,
            epoch_id,
            &[
                PubDataType::CompressedXofKeySet.to_string(),
                PubDataType::PublicKey.to_string(),
            ],
            &priv_types,
        )
        .await
    }

    /// Check if a CRS exists for `(crs_id, epoch_id)`.
    ///
    /// Returns `Ok(true)` if both the public CRS and the private metadata are
    /// present, `Ok(false)` if either is missing, or `Err(StorageError)` on a
    /// storage backend failure.
    pub async fn crs_exists(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
    ) -> Result<bool, StorageError> {
        self.data_exists_at_epoch(
            crs_id,
            epoch_id,
            &[PubDataType::CRS.to_string()],
            &[PrivDataType::CrsInfo.to_string()],
        )
        .await
    }

    /// Note that this method must not be executed by multiple threads in parallel to avoid an inconsistent storage state.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_persistent_and_meta_storage<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
        PrivData: Serialize + Versionize + Named + Send + Sync,
        MetaT: Clone,
    >(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        pub_data: Option<(&'a PubData, PubDataType)>,
        priv_data: Option<(&'a PrivData, PrivDataType)>,
        meta_data: MetaT,
        meta_store: Arc<RwLock<MetaStore<MetaT>>>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError>
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        // First ensure that the meta store request is pending
        ensure_meta_store_request_pending(&meta_store, req_id)
            .await
            .map_err(|e| StorageError::MetaStoreError(e.to_string()))?;
        let res = self
            .handle_all_storage(req_id, epoch_id, pub_data, priv_data, true, op_metric_tag)
            .await;
        update_meta_store(res, req_id, meta_data, meta_store, op_metric_tag).await
    }

    /// General method for handling the storage of material, including backup.
    pub(in crate::vault::storage::crypto_material) async fn handle_all_storage<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
        PrivData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        pub_data: Option<(&'a PubData, PubDataType)>,
        priv_data: Option<(&'a PrivData, PrivDataType)>,
        update_backup: bool,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError>
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let pub_type = pub_data.map(|(_, t)| t);
        let priv_type = priv_data.map(|(_, t)| t);
        if self
            .write_data_pair(req_id, epoch_id, pub_data, priv_data)
            .await
        {
            if update_backup {
                // If storage is ok, then update the backup
                if !self.update_backup_vault(false, op_metric_tag).await {
                    // Observe that even if backup fails, we do not want to purge the material
                    return Err(StorageError::BackupError);
                }
            }
        } else {
            // If storage write failed then purge
            let pub_types: Vec<PubDataType> = pub_type.into_iter().collect();
            let priv_types: Vec<PrivDataType> = priv_type.into_iter().collect();
            if !self
                .purge_material(req_id, epoch_id, &pub_types, &priv_types)
                .await
            {
                return Err(StorageError::PurgingError);
            }
            return Err(StorageError::WritingError);
        }
        tracing::info!(
            "Successfully stored public data element {pub_type:?} and private data element {priv_type:?} under the handle {req_id} with epoch {epoch_id:?} for metric {op_metric_tag}",
        );
        Ok(())
    }

    pub(crate) async fn purge_crs_material(&self, req_id: &RequestId, epoch_id: &EpochId) -> bool {
        self.purge_material(
            req_id,
            Some(epoch_id),
            &[PubDataType::CRS],
            &[PrivDataType::CrsInfo],
        )
        .await
    }

    /// Helper method to purge material.
    /// Returns true if purge is successful, false otherwise.
    /// Even if no data exists, it is still considered a successful purge.
    pub(in crate::vault::storage::crypto_material) async fn purge_material(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        public_types: &[PubDataType],
        private_types: &[PrivDataType],
    ) -> bool {
        // Lock both stores up front to enforce the public-then-private locking order.
        let mut pub_storage = self.public_storage.lock().await;
        let mut priv_storage = self.private_storage.lock().await;

        let f_pub = async {
            let mut failed = false;
            for cur_pub_type in public_types {
                // Note that no public data is epoched
                let del_res =
                    delete_at_request_id(&mut (*pub_storage), req_id, &cur_pub_type.to_string())
                        .await;
                if let Err(e) = &del_res {
                    failed = true;
                    tracing::warn!(
                        "Failed to delete public type {cur_pub_type} for request {req_id}: {e}"
                    );
                }
            }
            failed
        };

        let f_priv = async {
            let mut failed = false;
            for cur_priv_type in private_types {
                match cur_priv_type {
                    // For FHE keys and CRS info, we need to delete at epoch level
                    PrivDataType::FheKeyInfo
                    | PrivDataType::FhePrivateKey
                    | PrivDataType::CrsInfo => {
                        if let Some(inner_epoch) = epoch_id {
                            let del_res = delete_at_request_and_epoch_id(
                                &mut (*priv_storage),
                                req_id,
                                inner_epoch,
                                &cur_priv_type.to_string(),
                            )
                            .await;
                            if let Err(e) = &del_res {
                                failed = true;
                                tracing::warn!(
                                    "Failed to delete private type {cur_priv_type} for request {req_id} and epoch {inner_epoch}: {e}"
                                );
                            }
                        } else {
                            failed = true;
                            tracing::error!(
                                "Epoch ID is required for deleting private type {cur_priv_type} for request {req_id}, but it is not provided. Skipping deletion of this type."
                            );
                        }
                    }
                    // For other private data, we can delete at request level
                    // Observe we make the types explicit to ensure a compile error when a new type is added
                    #[allow(deprecated)]
                    PrivDataType::SigningKey
                    | PrivDataType::PrssSetup
                    | PrivDataType::PrssSetupCombined
                    | PrivDataType::ContextInfo => {
                        let del_res = delete_at_request_id(
                            &mut (*priv_storage),
                            req_id,
                            &cur_priv_type.to_string(),
                        )
                        .await;
                        if let Err(e) = &del_res {
                            failed = true;
                            tracing::warn!(
                                "Failed to delete private type {cur_priv_type} for request {req_id}: {e}"
                            );
                        }
                    }
                }
            }
            failed
        };

        let (pub_failed, priv_failed) = tokio::join!(f_pub, f_priv);
        // If anything failed, return false. Else return true
        !(pub_failed || priv_failed)
    }

    /// Write both public and private data to storage in an atomic manner.
    /// Returns true if both writes are successful, false otherwise.
    /// WARNING: Does NOT validate the type of `pub_data` matches the `pub_data_type` nor `priv_data` matches `priv_data_type`.
    pub(in crate::vault::storage::crypto_material) async fn write_data_pair<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
        PrivData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        pub_data: Option<(&'a PubData, PubDataType)>,
        priv_data: Option<(&'a PrivData, PrivDataType)>,
    ) -> bool
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let pub_write = async {
            let Some((pub_d, pub_t)) = pub_data else {
                return true;
            };
            self.write_pub_data(req_id, pub_d, &pub_t).await
        };
        let priv_write = async {
            let Some((priv_d, priv_t)) = priv_data else {
                return true;
            };
            self.write_priv_data(req_id, epoch_id, priv_d, &priv_t)
                .await
        };
        let (pub_ok, priv_ok) = tokio::join!(pub_write, priv_write);
        pub_ok && priv_ok
    }

    /// Write data to the public storage backend.
    /// Returns true if the write is successful, false otherwise.
    /// WARNING: Does NOT validate the type of `pub_data` matches the `pub_data_type`.
    pub(in crate::vault::storage::crypto_material) async fn write_pub_data<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        pub_data: &'a PubData,
        pub_data_type: &PubDataType,
    ) -> bool
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let mut pub_storage = self.public_storage.lock().await;
        // Observe that there is no epoched version for public data
        if let Err(e) = store_versioned_at_request_id(
            &mut *pub_storage,
            req_id,
            pub_data,
            &pub_data_type.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store public type {pub_data_type} for request {req_id}: {e}"
            );
            return false;
        }
        true
    }

    /// Write data to the private storage backend.
    /// Returns true if the write is successful, false otherwise.
    /// WARNING: Does NOT validate the type of `priv_data` matches the `priv_data_type`.
    pub(in crate::vault::storage::crypto_material) async fn write_priv_data<
        'a,
        PrivData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        priv_data: &'a PrivData,
        priv_data_type: &PrivDataType,
    ) -> bool
    where
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let mut priv_storage = self.private_storage.lock().await;
        match priv_data_type {
            // For FHE keys and CRS info, we need to delete at epoch level
            PrivDataType::FheKeyInfo | PrivDataType::FhePrivateKey | PrivDataType::CrsInfo => {
                if let Some(inner_epoch) = epoch_id {
                    if let Err(e) = store_versioned_at_request_and_epoch_id(
                        &mut *priv_storage,
                        req_id,
                        inner_epoch,
                        priv_data,
                        &priv_data_type.to_string(),
                    )
                    .await
                    {
                        tracing::error!(
                            "Failed to store private type {priv_data_type} for request {req_id} and epoch {inner_epoch}: {e}"
                        );
                        return false;
                    }
                } else {
                    tracing::error!(
                        "Epoch ID is required for writing private type {priv_data_type} for request {req_id}, but it is not provided. Skipping writing this type."
                    );
                    return false;
                }
            }
            // For other private data, we can delete at request level
            // Observe we make the types explicit to ensure a compile error when a new type is added
            #[allow(deprecated)]
            PrivDataType::SigningKey
            | PrivDataType::PrssSetup
            | PrivDataType::PrssSetupCombined
            | PrivDataType::ContextInfo => {
                if let Err(e) = store_versioned_at_request_id(
                    &mut *priv_storage,
                    req_id,
                    priv_data,
                    &priv_data_type.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store private type {priv_data_type} for request {req_id}: {e}"
                    );
                    return false;
                }
            }
        };
        true
    }

    /// Helper function to write the FHE keys to storage, along with updating the cache if the storage operation was successful.
    ///
    /// Note that backup errors are not treated as fatal since the keys are safely stored.
    #[allow(clippy::too_many_arguments)]
    pub(in crate::vault::storage::crypto_material) async fn handle_fhe_keys<
        PrivKeyData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        priv_fhe_data: PrivKeyData,
        priv_data_type: PrivDataType,
        fhe_key_set: PublicKeySet,
        cache: Arc<RwLock<HashMap<(RequestId, EpochId), PrivKeyData>>>,
        update_backup: bool,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError>
    where
        for<'a> <PrivKeyData as Versionize>::Versioned<'a>: Send + Sync,
    {
        // First try to store the special key (server key or compressed keyset).
        match &fhe_key_set {
            PublicKeySet::Standard(keys) => {
                self.handle_all_storage::<tfhe::ServerKey, tfhe::ServerKey>(
                    key_id,
                    Some(epoch_id),
                    Some((&keys.server_key, PubDataType::ServerKey)),
                    None,
                    false, // Defer backup
                    op_metric_tag,
                )
                .await?;
            }
            PublicKeySet::Compressed {
                compressed_keyset, ..
            } => {
                self
                    .handle_all_storage::<tfhe::xof_key_set::CompressedXofKeySet, tfhe::xof_key_set::CompressedXofKeySet>(
                        key_id,
                        Some(epoch_id),
                        Some((compressed_keyset, PubDataType::CompressedXofKeySet)),
                        None,
                        false, // Defer backup
                        op_metric_tag,
                    )
                    .await?;
            }
        };
        let pk_to_store = match &fhe_key_set {
            PublicKeySet::Standard(keys) => &keys.public_key,
            PublicKeySet::Compressed {
                compact_public_key, ..
            } => compact_public_key,
        };
        // Store the public key and private state.
        let res = self
            .handle_all_storage(
                key_id,
                Some(epoch_id),
                Some((pk_to_store, PubDataType::PublicKey)),
                Some((&priv_fhe_data, priv_data_type)),
                update_backup,
                op_metric_tag,
            )
            .await;
        if res.is_ok() || res.as_ref().is_err_and(|e| e == &StorageError::BackupError) {
            // Update cache
            let mut guarded_fhe_keys = cache.write().await;
            let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), priv_fhe_data);
            if previous.is_some() {
                tracing::warn!(
                    "Private FHE key data already exist in cache for {}, overwriting",
                    key_id
                );
            }
        }
        res
    }

    /// Write the CRS to public and private storage and update the meta
    /// store with the outcome. On a write failure the partial data is
    /// purged before the error is returned.
    pub(crate) async fn write_crs(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        pp: CompactPkeCrs,
        crs_info: CrsGenMetadata,
        meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        self.handle_persistent_and_meta_storage(
            crs_id,
            Some(epoch_id),
            Some((&pp, PubDataType::CRS)),
            Some((&crs_info.clone(), PrivDataType::CrsInfo)),
            crs_info,
            meta_store,
            op_metric_tag,
        )
        .await
    }

    pub(crate) async fn write_decompression_key(
        &self,
        key_id: &RequestId,
        meta_data: KeyGenMetadata,
        decompression_key: DecompressionKey,
        meta_store: Arc<RwLock<MetaStore<KeyGenMetadata>>>,
    ) -> Result<(), StorageError> {
        // First ensure that the meta store request is pending
        ensure_meta_store_request_pending(&meta_store, key_id)
            .await
            .map_err(|e| StorageError::MetaStoreError(e.to_string()))?;
        let res = self
            .handle_all_storage::<DecompressionKey, DecompressionKey>(
                key_id,
                None,
                Some((&decompression_key, PubDataType::DecompressionKey)),
                None,
                false, // No private data to back up
                OP_DECOMPRESSION_KEYGEN,
            )
            .await;
        // Finally update meta store
        update_meta_store(res, key_id, meta_data, meta_store, OP_DECOMPRESSION_KEYGEN).await
    }

    /// Write the backup keys to the storage and update the meta store.
    /// This methods writes all the material associated with backups to storage,
    /// and updates the meta store accordingly.
    ///
    /// This means that the public encryption key for backup is written to the public storage.
    /// The same goes for the commitments to the custodian shares and the recovery request.
    /// Finally the custodian context, with the information about the custodian nodes, is also written to public storage.
    /// The private key for decrypting backups is written to the private storage.
    ///
    /// NOTE: Unlike most other storage methods, this one will fail if there is no backup vault or if backup fails,
    /// since the goal of this method is exactly to setup a backup.
    pub async fn write_backup_keys(
        &self,
        recovery_material: RecoveryValidationMaterial,
        meta_store: Arc<RwLock<CustodianMetaStore>>,
    ) -> Result<(), StorageError> {
        let req_id = recovery_material.custodian_context().context_id;
        // First ensure that the meta store request is pending
        ensure_meta_store_request_pending(&meta_store, &req_id)
            .await
            .map_err(|e| {
                StorageError::MetaStoreError(format!(
                    "Meta store is not ready for request ID {req_id}: {e}"
                ))
            })?;
        // Ensure we have a backup vault before starting
        let vault = match self.backup_vault.as_ref() {
            Some(vault) => vault,
            None => {
                tracing::error!(
                    "No backup vault configured, cannot write backup keys for request {req_id}"
                );
                return Err(StorageError::BackupError);
            }
        };
        let mut res = self
            .handle_all_storage::<RecoveryValidationMaterial, RecoveryValidationMaterial>(
                &req_id,
                None,
                Some((&recovery_material, PubDataType::RecoveryMaterial)),
                None,
                true,
                OP_NEW_CUSTODIAN_CONTEXT,
            )
            .await;
        if res.is_err() {
            // Note that we also care about a BackupError here, since we are actually setting up the initial backup
            // Something went wrong so we will also purge the backup
            res = delete_all_at_request_id(&mut *vault.lock().await, &req_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Failed to purge backup vault after failed backup setup for request {req_id}: {e}"
                    );
                    StorageError::BackupVaultPurgingError
                });
        }
        // Update the current backup key in the storage
        {
            let mut guarded_backup_vault = vault.lock().await;
            match &mut guarded_backup_vault.keychain {
                Some(keychain) => {
                    if let KeychainProxy::SecretSharing(sharing_chain) = keychain {
                        // Store the public key in the secret sharing keychain
                        sharing_chain.set_backup_enc_key(
                            req_id,
                            recovery_material.custodian_context().backup_enc_key.clone(),
                        );
                    }
                }
                None => {
                    tracing::info!(
                        "No keychain in backup vault, skipping setting backup encryption key for request {req_id}"
                    );
                }
            }
        }
        // Finally update meta store
        update_meta_store(
            res,
            &req_id,
            recovery_material,
            meta_store,
            OP_NEW_CUSTODIAN_CONTEXT,
        )
        .await
    }

    // TODO(#2849) should be changed to KeyId
    pub(in crate::vault::storage::crypto_material) async fn read_guarded_crypto_material_from_cache<
        T: Clone,
    >(
        key_id: &RequestId,
        epoch_id: &EpochId,
        fhe_keys: Arc<RwLock<HashMap<(RequestId, EpochId), T>>>,
    ) -> anyhow::Result<OwnedRwLockReadGuard<HashMap<(RequestId, EpochId), T>, T>> {
        // Returning a OwnedRwLockReadGuard just saves some data-copying
        // if the value is already in the cache.
        let fhe_keys = fhe_keys.clone();
        let guard = fhe_keys.read_owned().await;
        OwnedRwLockReadGuard::try_map(guard, |m| m.get(&(*key_id, *epoch_id))).map_err(|_| {
            anyhow_error_and_warn_log(format!(
                "Failed to find crypto material in cache for request ID {key_id}, epoch ID {epoch_id}"
            ))
        })
    }

    pub(in crate::vault::storage::crypto_material) async fn refresh_fhe_private_material<T>(
        &self,
        cache: Arc<RwLock<HashMap<(RequestId, EpochId), T>>>,
        req_id: &RequestId,
        epoch_id: &EpochId,
    ) -> anyhow::Result<()>
    where
        T: PrivateCryptoMaterialReader + PrivateMaterialUnderEpoch,
    {
        // This function does not need to be atomic, so we take a read lock
        // on the cache first and check for existence, then release it.
        // We do this because we want to avoid write locks unless necessary.
        let exists = {
            let guarded_fhe_keys = cache.read().await;
            guarded_fhe_keys.contains_key(&(*req_id, *epoch_id))
        };

        if !exists {
            let storage = self.private_storage.lock().await;
            match T::read_from_storage_at_epoch(&(*storage), req_id, epoch_id).await {
                Ok(new_fhe_keys) => {
                    let mut guarded_fhe_keys = cache.write().await;
                    guarded_fhe_keys.insert((*req_id, *epoch_id), new_fhe_keys);
                }
                Err(e) => {
                    return Err(anyhow_error_and_warn_log(format!(
                        "Failed to refresh crypto material from storage for request ID {req_id}: {e}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Write the context info to the private storage backend.
    pub(crate) async fn write_context_info(
        &self,
        context_id: &ContextId,
        context_info: &ContextInfo,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        // No public data so we just reuse ContextInfo to appease the compiler
        self.handle_all_storage::<ContextInfo, ContextInfo>(
            &((*context_id).into()),
            None,
            None,
            Some((context_info, PrivDataType::ContextInfo)),
            true,
            op_metric_tag,
        )
        .await
    }

    pub async fn read_context_info(&self, context_id: &ContextId) -> anyhow::Result<ContextInfo> {
        let priv_storage = self.private_storage.lock().await;
        let res = read_context_at_id(&*priv_storage, context_id).await?;
        log_storage_success_optional_variant(
            context_id,
            priv_storage.info(),
            &PrivDataType::ContextInfo.to_string(),
            false,
            None,
        );
        Ok(res)
    }

    /// Read all context info entries from storage.
    pub async fn read_all_context_info(&self) -> anyhow::Result<Vec<ContextInfo>> {
        let priv_storage = self.private_storage.lock().await;

        let context_map: HashMap<_, ContextInfo> =
            read_all_data_versioned(&*priv_storage, &PrivDataType::ContextInfo.to_string())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to read context info: {}", e))?;
        Ok(context_map.into_values().collect())
    }

    /// Synchronize the backup vault with the current private storage contents
    /// and log and update the metrics in case of an error.
    ///
    /// Iterates over all [`PrivDataType`] variants and copies any data present
    /// in private storage but missing from the backup vault.
    ///
    /// When `overwrite` is `true`, existing backup entries are deleted and
    /// re-written (used when the backup encryption key changes, e.g. on a new
    /// custodian context). When `false`, existing entries are skipped.
    ///
    /// Returns `true` if the update succeeded, `false` if it failed (in which case the error is also logged and the metrics are updated).
    pub async fn update_backup_vault(&self, overwrite: bool, op_metric_tag: &'static str) -> bool {
        if let Err(e) = self.inner_update_backup_vault(overwrite).await {
            tracing::error!("Failed to update backup vault for operation {op_metric_tag}: {e}",);
            METRICS.increment_backup_error_counter(op_metric_tag, ERR_BACKUP);
            false
        } else {
            tracing::info!("Successfully updated backup vault for {op_metric_tag}",);
            true
        }
    }

    /// Synchronize the backup vault with the current private storage contents
    ///
    /// Iterates over all [`PrivDataType`] variants and copies any data present
    /// in private storage but missing from the backup vault.
    ///
    /// When `overwrite` is `true`, existing backup entries are deleted and
    /// re-written (used when the backup encryption key changes, e.g. on a new
    /// custodian context). When `false`, existing entries are skipped.
    pub(in crate::vault::storage::crypto_material) async fn inner_update_backup_vault(
        &self,
        overwrite: bool,
    ) -> anyhow::Result<()> {
        match self.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.get_private_storage();
                let private_storage = private_storage.lock().await;
                let mut backup_vault = backup_vault.lock().await;
                if !crate::engine::backup_operator::keychain_initialized(&backup_vault).await {
                    tracing::warn!(
                        "Secret sharing keychain in the backup vault has not been initialized yet. Skipping backup update."
                    );
                    return Ok(());
                }
                for cur_type in PrivDataType::iter() {
                    match cur_type {
                        // These types might have epoch-specific data
                        PrivDataType::FheKeyInfo => {
                            crate::engine::backup_operator::update_specific_backup_vault_for_all_epochs::<PrivS, ThresholdFheKeys>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                                overwrite,
                            )
                            .await?;
                        }
                        PrivDataType::FhePrivateKey => {
                            crate::engine::backup_operator::update_specific_backup_vault_for_all_epochs::<PrivS, KmsFheKeyHandles>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                                overwrite,
                            )
                            .await?;
                        }
                        // Non epoched types
                        PrivDataType::PrssSetupCombined => {
                            crate::engine::backup_operator::update_specific_backup_vault::<
                                PrivS,
                                PRSSSetupCombined,
                            >(
                                &private_storage, &mut backup_vault, cur_type, overwrite
                            )
                            .await?;
                        }
                        #[expect(deprecated)]
                        PrivDataType::PrssSetup => {
                            crate::engine::backup_operator::update_legacy_prss_13_4::<PrivS>(
                                &private_storage,
                                &mut backup_vault,
                                overwrite,
                            )
                            .await?;
                        }
                        PrivDataType::SigningKey => {
                            // TODO(#2862) will eventually be epoched
                            crate::engine::backup_operator::update_specific_backup_vault::<
                                PrivS,
                                PrivateSigKey,
                            >(
                                &private_storage, &mut backup_vault, cur_type, overwrite
                            )
                            .await?;
                        }
                        PrivDataType::CrsInfo => {
                            crate::engine::backup_operator::update_specific_backup_vault_for_all_epochs::<PrivS, CrsGenMetadata>(
                                &private_storage,
                                &mut backup_vault,
                                cur_type,
                                overwrite,
                            )
                            .await?;
                        }
                        PrivDataType::ContextInfo => {
                            crate::engine::backup_operator::update_specific_backup_vault::<
                                PrivS,
                                ContextInfo,
                            >(
                                &private_storage, &mut backup_vault, cur_type, overwrite
                            )
                            .await?;
                        }
                    }
                }
                Ok(())
            }
            None => Ok(()),
        }
    }
}

/// Update the meta store based on the result of a storage operation, and log and update the metrics in case of an error.
/// If the meta store is updated successfully, then the orginal storage result is returned.
/// If the meta store update fails, then a MetaStoreError is returned, which includes the original StorageError.
pub(in crate::vault::storage::crypto_material) async fn update_meta_store<MetaT: Clone>(
    storage_res: Result<(), StorageError>,
    req_id: &RequestId,
    meta_data: MetaT,
    meta_store: Arc<RwLock<MetaStore<MetaT>>>,
    op_metric_tag: &'static str,
) -> Result<(), StorageError> {
    let mut meta_store_ok = true;
    if let Err(e) = &storage_res
        && e != &StorageError::BackupError
    {
        // We don't want to fail on backup errors
        meta_store_ok &= update_err_req_in_meta_store(
            &mut meta_store.write().await,
            req_id,
            e.to_string(),
            op_metric_tag,
        );
    } else {
        meta_store_ok &= update_ok_req_in_meta_store(
            &mut meta_store.write().await,
            req_id,
            meta_data,
            op_metric_tag,
        );
    }
    if !meta_store_ok {
        // NOTE this would indicate a bug since we have just verified that the meta can be updated in the start of this method
        // Thus the meta store update can only fail in case of a race condition, which would indicate a bug
        tracing::error!(
            "Failed to update meta store in metric {op_metric_tag} for request {req_id}",
        );
        if let Err(e) = &storage_res {
            return Err(StorageError::MetaStoreError(format!(
                "Failed to update meta store for request {req_id}. Also failed to store data with error: {e}",
            )));
        } else {
            return Err(StorageError::MetaStoreError(format!(
                "Failed to update meta store for request {req_id}, but storage succeeded."
            )));
        }
    }
    storage_res
}

// we need to manually implement clone, see  https://github.com/rust-lang/rust/issues/26925
impl<PubS: Storage + Send + Sync + 'static, PrivS: StorageExt + Send + Sync + 'static> Clone
    for CryptoMaterialStorage<PubS, PrivS>
{
    fn clone(&self) -> Self {
        Self {
            public_storage: Arc::clone(&self.public_storage),
            private_storage: Arc::clone(&self.private_storage),
            backup_vault: self.backup_vault.as_ref().map(Arc::clone),
        }
    }
}
