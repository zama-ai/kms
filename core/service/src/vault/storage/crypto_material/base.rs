//! Base implementation of cryptographic material storage
//!
//! This module provides the foundational storage implementation used by
//! both centralized and threshold KMS variants.
use crate::engine::threshold::service::epoch_manager::EpochData;
use crate::engine::threshold::service::session::PRSSSetupCombined;
use crate::util::meta_store::{
    MetaStorePermit, update_err_req_in_meta_store, update_ok_req_in_meta_store,
};
use crate::vault::storage::crypto_material::{data_exists, data_exists_at_epoch};
use crate::{
    anyhow_error_and_warn_log,
    backup::operator::RecoveryValidationMaterial,
    consts::SIGNING_KEY_ID,
    cryptography::signatures::PrivateSigKey,
    cryptography::signing::seed::RootSigningSeed,
    engine::{
        base::{CrsGenMetadata, KeyGenMetadata, KmsFheKeyHandles},
        context::ContextInfo,
        threshold::service::ThresholdFheKeys,
    },
    grpc::metastore_status_service::CustodianMetaStore,
    util::meta_store::MetaStore,
    vault::{
        Vault,
        storage::{
            Storage, StorageExt, StoreWriteOutcome,
            crypto_material::{
                log_storage_success_optional_variant, traits::PrivateCryptoMaterialReader,
            },
            delete_at_request_and_epoch_id, delete_at_request_id, delete_recovery_material_at_id,
            read_all_data_versioned, read_context_at_id, read_custodian_context_anchor,
            store_custodian_context_anchor, store_recovery_material,
        },
    },
};
use kms_grpc::EpochId;
use kms_grpc::{
    RequestId,
    identifiers::ContextId,
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
    Duplicate,
    #[error("Writing error")]
    Writing,
    #[error("Reading error")]
    Reading,
    #[error("Purging error")]
    Purging,
    #[error("MetaStore error: {0}")]
    MetaStore(String),
    #[error("Error when backing up material")]
    Backup,
    #[error("Other error: {0}")]
    Other(String),
}

/// Result of one public or private store requested by [`CryptoMaterialStorage::write_all`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MaterialWriteOutcome {
    /// The caller supplied no value for this public or private slot.
    NotRequested,
    /// The backend either created the entry or kept an entry that already existed.
    Stored(StoreWriteOutcome),
    /// The backend returned an error and may or may not have applied the write.
    Failed,
}

impl MaterialWriteOutcome {
    /// Whether this public or private store completed without an error.
    fn succeeded(self) -> bool {
        !matches!(self, Self::Failed)
    }

    /// Whether rollback should remove this public or private entry.
    fn should_purge(self, existed_before: bool) -> bool {
        match self {
            Self::Stored(StoreWriteOutcome::Created) => true,
            Self::Stored(StoreWriteOutcome::SkippedExisting) | Self::NotRequested => false,
            // A backend error may arrive after the write took effect. Never delete an entry that
            // was already there; otherwise cleanup must remove any partial result.
            Self::Failed => !existed_before,
        }
    }
}

/// Store outcomes for the optional public and private entries passed to `write_all`.
///
/// Threshold callers pair `PublicKey` with `FheKeyInfo`, or `CRS` with `CrsInfo`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PairWriteOutcome {
    public: MaterialWriteOutcome,
    private: MaterialWriteOutcome,
}

impl PairWriteOutcome {
    /// Whether both halves completed without a storage error.
    fn succeeded(self) -> bool {
        self.public.succeeded() && self.private.succeeded()
    }
}

/// Returns whether private data is stored under both an epoch ID and a request ID.
fn private_data_is_epoch_scoped(data_type: PrivDataType) -> bool {
    match data_type {
        PrivDataType::FheKeyInfo | PrivDataType::FhePrivateKey | PrivDataType::CrsInfo => true,
        #[expect(deprecated)]
        PrivDataType::SigningKey
        | PrivDataType::SigningSeed
        | PrivDataType::PrssSetup
        | PrivDataType::PrssSetupCombined
        | PrivDataType::ContextInfo
        | PrivDataType::EpochData
        | PrivDataType::CustodianContextAnchor => false,
    }
}

/// How a caller of [`update_meta_store`] wants a failed backup to be recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::vault::storage::crypto_material) enum BackupPolicy {
    /// The primary material is the deliverable and is already persisted, so a failed
    /// backup is recorded as a success and can be redone later.
    BackupIsBestEffort,
    /// The backup itself is the deliverable (see `write_backup_keys`), so a failed
    /// backup must be recorded as a failed request.
    BackupIsRequired,
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
/// The inner values are wrapped in `Arc` so the enum is cheap to clone and
/// share without deep-copying the underlying key material.
#[derive(Clone)]
pub enum PublicKeySet {
    Uncompressed(Arc<FhePubKeySet>),
    Compressed {
        compact_public_key: Arc<tfhe::CompactPublicKey>,
        compressed_keyset: Arc<CompressedXofKeySet>,
    },
}

/// A cached generic storage entity for the common data structures
/// used by both the centralized and the threshold KMS.
///
/// This struct provides thread-safe access to public, private, and optional backup storage,
/// along with a cache for generated public keys. Cloning is cheap due to internal Arc usage.
///
/// Warning: In relation to concurrency where multiple locks are needed always lock as follows:
/// meta_store -> public_storage -> private_storage second -> backup_vault -> pk_cache.
///
/// TODO(#3036) Note that holding a MetaStore lock should eventually be sufficient to not require locking multiple things at once.
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

    /// Serializes setup, destruction and recovery of the custodian context: each reads the anchor,
    /// the keychain and the vault, then rewrites some of them.
    pub(crate) custodian_context_lock: Arc<Mutex<()>>,
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
            custodian_context_lock: Arc::new(Mutex::new(())),
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
    pub(in crate::vault::storage::crypto_material) async fn data_exists(
        &self,
        req_id: &RequestId,
        pub_data_type: &[PubDataType],
        priv_data_type: &[PrivDataType],
    ) -> anyhow::Result<bool> {
        // First locking public storage, then private storage as per concurrency rules
        let pub_storage = self.public_storage.lock().await;
        let priv_storage = self.private_storage.lock().await;

        for cur_pub_data in pub_data_type {
            if !data_exists(&*pub_storage, req_id, &cur_pub_data.to_string()).await? {
                return Ok(false);
            }
        }
        for cur_priv_data in priv_data_type {
            if !data_exists(&*priv_storage, req_id, &cur_priv_data.to_string()).await? {
                return Ok(false);
            }
        }
        Ok(true)
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
        pub_data_type: &[PubDataType],
        priv_data_type: &[PrivDataType],
    ) -> Result<bool, StorageError> {
        // First locking public storage, then private storage as per concurrency rules
        let pub_storage = self.public_storage.lock().await;
        let priv_storage = self.private_storage.lock().await;
        for cur_pub_data in pub_data_type {
            if !data_exists(&*pub_storage, req_id, &cur_pub_data.to_string())
                .await
                .map_err(|_| StorageError::Reading)?
            {
                return Ok(false);
            }
        }
        for cur_priv_data in priv_data_type {
            if !data_exists_at_epoch(&*priv_storage, req_id, epoch_id, &cur_priv_data.to_string())
                .await
                .map_err(|_| StorageError::Reading)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Check if FHE keys exist.
    /// Observe that this operation reads the file system and is thus relatively slow.
    ///
    /// The `epoch_id` identifies the epoch that the secret key belongs to.
    /// This checks for both uncompressed keys (`CompactPublicKey` + `ServerKey`) and the current
    /// compressed layout (`CompressedXofKeySet` + `CompactPublicKey`).
    /// The `threshold` parameter is used to indicate if the check is for threshold or centralized keys.
    ///
    /// Returns `Ok(true)` if either layout is fully present, `Ok(false)` if
    /// neither is, or `Err(StorageError)` on a storage backend failure.
    pub(in crate::vault::storage::crypto_material) async fn fhe_keys_exists(
        &self,
        key_id: &RequestId,
        epoch_id: &EpochId,
        threshold: bool,
    ) -> Result<bool, StorageError> {
        let priv_types = if threshold {
            vec![PrivDataType::FheKeyInfo]
        } else {
            vec![PrivDataType::FhePrivateKey]
        };
        // Try the compressed layout first.
        if self
            .data_exists_at_epoch(
                key_id,
                epoch_id,
                &[PubDataType::CompressedXofKeySet, PubDataType::PublicKey],
                &priv_types,
            )
            .await?
        {
            return Ok(true);
        }
        // Fallback: check for the current uncompressed layout.
        self.data_exists_at_epoch(
            key_id,
            epoch_id,
            &[PubDataType::PublicKey, PubDataType::ServerKey],
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
            &[PubDataType::CRS],
            &[PrivDataType::CrsInfo],
        )
        .await
    }

    /// Handle the storage of data after generation, and update the meta store accordingly.
    /// This methods assumes that `req_id` has already been added to the meta store and will fail if not.
    ///
    /// WARNING: this method is not safe to call concurrently with the _same_ arguments.
    /// However, this should never happen, since since any `req_id` should have been added
    /// to the meta store as pending before this call, which can only be done for a fresh `req_id`.
    #[expect(clippy::too_many_arguments)]
    async fn handle_persistent_and_meta_storage<
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
        permit: MetaStorePermit<MetaT>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError>
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let res = self
            .write_all(req_id, epoch_id, pub_data, priv_data, true, op_metric_tag)
            .await;
        update_meta_store(
            res,
            meta_data,
            &meta_store,
            permit,
            BackupPolicy::BackupIsBestEffort,
            op_metric_tag,
        )
        .await
    }

    /// Stores up to one public entry and one private entry, then optionally updates the backup.
    ///
    /// Threshold callers use this for `PublicKey`/`FheKeyInfo` and `CRS`/`CrsInfo` pairs.
    /// If one requested half exists, the method preserves it and stores the missing half. The
    /// caller must ensure that the two halves belong together.
    /// Resharing passes only the new epoch's private half. If a store fails, cleanup preserves
    /// entries that existed before the call and removes entries created during the call.
    /// Callers must serialize calls that can write the same entries until this method returns.
    pub(in crate::vault::storage::crypto_material) async fn write_all<
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
        let pub_type = match pub_data {
            Some((_, t)) => vec![t],
            None => vec![],
        };
        let priv_type = match priv_data {
            Some((_, t)) => vec![t],
            None => vec![],
        };
        // First ensure that the data to be written does not already exist
        if let Some(inner_epoch_id) = epoch_id
            && self
                .data_exists_at_epoch(req_id, inner_epoch_id, &pub_type, &priv_type)
                .await?
        {
            return Err(StorageError::Duplicate);
        }
        if self
            .data_exists(req_id, &pub_type, &priv_type)
            .await
            .map_err(|e| StorageError::Other(e.to_string()))?
        {
            return Err(StorageError::Duplicate);
        }

        // Capture existence before either store starts. A backend can apply a write and then
        // return an error, so a later query cannot tell whether this call created the entry.
        let public_existed = if pub_type.is_empty() {
            false
        } else {
            self.data_exists(req_id, &pub_type, &[])
                .await
                .map_err(|e| StorageError::Other(e.to_string()))?
        };
        let private_existed = match priv_type.first() {
            None => false,
            Some(private_type) => {
                if private_data_is_epoch_scoped(*private_type) {
                    match epoch_id {
                        Some(epoch_id) => {
                            self.data_exists_at_epoch(req_id, epoch_id, &[], &priv_type)
                                .await?
                        }
                        None => false,
                    }
                } else {
                    self.data_exists(req_id, &[], &priv_type)
                        .await
                        .map_err(|e| StorageError::Other(e.to_string()))?
                }
            }
        };

        // Now proceed with writing
        let write_outcome = self
            .write_data_pair(req_id, epoch_id, pub_data, priv_data)
            .await;
        if write_outcome.succeeded() {
            if update_backup {
                // If storage is ok, then update the backup
                if !self.update_backup_vault(false, op_metric_tag).await {
                    // Observe that even if backup fails, we do not want to purge the material
                    return Err(StorageError::Backup);
                }
            }
        } else {
            let public_types_to_purge: &[PubDataType] =
                if write_outcome.public.should_purge(public_existed) {
                    &pub_type
                } else {
                    &[]
                };
            let private_types_to_purge: &[PrivDataType] =
                if write_outcome.private.should_purge(private_existed) {
                    &priv_type
                } else {
                    &[]
                };
            if !self
                .purge_material(
                    req_id,
                    epoch_id,
                    public_types_to_purge,
                    private_types_to_purge,
                )
                .await
            {
                return Err(StorageError::Purging);
            }
            return Err(StorageError::Writing);
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
                if private_data_is_epoch_scoped(*cur_priv_type) {
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
                } else {
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
            failed
        };

        let (pub_failed, priv_failed) = tokio::join!(f_pub, f_priv);
        // If anything failed, return false. Else return true
        !(pub_failed || priv_failed)
    }

    /// Stores the optional public and private entries and retains each store outcome.
    /// WARNING: Does NOT validate the type of `pub_data` matches the `pub_data_type` nor `priv_data` matches `priv_data_type`.
    async fn write_data_pair<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
        PrivData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        epoch_id: Option<&EpochId>,
        pub_data: Option<(&'a PubData, PubDataType)>,
        priv_data: Option<(&'a PrivData, PrivDataType)>,
    ) -> PairWriteOutcome
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let pub_write = async {
            let Some((pub_d, pub_t)) = pub_data else {
                return MaterialWriteOutcome::NotRequested;
            };
            match self.write_pub_data(req_id, pub_d, &pub_t).await {
                Some(outcome) => MaterialWriteOutcome::Stored(outcome),
                None => MaterialWriteOutcome::Failed,
            }
        };
        let priv_write = async {
            let Some((priv_d, priv_t)) = priv_data else {
                return MaterialWriteOutcome::NotRequested;
            };
            match self
                .write_priv_data(req_id, epoch_id, priv_d, &priv_t)
                .await
            {
                Some(outcome) => MaterialWriteOutcome::Stored(outcome),
                None => MaterialWriteOutcome::Failed,
            }
        };
        let (public, private) = tokio::join!(pub_write, priv_write);
        PairWriteOutcome { public, private }
    }

    /// Write data to the public storage backend.
    /// Returns the store outcome, or `None` if the write fails.
    /// WARNING: Does NOT validate the type of `pub_data` matches the `pub_data_type`.
    pub(in crate::vault::storage::crypto_material) async fn write_pub_data<
        'a,
        PubData: Serialize + Versionize + Named + Send + Sync,
    >(
        &self,
        req_id: &RequestId,
        pub_data: &'a PubData,
        pub_data_type: &PubDataType,
    ) -> Option<StoreWriteOutcome>
    where
        <PubData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let mut pub_storage = self.public_storage.lock().await;
        // Observe that there is no epoched version for public data
        match pub_storage
            .store_data(pub_data, req_id, &pub_data_type.to_string())
            .await
        {
            Ok(outcome) => Some(outcome),
            Err(e) => {
                tracing::error!(
                    "Failed to store public type {pub_data_type} for request {req_id}: {e}"
                );
                None
            }
        }
    }

    /// Write data to the private storage backend.
    /// Returns the store outcome, or `None` if the write fails.
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
    ) -> Option<StoreWriteOutcome>
    where
        <PrivData as Versionize>::Versioned<'a>: Send + Sync,
    {
        let mut priv_storage = self.private_storage.lock().await;
        if private_data_is_epoch_scoped(*priv_data_type) {
            if let Some(inner_epoch) = epoch_id {
                match priv_storage
                    .store_data_at_epoch(
                        priv_data,
                        req_id,
                        inner_epoch,
                        &priv_data_type.to_string(),
                    )
                    .await
                {
                    Ok(outcome) => Some(outcome),
                    Err(e) => {
                        tracing::error!(
                            "Failed to store private type {priv_data_type} for request {req_id} and epoch {inner_epoch}: {e}"
                        );
                        None
                    }
                }
            } else {
                tracing::error!(
                    "Epoch ID is required for writing private type {priv_data_type} for request {req_id}, but it is not provided. Skipping writing this type."
                );
                None
            }
        } else {
            match priv_storage
                .store_data(priv_data, req_id, &priv_data_type.to_string())
                .await
            {
                Ok(outcome) => Some(outcome),
                Err(e) => {
                    tracing::error!(
                        "Failed to store private type {priv_data_type} for request {req_id}: {e}"
                    );
                    None
                }
            }
        }
    }

    /// Helper function to write the FHE keys to storage, along with updating the cache if the storage operation was successful.
    ///
    /// Note that backup errors are not treated as fatal since the keys are safely stored.
    #[expect(clippy::too_many_arguments)]
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
        let special_pub_type = match &fhe_key_set {
            PublicKeySet::Uncompressed(_) => PubDataType::ServerKey,
            PublicKeySet::Compressed { .. } => PubDataType::CompressedXofKeySet,
        };

        // First try to store the special key (server key or compressed keyset).
        match &fhe_key_set {
            PublicKeySet::Uncompressed(keys) => {
                self.write_all::<tfhe::ServerKey, tfhe::ServerKey>(
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
                    .write_all::<tfhe::xof_key_set::CompressedXofKeySet, tfhe::xof_key_set::CompressedXofKeySet>(
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
            PublicKeySet::Uncompressed(keys) => &keys.public_key,
            PublicKeySet::Compressed {
                compact_public_key, ..
            } => compact_public_key,
        };
        // Store the public key and private state.
        let res = self
            .write_all(
                key_id,
                Some(epoch_id),
                Some((pk_to_store, PubDataType::PublicKey)),
                Some((&priv_fhe_data, priv_data_type)),
                update_backup,
                op_metric_tag,
            )
            .await;
        match &res {
            Ok(_) | Err(StorageError::Backup) => {
                // Backup-only failures still leave the keys safely persisted, so
                // refresh the cache as if the write had succeeded.
                let mut guarded_fhe_keys = cache.write().await;
                let previous = guarded_fhe_keys.insert((*key_id, *epoch_id), priv_fhe_data);
                if previous.is_some() {
                    tracing::warn!(
                        "Private FHE key data already exist in cache for {}, overwriting",
                        key_id
                    );
                }
            }
            Err(_) => {
                // Clean up the "special" key data stored in the first step, in case the second storage step fails, to avoid having orphaned data
                if !self
                    .purge_material(key_id, Some(epoch_id), &[special_pub_type], &[])
                    .await
                {
                    tracing::error!(
                        "Failed to purge orphan {special_pub_type} for {key_id} after FHE-key write failure; original error: {:?}",
                        res
                    );
                    return Err(StorageError::Purging);
                }
            }
        }
        res
    }

    /// Write the CRS to public and private storage and update the meta
    /// store with the outcome. On a write failure the partial data is
    /// purged before the error is returned.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_crs(
        &self,
        crs_id: &RequestId,
        epoch_id: &EpochId,
        pp: CompactPkeCrs,
        crs_info: CrsGenMetadata,
        meta_store: Arc<RwLock<MetaStore<CrsGenMetadata>>>,
        permit: MetaStorePermit<CrsGenMetadata>,
        op_metric_tag: &'static str,
    ) -> Result<(), StorageError> {
        self.handle_persistent_and_meta_storage(
            crs_id,
            Some(epoch_id),
            Some((&pp, PubDataType::CRS)),
            Some((&crs_info.clone(), PrivDataType::CrsInfo)),
            crs_info,
            meta_store,
            permit,
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
        permit: MetaStorePermit<KeyGenMetadata>,
    ) -> Result<(), StorageError> {
        let res = self
            .write_all::<DecompressionKey, DecompressionKey>(
                key_id,
                None,
                Some((&decompression_key, PubDataType::DecompressionKey)),
                None,
                false, // No private data to back up
                OP_DECOMPRESSION_KEYGEN,
            )
            .await;
        update_meta_store(
            res,
            meta_data,
            &meta_store,
            permit,
            BackupPolicy::BackupIsBestEffort,
            OP_DECOMPRESSION_KEYGEN,
        )
        .await
    }

    /// Persist the recovery material of a new custodian context and update the meta store.
    ///
    /// The material goes to the backup vault unencrypted; see [`store_recovery_material`].
    ///
    /// The anchor in private storage is written last: it is what makes this context the one the
    /// node adopts after a restart, so an earlier failure leaves the previous context in place.
    ///
    /// NOTE: Unlike most other storage methods, this one WILL fail if there is no backup vault,
    /// since the goal of this method is exactly to setup a backup. On failure the material of the
    /// failed setup is purged. Two cases keep it. On a duplicate nothing was written, so what is
    /// stored under `req_id` pre-existed this call. When a failed anchor write cannot be read back,
    /// the anchor may name this context. An anchor write that reports an error but took effect is
    /// a success. Callers that also need the keychain rolled back must do that themselves; see
    /// `rollback_failed_custodian_setup`.
    pub async fn write_backup_keys(
        &self,
        recovery_material: RecoveryValidationMaterial,
        meta_store: Arc<RwLock<CustodianMetaStore>>,
        permit: MetaStorePermit<RecoveryValidationMaterial>,
    ) -> Result<(), StorageError> {
        let req_id = recovery_material.custodian_context().context_id;
        // Ensure we have a backup vault before starting
        let vault = match self.backup_vault.as_ref() {
            Some(vault) => vault,
            None => {
                tracing::error!(
                    "No backup vault configured, cannot write backup keys for request {req_id}"
                );
                return Err(StorageError::Backup);
            }
        };
        let (res, purge) = match self
            .write_recovery_material(vault, &req_id, &recovery_material)
            .await
        {
            Ok(()) => {
                let mut private_storage = self.private_storage.lock().await;
                match store_custodian_context_anchor(&mut *private_storage, &req_id).await {
                    Ok(()) => (Ok(()), false),
                    // Storage may apply a write and still report an error, so the anchor decides.
                    // If it names this context, the setup succeeded. If it names another, the
                    // material can go. If it cannot be read, the material stays so whichever anchor
                    // wins still resolves.
                    Err(e) => match read_custodian_context_anchor(&*private_storage).await {
                        Ok(Some(anchored)) if anchored == req_id => {
                            tracing::warn!(
                                "Anchoring custodian context {req_id} reported an error but took effect: {e}"
                            );
                            (Ok(()), false)
                        }
                        Ok(_) => {
                            tracing::error!("Failed to anchor custodian context {req_id}: {e}");
                            (Err(StorageError::Writing), true)
                        }
                        Err(read_err) => {
                            tracing::error!(
                                "Failed to anchor custodian context {req_id} ({e}) and to read the anchor back ({read_err}); its material is kept"
                            );
                            (Err(StorageError::Writing), false)
                        }
                    },
                }
            }
            // A duplicate means nothing was written and what is stored under `req_id` pre-existed
            // (possibly a live backup), so it must be kept.
            Err(write_err) => {
                let purge = !matches!(write_err, StorageError::Duplicate);
                (Err(write_err), purge)
            }
        };
        // Roll back both the entries the caller re-encrypted under `req_id` and any recovery
        // material this call wrote. Purge failures are only logged: they must not mask the root
        // cause in the meta store.
        if purge {
            let mut guarded_vault = vault.lock().await;
            if let Err(e) = guarded_vault.purge_backup(&req_id).await {
                tracing::error!(
                    "Failed to purge backup vault after failed backup setup for request {req_id}: {e}"
                );
            }
            if let Err(e) =
                delete_recovery_material_at_id(&mut guarded_vault.storage, &req_id).await
            {
                tracing::error!(
                    "Failed to purge recovery material for {req_id} after failed backup setup: {e}"
                );
            }
        }
        update_meta_store(
            res,
            recovery_material,
            &meta_store,
            permit,
            BackupPolicy::BackupIsRequired,
            OP_NEW_CUSTODIAN_CONTEXT,
        )
        .await
    }

    /// Record the recovery material of a new custodian context.
    ///
    /// The caller backs up private storage under the context first, and anchors the context after,
    /// so a failure here leaves the previous context anchored and intact.
    async fn write_recovery_material(
        &self,
        vault: &Arc<Mutex<Vault>>,
        req_id: &RequestId,
        recovery_material: &RecoveryValidationMaterial,
    ) -> Result<(), StorageError> {
        let mut guarded_vault = vault.lock().await;
        match store_recovery_material(&mut guarded_vault.storage, recovery_material).await {
            Ok(StoreWriteOutcome::SkippedExisting) => Err(StorageError::Duplicate),
            Ok(_) => {
                tracing::info!("Stored recovery material for custodian context {req_id}");
                Ok(())
            }
            Err(e) => {
                tracing::error!("Failed to store recovery material for request {req_id}: {e}");
                Err(StorageError::Writing)
            }
        }
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
        self.write_all::<ContextInfo, ContextInfo>(
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
    ///
    /// A node with no vault, or one whose keychain has no custodian context, backs nothing up. That
    /// is not a failure the caller can act on, so it still returns `true` — but it is not a success
    /// either, and saying so would bury the line that says why nothing was written.
    pub async fn update_backup_vault(&self, overwrite: bool, op_metric_tag: &'static str) -> bool {
        match self.inner_update_backup_vault(overwrite).await {
            Err(e) => {
                tracing::error!("Failed to update backup vault for operation {op_metric_tag}: {e}",);
                METRICS.increment_backup_error_counter(op_metric_tag, ERR_BACKUP);
                false
            }
            Ok(true) => {
                tracing::info!("Successfully updated backup vault for {op_metric_tag}",);
                true
            }
            Ok(false) => true,
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
    /// `Ok(false)` when there was nothing to update: no backup vault, or a keychain with no
    /// custodian context; the latter is logged with the reason.
    pub(in crate::vault::storage::crypto_material) async fn inner_update_backup_vault(
        &self,
        overwrite: bool,
    ) -> anyhow::Result<bool> {
        match self.backup_vault {
            Some(ref backup_vault) => {
                let private_storage = self.get_private_storage();
                let private_storage = private_storage.lock().await;
                let mut backup_vault = backup_vault.lock().await;
                if !crate::engine::backup_operator::keychain_initialized(&backup_vault).await {
                    // A node holding key material with no custodian context backs nothing up,
                    // and cannot fix itself on restart: the recovery material naming a context
                    // would live in this same vault, and there is none.
                    // On a probe failure assume material is present, so a degraded storage
                    // backend cannot quietly demote the alert to a warning.
                    let holds_key_material = private_storage
                        .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningKey.to_string())
                        .await
                        .unwrap_or_else(|e| {
                            tracing::warn!("Could not check for a signing key: {e}");
                            true
                        });
                    if holds_key_material {
                        tracing::error!(
                            "Secret sharing keychain in the backup vault has not been initialized, but this node holds private key material. No backups are being made; create a new custodian context."
                        );
                    } else {
                        tracing::warn!(
                            "Secret sharing keychain in the backup vault has not been initialized yet. Skipping backup update."
                        );
                    }
                    return Ok(false);
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
                        #[expect(deprecated)]
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
                        // Node-local and stale the moment it is copied: a backup is taken under
                        // the current context, so a restored anchor would name the context the
                        // node is leaving. Recovery sets it from the context it recovered.
                        PrivDataType::CustodianContextAnchor => {}
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
                        PrivDataType::SigningSeed => {
                            crate::engine::backup_operator::update_specific_backup_vault::<
                                PrivS,
                                RootSigningSeed,
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
                        PrivDataType::EpochData => {
                            crate::engine::backup_operator::update_specific_backup_vault::<
                                PrivS,
                                EpochData,
                            >(
                                &private_storage, &mut backup_vault, cur_type, overwrite
                            )
                            .await?;
                        }
                    }
                }
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// Update the meta store based on the result of a storage operation, and log and update the metrics in case of an error.
/// If the meta store is updated successfully, then the original storage result is returned.
/// If the meta store update fails, then a MetaStoreError is returned, which includes the original StorageError.
///
/// `backup_policy` decides how an `Err(StorageError::Backup)` outcome is recorded; the error is
/// returned to the caller either way. See [`BackupPolicy`].
pub(in crate::vault::storage::crypto_material) async fn update_meta_store<MetaT: Clone>(
    storage_res: Result<(), StorageError>,
    meta_data: MetaT,
    meta_store: &RwLock<MetaStore<MetaT>>,
    permit: MetaStorePermit<MetaT>,
    backup_policy: BackupPolicy,
    op_metric_tag: &'static str,
) -> Result<(), StorageError> {
    let req_id = *permit.req_id();
    let is_storage_err = match &storage_res {
        Ok(()) => false,
        Err(StorageError::Backup) => backup_policy == BackupPolicy::BackupIsRequired,
        Err(_) => true,
    };
    let meta_store_ok = if is_storage_err {
        update_err_req_in_meta_store(
            meta_store,
            permit,
            storage_res.as_ref().err().unwrap().to_string(),
            op_metric_tag,
        )
        .await
    } else {
        update_ok_req_in_meta_store(meta_store, permit, meta_data, op_metric_tag).await
    };
    if !meta_store_ok {
        // NOTE this would indicate a bug since we have just verified that the meta can be updated in the start of this method
        // Thus the meta store update can only fail in case of a race condition, which would indicate a bug
        tracing::error!(
            "Failed to update meta store in metric {op_metric_tag} for request {req_id}",
        );
        if let Err(e) = &storage_res {
            return Err(StorageError::MetaStore(format!(
                "Failed to update meta store for request {req_id}. Also failed to store data with error: {e}",
            )));
        } else {
            return Err(StorageError::MetaStore(format!(
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
            custodian_context_lock: Arc::clone(&self.custodian_context_lock),
        }
    }
}
