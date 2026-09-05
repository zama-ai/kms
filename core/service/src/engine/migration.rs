use crate::conf::MigrationConfig;
use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, SIGNING_KEY_ID};
use crate::cryptography::signatures::PublicSigKey;
use crate::engine::base::derive_request_id;
use crate::engine::threshold::service::epoch_manager::EpochData;
use crate::engine::threshold::service::session::PRSSSetupCombined;
use crate::util::key_setup::ensure_all_verf_material;
use crate::vault::storage::crypto_material::get_core_signing_key;
use crate::vault::storage::{
    Storage, StorageExt, StorageReader, delete_at_request_id, read_context_at_id,
    read_custodian_context_anchor, read_recovery_material_at_id, read_versioned_at_request_id,
    store_custodian_context_anchor, store_recovery_material, store_versioned_at_request_id,
};
use algebra::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::{KMSType, PrivDataType, PubDataType};
use kms_grpc::{ContextId, RequestId};
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::LazyLock;
use threshold_execution::small_execution::prss::PRSSSetup;

static LEGACY_DEFAULT_MPC_CONTEXT: LazyLock<ContextId> = LazyLock::new(|| {
    ContextId::from_bytes([
        1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2,
        3, 4,
    ])
});

// The default epoch ID used for initial PRSS setup and as fallback when no epoch is specified.
static LEGACY_DEFAULT_EPOCH_ID: LazyLock<EpochId> = LazyLock::new(|| {
    EpochId::from_bytes([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1,
    ])
});

/// Outcome of [`migrate_legacy_prss`] (split Z128/Z64 → combined).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyPrssMigrationOutcome {
    /// MPC context could not be loaded (e.g. fresh install).
    SkippedNoMpcContext,
    /// Combined PRSS already stored under the legacy epoch id.
    SkippedAlreadyMigrated,
    /// Both legacy halves were read and combined successfully.
    MigratedFromLegacy,
    /// One or both legacy halves were missing or inconsistent.
    SkippedIncompleteLegacyData,
}

/// Outcome of [`migrate_context_before_0_13_10`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyContextMigrationOutcome {
    /// No context under the legacy default MPC context id.
    SkippedNoLegacyContext,
    /// Context was copied to the new default id and the legacy entry removed.
    Migrated,
}

/// Outcome of [`migrate_combined_prss_to_0_13_10`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrssCombinedEpochMigrationOutcome {
    /// No combined PRSS at the legacy default epoch id.
    SkippedNoLegacyCombined,
    /// Data was moved to the current default epoch id and the legacy key removed.
    Migrated,
}

/// Migrate from 0.12.x to 0.13.x (including all 0.13.0 to 0.13.9 versions)
/// This involves migrating FHE key material from the legacy storage format to the new epoch-aware format, and migrating the legacy PRSS setup to the new combined format.
#[deprecated(
    since = "0.13.10",
    note = "The migration to 0.13.x is no longer needed and migrate_to_0_13_10 should be used instead"
)]
pub async fn migrate_to_0_13_x<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    migrate_fhe_keys_v0_12_to_v0_13(priv_storage, kms_type).await?;
    if let KMSType::Threshold = kms_type {
        migrate_legacy_prss(priv_storage).await.map(|_| ())?;
    }
    Ok(())
}

/// Migrate from 0.12.x or 0.13.x to 0.13.10
///
/// This involves removing already migrated FHE key material in the legacy storage location.
pub async fn migrate_to_0_13_10<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    // Ensure old migration is done
    #[expect(deprecated)]
    migrate_to_0_13_x(priv_storage, kms_type).await?;
    if let KMSType::Threshold = kms_type {
        // Migrate any remaining combined PRSS data that might not have been migrated in the previous migration
        // That is, if a conversion to the PRSSCombined format has already been done, but under the legacy default epoch id
        migrate_combined_prss_to_0_13_10(priv_storage)
            .await
            .map(|_| ())?;
    }
    migrate_context_before_0_13_10(priv_storage)
        .await
        .map(|_| ())?;
    migrate_fhe_keys_0_13_x_to_0_13_10(priv_storage, kms_type).await?;
    // Remove moved keys (keys with legacy ID still remains)
    migrate_fhe_keys_after_0_13_x(priv_storage, kms_type).await?;
    Ok(())
}

/// Migrate to 0.13.20
pub async fn migrate_to_0_13_20<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    // Ensure old migration is done
    migrate_to_0_13_10(priv_storage, kms_type).await?;
    // Remove old keys with legacy epoch id.
    remove_old_keys_for_0_13_20(priv_storage, kms_type).await?;
    Ok(())
}

pub async fn migrate_to_0_15_x<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    kms_type: KMSType,
    migration_config: Option<&MigrationConfig>,
) -> anyhow::Result<()>
where
    PubS: StorageExt + Sync + Send,
    PrivS: StorageExt + Sync + Send,
{
    // No migration to 0.14 done, but previous version did use migrate_to_0_13_20 so we keep it for completeness
    migrate_to_0_13_20(priv_storage, kms_type).await?;
    // Migration for 0.15
    migrate_prss_to_epoch(priv_storage, kms_type, migration_config).await?;
    migrate_public_verification_material(priv_storage, pub_storage).await
}

/// Import the recovery material of `context_id` from public storage, where releases before the
/// move kept it, and anchor that context.
///
/// The operator names the context: public storage is modifiable, so deleting the current object
/// would otherwise be enough to leave a retired one as the node's only candidate. Nothing else
/// there is read, listed or trusted, and the anchor this writes is what stops the import running
/// again.
pub async fn import_configured_legacy_context<PubS, PrivS, BackS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    backup_storage: &mut BackS,
    migration: Option<&MigrationConfig>,
    verf_key: &PublicSigKey,
) -> anyhow::Result<()>
where
    PubS: Storage + Sync + Send,
    PrivS: Storage + Sync + Send,
    BackS: Storage + Sync + Send,
{
    let Some(configured) = migration.and_then(|m| m.custodian_context_id.as_deref()) else {
        return Ok(());
    };
    if read_custodian_context_anchor(priv_storage).await?.is_some() {
        tracing::warn!(
            "A custodian context is already anchored; remove [migration] custodian_context_id, \
             which would otherwise be applied again if the anchor is ever lost"
        );
        return Ok(());
    }
    let context_id = &RequestId::from_str(configured).map_err(|e| {
        anyhow::anyhow!("Invalid [migration] custodian_context_id {configured}: {e}")
    })?;
    // Material for any other context means this node has installed one since, so the configured id
    // is stale and applying it would move the node backwards. Only the operator can resolve that.
    let data_type = PubDataType::RecoveryMaterial.to_string();
    let vault_ids = backup_storage.all_data_ids(&data_type).await?;
    if vault_ids.iter().any(|id| id != context_id) {
        tracing::error!(
            "[migration] custodian_context_id names {context_id} but the backup vault already \
             holds other custodian contexts, so this node has moved on and the setting was not \
             applied. Remove it."
        );
        return Ok(());
    }
    if backup_storage.data_exists(context_id, &data_type).await? {
        tracing::info!("Custodian recovery material {context_id} is already in the backup vault");
    } else {
        let Ok(material) = read_recovery_material_at_id(pub_storage, context_id).await else {
            // Public storage is modifiable, so a missing or corrupt object here is not a reason to
            // stop: the node runs without backups until an operator sorts it out.
            tracing::error!(
                "Could not read custodian recovery material {context_id} from public storage, so \
                 no context is installed and no backups will be made. Copy it into the backup \
                 vault by hand, or correct [migration] custodian_context_id."
            );
            return Ok(());
        };
        if !material.validate(verf_key) {
            tracing::error!(
                "Custodian recovery material {context_id} in public storage is not signed by this \
                 node, so it was not imported and no backups will be made."
            );
            return Ok(());
        }
        store_recovery_material(backup_storage, &material).await?;
        tracing::info!("Imported custodian recovery material {context_id} into the backup vault");
    }
    // Both branches land here, so a hand-placed or truncated vault object cannot cost the node the
    // public copy it was told to replace.
    if let Err(e) = read_recovery_material_at_id(backup_storage, context_id).await {
        tracing::error!(
            "Custodian recovery material {context_id} in the backup vault is unreadable ({e}), so \
             no context is installed and no backups will be made. Replace it, or correct \
             [migration] custodian_context_id."
        );
        return Ok(());
    }
    store_custodian_context_anchor(priv_storage, context_id).await?;
    // A failed delete leaves the object for the startup sweep to report; nothing reads it.
    if let Err(e) = delete_at_request_id(pub_storage, context_id, &data_type).await {
        tracing::warn!(
            "Could not delete custodian recovery material {context_id} from public storage: {e}"
        );
    }
    Ok(())
}

/// TODO Placeholder method to ensure we remember to clean up upgraded material at the next version (0.16.0)
#[allow(dead_code)]
pub async fn migrate_to_0_16_x<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    remove_old_prss_data(priv_storage, kms_type).await?;
    Ok(())
}

/// Backfill the multi-scheme verification material for existing deployments.
///
/// Derives every non-ECDSA signature scheme's public verification key and digest
/// from the node's root signing seed — and ECDSA's from the persisted signing key —
/// and stores them in public storage, leaving the ECDSA material at its historic
/// location untouched. This lets a node that predates multi-scheme support gain the
/// new public material on restart, without re-running key generation.
///
/// A node with no root seed is skipped with a warning rather than backfilled.
async fn migrate_public_verification_material<PrivS, PubS>(
    priv_storage: &PrivS,
    pub_storage: &mut PubS,
) -> anyhow::Result<()>
where
    PrivS: StorageReader + Sync + Send,
    PubS: Storage + Sync + Send,
{
    if !priv_storage
        .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningKey.to_string())
        .await?
    {
        tracing::info!(
            "No ECDSA signing key present; skipping multi-scheme verification-material backfill"
        );
        return Ok(());
    }
    let sk = get_core_signing_key(priv_storage).await?;
    if !sk.has_root_seed() {
        tracing::warn!(
            "No root signing seed present; skipping the multi-scheme verification-material \
             backfill."
        );
        return Ok(());
    }
    ensure_all_verf_material(pub_storage, &sk).await
}

async fn migrate_prss_to_epoch<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
    migration_config: Option<&MigrationConfig>,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    if kms_type == KMSType::Centralized {
        tracing::info!("No migration needed for centralized KMS");
        return Ok(());
    }
    let inner_migration_conf = match migration_config.filter(|c| !c.context_associations.is_empty())
    {
        Some(inner_migration_conf) => inner_migration_conf,
        None => {
            // This should only be allowed on a fresh system, and not an upgraded system
            #[expect(deprecated)]
            let data_ids = priv_storage
                .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
                .await?;
            if data_ids.is_empty() {
                tracing::info!("No old PRSS data found, skipping migration");
                return Ok(());
            } else {
                anyhow::bail!(
                    "Migration config must be provided for 0.15.x migration when PRSS data is present"
                );
            }
        }
    };
    threshold_prss_to_epoch(priv_storage, inner_migration_conf).await
}

async fn threshold_prss_to_epoch<PrivS>(
    priv_storage: &mut PrivS,
    migration_config: &MigrationConfig,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    // Check and parse the migration information
    let migration_map = parse_migration_map(migration_config)?;

    // Reconcile the config against what is actually on disk before writing anything. Every legacy
    // PrssSetupCombined epoch must be listed in the config, and every configured epoch must exist on
    // disk. Failing here (rather than mid-write) prevents two operator-mapping mistakes: an
    // under-listed epoch would be silently dropped and then permanently lost when the 0.16 migration
    // deletes the legacy PRSS data, while an over-listed epoch would crash the per-epoch read below.
    #[expect(deprecated)]
    let stored_epochs: HashSet<EpochId> = priv_storage
        .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
        .await?
        .into_iter()
        .map(EpochId::from)
        .collect();
    let configured_epochs: HashSet<EpochId> = migration_map.values().flatten().copied().collect();

    let not_in_config: Vec<EpochId> = stored_epochs
        .difference(&configured_epochs)
        .copied()
        .collect();
    if !not_in_config.is_empty() {
        anyhow::bail!(
            "Migration config does not cover {} stored epoch(s) with PRSS data: {}. Every stored epoch must be associated with exactly one context.",
            not_in_config.len(),
            not_in_config
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let not_on_disk: Vec<EpochId> = configured_epochs
        .difference(&stored_epochs)
        .copied()
        .collect();
    if !not_on_disk.is_empty() {
        anyhow::bail!(
            "Migration config references {} epoch(s) that have no PRSS data on disk: {}.",
            not_on_disk.len(),
            not_on_disk
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let num_contexts = migration_map.len();
    let mut migrated_epochs = 0usize;
    // Next update the actual storage
    for (cur_context, epoch_list) in migration_map {
        for cur_epoch in epoch_list {
            // Check that we did not already do the migration of this epoch
            if priv_storage
                .data_exists(&cur_epoch.into(), &PrivDataType::EpochData.to_string())
                .await?
            {
                tracing::info!(
                    "Epoch {} under context {} already migrated, skipping",
                    cur_epoch,
                    cur_context
                );
                continue;
            }
            let prss = read_versioned_at_request_id::<_, PRSSSetupCombined>(
                priv_storage,
                &cur_epoch.into(),
                #[expect(deprecated)]
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;
            let epoch = EpochData {
                context_id: cur_context,
                prss,
            };
            store_versioned_at_request_id(
                priv_storage,
                &cur_epoch.into(),
                &epoch,
                &PrivDataType::EpochData.to_string(),
            )
            .await?;
            tracing::info!(
                "Migrated epoch {} to the epoch-aware format under context {}",
                cur_epoch,
                cur_context
            );
            migrated_epochs += 1;
        }
    }
    tracing::info!(
        "Successfully migrated {} epoch(s) across {} context(s) to the epoch-aware storage format",
        migrated_epochs,
        num_contexts
    );
    Ok(())
}

/// Parse the migration config into a map of context IDs to epoch IDs, ensuring that each epoch ID is unique and each context ID is unique.
/// Also validates that the default context ID and default epoch ID are present in the migration config.
fn parse_migration_map(
    migration_config: &MigrationConfig,
) -> anyhow::Result<std::collections::HashMap<ContextId, Vec<EpochId>>> {
    let mut seen_epochs = std::collections::HashSet::new();
    let mut context_to_epoch_map = HashMap::new();
    for association in &migration_config.context_associations {
        let context_id = ContextId::from_str(&association.context_id)
            .map_err(|e| anyhow::anyhow!("Invalid context id {}: {}", association.context_id, e))?;
        if association.epoch_ids.is_empty() {
            anyhow::bail!(
                "Context ID {} has no associated epoch IDs in migration config",
                association.context_id
            );
        }
        let mut cur_epochs = Vec::new();
        for epoch_id in &association.epoch_ids {
            let epoch_id = EpochId::from_str(epoch_id)
                .map_err(|e| anyhow::anyhow!("Invalid epoch ID {}: {}", epoch_id, e))?;
            if !seen_epochs.insert(epoch_id) {
                anyhow::bail!("Duplicate epoch ID {} found in migration config", epoch_id);
            }
            cur_epochs.push(epoch_id);
        }
        if context_to_epoch_map.contains_key(&context_id) {
            anyhow::bail!(
                "Duplicate context ID {} found in migration config",
                association.context_id
            );
        }
        context_to_epoch_map.insert(context_id, cur_epochs);
    }
    match context_to_epoch_map.get(&DEFAULT_MPC_CONTEXT) {
        Some(default) => {
            if !default.contains(&DEFAULT_EPOCH_ID) {
                anyhow::bail!(
                    "Default epoch ID {} should be part of the migration config for default context ID {}",
                    *DEFAULT_EPOCH_ID,
                    *DEFAULT_MPC_CONTEXT
                );
            }
        }
        None => anyhow::bail!(
            "Default context ID {} should be part of the migration config",
            *DEFAULT_MPC_CONTEXT
        ),
    }
    Ok(context_to_epoch_map)
}

async fn remove_old_prss_data<PrivS: StorageExt + Sync + Send>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()> {
    if kms_type == KMSType::Centralized {
        tracing::info!("No PRSS data to remove for centralized KMS");
        return Ok(());
    }

    #[expect(deprecated)]
    let data_ids = priv_storage
        .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
        .await?;
    for cur_id in data_ids {
        #[expect(deprecated)]
        priv_storage
            .delete_data(&cur_id, &PrivDataType::PrssSetupCombined.to_string())
            .await?;
    }
    Ok(())
}

/// Migrate FHE key material from legacy storage format to epoch-aware format.
/// The migration should be applied to private storage created in v0.12.x,
/// after the migration the private storage format should follow v0.13.x.
/// Applying the migration on private storage format in v0.13.x will have no effect.
/// This function should be removed in 0.13.20.
///
/// In more detail, legacy format (v0.12.x) stores keys at: `<prefix>/<data_type>/<key_id>`.
/// This function checks for FhePrivateKey (centralized) or FheKeyInfo (threshold) data
/// stored in the legacy format and migrates them to the new epoch-aware format using
/// `DEFAULT_EPOCH_ID` as the default epoch ID.
///
/// # Arguments
/// * `priv_storage` - Private storage instance supporting both legacy and epoch-aware operations
/// * `kms_type` - The KMS type (Centralized or Threshold) which determines which data type to migrate
///
/// # Returns
/// * `Ok(migrated_count)` - Number of keys successfully migrated
/// * `Err(...)` - If any migration operation fails
async fn migrate_fhe_keys_v0_12_to_v0_13<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<usize>
where
    PrivS: StorageExt + Sync + Send,
{
    let data_type = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey,
        KMSType::Threshold => PrivDataType::FheKeyInfo,
    };
    let data_type_str = data_type.to_string();

    // Get the default epoch ID for migrated keys
    let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;

    // Get all key IDs stored in the legacy format (directly under data_type directory)
    let legacy_key_ids = priv_storage.all_data_ids(&data_type_str).await?;

    if legacy_key_ids.is_empty() {
        tracing::info!("No legacy {} keys found to migrate", data_type_str);
        return Ok(0);
    }

    tracing::info!(
        "Found {} legacy {} keys to migrate to epoch-aware format",
        legacy_key_ids.len(),
        data_type_str
    );

    let mut migrated_count = 0;

    for key_id in legacy_key_ids {
        // Check if this key already exists in the new epoch-aware format
        if priv_storage
            .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type_str)
            .await?
        {
            tracing::info!(
                "Key {} already exists at epoch {}, skipping migration",
                key_id,
                legacy_epoch_id
            );
            continue;
        }

        // Read the data from the legacy location as raw bytes
        // We read raw bytes to avoid type-specific deserialization issues
        let data: Vec<u8> = priv_storage.load_bytes(&key_id, &data_type_str).await?;

        // Store the data at the new epoch-aware location
        priv_storage
            .store_bytes_at_epoch(&data, &key_id, &legacy_epoch_id, &data_type_str)
            .await
            .map(|_| ())?;

        tracing::info!(
            "Migrated key {} from legacy format to epoch {}",
            key_id,
            legacy_epoch_id
        );
        migrated_count += 1;
    }

    tracing::info!(
        "Successfully migrated {} {} keys to epoch-aware format",
        migrated_count,
        data_type_str
    );

    Ok(migrated_count)
}

/// Deletes obsolete threshold keys after having confirmed that the upgrade in `migrate_fhe_keys_v0_12_to_v0_13` has been successful.
async fn migrate_fhe_keys_after_0_13_x<S>(storage: &mut S, kms_type: KMSType) -> anyhow::Result<()>
where
    S: StorageExt + Sync + Send,
{
    let data_type = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey,
        KMSType::Threshold => PrivDataType::FheKeyInfo,
    };
    let data_type_str = data_type.to_string();
    // Get the default epoch ID for migrated keys
    let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;
    let legacy_key_ids = storage.all_data_ids(&data_type_str).await?;

    for key_id in legacy_key_ids {
        // Check the converted key indeed exists before removing anything
        if storage
            .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type_str)
            .await?
        {
            // Removes obsolete keys that have already been converted
            storage.delete_data(&key_id, &data_type_str).await?;
        } else {
            tracing::error!(
                "Legacy key {} still exists but no migrated key found at epoch {}, skipping deletion",
                key_id,
                legacy_epoch_id
            );
        }
    }
    Ok(())
}

/// This will try to load the legacy PRSS setup [`PRSSSetup`] from storage
/// by using the default value for the epoch ID.
/// It then converts the old PRSSSetup data into the new PRSSSetupCombined format and stores it back in storage under the new epoch-aware path.
#[expect(deprecated)]
async fn migrate_legacy_prss<PrivS>(
    priv_storage: &mut PrivS,
) -> anyhow::Result<LegacyPrssMigrationOutcome>
where
    PrivS: StorageExt + Sync + Send,
{
    // Load context; if it does not exist (e.g., fresh installation), skip PRSS migration
    let (threshold, num_parties) = {
        match read_context_at_id(priv_storage, &LEGACY_DEFAULT_MPC_CONTEXT).await {
            Ok(context) => (context.threshold as u8, context.mpc_nodes.len()),
            Err(err) => {
                tracing::warn!(
                    "Skipping legacy PRSS migration: failed to load MPC context '{}' ({err}). \
This likely means threshold MPC has not been initialized yet on this installation, \
so there is no legacy PRSS state to migrate.",
                    *LEGACY_DEFAULT_MPC_CONTEXT,
                );
                return Ok(LegacyPrssMigrationOutcome::SkippedNoMpcContext);
            }
        }
    };
    // Check if this key already exists in the new epoch-aware format
    if priv_storage
        .data_exists(
            &(*LEGACY_DEFAULT_EPOCH_ID).into(),
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?
    {
        tracing::info!(
            "PRSS Setup for epoch {} already exists and has been migrated, skipping migration",
            &(*LEGACY_DEFAULT_EPOCH_ID)
        );
        return Ok(LegacyPrssMigrationOutcome::SkippedAlreadyMigrated);
    }
    let prss_128_legacy_id = derive_request_id(&format!(
        "PRSSSetup_Z128_ID_{}_{}_{}",
        (*LEGACY_DEFAULT_EPOCH_ID),
        num_parties,
        threshold,
    ))?;
    let prss_64_legacy_id = derive_request_id(&format!(
        "PRSSSetup_Z64_ID_{}_{}_{}",
        (*LEGACY_DEFAULT_EPOCH_ID),
        num_parties,
        threshold,
    ))?;
    let prss_from_storage = {
        let prss_128 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z128>>(
            priv_storage,
            &prss_128_legacy_id,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .inspect_err(|e| {
            tracing::warn!("failed to read legacy PRSS Z128 from file with error: {e}");
        });
        let prss_64 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z64>>(
            priv_storage,
            &prss_64_legacy_id,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .inspect_err(|e| {
            tracing::warn!("failed to read legacy PRSS Z64 from file with error: {e}");
        });

        (prss_128, prss_64)
    };

    let outcome = match prss_from_storage {
        (Ok(prss_128), Ok(prss_64)) => {
            let new_prss = PRSSSetupCombined {
                prss_setup_z128: prss_128,
                prss_setup_z64: prss_64,
                num_parties: num_parties as u8,
                threshold,
            };
            store_versioned_at_request_id(
                priv_storage,
                &(*LEGACY_DEFAULT_EPOCH_ID).into(),
                &new_prss,
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;

            // Delete the old prss! Note that this is safe since they can always be regenerated very quickly without any change beyond the KMS
            priv_storage
                .delete_data(&prss_128_legacy_id, &PrivDataType::PrssSetup.to_string())
                .await?;
            priv_storage
                .delete_data(&prss_64_legacy_id, &PrivDataType::PrssSetup.to_string())
                .await?;
            tracing::info!(
                "Successfully converted legacy PRSS Setup from storage for epoch ID {}.",
                (*LEGACY_DEFAULT_EPOCH_ID)
            );
            LegacyPrssMigrationOutcome::MigratedFromLegacy
        }
        (Err(e), Ok(_)) => {
            tracing::error!(
                "Failed to read legacy PRSS Z128 from file with error: {e}, but was able to read Z64, skipping migration since we don't have the full data"
            );
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        }
        (Ok(_), Err(e)) => {
            tracing::error!(
                "Failed to read legacy PRSS Z64 from file with error: {e}, but was able to read Z128, skipping migration since we don't have the full data"
            );
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        }
        (Err(_e), Err(e)) => {
            tracing::error!(
                "Failed to read both legacy PRSS Z128 and Z64 from file with errors: Z128 error: {_e}, Z64 error: {e}, skipping migration"
            );
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        }
    };
    Ok(outcome)
}

async fn migrate_combined_prss_to_0_13_10<PrivS>(
    priv_storage: &mut PrivS,
) -> anyhow::Result<PrssCombinedEpochMigrationOutcome>
where
    PrivS: StorageExt + Sync + Send,
{
    let prss: PRSSSetupCombined = match read_versioned_at_request_id(
        priv_storage,
        &(*LEGACY_DEFAULT_EPOCH_ID).into(),
        #[expect(deprecated)]
        &PrivDataType::PrssSetupCombined.to_string(),
    )
    .await
    {
        Ok(prss) => prss,
        Err(err) => {
            tracing::warn!(
                "Skipping legacy PRSSCombined migration: failed to load PRSSCombined '{}' ({err})",
                *LEGACY_DEFAULT_EPOCH_ID
            );
            return Ok(PrssCombinedEpochMigrationOutcome::SkippedNoLegacyCombined);
        }
    };
    store_versioned_at_request_id(
        priv_storage,
        &(*DEFAULT_EPOCH_ID).into(),
        &prss,
        #[expect(deprecated)]
        &PrivDataType::PrssSetupCombined.to_string(),
    )
    .await?;
    priv_storage
        .delete_data(
            &(*LEGACY_DEFAULT_EPOCH_ID).into(),
            #[expect(deprecated)]
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;
    tracing::info!(
        "Successfully migrated PRSS Combined with legacy ID {} to new ID {}",
        *LEGACY_DEFAULT_EPOCH_ID,
        *DEFAULT_EPOCH_ID
    );
    Ok(PrssCombinedEpochMigrationOutcome::Migrated)
}

/// Reads context under the old legacy default context ID and if it exists, re-stores it under the new default context ID.
async fn migrate_context_before_0_13_10<PrivS>(
    priv_storage: &mut PrivS,
) -> anyhow::Result<LegacyContextMigrationOutcome>
where
    PrivS: StorageExt + Sync + Send,
{
    // Load context; if it does not exist (e.g., fresh installation), skip migration
    let mut context = match read_context_at_id(priv_storage, &LEGACY_DEFAULT_MPC_CONTEXT).await {
        Ok(context) => context,
        Err(err) => {
            tracing::warn!(
                "Skipping legacy context migration: failed to load context '{}' ({err})",
                *LEGACY_DEFAULT_MPC_CONTEXT
            );
            return Ok(LegacyContextMigrationOutcome::SkippedNoLegacyContext);
        }
    };
    // Update context id
    context.context_id = *DEFAULT_MPC_CONTEXT;
    store_versioned_at_request_id(
        priv_storage,
        &(*DEFAULT_MPC_CONTEXT).into(),
        &context,
        &PrivDataType::ContextInfo.to_string(),
    )
    .await?;
    // Remove old context. It is safe to do in this migration as it does not contain any critical, non restorable info
    priv_storage
        .delete_data(
            &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
            &PrivDataType::ContextInfo.to_string(),
        )
        .await?;
    tracing::info!(
        "Successfully migrated context from legacy context ID {} to new default context ID {}",
        *LEGACY_DEFAULT_MPC_CONTEXT,
        *DEFAULT_MPC_CONTEXT
    );
    Ok(LegacyContextMigrationOutcome::Migrated)
}

async fn migrate_fhe_keys_0_13_x_to_0_13_10<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<usize>
where
    PrivS: StorageExt + Sync + Send,
{
    // Note that these are the only epoched types, besides the epoch (PRSS) itself
    let data_type_str = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey.to_string(),
        KMSType::Threshold => PrivDataType::FheKeyInfo.to_string(),
    };
    let legacy_key_ids = priv_storage
        .all_data_ids_at_epoch(&LEGACY_DEFAULT_EPOCH_ID, &data_type_str)
        .await?;
    if legacy_key_ids.is_empty() {
        tracing::info!(
            "No legacy {} keys found to migrate from 0.13.3 to 0.13.10",
            data_type_str
        );
        return Ok(0);
    }

    tracing::info!(
        "Found {} legacy {} keys to migrate to epoch-aware format",
        legacy_key_ids.len(),
        data_type_str
    );

    let mut migrated_count = 0;

    for key_id in legacy_key_ids {
        // Check if this key already exists at the new epoch
        if priv_storage
            .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type_str)
            .await?
        {
            tracing::info!(
                "Key {} already exists at epoch {}, skipping migration",
                key_id,
                *DEFAULT_EPOCH_ID
            );
            continue;
        }

        // Read the data from the legacy location as raw bytes
        // We read raw bytes to avoid type-specific deserialization issues
        let data: Vec<u8> = priv_storage
            .load_bytes_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type_str)
            .await?;

        // Store the data at the new epoch-aware location
        priv_storage
            .store_bytes_at_epoch(&data, &key_id, &DEFAULT_EPOCH_ID, &data_type_str)
            .await
            .map(|_| ())?;

        tracing::info!(
            "Migrated key {} from legacy format to epoch {}",
            key_id,
            *DEFAULT_EPOCH_ID
        );
        migrated_count += 1;
    }

    tracing::info!(
        "Successfully migrated {} {} keys from 0.13.3 to 0.13.10 epoch id",
        migrated_count,
        data_type_str
    );

    Ok(migrated_count)
}

/// Remove private keys stored under the legacy epoch ID
async fn remove_old_keys_for_0_13_20<PrivS>(
    priv_storage: &mut PrivS,
    kms_type: KMSType,
) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    let data_type = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey,
        KMSType::Threshold => PrivDataType::FheKeyInfo,
    };
    let data_type_str = data_type.to_string();
    // Get the default epoch ID for migrated keys
    let new_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
    let legacy_key_ids = priv_storage
        .all_data_ids_at_epoch(&LEGACY_DEFAULT_EPOCH_ID, &data_type_str)
        .await?;

    for key_id in legacy_key_ids {
        // Check the converted key indeed exists before removing anything
        if priv_storage
            .data_exists_at_epoch(&key_id, &new_epoch_id, &data_type_str)
            .await?
        {
            // Removes obsolete keys that have already been converted,
            // specifically from the legacy epoch.
            priv_storage
                .delete_data_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type_str)
                .await?;
        } else {
            tracing::error!(
                "No key {} under epoch ID {} appears to exist. This implies an inconsistent file system",
                key_id,
                new_epoch_id
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::migrate_public_verification_material;
    use super::*;
    use crate::conf::ContextEpochAssociation;
    use crate::consts::signing_material_id;
    use crate::cryptography::signatures::{PrivateSigKey, gen_sig_keys};
    use crate::cryptography::signing::SigningSchemeType;
    use crate::engine::context::{ContextInfo, NodeInfo, SchemeDigests, SoftwareVersion};
    use crate::util::key_setup::{
        LEGACY_VERF_MATERIAL_TYPES, NON_LEGACY_VERF_MATERIAL_TYPES,
        delete_non_legacy_verf_material, ensure_central_server_signing_keys_exist,
    };
    use crate::vault::storage::crypto_material::{get_core_signing_key, read_verf_key_at};
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::ram::{self, RamStorage};
    use crate::vault::storage::{
        Storage, StorageExt, StorageReader, StorageReaderExt, StorageType, read_text_at_request_id,
        store_context_at_id, store_versioned_at_request_id,
    };
    use aes_prng::AesRng;
    use kms_grpc::RequestId;
    use kms_grpc::rpc_types::PubDataType;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

    /// Test migration of threshold FHE keys (FheKeyInfo)
    pub async fn test_migrate_legacy_fhe_keys_threshold<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        // Store some legacy data (directly under data_type without epoch)
        // Note: key IDs must not collide with the epoch id to avoid path conflicts
        let key_id_1 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let key_id_2 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000bb",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let legacy_data_1 = vec![1, 2, 3, 4, 5];
        let legacy_data_2 = vec![6, 7, 8, 9, 10];

        storage
            .store_bytes(&legacy_data_1, &key_id_1, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes(&legacy_data_2, &key_id_2, &data_type)
            .await
            .unwrap();

        // Verify legacy data exists
        assert!(storage.data_exists(&key_id_1, &data_type).await.unwrap());
        assert!(storage.data_exists(&key_id_2, &data_type).await.unwrap());

        // Run migration
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();

        assert_eq!(migrated_count, 2);

        // Verify legacy data still exists
        assert!(storage.data_exists(&key_id_1, &data_type).await.unwrap());
        assert!(storage.data_exists(&key_id_2, &data_type).await.unwrap());

        // Verify data exists at the new (legacy) epoch location
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(
            storage
                .data_exists_at_epoch(&key_id_1, &legacy_epoch_id, &data_type)
                .await
                .unwrap()
        );
        assert!(
            storage
                .data_exists_at_epoch(&key_id_2, &legacy_epoch_id, &data_type)
                .await
                .unwrap()
        );

        // Verify the data content is preserved
        let migrated_data_1 = storage
            .load_bytes_at_epoch(&key_id_1, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        let migrated_data_2 = storage
            .load_bytes_at_epoch(&key_id_2, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(migrated_data_1, legacy_data_1);
        assert_eq!(migrated_data_2, legacy_data_2);

        // Run migration again and verify it skips already migrated keys
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated_count, 0);
    }

    /// Test migration of centralized FHE keys (FhePrivateKey)
    pub async fn test_migrate_legacy_fhe_keys_centralized<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();

        let legacy_data = vec![42, 43, 44, 45];

        storage
            .store_bytes(&legacy_data, &key_id, &data_type)
            .await
            .unwrap();

        // Run migration
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Centralized)
            .await
            .unwrap();

        assert_eq!(migrated_count, 1);

        // Verify legacy data still exists
        assert!(storage.data_exists(&key_id, &data_type).await.unwrap());

        // Verify data exists at the new epoch location
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type)
                .await
                .unwrap()
        );

        // Verify the data content is preserved
        let migrated_data = storage
            .load_bytes_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(migrated_data, legacy_data);

        // Run migration again and verify it skips already migrated keys
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Centralized)
            .await
            .unwrap();
        assert_eq!(migrated_count, 0);
    }

    /// Test that migration skips keys that already exist at the target epoch
    pub async fn test_migrate_legacy_fhe_keys_skips_existing<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000099",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;

        let legacy_data = vec![1, 2, 3];
        let existing_epoch_data = vec![4, 5, 6];

        // Store legacy data
        storage
            .store_bytes(&legacy_data, &key_id, &data_type)
            .await
            .unwrap();

        // Also store at the target epoch (simulating already migrated or new data)
        storage
            .store_bytes_at_epoch(&existing_epoch_data, &key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();

        // Run migration
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Should skip the key since it already exists at the epoch
        assert_eq!(migrated_count, 0);

        // Legacy data should still exist (not deleted since we skipped)
        assert!(storage.data_exists(&key_id, &data_type).await.unwrap());

        // Epoch data should be unchanged (the epoched data)
        let epoch_data = storage
            .load_bytes_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(epoch_data, existing_epoch_data);
    }

    /// Test migration with no legacy data
    pub async fn test_migrate_legacy_fhe_keys_no_legacy_data<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        // No legacy data stored
        let migrated_count = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();

        assert_eq!(migrated_count, 0);
    }

    /// Test that migration is idempotent
    pub async fn test_migrate_legacy_fhe_keys_idempotent<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000077",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let legacy_data = vec![7, 7, 7];

        storage
            .store_bytes(&legacy_data, &key_id, &data_type)
            .await
            .unwrap();

        // First migration
        let migrated_count_1 = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated_count_1, 1);

        // Second migration should do nothing (data already migrated, legacy deleted)
        let migrated_count_2 = migrate_fhe_keys_v0_12_to_v0_13(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated_count_2, 0);

        // Data should still be at the epoch location
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;
        let epoch_data = storage
            .load_bytes_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(epoch_data, legacy_data);
    }

    // RAM storage tests
    #[tokio::test]
    async fn test_migrate_threshold_ram() {
        let mut storage = RamStorage::new();
        test_migrate_legacy_fhe_keys_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_centralized_ram() {
        let mut storage = RamStorage::new();
        test_migrate_legacy_fhe_keys_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_skips_existing_ram() {
        let mut storage = RamStorage::new();
        test_migrate_legacy_fhe_keys_skips_existing(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_no_legacy_data_ram() {
        let mut storage = RamStorage::new();
        test_migrate_legacy_fhe_keys_no_legacy_data(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_idempotent_ram() {
        let mut storage = RamStorage::new();
        test_migrate_legacy_fhe_keys_idempotent(&mut storage).await;
    }

    // File storage tests
    #[tokio::test]
    async fn test_migrate_threshold_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_legacy_fhe_keys_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_centralized_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_legacy_fhe_keys_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_skips_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_legacy_fhe_keys_skips_existing(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_no_legacy_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_legacy_fhe_keys_no_legacy_data(&mut storage).await;
    }

    #[tokio::test]
    async fn test_migrate_idempotent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_legacy_fhe_keys_idempotent(&mut storage).await;
    }

    // write prss to storage using the legacy method
    async fn write_legacy_empty_prss_to_storage(
        private_storage: &mut ram::RamStorage,
        threshold: u8,
        num_parties: usize,
    ) {
        let legacy_epoch_id = *LEGACY_DEFAULT_EPOCH_ID;

        let prss_setup_obj_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
        let prss_setup_obj_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

        // serialize and write PRSS Setup to storage into private storage
        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                legacy_epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z128,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                legacy_epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z64,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();
    }

    async fn store_legacy_test_context(
        priv_storage: &mut ram::RamStorage,
        threshold: u8,
        num_parties: usize,
    ) {
        let mut mpc_nodes = Vec::new();
        for i in 0..num_parties {
            mpc_nodes.push(NodeInfo {
                mpc_identity: format!("testnode{}", i),
                party_id: (i + 1) as u32,
                external_url: "https://doesnotexist.zama.ai".to_string(),
                ca_cert: None,
                public_storage_url: "".to_string(),
                public_storage_prefix: None,
                extra_signer_addresses: vec![],
                scheme_digests: SchemeDigests::new(),
            });
        }
        let context_info = ContextInfo {
            mpc_nodes,
            context_id: *LEGACY_DEFAULT_MPC_CONTEXT,
            software_version: SoftwareVersion::current().unwrap(),
            threshold: threshold as u32,
            pcr_values: vec![],
        };
        store_context_at_id(priv_storage, &LEGACY_DEFAULT_MPC_CONTEXT, &context_info)
            .await
            .expect("Could not store default context");
    }

    // ── Tests for migrate_fhe_keys_after_0_13_x ──

    /// Test that legacy keys with epoch counterparts are deleted (threshold)
    pub async fn test_migrate_fhe_keys_after_0_13_x_threshold<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id_1 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let key_id_2 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000bb",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;

        let legacy_data_1 = vec![1, 2, 3, 4, 5];
        let legacy_data_2 = vec![6, 7, 8, 9, 10];

        // Store legacy data
        storage
            .store_bytes(&legacy_data_1, &key_id_1, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes(&legacy_data_2, &key_id_2, &data_type)
            .await
            .unwrap();

        // Store epoch data (simulating successful prior migration)
        storage
            .store_bytes_at_epoch(&legacy_data_1, &key_id_1, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&legacy_data_2, &key_id_2, &legacy_epoch_id, &data_type)
            .await
            .unwrap();

        // Run the cleanup migration
        migrate_fhe_keys_after_0_13_x(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Legacy data should be deleted
        assert!(!storage.data_exists(&key_id_1, &data_type).await.unwrap());
        assert!(!storage.data_exists(&key_id_2, &data_type).await.unwrap());

        // Epoch data should still exist and be unchanged
        let loaded_1 = storage
            .load_bytes_at_epoch(&key_id_1, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        let loaded_2 = storage
            .load_bytes_at_epoch(&key_id_2, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded_1, legacy_data_1);
        assert_eq!(loaded_2, legacy_data_2);
    }

    /// Test that legacy keys with epoch counterparts are deleted (centralized)
    pub async fn test_migrate_fhe_keys_after_0_13_x_centralized<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;

        let data = vec![42, 43, 44, 45];

        storage
            .store_bytes(&data, &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&data, &key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();

        migrate_fhe_keys_after_0_13_x(storage, KMSType::Centralized)
            .await
            .unwrap();

        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type)
                .await
                .unwrap()
        );
    }

    /// Test with no legacy keys at all
    pub async fn test_migrate_fhe_keys_after_0_13_x_no_legacy<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        migrate_fhe_keys_after_0_13_x(storage, KMSType::Threshold)
            .await
            .unwrap();
    }

    /// Test idempotency of the cleanup migration
    pub async fn test_migrate_fhe_keys_after_0_13_x_idempotent<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000077",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let legacy_epoch_id: EpochId = *LEGACY_DEFAULT_EPOCH_ID;

        storage
            .store_bytes(&[7, 7, 7], &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&[7, 7, 7], &key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();

        // First run deletes legacy
        migrate_fhe_keys_after_0_13_x(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());

        // Second run is a no-op (no legacy keys left)
        migrate_fhe_keys_after_0_13_x(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Epoch data still intact
        let loaded = storage
            .load_bytes_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded, vec![7, 7, 7]);
    }

    // RAM storage tests — migrate_fhe_keys_after_0_13_x
    #[tokio::test]
    async fn test_after_0_13_x_threshold_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_x_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_centralized_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_x_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_no_legacy_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_x_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_idempotent_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_x_idempotent(&mut storage).await;
    }

    // File storage tests — migrate_fhe_keys_after_0_13_x
    #[tokio::test]
    async fn test_after_0_13_x_threshold_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_x_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_centralized_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_x_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_no_legacy_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_x_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_x_idempotent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_x_idempotent(&mut storage).await;
    }

    // ── Tests for migrate_legacy_prss_before_0_13_x ──

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_legacy_prss_sunshine() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;

        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        assert_eq!(
            migrate_legacy_prss(&mut storage).await.unwrap(),
            LegacyPrssMigrationOutcome::MigratedFromLegacy
        );

        // Verify PrssSetupCombined was created at the legacy epoch ID (where we asked it to store)
        let legacy_epoch_id = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(
            storage
                .data_exists(
                    &legacy_epoch_id.into(),
                    &PrivDataType::PrssSetupCombined.to_string(),
                )
                .await
                .unwrap()
        );

        // Verify legacy PRSS data was deleted
        let prss_128_id = derive_request_id(&format!(
            "PRSSSetup_Z128_ID_{}_{}_{}",
            legacy_epoch_id, num_parties, threshold,
        ))
        .unwrap();
        let prss_64_id = derive_request_id(&format!(
            "PRSSSetup_Z64_ID_{}_{}_{}",
            legacy_epoch_id, num_parties, threshold,
        ))
        .unwrap();
        assert!(
            !storage
                .data_exists(&prss_128_id, &PrivDataType::PrssSetup.to_string())
                .await
                .unwrap()
        );
        assert!(
            !storage
                .data_exists(&prss_64_id, &PrivDataType::PrssSetup.to_string())
                .await
                .unwrap()
        );

        // Verify the combined PRSS can be read back with correct metadata
        let combined: PRSSSetupCombined = read_versioned_at_request_id(
            &storage,
            &legacy_epoch_id.into(),
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(combined.num_parties, num_parties as u8);
        assert_eq!(combined.threshold, threshold);
    }

    #[tokio::test]
    async fn test_migrate_prss_already_migrated_skips() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;

        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        assert_eq!(
            migrate_legacy_prss(&mut storage).await.unwrap(),
            LegacyPrssMigrationOutcome::MigratedFromLegacy
        );

        // Write fresh legacy data again
        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;

        // Second migration should skip (PrssSetupCombined already exists)
        assert_eq!(
            migrate_legacy_prss(&mut storage).await.unwrap(),
            LegacyPrssMigrationOutcome::SkippedAlreadyMigrated
        );

        // PrssSetupCombined should still exist
        let epoch_id = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(
            storage
                .data_exists(
                    &epoch_id.into(),
                    #[expect(deprecated)]
                    &PrivDataType::PrssSetupCombined.to_string(),
                )
                .await
                .unwrap()
        );

        // The newly written legacy data should NOT have been deleted
        // (because the migration returned early)
        let prss_128_id = derive_request_id(&format!(
            "PRSSSetup_Z128_ID_{}_{}_{}",
            epoch_id, num_parties, threshold,
        ))
        .unwrap();
        #[expect(deprecated)]
        let prss_data_type = PrivDataType::PrssSetup.to_string();
        assert!(
            storage
                .data_exists(&prss_128_id, &prss_data_type)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_prss_no_legacy_data_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        let result = migrate_legacy_prss(&mut storage).await.unwrap();
        assert_eq!(
            result,
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        );
    }

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_prss_missing_z64_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        let epoch_id = *LEGACY_DEFAULT_EPOCH_ID;

        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        // Only write Z128 legacy data
        let prss_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
        store_versioned_at_request_id(
            &mut storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_z128,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();

        let result = migrate_legacy_prss(&mut storage).await.unwrap();
        assert_eq!(
            result,
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        );
    }

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_prss_missing_z128_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        let epoch_id = *LEGACY_DEFAULT_EPOCH_ID;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        // Only write Z64 legacy data
        let prss_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);
        store_versioned_at_request_id(
            &mut storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z64_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_z64,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();

        let result = migrate_legacy_prss(&mut storage).await.unwrap();
        assert_eq!(
            result,
            LegacyPrssMigrationOutcome::SkippedIncompleteLegacyData
        );
    }

    // ── Tests for migrate_context_before_0_13_10 ──

    #[tokio::test]
    async fn test_migrate_context_sunshine() {
        let mut storage = RamStorage::new();
        let threshold = 1u8;
        let num_parties = 4;

        // Store context under the legacy context ID
        store_legacy_test_context(&mut storage, threshold, num_parties).await;
        assert!(
            storage
                .data_exists(
                    &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
                    &PrivDataType::ContextInfo.to_string(),
                )
                .await
                .unwrap()
        );

        assert_eq!(
            migrate_context_before_0_13_10(&mut storage).await.unwrap(),
            LegacyContextMigrationOutcome::Migrated
        );

        // Context should now exist at the new default ID
        let migrated: ContextInfo = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_MPC_CONTEXT).into(),
            &PrivDataType::ContextInfo.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(*migrated.context_id(), *DEFAULT_MPC_CONTEXT);
        assert_eq!(migrated.threshold, threshold as u32);
        assert_eq!(migrated.mpc_nodes.len(), num_parties);

        // Legacy context should be deleted
        assert!(
            !storage
                .data_exists(
                    &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
                    &PrivDataType::ContextInfo.to_string(),
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_context_no_legacy() {
        let mut storage = RamStorage::new();
        // No context stored, should skip gracefully
        let result = migrate_context_before_0_13_10(&mut storage).await.unwrap();
        assert_eq!(
            result,
            LegacyContextMigrationOutcome::SkippedNoLegacyContext
        );
    }

    #[tokio::test]
    async fn test_migrate_context_idempotent() {
        let mut storage = RamStorage::new();
        let threshold = 2u8;
        let num_parties = 3;

        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        // First migration
        assert_eq!(
            migrate_context_before_0_13_10(&mut storage).await.unwrap(),
            LegacyContextMigrationOutcome::Migrated
        );

        // Context at new location
        let migrated: ContextInfo = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_MPC_CONTEXT).into(),
            &PrivDataType::ContextInfo.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(*migrated.context_id(), *DEFAULT_MPC_CONTEXT);
        assert_eq!(migrated.threshold, threshold as u32);

        // Second migration should skip (legacy context was deleted, nothing to migrate)
        assert_eq!(
            migrate_context_before_0_13_10(&mut storage).await.unwrap(),
            LegacyContextMigrationOutcome::SkippedNoLegacyContext
        );

        // Data at new location should be unchanged
        let still_migrated: ContextInfo = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_MPC_CONTEXT).into(),
            &PrivDataType::ContextInfo.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(*still_migrated.context_id(), *DEFAULT_MPC_CONTEXT);
        assert_eq!(still_migrated.threshold, threshold as u32);
    }

    // ── Tests for migrate_combined_prss_to_0_13_10 ──

    #[tokio::test]
    async fn test_migrate_combined_prss_sunshine() {
        let mut storage = RamStorage::new();
        let num_parties = 4u8;
        let threshold = 1u8;

        // Store a PRSSSetupCombined at the legacy epoch ID
        let prss_combined = PRSSSetupCombined {
            prss_setup_z128: PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]),
            prss_setup_z64: PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]),
            num_parties,
            threshold,
        };
        store_versioned_at_request_id(
            &mut storage,
            &(*LEGACY_DEFAULT_EPOCH_ID).into(),
            &prss_combined,
            #[expect(deprecated)]
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await
        .unwrap();

        assert_eq!(
            migrate_combined_prss_to_0_13_10(&mut storage)
                .await
                .unwrap(),
            PrssCombinedEpochMigrationOutcome::Migrated
        );

        assert!(
            storage
                .data_exists(
                    &(*DEFAULT_EPOCH_ID).into(),
                    #[expect(deprecated)]
                    &PrivDataType::PrssSetupCombined.to_string(),
                )
                .await
                .unwrap()
        );
        assert!(
            !storage
                .data_exists(
                    #[allow(deprecated)]
                    &(*LEGACY_DEFAULT_EPOCH_ID).into(),
                    #[expect(deprecated)]
                    &PrivDataType::PrssSetupCombined.to_string(),
                )
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_combined_prss_no_data_ram() {
        let mut storage = RamStorage::new();
        let result = migrate_combined_prss_to_0_13_10(&mut storage)
            .await
            .unwrap();
        assert_eq!(
            result,
            PrssCombinedEpochMigrationOutcome::SkippedNoLegacyCombined
        );
    }

    #[tokio::test]
    async fn test_migrate_combined_prss_no_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        let result = migrate_combined_prss_to_0_13_10(&mut storage)
            .await
            .unwrap();
        assert_eq!(
            result,
            PrssCombinedEpochMigrationOutcome::SkippedNoLegacyCombined
        );
    }

    // ── Tests for migrate_fhe_keys_0_13_x_to_0_13_10 ──

    /// Helper: sets up a key at both the base path and the legacy epoch path,
    /// simulating the state after migrate_fhe_keys_v0_12_to_v0_13 ran.
    async fn setup_key_at_legacy_epoch<S: StorageExt + Sync + Send>(
        storage: &mut S,
        key_id: &RequestId,
        data: &[u8],
        data_type: &str,
    ) {
        // Base path (from original v0.12 layout, kept by migrate_fhe_keys_v0_12_to_v0_13)
        storage.store_bytes(data, key_id, data_type).await.unwrap();
        // Legacy epoch path (created by migrate_fhe_keys_v0_12_to_v0_13 using old DEFAULT_EPOCH_ID)
        storage
            .store_bytes_at_epoch(data, key_id, &LEGACY_DEFAULT_EPOCH_ID, data_type)
            .await
            .unwrap();
    }

    pub async fn test_migrate_fhe_keys_0_13_x_to_0_13_10_threshold<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id_1 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let key_id_2 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000bb",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let data_1 = vec![10, 20, 30];
        let data_2 = vec![40, 50, 60];

        setup_key_at_legacy_epoch(storage, &key_id_1, &data_1, &data_type).await;
        setup_key_at_legacy_epoch(storage, &key_id_2, &data_2, &data_type).await;

        let migrated = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated, 2);

        // Keys should now exist at DEFAULT_EPOCH_ID
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
        assert!(
            storage
                .data_exists_at_epoch(&key_id_1, &default_epoch_id, &data_type)
                .await
                .unwrap()
        );
        assert!(
            storage
                .data_exists_at_epoch(&key_id_2, &default_epoch_id, &data_type)
                .await
                .unwrap()
        );

        // Verify data content is preserved
        let loaded_1 = storage
            .load_bytes_at_epoch(&key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap();
        let loaded_2 = storage
            .load_bytes_at_epoch(&key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded_1, data_1);
        assert_eq!(loaded_2, data_2);
    }

    pub async fn test_migrate_fhe_keys_0_13_x_to_0_13_10_centralized<
        S: StorageExt + Sync + Send,
    >(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        let data = vec![99, 88, 77];

        setup_key_at_legacy_epoch(storage, &key_id, &data, &data_type).await;

        let migrated = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Centralized)
            .await
            .unwrap();
        assert_eq!(migrated, 1);

        let loaded = storage
            .load_bytes_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded, data);
    }

    pub async fn test_migrate_fhe_keys_0_13_x_to_0_13_10_no_legacy<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let migrated = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated, 0);
    }

    pub async fn test_migrate_fhe_keys_0_13_x_to_0_13_10_skips_existing<
        S: StorageExt + Sync + Send,
    >(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000099",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

        let legacy_data = vec![1, 2, 3];
        let existing_data = vec![4, 5, 6];

        // Set up at legacy epoch + base path
        setup_key_at_legacy_epoch(storage, &key_id, &legacy_data, &data_type).await;

        // Already exists at the target epoch
        storage
            .store_bytes_at_epoch(&existing_data, &key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();

        let migrated = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated, 0);

        // Target data should be unchanged
        let loaded = storage
            .load_bytes_at_epoch(&key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded, existing_data);
    }

    pub async fn test_migrate_fhe_keys_0_13_x_to_0_13_10_idempotent<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000077",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let data = vec![7, 7, 7];
        setup_key_at_legacy_epoch(storage, &key_id, &data, &data_type).await;

        // First migration
        let count_1 = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(count_1, 1);

        // Second migration should skip (already at target)
        let count_2 = migrate_fhe_keys_0_13_x_to_0_13_10(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(count_2, 0);

        // Data should be intact at new epoch
        let loaded = storage
            .load_bytes_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded, data);
    }

    // RAM storage tests — migrate_fhe_keys_0_13_x_to_0_13_10
    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_threshold_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_centralized_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_no_legacy_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_skips_existing_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_skips_existing(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_idempotent_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_idempotent(&mut storage).await;
    }

    // File storage tests — migrate_fhe_keys_0_13_x_to_0_13_10
    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_threshold_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_centralized_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_no_legacy_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_skips_existing_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_skips_existing(&mut storage).await;
    }

    #[tokio::test]
    async fn test_0_13_x_to_0_13_10_idempotent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_0_13_x_to_0_13_10_idempotent(&mut storage).await;
    }

    // ── Tests for remove_old_keys_for_0_13_20 ──

    /// Test that legacy epoch keys are deleted when DEFAULT_EPOCH_ID counterparts exist (threshold)
    pub async fn test_remove_old_keys_for_0_13_20_threshold<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id_1 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let key_id_2 = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000bb",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let data_1 = vec![1, 2, 3];
        let data_2 = vec![4, 5, 6];

        // Store at legacy epoch (so keys appear in all_data_ids_at_epoch)
        storage
            .store_bytes_at_epoch(&data_1, &key_id_1, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&data_2, &key_id_2, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        // Store at DEFAULT_EPOCH_ID (the check the function uses before deleting)
        storage
            .store_bytes_at_epoch(&data_1, &key_id_1, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&data_2, &key_id_2, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        remove_old_keys_for_0_13_20(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Legacy epoch keys should be deleted
        assert!(
            !storage
                .data_exists_at_epoch(&key_id_1, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
        assert!(
            !storage
                .data_exists_at_epoch(&key_id_2, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );

        // DEFAULT_EPOCH_ID data should still exist
        assert!(
            storage
                .data_exists_at_epoch(&key_id_1, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
        assert!(
            storage
                .data_exists_at_epoch(&key_id_2, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    /// Test that legacy epoch keys are deleted when DEFAULT_EPOCH_ID counterparts exist (centralized)
    pub async fn test_remove_old_keys_for_0_13_20_centralized<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        let data = vec![42, 43, 44];

        // Store at legacy epoch and DEFAULT_EPOCH_ID
        storage
            .store_bytes_at_epoch(&data, &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&data, &key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        remove_old_keys_for_0_13_20(storage, KMSType::Centralized)
            .await
            .unwrap();

        // Legacy epoch key should be deleted
        assert!(
            !storage
                .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
        // DEFAULT_EPOCH_ID data should still exist
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    /// Test with no legacy epoch keys — nothing to remove
    pub async fn test_remove_old_keys_for_0_13_20_no_legacy<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        remove_old_keys_for_0_13_20(storage, KMSType::Threshold)
            .await
            .unwrap();
    }

    /// Test that legacy epoch keys are NOT deleted when no DEFAULT_EPOCH_ID counterpart exists
    pub async fn test_remove_old_keys_for_0_13_20_skips_without_new_epoch<
        S: StorageExt + Sync + Send,
    >(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000cc",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let data = vec![9, 8, 7];

        // Store at legacy epoch only, NOT at DEFAULT_EPOCH_ID
        storage
            .store_bytes_at_epoch(&data, &key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        remove_old_keys_for_0_13_20(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Legacy epoch key should still exist (not deleted because no DEFAULT_EPOCH_ID copy)
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    // RAM storage tests — remove_old_keys_for_0_13_20
    #[tokio::test]
    async fn test_remove_old_keys_threshold_ram() {
        let mut storage = RamStorage::new();
        test_remove_old_keys_for_0_13_20_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_centralized_ram() {
        let mut storage = RamStorage::new();
        test_remove_old_keys_for_0_13_20_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_no_legacy_ram() {
        let mut storage = RamStorage::new();
        test_remove_old_keys_for_0_13_20_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_skips_without_new_epoch_ram() {
        let mut storage = RamStorage::new();
        test_remove_old_keys_for_0_13_20_skips_without_new_epoch(&mut storage).await;
    }

    // File storage tests — remove_old_keys_for_0_13_20
    #[tokio::test]
    async fn test_remove_old_keys_threshold_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_remove_old_keys_for_0_13_20_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_centralized_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_remove_old_keys_for_0_13_20_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_no_legacy_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_remove_old_keys_for_0_13_20_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_remove_old_keys_skips_without_new_epoch_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_remove_old_keys_for_0_13_20_skips_without_new_epoch(&mut storage).await;
    }

    // ── Tests for migrate_to_0_13_x (orchestrator) ──

    #[tokio::test]
    async fn test_migrate_to_0_13_x_threshold() {
        let mut storage = RamStorage::new();
        let threshold = 1u8;
        let num_parties = 4;

        // Set up legacy FHE key
        let key_id = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        storage
            .store_bytes(&[1, 2, 3], &key_id, &data_type)
            .await
            .unwrap();

        // Set up legacy PRSS + context
        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        #[expect(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Threshold)
            .await
            .unwrap();

        // FHE key should be migrated to LEGACY_DEFAULT_EPOCH_ID
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_to_0_13_x_centralized() {
        let mut storage = RamStorage::new();

        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        storage
            .store_bytes(&[4, 5, 6], &key_id, &data_type)
            .await
            .unwrap();

        #[expect(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Centralized)
            .await
            .unwrap();

        // FHE key should be migrated to LEGACY_DEFAULT_EPOCH_ID
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_to_0_13_x_empty_storage() {
        let mut storage = RamStorage::new();
        // Should succeed with no data to migrate
        #[expect(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Threshold)
            .await
            .unwrap();
        #[expect(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Centralized)
            .await
            .unwrap();
    }

    // ── Tests for migrate_to_0_13_10 (orchestrator) ──

    #[tokio::test]
    async fn test_migrate_to_0_13_10_threshold() {
        let mut storage = RamStorage::new();
        let threshold = 1u8;
        let num_parties = 4;

        // Set up state as if migrate_to_0_13_x already ran:
        // FHE key at base path + DEFAULT_EPOCH_ID (from v0.12→v0.13 migration)
        let key_id = RequestId::from_str(
            "0x00000000000000000000000000000000000000000000000000000000000000aa",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let key_data = vec![1, 2, 3];
        storage
            .store_bytes(&key_data, &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&key_data, &key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        // Legacy context under LEGACY_DEFAULT_MPC_CONTEXT
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        // Legacy PRSS under LEGACY_DEFAULT_EPOCH_ID
        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;

        migrate_to_0_13_10(&mut storage, KMSType::Threshold)
            .await
            .unwrap();

        // Legacy base-path key should be cleaned up
        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());

        // Key should still exist at epoch
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_to_0_13_10_centralized() {
        let mut storage = RamStorage::new();

        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        let key_data = vec![4, 5, 6];

        // State after v0.12→v0.13: key at base + DEFAULT_EPOCH_ID
        storage
            .store_bytes(&key_data, &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&key_data, &key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap();

        migrate_to_0_13_10(&mut storage, KMSType::Centralized)
            .await
            .unwrap();

        // Legacy base-path key should be cleaned up
        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());

        // Epoch data still present
        assert!(
            storage
                .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_migrate_to_0_13_10_empty_storage() {
        let mut storage = RamStorage::new();
        migrate_to_0_13_10(&mut storage, KMSType::Threshold)
            .await
            .unwrap();
        migrate_to_0_13_10(&mut storage, KMSType::Centralized)
            .await
            .unwrap();
    }

    // ── Helpers for the 0.15.x (PRSS → epoch) migration tests ──

    fn make_test_prss_combined(num_parties: u8, threshold: u8) -> PRSSSetupCombined {
        PRSSSetupCombined {
            prss_setup_z128: PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]),
            prss_setup_z64: PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]),
            num_parties,
            threshold,
        }
    }

    /// Build a [`MigrationConfig`] from `(context_id, [epoch_id, ...])` pairs.
    fn migration_config(entries: Vec<(String, Vec<String>)>) -> MigrationConfig {
        MigrationConfig {
            context_associations: entries
                .into_iter()
                .map(|(context_id, epoch_ids)| ContextEpochAssociation {
                    context_id,
                    epoch_ids,
                })
                .collect(),
            custodian_context_id: None,
        }
    }

    /// The single-context / single-epoch config that maps the default context to the default epoch.
    fn default_migration_config() -> MigrationConfig {
        migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec![DEFAULT_EPOCH_ID.to_string()],
        )])
    }

    /// Store a combined PRSS under the (deprecated) `PrssSetupCombined` type at `epoch_id`.
    async fn store_combined_prss_at_epoch(
        storage: &mut RamStorage,
        epoch_id: &EpochId,
        num_parties: u8,
        threshold: u8,
    ) {
        store_versioned_at_request_id(
            storage,
            &epoch_id.into(),
            &make_test_prss_combined(num_parties, threshold),
            #[expect(deprecated)]
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await
        .unwrap();
    }

    // ── Tests for parse_migration_map ──

    #[test]
    fn test_parse_migration_map_sunshine() {
        // Default context + default epoch, plus an additional context with its own epoch.
        let config = migration_config(vec![
            (
                DEFAULT_MPC_CONTEXT.to_string(),
                vec![DEFAULT_EPOCH_ID.to_string()],
            ),
            (
                LEGACY_DEFAULT_MPC_CONTEXT.to_string(),
                vec![LEGACY_DEFAULT_EPOCH_ID.to_string()],
            ),
        ]);

        let map = parse_migration_map(&config).unwrap();

        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get(&DEFAULT_MPC_CONTEXT).unwrap(),
            &vec![*DEFAULT_EPOCH_ID]
        );
        assert_eq!(
            map.get(&LEGACY_DEFAULT_MPC_CONTEXT).unwrap(),
            &vec![*LEGACY_DEFAULT_EPOCH_ID]
        );
    }

    #[test]
    fn test_parse_migration_map_missing_default_context() {
        // Only a non-default context is present.
        let config = migration_config(vec![(
            LEGACY_DEFAULT_MPC_CONTEXT.to_string(),
            vec![LEGACY_DEFAULT_EPOCH_ID.to_string()],
        )]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(
            err.contains("Default context ID"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_migration_map_missing_default_epoch() {
        // Default context present, but it does not list the default epoch.
        let config = migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec![LEGACY_DEFAULT_EPOCH_ID.to_string()],
        )]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(err.contains("Default epoch ID"), "unexpected error: {err}");
    }

    #[test]
    fn test_parse_migration_map_empty_epoch_list() {
        let config = migration_config(vec![(DEFAULT_MPC_CONTEXT.to_string(), vec![])]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(
            err.contains("no associated epoch IDs"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_migration_map_invalid_context_id() {
        let config = migration_config(vec![(
            "not-a-hex-context".to_string(),
            vec![DEFAULT_EPOCH_ID.to_string()],
        )]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(
            err.contains("Invalid context id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_parse_migration_map_invalid_epoch_id() {
        let config = migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec!["not-a-hex-epoch".to_string()],
        )]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(err.contains("Invalid epoch ID"), "unexpected error: {err}");
    }

    #[test]
    fn test_parse_migration_map_duplicate_epoch() {
        // The same epoch listed twice (here under the default context) must be rejected.
        let config = migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec![DEFAULT_EPOCH_ID.to_string(), DEFAULT_EPOCH_ID.to_string()],
        )]);

        let err = parse_migration_map(&config).unwrap_err().to_string();
        assert!(
            err.contains("Duplicate epoch ID"),
            "unexpected error: {err}"
        );
    }

    // ── Tests for threshold_prss_to_epoch ──

    #[tokio::test]
    async fn test_threshold_prss_to_epoch_sunshine() {
        let mut storage = RamStorage::new();
        let num_parties = 4u8;
        let threshold = 1u8;

        // Combined PRSS present at the default epoch, as produced by the earlier migrations.
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, num_parties, threshold).await;

        threshold_prss_to_epoch(&mut storage, &default_migration_config())
            .await
            .unwrap();

        // EpochData should now exist at the default epoch, tagged with the default context.
        let epoch: EpochData = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(epoch.context_id, *DEFAULT_MPC_CONTEXT);
        assert_eq!(epoch.prss.num_parties, num_parties);
        assert_eq!(epoch.prss.threshold, threshold);
    }

    #[tokio::test]
    async fn test_threshold_prss_to_epoch_missing_prss_errors() {
        let mut storage = RamStorage::new();
        // No combined PRSS stored, so reading it back for the mapped epoch must fail.
        let result = threshold_prss_to_epoch(&mut storage, &default_migration_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_threshold_prss_to_epoch_stored_epoch_missing_from_config_errors() {
        let mut storage = RamStorage::new();
        // Two epochs have PRSS on disk, but the config only lists the default one (DEFAULT_EPOCH_ID).
        // The unlisted epoch must be rejected before any write, so it can never be silently dropped
        // (and then lost when the 0.16 migration deletes the legacy PRSS).
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;
        store_combined_prss_at_epoch(&mut storage, &LEGACY_DEFAULT_EPOCH_ID, 4, 1).await;

        let err = threshold_prss_to_epoch(&mut storage, &default_migration_config())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not cover"), "unexpected error: {err}");
        assert!(
            err.contains(&LEGACY_DEFAULT_EPOCH_ID.to_string()),
            "error should name the uncovered epoch: {err}"
        );

        // Coverage is checked before any write, so no EpochData must have been produced.
        assert!(
            storage
                .all_data_ids(&PrivDataType::EpochData.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_threshold_prss_to_epoch_configured_epoch_missing_on_disk_errors() {
        let mut storage = RamStorage::new();
        // Only the default epoch has PRSS on disk, but the config also lists an extra epoch under
        // the default context. The phantom epoch must be rejected up front rather than crashing
        // mid-write on the missing read.
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;

        let config = migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec![
                DEFAULT_EPOCH_ID.to_string(),
                LEGACY_DEFAULT_EPOCH_ID.to_string(),
            ],
        )]);

        let err = threshold_prss_to_epoch(&mut storage, &config)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no PRSS data on disk"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains(&LEGACY_DEFAULT_EPOCH_ID.to_string()),
            "error should name the phantom epoch: {err}"
        );

        // No partial migration should have happened.
        assert!(
            storage
                .all_data_ids(&PrivDataType::EpochData.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_threshold_prss_to_epoch_skips_already_migrated_epoch() {
        let mut storage = RamStorage::new();

        // Two epochs under the default context both still have their legacy combined PRSS on disk
        // (the 0.16 migration that deletes it has not run yet). The default epoch was already
        // migrated on an earlier, partially-completed run — its EpochData already exists — while the
        // second epoch has not been. Re-running must migrate only the second epoch and must never
        // overwrite the already-migrated one.
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;
        store_combined_prss_at_epoch(&mut storage, &LEGACY_DEFAULT_EPOCH_ID, 4, 1).await;

        // Pre-existing EpochData for the default epoch, tagged with a sentinel party count (9) that
        // differs from the combined PRSS on disk (4) so any accidental overwrite would be detectable.
        let already_migrated = EpochData {
            context_id: *DEFAULT_MPC_CONTEXT,
            prss: make_test_prss_combined(9, 2),
        };
        store_versioned_at_request_id(
            &mut storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &already_migrated,
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();

        let config = migration_config(vec![(
            DEFAULT_MPC_CONTEXT.to_string(),
            vec![
                DEFAULT_EPOCH_ID.to_string(),
                LEGACY_DEFAULT_EPOCH_ID.to_string(),
            ],
        )]);

        threshold_prss_to_epoch(&mut storage, &config)
            .await
            .unwrap();

        // The already-migrated epoch is left untouched: still the sentinel 9-party EpochData, not
        // the 4-party PRSS that lingers alongside it on disk.
        let kept: EpochData = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(kept.prss.num_parties, 9);
        assert_eq!(kept.prss.threshold, 2);

        // The second epoch is freshly migrated from its combined PRSS.
        let migrated: EpochData = read_versioned_at_request_id(
            &storage,
            &(*LEGACY_DEFAULT_EPOCH_ID).into(),
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(migrated.context_id, *DEFAULT_MPC_CONTEXT);
        assert_eq!(migrated.prss.num_parties, 4);
        assert_eq!(migrated.prss.threshold, 1);
    }

    // ── Tests for migrate_prss_to_epoch ──

    #[tokio::test]
    async fn test_migrate_prss_to_epoch_centralized_noop() {
        let mut storage = RamStorage::new();
        // Even with a config present, centralized KMS performs no migration.
        migrate_prss_to_epoch(
            &mut storage,
            KMSType::Centralized,
            Some(&default_migration_config()),
        )
        .await
        .unwrap();

        assert!(
            storage
                .all_data_ids(&PrivDataType::EpochData.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_migrate_prss_to_epoch_already_migrated_skips() {
        let mut storage = RamStorage::new();
        let num_parties = 4u8;
        let threshold = 1u8;

        // EpochData already present → migration is a no-op even without a config.
        let existing = EpochData {
            context_id: *DEFAULT_MPC_CONTEXT,
            prss: make_test_prss_combined(num_parties, threshold),
        };
        store_versioned_at_request_id(
            &mut storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &existing,
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();

        migrate_prss_to_epoch(&mut storage, KMSType::Threshold, None)
            .await
            .unwrap();

        // Still exactly one EpochData entry, unchanged.
        let ids = storage
            .all_data_ids(&PrivDataType::EpochData.to_string())
            .await
            .unwrap();
        assert_eq!(ids.len(), 1);
    }

    #[tokio::test]
    async fn test_migrate_prss_to_epoch_no_config_no_old_data_skips() {
        let mut storage = RamStorage::new();
        // Fresh threshold system: no EpochData, no old PRSS, no config → graceful skip.
        migrate_prss_to_epoch(&mut storage, KMSType::Threshold, None)
            .await
            .unwrap();

        assert!(
            storage
                .all_data_ids(&PrivDataType::EpochData.to_string())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_migrate_prss_to_epoch_no_config_with_old_data_errors() {
        let mut storage = RamStorage::new();
        // Old combined PRSS present but no migration config supplied → must fail loudly.
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;

        let result = migrate_prss_to_epoch(&mut storage, KMSType::Threshold, None).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_migrate_prss_to_epoch_with_config_sunshine() {
        let mut storage = RamStorage::new();
        let num_parties = 4u8;
        let threshold = 1u8;

        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, num_parties, threshold).await;

        migrate_prss_to_epoch(
            &mut storage,
            KMSType::Threshold,
            Some(&default_migration_config()),
        )
        .await
        .unwrap();

        let epoch: EpochData = read_versioned_at_request_id(
            &storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(epoch.context_id, *DEFAULT_MPC_CONTEXT);
        assert_eq!(epoch.prss.num_parties, num_parties);
    }

    // ── Tests for remove_old_prss_data ──

    #[tokio::test]
    async fn test_remove_old_prss_data_centralized_noop() {
        let mut storage = RamStorage::new();
        // Centralized never has combined PRSS data; call is a no-op and must not error.
        remove_old_prss_data(&mut storage, KMSType::Centralized)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_remove_old_prss_data_threshold_removes_all() {
        let mut storage = RamStorage::new();

        // Two combined PRSS entries under different epoch IDs.
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;
        store_combined_prss_at_epoch(&mut storage, &LEGACY_DEFAULT_EPOCH_ID, 4, 1).await;

        #[expect(deprecated)]
        let before = storage
            .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
            .await
            .unwrap();
        assert_eq!(before.len(), 2);

        remove_old_prss_data(&mut storage, KMSType::Threshold)
            .await
            .unwrap();

        #[expect(deprecated)]
        let after = storage
            .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
            .await
            .unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn test_remove_old_prss_data_threshold_no_data() {
        let mut storage = RamStorage::new();
        // Nothing stored → still succeeds.
        remove_old_prss_data(&mut storage, KMSType::Threshold)
            .await
            .unwrap();
    }

    // ── Tests for migrate_to_0_15_x (orchestrator) ──

    /// Asserts every scheme's verification material is (or is not) present in public
    /// storage, excluding the legacy ECDSA material.
    async fn assert_non_legacy_verf_material_present<S: StorageReader>(
        pub_storage: &S,
        expected: bool,
    ) {
        for scheme in SigningSchemeType::iter() {
            let id = signing_material_id(scheme);
            for data_type in NON_LEGACY_VERF_MATERIAL_TYPES.map(|t| t.to_string()) {
                assert_eq!(
                    pub_storage.data_exists(&id, &data_type).await.unwrap(),
                    expected,
                    "{scheme} {data_type} presence did not match"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_migrate_to_0_15_x_threshold_sunshine() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();
        let num_parties = 4u8;
        let threshold = 1u8;

        // Simulate a post-0.13.20 state: combined PRSS already sits at the default epoch and signing key.
        // The earlier migration steps are no-ops here (no legacy keys/context), so this data
        // survives and migrate_prss_to_epoch converts it into EpochData.
        store_combined_prss_at_epoch(&mut priv_storage, &DEFAULT_EPOCH_ID, num_parties, threshold)
            .await;
        // Derive signing key and use central for convenience since we test with a single server
        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        migrate_to_0_15_x(
            &mut pub_storage,
            &mut priv_storage,
            KMSType::Threshold,
            Some(&default_migration_config()),
        )
        .await
        .unwrap();

        // Check epoch data
        let epoch: EpochData = read_versioned_at_request_id(
            &priv_storage,
            &(*DEFAULT_EPOCH_ID).into(),
            &PrivDataType::EpochData.to_string(),
        )
        .await
        .unwrap();
        assert_eq!(epoch.context_id, *DEFAULT_MPC_CONTEXT);
        assert_eq!(epoch.prss.num_parties, num_parties);
        assert_eq!(epoch.prss.threshold, threshold);

        assert_non_legacy_verf_material_present(&pub_storage, true).await;
    }

    #[tokio::test]
    async fn test_migrate_to_0_15_x_threshold_idempotent() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();
        store_combined_prss_at_epoch(&mut priv_storage, &DEFAULT_EPOCH_ID, 4, 1).await;
        // Derive signing key and use central for convenience since we test with a single server
        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        let config = default_migration_config();

        // Second run: EpochData already exists, so PRSS migration short-circuits without error.
        // Furthermore, validation keys should already have been made and hence key migration
        // also short-circuits without error.
        for _ in 0..2 {
            migrate_to_0_15_x(
                &mut pub_storage,
                &mut priv_storage,
                KMSType::Threshold,
                Some(&config),
            )
            .await
            .unwrap();

            // Check epoch ids
            let ids = priv_storage
                .all_data_ids(&PrivDataType::EpochData.to_string())
                .await
                .unwrap();
            assert_eq!(ids.len(), 1);
            assert_non_legacy_verf_material_present(&pub_storage, true).await;
        }
    }

    #[tokio::test]
    async fn test_migrate_to_0_15_x_centralized_with_signing_key() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();
        // Derive signing key
        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();

        migrate_to_0_15_x(
            &mut pub_storage,
            &mut priv_storage,
            KMSType::Centralized,
            None,
        )
        .await
        .unwrap();
        assert_non_legacy_verf_material_present(&pub_storage, true).await;
    }

    /// A node upgraded from a release that predates the root signing seed keeps its
    /// ECDSA key and publishes *nothing*.
    #[tokio::test]
    async fn test_migrate_to_0_15_x_skips_backfill_without_a_seed() {
        let mut rng = AesRng::seed_from_u64(31);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        // Pre-multi-scheme private storage: an ECDSA signing key and no seed.
        store_versioned_at_request_id(
            &mut priv_storage,
            &SIGNING_KEY_ID,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();

        migrate_to_0_15_x(
            &mut pub_storage,
            &mut priv_storage,
            KMSType::Centralized,
            None,
        )
        .await
        .unwrap();

        assert_non_legacy_verf_material_present(&pub_storage, false).await;
        assert!(
            !priv_storage
                .data_exists(&SIGNING_KEY_ID, &PrivDataType::SigningSeed.to_string())
                .await
                .unwrap(),
            "the boot migration minted a root signing seed"
        );
    }

    #[tokio::test]
    async fn test_migrate_to_0_15_x_centralized_empty() {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();

        migrate_to_0_15_x(
            &mut pub_storage,
            &mut priv_storage,
            KMSType::Centralized,
            None,
        )
        .await
        .unwrap();

        assert_non_legacy_verf_material_present(&pub_storage, false).await;
    }

    // ── Tests for migrate_to_0_16_x (orchestrator) ──

    #[tokio::test]
    async fn test_migrate_to_0_16_x_threshold_removes_combined_prss() {
        let mut storage = RamStorage::new();
        store_combined_prss_at_epoch(&mut storage, &DEFAULT_EPOCH_ID, 4, 1).await;

        migrate_to_0_16_x(&mut storage, KMSType::Threshold)
            .await
            .unwrap();

        #[expect(deprecated)]
        let remaining = storage
            .all_data_ids(&PrivDataType::PrssSetupCombined.to_string())
            .await
            .unwrap();
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn test_migrate_to_0_16_x_centralized_noop() {
        let mut storage = RamStorage::new();
        migrate_to_0_16_x(&mut storage, KMSType::Centralized)
            .await
            .unwrap();
    }

    /// Helper method:
    /// A node from before multi-scheme support: an ECDSA signing key in private
    /// storage, and in public storage only the deprecated ECDSA material.
    async fn pre_multi_scheme_node() -> (RamStorage, RamStorage) {
        let mut pub_storage = RamStorage::new();
        let mut priv_storage = RamStorage::new();
        ensure_central_server_signing_keys_exist(&mut pub_storage, &mut priv_storage, true)
            .await
            .unwrap();
        delete_non_legacy_verf_material(&mut pub_storage)
            .await
            .unwrap();
        (pub_storage, priv_storage)
    }

    /// Every object stored under `data_types`, keyed by data type and handle, so
    /// that two points in time can be compared byte for byte.
    async fn snapshot<S: StorageReader>(
        storage: &S,
        data_types: &[PubDataType],
    ) -> HashMap<(String, String), Vec<u8>> {
        let mut out = HashMap::new();
        for data_type in data_types {
            let data_type = data_type.to_string();
            for id in storage.all_data_ids(&data_type).await.unwrap() {
                let bytes = storage.load_bytes(&id, &data_type).await.unwrap();
                out.insert((data_type.clone(), id.to_string()), bytes);
            }
        }
        out
    }

    /// Validates that the published key and digest are the ones `sk` derives.
    async fn assert_material_matches<S: StorageReader>(pub_storage: &S, sk: &PrivateSigKey) {
        let addr_type = PubDataType::TypedVerfAddress.to_string();
        for scheme in SigningSchemeType::iter() {
            let expected = sk.unified_verifying_key(scheme).unwrap();
            assert_eq!(
                read_verf_key_at(
                    pub_storage,
                    &signing_material_id(scheme),
                    PubDataType::TypedVerfKey,
                    scheme
                )
                .await
                .unwrap(),
                expected,
                "{scheme} verification key does not match the signing key"
            );
            assert_eq!(
                read_text_at_request_id(pub_storage, &signing_material_id(scheme), &addr_type)
                    .await
                    .unwrap(),
                expected.address_text(),
                "{scheme} digest does not match the signing key"
            );
        }
    }

    /// The case the migration exists for: a node that predates multi-scheme support
    /// gains every scheme's material on restart, derived from the key it already
    /// has, and its historic ECDSA material is left byte-for-byte alone.
    #[tokio::test]
    async fn backfills_material_for_a_pre_multi_scheme_node() {
        let (mut pub_storage, priv_storage) = pre_multi_scheme_node().await;
        let legacy_before = snapshot(&pub_storage, &LEGACY_VERF_MATERIAL_TYPES).await;
        assert!(
            snapshot(&pub_storage, &NON_LEGACY_VERF_MATERIAL_TYPES)
                .await
                .is_empty(),
            "the fixture is not a pre-multi-scheme node"
        );

        migrate_public_verification_material(&priv_storage, &mut pub_storage)
            .await
            .unwrap();

        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        assert_material_matches(&pub_storage, &sk).await;
        assert_eq!(
            snapshot(&pub_storage, &LEGACY_VERF_MATERIAL_TYPES).await,
            legacy_before,
            "the deprecated ECDSA material was modified"
        );
    }

    /// A node with no signing key — storage prepared before key generation — must
    /// migrate cleanly rather than fail the boot, and must not invent material it
    /// has nothing to derive from.
    #[tokio::test]
    async fn skips_when_no_signing_key_exists() {
        let mut pub_storage = RamStorage::new();
        let priv_storage = RamStorage::new();

        migrate_public_verification_material(&priv_storage, &mut pub_storage)
            .await
            .unwrap();

        assert!(
            snapshot(&pub_storage, &NON_LEGACY_VERF_MATERIAL_TYPES)
                .await
                .is_empty(),
            "material was written without a signing key to derive it from"
        );
    }

    /// The migration runs on every start, so the second and later runs must be
    /// inert — not merely non-failing, but not rewriting the published objects
    /// either.
    #[tokio::test]
    async fn rerunning_changes_nothing() {
        let (mut pub_storage, priv_storage) = pre_multi_scheme_node().await;
        migrate_public_verification_material(&priv_storage, &mut pub_storage)
            .await
            .unwrap();
        let after_first_run = snapshot(&pub_storage, &NON_LEGACY_VERF_MATERIAL_TYPES).await;

        migrate_public_verification_material(&priv_storage, &mut pub_storage)
            .await
            .unwrap();

        assert_eq!(
            snapshot(&pub_storage, &NON_LEGACY_VERF_MATERIAL_TYPES).await,
            after_first_run
        );
    }

    mod recovery_material {
        use super::*;
        use crate::conf::MigrationConfig;
        use crate::cryptography::signatures::gen_sig_keys;
        use crate::vault::storage::tests::{
            dummy_recovery_material_at_id, store_dummy_recovery_material,
        };
        use crate::vault::storage::{
            read_all_recovery_material, read_custodian_context_anchor, read_recovery_material_at_id,
        };
        use aes_prng::AesRng;
        use rand::SeedableRng;

        fn config_for(id: &RequestId) -> MigrationConfig {
            MigrationConfig {
                context_associations: Vec::new(),
                custodian_context_id: Some(id.to_string()),
            }
        }

        /// Public storage holding recovery material for `id`, and the key it is signed with.
        async fn legacy_node(id: &RequestId) -> (RamStorage, PrivateSigKey) {
            let (_verf_key, sig_key) = gen_sig_keys(&mut AesRng::seed_from_u64(0));
            let mut pub_storage = RamStorage::new();
            store_dummy_recovery_material(&mut pub_storage, id, &sig_key).await;
            (pub_storage, sig_key)
        }

        #[tokio::test]
        async fn imports_the_configured_context_and_anchors_it() {
            let id = RequestId::from_bytes([1; 32]);
            let (mut pub_storage, sig_key) = legacy_node(&id).await;
            let (mut priv_storage, mut backup_storage) = (RamStorage::new(), RamStorage::new());

            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                Some(&config_for(&id)),
                &PublicSigKey::from_sk(&sig_key),
            )
            .await
            .unwrap();

            assert!(
                read_recovery_material_at_id(&backup_storage, &id)
                    .await
                    .is_ok()
            );
            assert_eq!(
                read_custodian_context_anchor(&priv_storage).await.unwrap(),
                Some(id)
            );
            assert!(
                pub_storage
                    .all_data_ids(&PubDataType::RecoveryMaterial.to_string())
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        /// The anchor is what stops the import, so public storage is never read again — the one
        /// boot that reads it is the only one an attacker could aim at.
        #[tokio::test]
        async fn does_nothing_once_a_context_is_anchored() {
            let id = RequestId::from_bytes([1; 32]);
            let (mut pub_storage, sig_key) = legacy_node(&id).await;
            let (mut priv_storage, mut backup_storage) = (RamStorage::new(), RamStorage::new());
            store_custodian_context_anchor(&mut priv_storage, &RequestId::from_bytes([2; 32]))
                .await
                .unwrap();

            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                Some(&config_for(&id)),
                &PublicSigKey::from_sk(&sig_key),
            )
            .await
            .unwrap();

            assert!(
                read_all_recovery_material(&backup_storage)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(
                read_custodian_context_anchor(&priv_storage).await.unwrap(),
                Some(RequestId::from_bytes([2; 32]))
            );
        }

        #[tokio::test]
        async fn does_nothing_without_configuration() {
            let id = RequestId::from_bytes([1; 32]);
            let (mut pub_storage, sig_key) = legacy_node(&id).await;
            let (mut priv_storage, mut backup_storage) = (RamStorage::new(), RamStorage::new());

            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                None,
                &PublicSigKey::from_sk(&sig_key),
            )
            .await
            .unwrap();

            assert!(
                read_custodian_context_anchor(&priv_storage)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                read_recovery_material_at_id(&pub_storage, &id)
                    .await
                    .is_ok(),
                "the public copy must be left for the operator"
            );
        }

        /// Material another node signed must not reach the vault, however it got into public storage.
        #[tokio::test]
        async fn refuses_material_this_node_did_not_sign() {
            let id = RequestId::from_bytes([1; 32]);
            let (mut pub_storage, _sig_key) = legacy_node(&id).await;
            let (_other_verf_key, other_sig_key) = gen_sig_keys(&mut AesRng::seed_from_u64(7));
            let (mut priv_storage, mut backup_storage) = (RamStorage::new(), RamStorage::new());

            // Reported, not fatal: public storage is modifiable, so its content must never be
            // able to stop the boot.
            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                Some(&config_for(&id)),
                &PublicSigKey::from_sk(&other_sig_key),
            )
            .await
            .unwrap();
            assert!(
                read_all_recovery_material(&backup_storage)
                    .await
                    .unwrap()
                    .is_empty()
            );
            assert!(
                read_custodian_context_anchor(&priv_storage)
                    .await
                    .unwrap()
                    .is_none()
            );
        }

        #[tokio::test]
        async fn anchors_material_already_in_the_vault() {
            let id = RequestId::from_bytes([1; 32]);
            let (_verf_key, sig_key) = gen_sig_keys(&mut AesRng::seed_from_u64(0));
            let (mut pub_storage, mut priv_storage) = (RamStorage::new(), RamStorage::new());
            let mut backup_storage = RamStorage::new();
            store_dummy_recovery_material(&mut backup_storage, &id, &sig_key).await;

            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                Some(&config_for(&id)),
                &PublicSigKey::from_sk(&sig_key),
            )
            .await
            .unwrap();

            assert_eq!(
                read_custodian_context_anchor(&priv_storage).await.unwrap(),
                Some(id)
            );
        }

        /// An operator told to hand-copy the material can leave a truncated or foreign object in the
        /// vault; the public copy is the only other one, so it must survive.
        #[tokio::test]
        async fn keeps_public_material_when_the_vault_copy_is_unreadable() {
            let id = RequestId::from_bytes([1; 32]);
            let (_verf_key, sig_key) = gen_sig_keys(&mut AesRng::seed_from_u64(0));
            let (mut pub_storage, mut priv_storage) = (RamStorage::new(), RamStorage::new());
            let mut backup_storage = RamStorage::new();
            let data_type = PubDataType::RecoveryMaterial.to_string();
            store_dummy_recovery_material(&mut pub_storage, &id, &sig_key).await;
            // Exists at `id`, but names another context, so it fails the payload-id check.
            backup_storage
                .store_data(
                    &dummy_recovery_material_at_id(&RequestId::from_bytes([2; 32]), &sig_key),
                    &id,
                    &data_type,
                )
                .await
                .unwrap();

            import_configured_legacy_context(
                &mut pub_storage,
                &mut priv_storage,
                &mut backup_storage,
                Some(&config_for(&id)),
                &PublicSigKey::from_sk(&sig_key),
            )
            .await
            .unwrap();

            assert_eq!(
                read_custodian_context_anchor(&priv_storage).await.unwrap(),
                None,
                "an unreadable vault copy must not be anchored"
            );
            assert!(
                pub_storage.data_exists(&id, &data_type).await.unwrap(),
                "the public copy must survive an unreadable vault copy"
            );
        }
    }

    // S3 storage tests, run against an in-process mock S3 (no MinIO) via `create_s3_storage`.
    #[cfg(all(feature = "non-wasm", feature = "testing"))]
    mod s3_tests {
        use super::*;
        use crate::vault::storage::s3::create_s3_storage;

        #[tokio::test]
        async fn test_migrate_threshold_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_migrate_threshold_s3),
            )
            .await;
            test_migrate_legacy_fhe_keys_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_centralized_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_migrate_centralized_s3),
            )
            .await;
            test_migrate_legacy_fhe_keys_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_skips_existing_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_migrate_skips_existing_s3),
            )
            .await;
            test_migrate_legacy_fhe_keys_skips_existing(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_no_legacy_data_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_migrate_no_legacy_data_s3),
            )
            .await;
            test_migrate_legacy_fhe_keys_no_legacy_data(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_idempotent_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_migrate_idempotent_s3),
            )
            .await;
            test_migrate_legacy_fhe_keys_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_threshold_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_after_0_13_x_threshold_s3),
            )
            .await;
            test_migrate_fhe_keys_after_0_13_x_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_centralized_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_after_0_13_x_centralized_s3),
            )
            .await;
            test_migrate_fhe_keys_after_0_13_x_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_no_legacy_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_after_0_13_x_no_legacy_s3),
            )
            .await;
            test_migrate_fhe_keys_after_0_13_x_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_idempotent_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_after_0_13_x_idempotent_s3),
            )
            .await;
            test_migrate_fhe_keys_after_0_13_x_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_threshold_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_0_13_x_to_0_13_10_threshold_s3),
            )
            .await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_centralized_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_0_13_x_to_0_13_10_centralized_s3),
            )
            .await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_no_legacy_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_0_13_x_to_0_13_10_no_legacy_s3),
            )
            .await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_skips_existing_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_0_13_x_to_0_13_10_skips_existing_s3),
            )
            .await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_skips_existing(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_idempotent_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_0_13_x_to_0_13_10_idempotent_s3),
            )
            .await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_threshold_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_remove_old_keys_threshold_s3),
            )
            .await;
            test_remove_old_keys_for_0_13_20_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_centralized_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_remove_old_keys_centralized_s3),
            )
            .await;
            test_remove_old_keys_for_0_13_20_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_no_legacy_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_remove_old_keys_no_legacy_s3),
            )
            .await;
            test_remove_old_keys_for_0_13_20_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_skips_without_new_epoch_s3() {
            let mut storage = create_s3_storage(
                StorageType::PRIV,
                std::stringify!(test_remove_old_keys_skips_without_new_epoch_s3),
            )
            .await;
            test_remove_old_keys_for_0_13_20_skips_without_new_epoch(&mut storage).await;
        }
    }
}
