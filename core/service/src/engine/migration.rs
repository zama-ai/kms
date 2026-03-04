use crate::consts::{DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT};
use crate::engine::base::derive_request_id;
use crate::engine::threshold::service::session::PRSSSetupCombined;
use crate::vault::storage::{
    read_context_at_id, read_versioned_at_request_id, store_versioned_at_request_id, StorageExt,
};
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use kms_grpc::ContextId;
use threshold_fhe::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
use threshold_fhe::execution::small_execution::prss::PRSSSetup;

lazy_static::lazy_static! {
pub static ref LEGACY_DEFAULT_MPC_CONTEXT: ContextId = ContextId::from_bytes([
    1u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3,
    4,
]);

// The default epoch ID used for initial PRSS setup and as fallback when no epoch is specified.
pub static ref LEGACY_DEFAULT_EPOCH_ID: EpochId = EpochId::from_bytes([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
]);
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
        migrate_legacy_prss(priv_storage).await?;
    }
    Ok(())
}

/// Migrate from 0.12.x or 0.13.x to 0.13.10
/// This is disabled for now and should only be enabled in the next version
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
    #[allow(deprecated)]
    migrate_to_0_13_x(priv_storage, kms_type).await?;
    if let KMSType::Threshold = kms_type {
        // Migrate any remaining combined PRSS data that might not have been migrated in the previous migration
        // That is, if a convertion to the PRSSCombined format has already been done, but under the legacy default epoch id
        migrate_combined_prss_to_0_13_10(priv_storage).await?;
    }
    migrate_context_before_0_13_10(priv_storage).await?;
    migrate_fhe_keys_0_13_x_to_0_13_10(priv_storage, kms_type).await?;
    // Remove moved keys (keys with legacy ID still remains)
    migrate_fhe_keys_after_0_13_x(priv_storage, kms_type).await?;
    Ok(())
}

/// Migrate to 0.13.20
/// This should only be activated after 0.13.10 has been released
#[allow(dead_code)]
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
            .await?;

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
            tracing::error!("Legacy key {} still exists but no migrated key found at epoch {}, skipping deletion", key_id, legacy_epoch_id);
        }
    }
    Ok(())
}

/// This will try to load the legacy PRSS setup [`PRSSSetup`] from storage
/// by using the default value for the epoch ID.
/// It then converts the old PRSSSetup data into the new PRSSSetupCombined format and stores it back in storage under the new epoch-aware path.
#[expect(deprecated)]
async fn migrate_legacy_prss<PrivS>(priv_storage: &mut PrivS) -> anyhow::Result<()>
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
                return Ok(());
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
        return Ok(());
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

    match prss_from_storage {
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
        }
        (Err(e), Ok(_)) => tracing::error!("Failed to read legacy PRSS Z128 from file with error: {e}, but was able to read Z64, skipping migration since we don't have the full data"),
        (Ok(_), Err(e)) => tracing::error!("Failed to read legacy PRSS Z64 from file with error: {e}, but was able to read Z128, skipping migration since we don't have the full data"),
        (Err(_e), Err(e)) => tracing::error!("Failed to read both legacy PRSS Z128 and Z64 from file with errors: Z128 error: {_e}, Z64 error: {e}, skipping migration"),
    }
    Ok(())
}

async fn migrate_combined_prss_to_0_13_10<PrivS>(priv_storage: &mut PrivS) -> anyhow::Result<()>
where
    PrivS: StorageExt + Sync + Send,
{
    let prss: PRSSSetupCombined = match read_versioned_at_request_id(
        priv_storage,
        &(*LEGACY_DEFAULT_EPOCH_ID).into(),
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
            return Ok(());
        }
    };
    store_versioned_at_request_id(
        priv_storage,
        &(*DEFAULT_EPOCH_ID).into(),
        &prss,
        &PrivDataType::PrssSetupCombined.to_string(),
    )
    .await?;
    priv_storage
        .delete_data(
            &(*LEGACY_DEFAULT_EPOCH_ID).into(),
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?;
    tracing::info!(
        "Successfully migrated PRSS Combined with legacy ID {} to new ID {}",
        *LEGACY_DEFAULT_EPOCH_ID,
        *DEFAULT_EPOCH_ID
    );
    Ok(())
}

/// Reads context under the old legacy default context ID and if it exists, re-stores it under the new default context ID.
async fn migrate_context_before_0_13_10<PrivS>(priv_storage: &mut PrivS) -> anyhow::Result<()>
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
            return Ok(());
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
    Ok(())
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
            .await?;

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
                "No keys {} under legacy epoch ID {} does not appear to exist",
                key_id,
                *LEGACY_DEFAULT_EPOCH_ID
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::context::{ContextInfo, NodeInfo, SoftwareVersion};
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::ram::{self, RamStorage};
    use crate::vault::storage::{
        store_context_at_id, store_versioned_at_request_id, Storage, StorageExt, StorageReader,
        StorageReaderExt, StorageType,
    };
    use kms_grpc::RequestId;
    use std::str::FromStr;

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
        assert!(storage
            .data_exists_at_epoch(&key_id_1, &legacy_epoch_id, &data_type)
            .await
            .unwrap());
        assert!(storage
            .data_exists_at_epoch(&key_id_2, &legacy_epoch_id, &data_type)
            .await
            .unwrap());

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
        assert!(storage
            .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap());

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
                verification_key: None,
                external_url: "https://doesnotexist.zama.ai".to_string(),
                ca_cert: None,
                public_storage_url: "".to_string(),
                public_storage_prefix: None,
                extra_verification_keys: vec![],
            });
        }
        // todo add check to context maanger that context id in context matches name
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
        assert!(storage
            .data_exists_at_epoch(&key_id, &legacy_epoch_id, &data_type)
            .await
            .unwrap());
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

        migrate_legacy_prss(&mut storage).await.unwrap();

        // Verify PrssSetupCombined was created at the legacy epoch ID (where we asked it to store)
        let legacy_epoch_id = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(storage
            .data_exists(
                &legacy_epoch_id.into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap());

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
        assert!(!storage
            .data_exists(&prss_128_id, &PrivDataType::PrssSetup.to_string())
            .await
            .unwrap());
        assert!(!storage
            .data_exists(&prss_64_id, &PrivDataType::PrssSetup.to_string())
            .await
            .unwrap());

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

        migrate_legacy_prss(&mut storage).await.unwrap();

        // Write fresh legacy data again
        write_legacy_empty_prss_to_storage(&mut storage, threshold, num_parties).await;

        // Second migration should skip (PrssSetupCombined already exists)
        migrate_legacy_prss(&mut storage).await.unwrap();

        // PrssSetupCombined should still exist
        let epoch_id = *LEGACY_DEFAULT_EPOCH_ID;
        assert!(storage
            .data_exists(
                &epoch_id.into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap());

        // The newly written legacy data should NOT have been deleted
        // (because the migration returned early)
        let prss_128_id = derive_request_id(&format!(
            "PRSSSetup_Z128_ID_{}_{}_{}",
            epoch_id, num_parties, threshold,
        ))
        .unwrap();
        #[expect(deprecated)]
        let prss_data_type = PrivDataType::PrssSetup.to_string();
        assert!(storage
            .data_exists(&prss_128_id, &prss_data_type)
            .await
            .unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_migrate_prss_no_legacy_data_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        let result = migrate_legacy_prss(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Failed to read both legacy PRSS Z128 and Z64"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
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

        let result = migrate_legacy_prss(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Failed to read legacy PRSS Z64 from file"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
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

        let result = migrate_legacy_prss(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Failed to read legacy PRSS Z128 from file"));
    }

    // ── Tests for migrate_context_before_0_13_10 ──

    #[tokio::test]
    async fn test_migrate_context_sunshine() {
        let mut storage = RamStorage::new();
        let threshold = 1u8;
        let num_parties = 4;

        // Store context under the legacy context ID
        store_legacy_test_context(&mut storage, threshold, num_parties).await;
        assert!(storage
            .data_exists(
                &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
                &PrivDataType::ContextInfo.to_string(),
            )
            .await
            .unwrap());

        migrate_context_before_0_13_10(&mut storage).await.unwrap();

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
        assert!(!storage
            .data_exists(
                &(*LEGACY_DEFAULT_MPC_CONTEXT).into(),
                &PrivDataType::ContextInfo.to_string(),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_migrate_context_no_legacy() {
        let mut storage = RamStorage::new();
        // No context stored, should skip gracefully
        let result = migrate_context_before_0_13_10(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Skipping legacy context migration"));
    }

    #[tokio::test]
    async fn test_migrate_context_idempotent() {
        let mut storage = RamStorage::new();
        let threshold = 2u8;
        let num_parties = 3;

        store_legacy_test_context(&mut storage, threshold, num_parties).await;

        // First migration
        migrate_context_before_0_13_10(&mut storage).await.unwrap();

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
        migrate_context_before_0_13_10(&mut storage).await.unwrap();

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
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await
        .unwrap();

        migrate_combined_prss_to_0_13_10(&mut storage)
            .await
            .unwrap();

        assert!(storage
            .data_exists(
                &(*DEFAULT_EPOCH_ID).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap());
        assert!(!storage
            .data_exists(
                &(*LEGACY_DEFAULT_EPOCH_ID).into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_migrate_combined_prss_no_data_ram() {
        let mut storage = RamStorage::new();
        let result = migrate_combined_prss_to_0_13_10(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Skipping legacy PRSSCombined migration"));
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_migrate_combined_prss_no_data_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        let result = migrate_combined_prss_to_0_13_10(&mut storage).await;
        assert!(result.is_ok());
        assert!(logs_contain("Skipping legacy PRSSCombined migration"));
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
        assert!(storage
            .data_exists_at_epoch(&key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap());
        assert!(storage
            .data_exists_at_epoch(&key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap());

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
        assert!(!storage
            .data_exists_at_epoch(&key_id_1, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
        assert!(!storage
            .data_exists_at_epoch(&key_id_2, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());

        // DEFAULT_EPOCH_ID data should still exist
        assert!(storage
            .data_exists_at_epoch(&key_id_1, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
        assert!(storage
            .data_exists_at_epoch(&key_id_2, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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
        assert!(!storage
            .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
        // DEFAULT_EPOCH_ID data should still exist
        assert!(storage
            .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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
        assert!(storage
            .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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

        #[allow(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Threshold)
            .await
            .unwrap();

        // FHE key should be migrated to LEGACY_DEFAULT_EPOCH_ID
        assert!(storage
            .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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

        #[allow(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Centralized)
            .await
            .unwrap();

        // FHE key should be migrated to LEGACY_DEFAULT_EPOCH_ID
        assert!(storage
            .data_exists_at_epoch(&key_id, &LEGACY_DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn test_migrate_to_0_13_x_empty_storage() {
        let mut storage = RamStorage::new();
        // Should succeed with no data to migrate
        #[allow(deprecated)]
        migrate_to_0_13_x(&mut storage, KMSType::Threshold)
            .await
            .unwrap();
        #[allow(deprecated)]
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
        assert!(storage
            .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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
        assert!(storage
            .data_exists_at_epoch(&key_id, &DEFAULT_EPOCH_ID, &data_type)
            .await
            .unwrap());
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

    // S3 storage tests
    #[cfg(feature = "s3_tests")]
    mod s3_tests {
        use super::*;
        use crate::vault::storage::s3::{build_s3_client, S3Storage, AWS_S3_ENDPOINT, BUCKET_NAME};
        use aes_prng::AesRng;
        use rand::distributions::{Alphanumeric, DistString};
        use rand::SeedableRng;
        use url::Url;

        async fn create_s3_storage() -> S3Storage {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
                .await
                .unwrap();
            let mut rng = AesRng::seed_from_u64(1964);
            let prefix = Alphanumeric.sample_string(&mut rng, 10);
            S3Storage::new(
                s3_client,
                BUCKET_NAME.to_string(),
                StorageType::PRIV,
                Some(&prefix),
                None,
            )
            .unwrap()
        }

        #[tokio::test]
        async fn test_migrate_threshold_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_legacy_fhe_keys_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_centralized_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_legacy_fhe_keys_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_skips_existing_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_legacy_fhe_keys_skips_existing(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_no_legacy_data_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_legacy_fhe_keys_no_legacy_data(&mut storage).await;
        }

        #[tokio::test]
        async fn test_migrate_idempotent_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_legacy_fhe_keys_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_threshold_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_after_0_13_x_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_centralized_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_after_0_13_x_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_no_legacy_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_after_0_13_x_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_after_0_13_x_idempotent_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_after_0_13_x_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_threshold_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_centralized_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_no_legacy_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_skips_existing_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_skips_existing(&mut storage).await;
        }

        #[tokio::test]
        async fn test_0_13_x_to_0_13_10_idempotent_s3() {
            let mut storage = create_s3_storage().await;
            test_migrate_fhe_keys_0_13_x_to_0_13_10_idempotent(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_threshold_s3() {
            let mut storage = create_s3_storage().await;
            test_remove_old_keys_for_0_13_20_threshold(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_centralized_s3() {
            let mut storage = create_s3_storage().await;
            test_remove_old_keys_for_0_13_20_centralized(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_no_legacy_s3() {
            let mut storage = create_s3_storage().await;
            test_remove_old_keys_for_0_13_20_no_legacy(&mut storage).await;
        }

        #[tokio::test]
        async fn test_remove_old_keys_skips_without_new_epoch_s3() {
            let mut storage = create_s3_storage().await;
            test_remove_old_keys_for_0_13_20_skips_without_new_epoch(&mut storage).await;
        }
    }
}
