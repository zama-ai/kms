use crate::consts::DEFAULT_EPOCH_ID;
use crate::engine::base::derive_request_id;
use crate::engine::threshold::service::session::PRSSSetupCombined;
use crate::vault::storage::{
    read_versioned_at_request_id, store_versioned_at_request_id, StorageExt,
};
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use threshold_fhe::algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64};
use threshold_fhe::execution::small_execution::prss::PRSSSetup;

/// Migrate from 0.12.x to 0.13.1
/// This involves migrating FHE key material from the legacy storage format to the new epoch-aware format, and migrating the legacy PRSS setup to the new combined format.
pub async fn migrate_to_0_13_1<S>(
    storage: &mut S,
    kms_type: KMSType,
    threshold: u8,
    num_parties: usize,
) -> anyhow::Result<()>
where
    S: StorageExt + Sync + Send,
{
    migrate_fhe_keys_v0_12_to_v0_13(storage, kms_type).await?;
    if let KMSType::Threshold = kms_type {
        migrate_legacy_prss_before_0_13_1(storage, threshold, num_parties).await?;
    }
    Ok(())
}

/// Migrate from 0.13.1 to 0.14.0
/// This is disabled for now and should only be enabled in the next version
///
/// This involves removing, already migrated FHE key material in the legacy storage location.
pub async fn migrate_to_0_14_0<S>(storage: &mut S, kms_type: KMSType) -> anyhow::Result<()>
where
    S: StorageExt + Sync + Send,
{
    migrate_fhe_keys_after_0_13_1(storage, kms_type).await?;
    Ok(())
}
/// Migrate FHE key material from legacy storage format to epoch-aware format.
/// The migration should be applied to private storage created in v0.12.x,
/// after the migration the private storage format should follow v0.13.x.
/// Applying the migration on private storage format in v0.13.x will have no effect.
/// This function should be removed in 0.14.x.
///
/// In more detail, legacy format (v0.12.x) stores keys at: `<prefix>/<data_type>/<key_id>`.
/// This function checks for FhePrivateKey (centralized) or FheKeyInfo (threshold) data
/// stored in the legacy format and migrates them to the new epoch-aware format using
/// `DEFAULT_EPOCH_ID` as the default epoch ID.
///
/// # Arguments
/// * `storage` - Storage instance supporting both legacy and epoch-aware operations
/// * `kms_type` - The KMS type (Centralized or Threshold) which determines which data type to migrate
///
/// # Returns
/// * `Ok(migrated_count)` - Number of keys successfully migrated
/// * `Err(...)` - If any migration operation fails
async fn migrate_fhe_keys_v0_12_to_v0_13<S>(
    storage: &mut S,
    kms_type: KMSType,
) -> anyhow::Result<usize>
where
    S: StorageExt + Sync + Send,
{
    let data_type = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey,
        KMSType::Threshold => PrivDataType::FheKeyInfo,
    };
    let data_type_str = data_type.to_string();

    // Get the default epoch ID for migrated keys
    let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

    // Get all key IDs stored in the legacy format (directly under data_type directory)
    let legacy_key_ids = storage.all_data_ids(&data_type_str).await?;

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
        if storage
            .data_exists_at_epoch(&key_id, &default_epoch_id, &data_type_str)
            .await?
        {
            tracing::info!(
                "Key {} already exists at epoch {}, skipping migration",
                key_id,
                default_epoch_id
            );
            continue;
        }

        // Read the data from the legacy location as raw bytes
        // We read raw bytes to avoid type-specific deserialization issues
        let data: Vec<u8> = storage.load_bytes(&key_id, &data_type_str).await?;

        // Store the data at the new epoch-aware location
        storage
            .store_bytes_at_epoch(&data, &key_id, &default_epoch_id, &data_type_str)
            .await?;

        tracing::info!(
            "Migrated key {} from legacy format to epoch {}",
            key_id,
            default_epoch_id
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
async fn migrate_fhe_keys_after_0_13_1<S>(storage: &mut S, kms_type: KMSType) -> anyhow::Result<()>
where
    S: StorageExt + Sync + Send,
{
    let data_type = match kms_type {
        KMSType::Centralized => PrivDataType::FhePrivateKey,
        KMSType::Threshold => PrivDataType::FheKeyInfo,
    };
    let data_type_str = data_type.to_string();
    // Get the default epoch ID for migrated keys
    let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
    let legacy_key_ids = storage.all_data_ids(&data_type_str).await?;

    for key_id in legacy_key_ids {
        // Check the converted key indeed exists before removing anything
        if storage
            .data_exists_at_epoch(&key_id, &default_epoch_id, &data_type_str)
            .await?
        {
            // Removes obsolete keys that have already been converted
            storage.delete_data(&key_id, &data_type_str).await?;
        } else {
            tracing::error!("Legacy key {} still exists but no migrated key found at epoch {}, skipping deletion", key_id, default_epoch_id);
        }
    }
    Ok(())
}

/// This will try to load the legacy PRSS setup [`PRSSSetup`] from storage
/// by using the default value for the epoch ID.
/// It then converts the old PRSSSetup data into the new PRSSSetupCombined format and stores it back in storage under the new epoch-aware path.
#[expect(deprecated)]
async fn migrate_legacy_prss_before_0_13_1<S>(
    storage: &mut S,
    threshold: u8,
    num_parties: usize,
) -> anyhow::Result<()>
where
    S: StorageExt + Sync + Send,
{
    // TODO(zama-ai/kms-internal#2530) set the correct context ID here.
    let epoch_id = *DEFAULT_EPOCH_ID;
    // Check if this key already exists in the new epoch-aware format
    if storage
        .data_exists(
            &epoch_id.into(),
            &PrivDataType::PrssSetupCombined.to_string(),
        )
        .await?
    {
        tracing::info!(
            "PRSS Setup for epoch {} already exists and has been migrated, skipping migration",
            epoch_id
        );
        return Ok(());
    }
    let prss_128_legacy_id = derive_request_id(&format!(
        "PRSSSetup_Z128_ID_{}_{}_{}",
        epoch_id, num_parties, threshold,
    ))?;
    let prss_64_legacy_id = derive_request_id(&format!(
        "PRSSSetup_Z64_ID_{}_{}_{}",
        epoch_id, num_parties, threshold,
    ))?;
    let prss_from_storage = {
        let prss_128 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z128>>(
            storage,
            &prss_128_legacy_id,
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .inspect_err(|e| {
            tracing::warn!("failed to read legacy PRSS Z128 from file with error: {e}");
        });
        let prss_64 = read_versioned_at_request_id::<_, PRSSSetup<ResiduePolyF4Z64>>(
            storage,
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
                storage,
                &(epoch_id).into(),
                &new_prss,
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await?;

            // Delete the old prss! Note that this is safe since they can always be regenerated very quickly without any change beyond the KMS
            storage
                .delete_data(&prss_128_legacy_id, &PrivDataType::PrssSetup.to_string())
                .await?;
            storage
                .delete_data(&prss_64_legacy_id, &PrivDataType::PrssSetup.to_string())
                .await?;
        }
        (Err(e), Ok(_)) => return Err(e),
        (Ok(_), Err(e)) => return Err(e),
        (Err(_e), Err(e)) => return Err(e),
    }

    tracing::info!(
        "Successfully converted legacy PRSS Setup from storage for epoch ID {}.",
        epoch_id
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use kms_grpc::RequestId;
    use std::str::FromStr;

    use super::*;
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::ram::{self, RamStorage};
    use crate::vault::storage::{
        store_versioned_at_request_id, StorageExt, StorageReader, StorageType,
    };

    /// Test migration of threshold FHE keys (FheKeyInfo)
    pub async fn test_migrate_legacy_fhe_keys_threshold<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        // Store some legacy data (directly under data_type without epoch)
        // Note: key IDs must not collide with DEFAULT_EPOCH_ID (0...01) to avoid path conflicts
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

        // Verify data exists at the new epoch location
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
        assert!(storage
            .data_exists_at_epoch(&key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap());
        assert!(storage
            .data_exists_at_epoch(&key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap());

        // Verify the data content is preserved
        let migrated_data_1 = storage
            .load_bytes_at_epoch(&key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap();
        let migrated_data_2 = storage
            .load_bytes_at_epoch(&key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(migrated_data_1, legacy_data_1);
        assert_eq!(migrated_data_2, legacy_data_2);
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
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
        assert!(storage
            .data_exists_at_epoch(&key_id, &default_epoch_id, &data_type)
            .await
            .unwrap());

        // Verify the data content is preserved
        let migrated_data = storage
            .load_bytes_at_epoch(&key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(migrated_data, legacy_data);
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
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

        let legacy_data = vec![1, 2, 3];
        let existing_epoch_data = vec![4, 5, 6];

        // Store legacy data
        storage
            .store_bytes(&legacy_data, &key_id, &data_type)
            .await
            .unwrap();

        // Also store at the target epoch (simulating already migrated or new data)
        storage
            .store_bytes_at_epoch(&existing_epoch_data, &key_id, &default_epoch_id, &data_type)
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

        // Epoch data should be unchanged (the existing data, not the legacy data)
        let epoch_data = storage
            .load_bytes_at_epoch(&key_id, &default_epoch_id, &data_type)
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
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;
        let epoch_data = storage
            .load_bytes_at_epoch(&key_id, &default_epoch_id, &data_type)
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
    async fn write_legacy_empty_prss_to_storage(private_storage: &mut ram::RamStorage) {
        let epoch_id = *DEFAULT_EPOCH_ID;
        let num_parties = 4;
        let threshold = 1u8;

        let prss_setup_obj_z128 = PRSSSetup::<ResiduePolyF4Z128>::new_testing_prss(vec![], vec![]);
        let prss_setup_obj_z64 = PRSSSetup::<ResiduePolyF4Z64>::new_testing_prss(vec![], vec![]);

        // serialize and write PRSS Setup to storage into private storage
        store_versioned_at_request_id(
            private_storage,
            &derive_request_id(&format!(
                "PRSSSetup_Z128_ID_{}_{}_{}",
                epoch_id, num_parties, threshold,
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
                epoch_id, num_parties, threshold,
            ))
            .unwrap(),
            &prss_setup_obj_z64,
            #[expect(deprecated)]
            &PrivDataType::PrssSetup.to_string(),
        )
        .await
        .unwrap();
    }

    // ── Tests for migrate_fhe_keys_after_0_13_1 ──

    /// Test that legacy keys with epoch counterparts are deleted (threshold)
    pub async fn test_migrate_fhe_keys_after_0_13_1_threshold<S: StorageExt + Sync + Send>(
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
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

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
            .store_bytes_at_epoch(&legacy_data_1, &key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&legacy_data_2, &key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap();

        // Run the cleanup migration
        migrate_fhe_keys_after_0_13_1(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Legacy data should be deleted
        assert!(!storage.data_exists(&key_id_1, &data_type).await.unwrap());
        assert!(!storage.data_exists(&key_id_2, &data_type).await.unwrap());

        // Epoch data should still exist and be unchanged
        let loaded_1 = storage
            .load_bytes_at_epoch(&key_id_1, &default_epoch_id, &data_type)
            .await
            .unwrap();
        let loaded_2 = storage
            .load_bytes_at_epoch(&key_id_2, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded_1, legacy_data_1);
        assert_eq!(loaded_2, legacy_data_2);
    }

    /// Test that legacy keys with epoch counterparts are deleted (centralized)
    pub async fn test_migrate_fhe_keys_after_0_13_1_centralized<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000042",
        )
        .unwrap();
        let data_type = PrivDataType::FhePrivateKey.to_string();
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

        let data = vec![42, 43, 44, 45];

        storage
            .store_bytes(&data, &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&data, &key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();

        migrate_fhe_keys_after_0_13_1(storage, KMSType::Centralized)
            .await
            .unwrap();

        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());
        assert!(storage
            .data_exists_at_epoch(&key_id, &default_epoch_id, &data_type)
            .await
            .unwrap());
    }

    /// Test with no legacy keys at all
    pub async fn test_migrate_fhe_keys_after_0_13_1_no_legacy<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        migrate_fhe_keys_after_0_13_1(storage, KMSType::Threshold)
            .await
            .unwrap();
    }

    /// Test idempotency of the cleanup migration
    pub async fn test_migrate_fhe_keys_after_0_13_1_idempotent<S: StorageExt + Sync + Send>(
        storage: &mut S,
    ) {
        let key_id = RequestId::from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000077",
        )
        .unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();
        let default_epoch_id: EpochId = *DEFAULT_EPOCH_ID;

        storage
            .store_bytes(&[7, 7, 7], &key_id, &data_type)
            .await
            .unwrap();
        storage
            .store_bytes_at_epoch(&[7, 7, 7], &key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();

        // First run deletes legacy
        migrate_fhe_keys_after_0_13_1(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());

        // Second run is a no-op (no legacy keys left)
        migrate_fhe_keys_after_0_13_1(storage, KMSType::Threshold)
            .await
            .unwrap();

        // Epoch data still intact
        let loaded = storage
            .load_bytes_at_epoch(&key_id, &default_epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(loaded, vec![7, 7, 7]);
    }

    // RAM storage tests — migrate_fhe_keys_after_0_13_1
    #[tokio::test]
    async fn test_after_0_13_1_threshold_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_1_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_centralized_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_1_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_no_legacy_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_1_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_idempotent_ram() {
        let mut storage = RamStorage::new();
        test_migrate_fhe_keys_after_0_13_1_idempotent(&mut storage).await;
    }

    // File storage tests — migrate_fhe_keys_after_0_13_1
    #[tokio::test]
    async fn test_after_0_13_1_threshold_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_1_threshold(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_centralized_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_1_centralized(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_no_legacy_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_1_no_legacy(&mut storage).await;
    }

    #[tokio::test]
    async fn test_after_0_13_1_idempotent_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut storage = FileStorage::new(Some(temp_dir.path()), StorageType::PRIV, None).unwrap();
        test_migrate_fhe_keys_after_0_13_1_idempotent(&mut storage).await;
    }

    // ── Tests for migrate_legacy_prss_before_0_13_1 ──

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_prss_sunshine() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;

        write_legacy_empty_prss_to_storage(&mut storage).await;

        migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties)
            .await
            .unwrap();

        // Verify PrssSetupCombined was created
        let epoch_id = *DEFAULT_EPOCH_ID;
        assert!(storage
            .data_exists(
                &epoch_id.into(),
                &PrivDataType::PrssSetupCombined.to_string(),
            )
            .await
            .unwrap());

        // Verify legacy PRSS data was deleted
        let prss_128_id = derive_request_id(&format!(
            "PRSSSetup_Z128_ID_{}_{}_{}",
            epoch_id, num_parties, threshold,
        ))
        .unwrap();
        let prss_64_id = derive_request_id(&format!(
            "PRSSSetup_Z64_ID_{}_{}_{}",
            epoch_id, num_parties, threshold,
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
            &epoch_id.into(),
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

        write_legacy_empty_prss_to_storage(&mut storage).await;

        // First migration
        migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties)
            .await
            .unwrap();

        // Write fresh legacy data again
        write_legacy_empty_prss_to_storage(&mut storage).await;

        // Second migration should skip (PrssSetupCombined already exists)
        migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties)
            .await
            .unwrap();

        // PrssSetupCombined should still exist
        let epoch_id = *DEFAULT_EPOCH_ID;
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
    async fn test_migrate_prss_no_legacy_data_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;

        let result = migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_prss_missing_z64_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        let epoch_id = *DEFAULT_EPOCH_ID;

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

        let result = migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    #[expect(deprecated)]
    async fn test_migrate_prss_missing_z128_errors() {
        let mut storage = RamStorage::new();
        let num_parties = 4;
        let threshold = 1u8;
        let epoch_id = *DEFAULT_EPOCH_ID;

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

        let result = migrate_legacy_prss_before_0_13_1(&mut storage, threshold, num_parties).await;
        assert!(result.is_err());
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
    }
}
