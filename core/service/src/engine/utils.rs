use crate::consts::DEFAULT_EPOCH_ID;
use crate::vault::storage::StorageExt;
use kms_grpc::identifiers::EpochId;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use kms_grpc::utils::tonic_result::top_1k_chars;
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{map_tonic_code_to_metric_err_tag, ERR_ASYNC};
use tonic::Status;

/// Query key material availability from private storage
///
/// This shared utility function queries FHE keys, CRS keys, and optionally preprocessing keys
/// from the given storage instance and returns a formatted response.
///
/// # Arguments
/// * `priv_storage` - Private storage instance to query FHE and CRS keys from
/// * `storage_type_info` - String describing the KMS type (e.g. "Centralized KMS" or "Threshold KMS")
/// * `preprocessing_ids` - Optional vector of preprocessing IDs (for threshold KMS with metastore)
pub async fn query_key_material_availability<S>(
    priv_storage: &S,
    kms_type: KMSType,
    preprocessing_ids: Vec<String>,
) -> Result<KeyMaterialAvailabilityResponse, Status>
where
    S: StorageExt + Sync + Send,
{
    // Query FHE key IDs
    let fhe_key_ids_set = match kms_type {
        KMSType::Centralized => priv_storage
            .all_data_ids_from_all_epochs(&PrivDataType::FhePrivateKey.to_string())
            .await
            .map_err(|e| Status::internal(format!("Failed to query central FHE keys: {}", e)))?,
        KMSType::Threshold => priv_storage
            .all_data_ids_from_all_epochs(&PrivDataType::FheKeyInfo.to_string())
            .await
            .map_err(|e| Status::internal(format!("Failed to query threshold FHE keys: {}", e)))?,
    };

    // Query CRS IDs
    let crs_ids_set = priv_storage
        .all_data_ids(&PrivDataType::CrsInfo.to_string())
        .await
        .map_err(|e| Status::internal(format!("Failed to query CRS: {}", e)))?;

    // Convert HashSet<RequestId> to Vec<String>
    let fhe_key_ids: Vec<String> = fhe_key_ids_set
        .into_iter()
        .map(|id| id.to_string())
        .collect();

    let crs_ids: Vec<String> = crs_ids_set.into_iter().map(|id| id.to_string()).collect();

    // Get storage info - combine type info with backend info
    let storage_info = format!("{} - {}", kms_type, priv_storage.info());

    // Build response
    Ok(KeyMaterialAvailabilityResponse {
        fhe_key_ids,
        crs_ids,
        preprocessing_ids,
        storage_info,
    })
}

/// MetricedError wraps an internal error with additional context for metrics and logging.
/// The struct is used to ensure that appropriate metrics are incremented and errors are logged
/// consistently across different operations.
/// * `op_metric` - The operation metric name associated with the error
/// * `request_id` - Optional RequestId associated with the error
/// * `internal_error` - The internal error being wrapped
/// * `error_code` - The tonic::Code representing the gRPC error code
/// * `counted` - A boolean flag indicating whether the error has already been counted in metrics
#[derive(Debug)]
pub struct MetricedError {
    op_metric: &'static str,
    request_id: Option<RequestId>,
    // Currently we do not return the internal error to the client
    #[expect(unused)]
    internal_error: Box<dyn std::error::Error + Send + Sync>,
    error_code: tonic::Code,
    counted: bool,
}

impl MetricedError {
    /// Create a new MetricedError, logging the error and incrementing metrics if it gets converted into a tonic error using the `From` trait.
    /// # Arguments
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being wrapped
    /// * `error_code` - The tonic::Code representing the gRPC error code
    pub fn new<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        op_metric: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
        error_code: tonic::Code,
    ) -> Self {
        let error = internal_error.into(); // converts anyhow::Error or any other error
        let error_string = format!(
            "Grpc failure on requestID {} with metric {}. Error: {}",
            request_id.unwrap_or_default(),
            op_metric,
            error
        );

        tracing::error!(
            error = ?error,
            request_id = ?request_id,
            "Grpc error {error_string}",
        );

        Self {
            op_metric,
            request_id,
            internal_error: error,
            error_code,
            counted: false,
        }
    }

    /// Return the gRPC error code associated with this MetricedError without incrementing the metrics.
    #[cfg(feature = "testing")]
    pub fn code(&self) -> tonic::Code {
        self.error_code
    }

    /// Helper function to log the error and increment metrics in places where no error return is possible.
    /// More specifically this is to be utilized in the async execution of KMS service commands where errors cannot be returned.
    ///
    /// Arguments:
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being handled
    ///   Returns:
    /// * Box<dyn std::error::Error + Send + Sync> - The boxed internal error after logging and metric incrementing
    pub fn handle_unreturnable_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        op_metric: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        let error = internal_error.into(); // converts anyhow::Error or any other error
        let error_string = format!(
            "Async failure on requestID {} with metric {}. Error: {}",
            request_id.unwrap_or_default(),
            op_metric,
            error
        );

        tracing::error!(
            error = ?error,
            request_id = ?request_id,
            "Async error {error_string}",
        );

        // Increment the method specific metric
        METRICS.increment_error_counter(op_metric, ERR_ASYNC);
        error
    }
}

impl Drop for MetricedError {
    fn drop(&mut self) {
        if !self.counted {
            // Increment the method specific metric
            METRICS.increment_error_counter(
                self.op_metric,
                map_tonic_code_to_metric_err_tag(self.error_code),
            );
        }
    }
}

impl From<MetricedError> for Status {
    fn from(mut metriced_error: MetricedError) -> Self {
        // Increment the method specific metric
        METRICS.increment_error_counter(
            metriced_error.op_metric,
            map_tonic_code_to_metric_err_tag(metriced_error.error_code),
        );
        metriced_error.counted = true;

        let error_string = top_1k_chars(format!(
            "Failed on requestID {} with metric {}",
            metriced_error.request_id.unwrap_or_default(),
            metriced_error.op_metric,
        ));

        tonic::Status::new(metriced_error.error_code, error_string)
    }
}

/// Migrate FHE key material from legacy storage format to epoch-aware format.
///
/// Legacy format stores keys at: `<prefix>/<data_type>/<key_id>`
///
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
pub async fn migrate_legacy_fhe_keys<S>(storage: &mut S, kms_type: KMSType) -> anyhow::Result<usize>
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

        // Delete the data from the legacy location
        storage.delete_data(&key_id, &data_type_str).await?;

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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::vault::storage::file::FileStorage;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::{StorageExt, StorageType};

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
        let migrated_count = migrate_legacy_fhe_keys(storage, KMSType::Threshold)
            .await
            .unwrap();

        assert_eq!(migrated_count, 2);

        // Verify legacy data is removed
        assert!(!storage.data_exists(&key_id_1, &data_type).await.unwrap());
        assert!(!storage.data_exists(&key_id_2, &data_type).await.unwrap());

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
        let migrated_count = migrate_legacy_fhe_keys(storage, KMSType::Centralized)
            .await
            .unwrap();

        assert_eq!(migrated_count, 1);

        // Verify legacy data is removed
        assert!(!storage.data_exists(&key_id, &data_type).await.unwrap());

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
        let migrated_count = migrate_legacy_fhe_keys(storage, KMSType::Threshold)
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
        let migrated_count = migrate_legacy_fhe_keys(storage, KMSType::Threshold)
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
        let migrated_count_1 = migrate_legacy_fhe_keys(storage, KMSType::Threshold)
            .await
            .unwrap();
        assert_eq!(migrated_count_1, 1);

        // Second migration should do nothing (data already migrated, legacy deleted)
        let migrated_count_2 = migrate_legacy_fhe_keys(storage, KMSType::Threshold)
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

    // S3 storage tests
    #[cfg(feature = "s3_tests")]
    mod s3_tests {
        use super::*;
        use crate::vault::storage::s3::{build_s3_client, S3Storage, AWS_S3_ENDPOINT, BUCKET_NAME};
        use aes_prng::AesRng;
        use rand::distributions::{Alphanumeric, DistString};
        use url::Url;

        async fn create_s3_storage() -> S3Storage {
            let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            let s3_client = build_s3_client(&config, Some(Url::parse(AWS_S3_ENDPOINT).unwrap()))
                .await
                .unwrap();
            let mut rng = AesRng::from_random_seed();
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
