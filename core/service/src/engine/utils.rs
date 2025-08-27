use crate::vault::storage::Storage;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::PrivDataType;
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
    storage_type_info: &str,
    preprocessing_ids: Vec<String>,
) -> Result<KeyMaterialAvailabilityResponse, Status>
where
    S: Storage + Sync + Send,
{
    // Query FHE key IDs
    let fhe_key_ids_set = priv_storage
        .all_data_ids(&PrivDataType::FheKeyInfo.to_string())
        .await
        .map_err(|e| Status::internal(format!("Failed to query FHE keys: {}", e)))?;

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
    let storage_info = format!("{} - {}", storage_type_info, priv_storage.info());

    // Build response
    Ok(KeyMaterialAvailabilityResponse {
        fhe_key_ids,
        crs_ids,
        preprocessing_ids,
        storage_info,
    })
}
