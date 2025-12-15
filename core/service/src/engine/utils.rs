use crate::vault::storage::Storage;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use kms_grpc::utils::tonic_result::top_1k_chars;
use kms_grpc::RequestId;
use observability::metrics::METRICS;
use observability::metrics_names::{map_scope_to_metric_err_tag, map_tonic_code_to_metric_err_tag};
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
    S: Storage + Sync + Send,
{
    // Query FHE key IDs
    let fhe_key_ids_set = match kms_type {
        KMSType::Centralized => priv_storage
            .all_data_ids(&PrivDataType::FhePrivateKey.to_string())
            .await
            .map_err(|e| Status::internal(format!("Failed to query central FHE keys: {}", e)))?,
        KMSType::Threshold => priv_storage
            .all_data_ids(&PrivDataType::FheKeyInfo.to_string())
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

#[derive(Debug)]
pub struct MetricedError {
    scope: &'static str,
    request_id: Option<RequestId>,
    // Currently we do not return the internal error to the client
    #[allow(unused)]
    internal_error: Box<dyn std::error::Error + Send + Sync>,
    error_code: tonic::Code,
}

impl MetricedError {
    pub fn new<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        metric_scope: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
        error_code: tonic::Code,
    ) -> Self {
        let error = Self::error_handler(metric_scope, request_id, internal_error);
        // Increment the error code metric
        METRICS.increment_error_counter(metric_scope, map_tonic_code_to_metric_err_tag(error_code));

        Self {
            scope: metric_scope,
            request_id,
            internal_error: error,
            error_code,
        }
    }

    pub fn code(&self) -> tonic::Code {
        self.error_code
    }

    pub fn error_handler<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        metric_scope: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
    ) -> Box<dyn std::error::Error + Send + Sync> {
        let error = internal_error.into(); // converts anyhow::Error or any other error
        let error_string = format!(
            "Failure on requestID {} with metric {}. Error: {}",
            request_id.unwrap_or_default(),
            metric_scope,
            error
        );

        tracing::error!(
            error = ?error,
            request_id = ?request_id,
            error_string,
        );

        // Increment the method specific metric
        METRICS.increment_error_counter(metric_scope, map_scope_to_metric_err_tag(metric_scope));
        error
    }
}

impl From<MetricedError> for Status {
    fn from(metriced_error: MetricedError) -> Self {
        let error_string = top_1k_chars(format!(
            "Failed on requestID {} with metric {}",
            metriced_error.request_id.unwrap_or_default(),
            metriced_error.scope,
        ));

        tonic::Status::new(metriced_error.error_code, error_string)
    }
}
