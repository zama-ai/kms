use crate::vault::storage::Storage;
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

/// MetricedError wraps an internal error with additional context for metrics and logging.
/// The struct is used to ensure that appropriate metrics are incremented and errors are logged
/// consistently across different operations.
/// # Fields
/// * `op_metric` - The operation metric name associated with the error
/// * `request_id` - Optional RequestId associated with the error
/// * `internal_error` - The internal error being wrapped
/// * `error_code` - The tonic::Code representing the gRPC error code
#[derive(Debug)]
pub struct MetricedError {
    op_metric: &'static str,
    request_id: Option<RequestId>,
    // Currently we do not return the internal error to the client
    #[expect(unused)]
    internal_error: Box<dyn std::error::Error + Send + Sync>,
    error_code: tonic::Code,
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

impl From<MetricedError> for Status {
    fn from(metriced_error: MetricedError) -> Self {
        // Increment the method specific metric
        METRICS.increment_error_counter(
            metriced_error.op_metric,
            map_tonic_code_to_metric_err_tag(metriced_error.error_code),
        );

        let error_string = top_1k_chars(format!(
            "Failed on requestID {} with metric {}",
            metriced_error.request_id.unwrap_or_default(),
            metriced_error.op_metric,
        ));

        tonic::Status::new(metriced_error.error_code, error_string)
    }
}
