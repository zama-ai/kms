use crate::vault::storage::StorageExt;
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
///
/// In case a MetricedError is dropped without being converted into a tonic::Status,
/// the Drop implementation will increment the appropriate error metric and log an error message.
///
/// # Fields
/// * `op_metric` - The operation metric name associated with the error
/// * `request_id` - Optional RequestId associated with the error
/// * `internal_error` - The internal error being handled
/// * `error_code` - The tonic::Code representing the gRPC error code
/// * `returned` - A boolean flag indicating whether the error has already been counted in metrics
#[derive(Debug)]
pub struct MetricedError {
    op_metric: &'static str,
    request_id: Option<RequestId>,
    internal_error: Box<dyn std::error::Error + Send + Sync>,
    error_code: tonic::Code,
    returned: bool,
}

impl MetricedError {
    /// Create a new MetricedError wrapping the given MetricedError and gRPC error code.
    ///
    /// # Arguments
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being handled
    /// * `error_code` - The tonic::Code representing the gRPC error code
    pub fn new<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        op_metric: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
        error_code: tonic::Code,
    ) -> Self {
        Self {
            op_metric,
            request_id,
            internal_error: internal_error.into(),
            error_code,
            returned: false,
        }
    }

    /// Return the gRPC error code associated with this MetricedError without incrementing the metrics.
    #[cfg(feature = "testing")]
    pub fn code(&self) -> tonic::Code {
        self.error_code
    }

    /// Handles an error that cannot be returned through gRPC by logging the error and incrementing metrics.
    /// This is _not_ indempotent and should only be called once per error.
    ///
    /// # Arguments
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being wrapped
    pub fn handle_unreturnable_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        op_metric: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
    ) {
        let error = internal_error.into(); // converts anyhow::Error or any other error
        let error_string = format!(
            "Failure on requestID {:?} with metric {}. Error: {}",
            request_id.unwrap_or_default(),
            op_metric,
            error
        );

        tracing::error!(error_string);

        // Increment the method specific metric
        METRICS.increment_error_counter(op_metric, ERR_ASYNC);
    }

    fn handle_error(&mut self) {
        // Ensure that we only handle the error once
        if !self.returned {
            self.returned = true;
            // Increment the method specific metric
            METRICS.increment_error_counter(
                self.op_metric,
                map_tonic_code_to_metric_err_tag(self.error_code),
            );
            let error_string = format!(
                "Grpc failure on requestID {} with metric {} and error code {}. Error message: {}",
                self.request_id.unwrap_or_default(),
                self.op_metric,
                self.error_code,
                self.internal_error
            );

            tracing::error!(error_string);
        }
    }
}

impl Drop for MetricedError {
    fn drop(&mut self) {
        if !self.returned {
            self.handle_error();
            // Print an error since a returnable error was dropped without being returned
            tracing::error!(
                "MetricedError for requestID {} with metric {} for error {} was dropped without being returned.",
                self.request_id.unwrap_or_default(),
                self.op_metric,
                self.error_code
            );
        }
    }
}

impl From<MetricedError> for Status {
    fn from(mut metriced_error: MetricedError) -> Self {
        metriced_error.handle_error();
        let error_string = top_1k_chars(format!(
            "Failed on requestID {} with metric {}",
            metriced_error.request_id.unwrap_or_default(),
            metriced_error.op_metric,
        ));
        tonic::Status::new(metriced_error.error_code, error_string)
    }
}
// Add tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[tracing_test::traced_test]
    fn test_metriced_error_creation() {
        let error = MetricedError::new(
            "test_op",
            Some(RequestId::zeros()),
            anyhow::anyhow!("test error"),
            tonic::Code::Internal,
        );
        assert_eq!(error.code(), tonic::Code::Internal);

        let status: Status = error.into();
        assert!(status.message().contains("test_op"));
        assert!(!status.message().contains("test error"));
        logs_contain("test error");
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_metriced_error_drop_logging() {
        let error = MetricedError::new(
            "test_op_drop",
            Some(RequestId::zeros()),
            anyhow::anyhow!("dropped error"),
            tonic::Code::Internal,
        );
        drop(error);
        // Check that the log contains the error message about being dropped without being returned
        assert!(logs_contain("dropped without being returned"));
        // Check that the error is indeed logged
        assert!(logs_contain("Grpc failure on requestID"));
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_metriced_error_no_dropping() {
        let error = MetricedError::new(
            "test_no_drop",
            Some(RequestId::zeros()),
            anyhow::anyhow!("dropped error"),
            tonic::Code::Internal,
        );
        let _status: Status = error.into();
        // Check that the log does NOT contains the error message about being dropped without being returned
        assert!(!logs_contain("dropped without being returned"));
        // Check that the error is indeed logged
        assert!(logs_contain("Grpc failure on requestID"));
    }
}
