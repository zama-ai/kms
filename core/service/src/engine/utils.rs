use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::vault::storage::StorageExt;
use aws_smithy_types::base64;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::{KMSType, PrivDataType};
use kms_grpc::utils::tonic_result::top_1k_chars;
use kms_grpc::{ContextId, EpochId, RequestId};
use observability::metrics::METRICS;
use observability::metrics_names::{
    ERR_ASYNC, OP_KEY_MATERIAL_AVAILABILITY, OP_PUBLIC_DECRYPT_REQUEST, OP_PUBLIC_DECRYPT_RESULT,
    OP_USER_DECRYPT_REQUEST, OP_USER_DECRYPT_RESULT, map_tonic_code_to_metric_err_tag,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt::Display;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tonic::Status;

/// Query key material availability from private storage
///
/// This shared utility function queries FHE keys, CRS keys, and optionally preprocessing keys
/// from the given storage instance and returns a formatted response.
///
/// # Arguments
/// * `priv_storage` - Private storage instance to query FHE and CRS keys from
/// * `kms_type` - The KMS type (centralized or threshold)
/// * `preprocessing_ids` - Vector of preprocessing IDs, may be empty (used for threshold KMS with metastore)
pub async fn query_key_material_availability<S>(
    priv_storage: &S,
    kms_type: KMSType,
    preprocessing_ids: Vec<String>,
) -> Result<KeyMaterialAvailabilityResponse, MetricedError>
where
    S: StorageExt + Sync + Send,
{
    // Query FHE key IDs
    let fhe_key_ids_set = match kms_type {
        KMSType::Centralized => priv_storage
            .all_data_ids_from_all_epochs(&PrivDataType::FhePrivateKey.to_string())
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_KEY_MATERIAL_AVAILABILITY,
                    None,
                    anyhow::anyhow!("Failed to query centralized FHE keys: {}", e),
                    tonic::Code::Internal,
                )
            })?,
        KMSType::Threshold => priv_storage
            .all_data_ids_from_all_epochs(&PrivDataType::FheKeyInfo.to_string())
            .await
            .map_err(|e| {
                MetricedError::new(
                    OP_KEY_MATERIAL_AVAILABILITY,
                    None,
                    anyhow::anyhow!("Failed to query threshold FHE keys: {}", e),
                    tonic::Code::Internal,
                )
            })?,
    };

    // Query CRS IDs
    let crs_ids_set = priv_storage
        .all_data_ids(&PrivDataType::CrsInfo.to_string())
        .await
        .map_err(|e| {
            MetricedError::new(
                OP_KEY_MATERIAL_AVAILABILITY,
                None,
                anyhow::anyhow!("Failed to query CRS: {}", e),
                tonic::Code::Internal,
            )
        })?;

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

/// Highest `extra_data` version understood by [`make_extra_data`].
/// Must stay in sync with `sanity_check_extra_data` in `engine::utils`.
pub const MAX_EXTRA_DATA_VERSION: u8 = 2;

/// Build an `extra_data` payload for a gRPC request, matching the format the KMS core expects
/// (see `sanity_check_extra_data` in `engine::utils`). Layout:
/// - byte 0: version
/// - v0: no extra bytes
/// - v1: 32 bytes of context_id
/// - v2: 32 bytes of context_id followed by 32 bytes of epoch_id
///
/// Errors when `version` is above [`MAX_EXTRA_DATA_VERSION`], when v1 is requested without a
/// `context_id`, or when v2 is requested without both a `context_id` and an `epoch_id`.
///
/// NOTE: This method should only be used in testing and CLIs. The KMS should always read `extra_data` verbatim from a request
/// in order to ensure forward compatibility with the contracts. This method is only for convenience to construct `extra_data`
/// in the expected format for tests and CLIs.
pub fn make_extra_data(
    version: u8,
    context_id: Option<&ContextId>,
    epoch_id: Option<&EpochId>,
) -> anyhow::Result<Vec<u8>> {
    let mut extra_data = vec![version];
    match version {
        0 => {
            // no extra data
        }
        1 => {
            let ctx = context_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 1 requires a context_id")
            })?;
            extra_data.extend_from_slice(ctx.as_bytes());
        }
        2 => {
            let ctx = context_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 2 requires a context_id")
            })?;
            let ep = epoch_id.ok_or_else(|| {
                anyhow::anyhow!("make_extra_data: version 2 requires an epoch_id")
            })?;
            extra_data.extend_from_slice(ctx.as_bytes());
            extra_data.extend_from_slice(ep.as_bytes());
        }
        _ => {
            return Err(anyhow::anyhow!(
                "make_extra_data: unknown version {version}, highest supported is {MAX_EXTRA_DATA_VERSION}"
            ));
        }
    }
    Ok(extra_data)
}

/// Helper method to sanity check the content of the extra data field.
///
/// This method will never fail, but only print a warning if the content is not as expected.
/// This is to ensure forward compatibility in case of the structure change on the sdk side.
pub fn sanity_check_extra_data(extra_data: &[u8], epoch_id: &EpochId, context_id: &ContextId) {
    if let Some(warning) = sanity_check_extra_data_helper(extra_data, epoch_id, context_id) {
        tracing::warn!("{}", warning);
    }
}

/// Helper method to return an Option<String> containing a warning message if the extra data is not in the expected format.
/// WARNING: As per design the KMS is supposed to be agnostic to the extra_data content for forward
/// compatibility reasons. Hence malformed extra_data will not cause a failure but only a warning logs.
fn sanity_check_extra_data_helper(
    extra_data: &[u8],
    epoch_id: &EpochId,
    context_id: &ContextId,
) -> Option<String> {
    if extra_data.is_empty() {
        // Empty input is allowed and treated as version 0 (no extra data)
        return None;
    }
    let version = extra_data[0];
    match version {
        0 => {
            if extra_data.len() != 1 {
                return Some(format!(
                    "Unexpected extra data length for version 0: {}, expected 1 byte for version",
                    extra_data.len()
                ));
            }
        }
        1 => {
            if extra_data.len() != 1 + 32 {
                return Some(format!(
                    "Unexpected extra data length for version 1: {}, expected 33 bytes (1 byte for version and 32 bytes for context ID)",
                    extra_data.len()
                ));
            }
            if &extra_data[1..33] != context_id.as_bytes() {
                return Some(format!(
                    "Context ID in extra data does not match expected context ID. \
                         Got {}, expected {}",
                    hex::encode(&extra_data[1..33]),
                    context_id
                ));
            }
        }
        2 => {
            if extra_data.len() != 1 + 32 + 32 {
                return Some(format!(
                    "Unexpected extra data length for version 2: {}, expected 65 bytes (1 byte for version and 32 bytes for context ID and 32 bytes for epoch ID)",
                    extra_data.len()
                ));
            }
            if &extra_data[1..33] != context_id.as_bytes() {
                return Some(format!(
                    "Context ID in extra data does not match expected context ID. \
                         Got {}, expected {}",
                    hex::encode(&extra_data[1..33]),
                    context_id
                ));
            }
            if &extra_data[33..65] != epoch_id.as_bytes() {
                return Some(format!(
                    "Epoch ID in extra data does not match expected epoch ID. \
                         Got {}, expected {}",
                    hex::encode(&extra_data[33..65]),
                    epoch_id
                ));
            }
        }
        _ => {
            return Some(format!(
                "Unknown extra data version: {}. Highest version understood is {MAX_EXTRA_DATA_VERSION}",
                version
            ));
        }
    }
    None
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
    internal_error: Box<dyn std::error::Error + Send + Sync + 'static>,
    error_code: tonic::Code,
    returned: bool,
}

fn is_expected_grpc_outcome(operation: &str, code: tonic::Code) -> bool {
    match operation {
        OP_PUBLIC_DECRYPT_RESULT | OP_USER_DECRYPT_RESULT => {
            code == tonic::Code::Unavailable || code == tonic::Code::NotFound
        }
        OP_PUBLIC_DECRYPT_REQUEST | OP_USER_DECRYPT_REQUEST => {
            code == tonic::Code::AlreadyExists || code == tonic::Code::ResourceExhausted
        }
        _ => false,
    }
}

impl MetricedError {
    /// Create a new MetricedError wrapping the given MetricedError and gRPC error code.
    ///
    /// # Arguments
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being handled
    /// * `error_code` - The tonic::Code representing the gRPC error code
    pub fn new<E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>>(
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
    pub fn code(&self) -> tonic::Code {
        self.error_code
    }

    /// Consume an error that the caller expected and has already accounted for, without recording
    /// it.
    pub(crate) fn defuse(mut self) {
        self.returned = true;
    }

    pub fn internal_err(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.internal_error
    }

    /// Handles an error that cannot be returned through gRPC by logging the error and incrementing metrics.
    /// This is _not_ idempotent and should only be called once per error.
    ///
    /// **RESTRICTED USAGE**: This function should only be used by `crate::util::meta_store` module.
    /// It is made crate-private to prevent misuse in other parts of the codebase.
    ///
    /// # Arguments
    /// * `op_metric` - The operation metric name associated with the error
    /// * `request_id` - Optional RequestId associated with the error
    /// * `internal_error` - The internal error being wrapped
    pub(crate) fn handle_unreturnable_error<E: Into<Box<dyn std::error::Error + Send + Sync>>>(
        op_metric: &'static str,
        request_id: Option<RequestId>,
        internal_error: E,
    ) {
        let error = internal_error.into(); // converts anyhow::Error or any other error
        tracing::error!(
            request_id = %request_id.unwrap_or_default(),
            operation = op_metric,
            error = %error,
            "asynchronous request failed"
        );

        // Increment the method specific metric
        METRICS.increment_error_counter(op_metric, ERR_ASYNC);
    }

    fn handle_error(&mut self) {
        // Ensure that we only handle the error once
        if !self.returned {
            self.returned = true;
            #[cfg(test)]
            HANDLE_ERROR_CALL_COUNT.with(|c| c.set(c.get() + 1));
            // Increment the method specific metric
            METRICS.increment_error_counter(
                self.op_metric,
                map_tonic_code_to_metric_err_tag(self.error_code),
            );
            if !is_expected_grpc_outcome(self.op_metric, self.error_code) {
                tracing::error!(
                    request_id = %self.request_id.unwrap_or_default(),
                    operation = self.op_metric,
                    code = %self.error_code,
                    error = %self.internal_error,
                    "gRPC request failed"
                );
            }
        }
    }
}

impl Display for MetricedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MetricedError on requestID {} with metric {} and error code {}: {}",
            self.request_id.unwrap_or_default(),
            self.op_metric,
            self.error_code,
            self.internal_error
        )
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
#[cfg(test)]
thread_local! {
    static HANDLE_ERROR_CALL_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many errors have been recorded on the current thread so far.
///
/// Test-only hook for asserting that a code path does *not* report a failure, which
/// is the regression guard for control-flow errors that must be defused rather than
/// dropped (see [`MetricedError::defuse`]).
#[cfg(test)]
pub(crate) fn handle_error_call_count() -> usize {
    HANDLE_ERROR_CALL_COUNT.with(|c| c.get())
}

/// Serialize an element to a base64 string using safe serialization.
pub fn base64_serialize<T>(element: &T) -> anyhow::Result<String>
where
    T: Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut serialized_data = Vec::new();
    safe_serialize(element, &mut serialized_data, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!("Serialization failed: {e:?}"))?;
    Ok(base64::encode(&serialized_data))
}

/// Deserialize an element from a base64 string using safe deserialization.
pub fn base64_deserialize<T>(element: &str) -> anyhow::Result<T>
where
    T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named,
{
    // Guard against allocating unbounded memory on untrusted input before `safe_deserialize` runs.
    let max_b64_len = (3 * SAFE_SER_SIZE_LIMIT).div_ceil(4) as usize;
    if element.len() > max_b64_len {
        return Err(anyhow::anyhow!(
            "Base64 payload too large (len={}, max={})",
            element.len(),
            max_b64_len
        ));
    }
    let decoded_data = base64::decode(element)?;
    let mut cursor = std::io::Cursor::new(decoded_data);
    let deserialized: T = safe_deserialize(&mut cursor, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!("Deserialization failed: {e:?}"))?;
    Ok(deserialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::{PublicSigKey, gen_sig_keys};

    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn test_metriced_error_creation() {
        let error = MetricedError::new(
            "test_op",
            Some(RequestId::zeros()),
            anyhow::anyhow!("test error"),
            tonic::Code::Internal,
        );
        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(error.to_string().contains("test error"));

        let status: Status = error.into();
        assert!(status.message().contains("test_op"));
        assert!(!status.message().contains("test error"));
    }

    #[test]
    fn classifies_expected_decrypt_outcomes() {
        assert!(is_expected_grpc_outcome(
            OP_USER_DECRYPT_RESULT,
            tonic::Code::Unavailable
        ));
        assert!(is_expected_grpc_outcome(
            OP_PUBLIC_DECRYPT_RESULT,
            tonic::Code::NotFound
        ));
        assert!(is_expected_grpc_outcome(
            OP_USER_DECRYPT_REQUEST,
            tonic::Code::ResourceExhausted
        ));
        assert!(is_expected_grpc_outcome(
            OP_PUBLIC_DECRYPT_REQUEST,
            tonic::Code::AlreadyExists
        ));

        assert!(!is_expected_grpc_outcome(
            OP_USER_DECRYPT_RESULT,
            tonic::Code::Internal
        ));
        assert!(!is_expected_grpc_outcome(
            OP_KEY_MATERIAL_AVAILABILITY,
            tonic::Code::ResourceExhausted
        ));
    }

    #[test]
    fn test_metriced_error_drop_without_return() {
        let before = super::HANDLE_ERROR_CALL_COUNT.with(|c| c.get());
        let error = MetricedError::new(
            "test_op_drop",
            Some(RequestId::zeros()),
            anyhow::anyhow!("dropped error"),
            tonic::Code::Internal,
        );
        // Error starts unreturned; Drop will invoke handle_error.
        assert!(!error.returned);
        drop(error);
        // Confirm that Drop invokes handle_error when the error was not returned.
        let after = super::HANDLE_ERROR_CALL_COUNT.with(|c| c.get());
        assert_eq!(
            after,
            before + 1,
            "Drop should have called handle_error exactly once"
        );
    }

    #[test]
    fn test_base64_serialize_deserialize_roundtrip() {
        let mut rng = AesRng::seed_from_u64(42);
        let (pk, _sk) = gen_sig_keys(&mut rng);

        let serialized = base64_serialize(&pk).expect("serialization should succeed");
        // The output must be valid base64 (decodable on its own).
        base64::decode(&serialized).expect("output should be valid base64");

        let deserialized: PublicSigKey =
            base64_deserialize(&serialized).expect("deserialization should succeed");
        assert_eq!(pk, deserialized, "roundtrip should preserve the value");
    }

    #[test]
    fn test_base64_deserialize_rejects_invalid_base64() {
        // '!' is not part of the base64 alphabet.
        let err = base64_deserialize::<PublicSigKey>("not valid base64!!").unwrap_err();
        assert!(
            err.to_string().to_lowercase().contains("base64")
                || err.downcast_ref::<base64::DecodeError>().is_some(),
            "expected a base64 decode error, got: {err}"
        );
    }

    #[test]
    fn test_metriced_error_no_dropping() {
        let error = MetricedError::new(
            "test_no_drop",
            Some(RequestId::zeros()),
            anyhow::anyhow!("dropped error"),
            tonic::Code::Internal,
        );
        // Converting to Status marks the error as returned, so Drop won't log the warning.
        let status: Status = error.into();
        assert!(status.message().contains("test_no_drop"));
    }

    #[test]
    fn sanity_check_extra_data_version_0_valid() {
        let epoch_id = EpochId::from_bytes([0x11; 32]);
        let context_id = ContextId::from_bytes([0x22; 32]);

        let extra_data = [0u8; 1];

        assert!(
            sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id).is_none(),
            "well-formed version 0 payload should not produce a warning"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_0_wrong_length() {
        let epoch_id = EpochId::from_bytes([0x11; 32]);
        let context_id = ContextId::from_bytes([0x22; 32]);

        let extra_data = vec![0u8, 0xAB];
        let warning = sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id)
            .expect("long v0 input should produce a warning");
        assert!(
            warning.contains("Unexpected extra data length for version 0: 2"),
            "unexpected warning: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_1_valid() {
        let epoch_id = EpochId::from_bytes([0x11; 32]);
        let context_id = ContextId::from_bytes([0x22; 32]);

        let mut extra_data = [0u8; 33];
        extra_data[0] = 1;
        extra_data[1..33].copy_from_slice(context_id.as_bytes());

        assert!(
            sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id).is_none(),
            "well-formed version 1 payload should not produce a warning"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_2_valid() {
        let epoch_id = EpochId::from_bytes([0x33; 32]);
        let context_id = ContextId::from_bytes([0x44; 32]);

        let mut extra_data = [0u8; 65];
        extra_data[0] = 2;
        extra_data[1..33].copy_from_slice(context_id.as_bytes());
        extra_data[33..65].copy_from_slice(epoch_id.as_bytes());

        assert!(
            sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id).is_none(),
            "well-formed version 2 payload should not produce a warning"
        );
    }

    #[test]
    fn sanity_check_extra_data_empty() {
        let epoch_id = EpochId::from_bytes([0x00; 32]);
        let context_id = ContextId::from_bytes([0x00; 32]);

        assert!(sanity_check_extra_data_helper(&[], &epoch_id, &context_id).is_none());
    }

    #[test]
    fn sanity_check_extra_data_unknown_version() {
        let epoch_id = EpochId::from_bytes([0x55; 32]);
        let context_id = ContextId::from_bytes([0x66; 32]);

        let extra_data = vec![99u8, 0, 0, 0];
        let warning = sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id)
            .expect("unknown version should produce a warning");
        assert!(
            warning.contains("Unknown extra data version: 99"),
            "unexpected warning: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_1_wrong_length() {
        let epoch_id = EpochId::from_bytes([0x77; 32]);
        let context_id = ContextId::from_bytes([0x88; 32]);

        // Too short — guard prevents an out-of-bounds slice.
        let short = vec![1u8, 0, 0, 0];
        let warning = sanity_check_extra_data_helper(&short, &epoch_id, &context_id)
            .expect("short v1 input should produce a warning");
        assert!(
            warning.contains("Unexpected extra data length for version 1: 4"),
            "unexpected warning: {warning}"
        );

        // Too long for version 1.
        let mut long = [0u8; 34];
        long[0] = 1;
        long[1..33].copy_from_slice(context_id.as_bytes());
        long[33] = 0xAB;
        let warning = sanity_check_extra_data_helper(&long, &epoch_id, &context_id)
            .expect("long v1 input should produce a warning");
        assert!(
            warning.contains("Unexpected extra data length for version 1: 34"),
            "unexpected warning: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_1_context_mismatch() {
        let epoch_id = EpochId::from_bytes([0x01; 32]);
        let context_id = ContextId::from_bytes([0x02; 32]);
        let other_context = ContextId::from_bytes([0xAA; 32]);

        let mut extra_data = [0u8; 33];
        extra_data[0] = 1;
        extra_data[1..33].copy_from_slice(other_context.as_bytes());

        let warning = sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id)
            .expect("mismatched context should produce a warning");
        assert!(
            warning.contains("Context ID in extra data does not match expected context ID"),
            "unexpected warning: {warning}"
        );
        assert!(
            warning.contains(&hex::encode(other_context.as_bytes())),
            "warning should include the received (other) context hex: {warning}"
        );
        assert!(
            warning.contains(&context_id.to_string()),
            "warning should include the expected context id: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_2_wrong_length() {
        let epoch_id = EpochId::from_bytes([0x03; 32]);
        let context_id = ContextId::from_bytes([0x04; 32]);

        // Length 33 (valid for v1) is not valid for v2.
        let mut short = [0u8; 33];
        short[0] = 2;
        short[1..33].copy_from_slice(context_id.as_bytes());
        let warning = sanity_check_extra_data_helper(&short, &epoch_id, &context_id)
            .expect("short v2 input should produce a warning");
        assert!(
            warning.contains("Unexpected extra data length for version 2: 33"),
            "unexpected warning: {warning}"
        );

        // Too long for version 2.
        let mut long = [0u8; 66];
        long[0] = 2;
        long[1..33].copy_from_slice(context_id.as_bytes());
        long[33..65].copy_from_slice(epoch_id.as_bytes());
        long[65] = 0xAB;

        let warning = sanity_check_extra_data_helper(&long, &epoch_id, &context_id)
            .expect("long v2 input should produce a warning");
        assert!(
            warning.contains("Unexpected extra data length for version 2: 66"),
            "unexpected warning: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_2_epoch_mismatch() {
        let epoch_id = EpochId::from_bytes([0x05; 32]);
        let context_id = ContextId::from_bytes([0x06; 32]);
        let other_epoch = EpochId::from_bytes([0xBB; 32]);

        let mut extra_data = [0u8; 65];
        extra_data[0] = 2;
        extra_data[1..33].copy_from_slice(context_id.as_bytes());
        extra_data[33..65].copy_from_slice(other_epoch.as_bytes());

        let warning = sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id)
            .expect("mismatched epoch should produce a warning");
        assert!(
            warning.contains("Epoch ID in extra data does not match expected epoch ID"),
            "unexpected warning: {warning}"
        );
        assert!(
            warning.contains(&hex::encode(other_epoch.as_bytes())),
            "warning should include the received (other) epoch hex: {warning}"
        );
        assert!(
            warning.contains(&epoch_id.to_string()),
            "warning should include the expected epoch id: {warning}"
        );
    }

    #[test]
    fn sanity_check_extra_data_version_2_context_mismatch() {
        let epoch_id = EpochId::from_bytes([0x07; 32]);
        let context_id = ContextId::from_bytes([0x08; 32]);
        let other_context = ContextId::from_bytes([0xCC; 32]);

        let mut extra_data = [0u8; 65];
        extra_data[0] = 2;
        extra_data[1..33].copy_from_slice(other_context.as_bytes());
        extra_data[33..65].copy_from_slice(epoch_id.as_bytes());

        let warning = sanity_check_extra_data_helper(&extra_data, &epoch_id, &context_id)
            .expect("mismatched context should produce a warning");
        assert!(
            warning.contains("Context ID in extra data does not match expected context ID"),
            "unexpected warning: {warning}"
        );
        assert!(
            warning.contains(&hex::encode(other_context.as_bytes())),
            "warning should include the received (other) context hex: {warning}"
        );
        assert!(
            warning.contains(&context_id.to_string()),
            "warning should include the expected context id: {warning}"
        );
    }
}
