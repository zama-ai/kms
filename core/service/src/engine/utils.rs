use crate::engine::base::{CrsGenMetadata, DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, KeyGenMetadata};
use crate::vault::storage::{StorageExt, StorageReader, read_versioned_at_request_id};
use hashing::hash_element;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::{KMSType, PrivDataType, PubDataType};
use kms_grpc::utils::tonic_result::top_1k_chars;
use kms_grpc::{ContextId, EpochId, RequestId};
use observability::metrics::METRICS;
use observability::metrics_names::{
    ERR_ASYNC, OP_KEY_MATERIAL_AVAILABILITY, map_tonic_code_to_metric_err_tag,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use tonic::Status;

pub(crate) const ERR_SERVER_KEY_DIGEST_MISMATCH: &str = "Server key digest mismatch";
pub(crate) const ERR_PUBLIC_KEY_DIGEST_MISMATCH: &str = "Public key digest mismatch";
pub(crate) const ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH: &str =
    "Compressed xof keyset digest mismatch";
pub(crate) const ERR_CRS_DIGEST_MISMATCH: &str = "CRS digest mismatch";

/// Verify key digests using raw bytes from storage.
/// This avoids re-serializing the keys, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_key_digest_from_bytes(
    server_key_bytes: &[u8],
    public_key_bytes: &[u8],
    expected_server_key_digest: &[u8],
    expected_public_key_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_server_key_digest = hash_element(&DSEP_PUBDATA_KEY, server_key_bytes);
    let actual_public_key_digest = hash_element(&DSEP_PUBDATA_KEY, public_key_bytes);

    if actual_server_key_digest != expected_server_key_digest {
        anyhow::bail!(ERR_SERVER_KEY_DIGEST_MISMATCH);
    }
    if actual_public_key_digest != expected_public_key_digest {
        anyhow::bail!(ERR_PUBLIC_KEY_DIGEST_MISMATCH);
    }

    Ok(())
}

/// Verify compressed key digest using raw bytes from storage.
/// This avoids re-serializing the keys, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_compressed_key_digest_from_bytes(
    compressed_keyset_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_KEY, compressed_keyset_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH);
    }
    Ok(())
}

/// Verify CRS digest using raw bytes from storage.
/// This avoids re-serializing the CRS, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_crs_digest_from_bytes(
    crs_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_CRS, crs_bytes);
    if actual_digest != expected_digest {
        anyhow::bail!(ERR_CRS_DIGEST_MISMATCH);
    }
    Ok(())
}

/// Load raw bytes from storage and verify their digests against the expected values
/// in `key_digest_map`. Returns an error if any digest does not match.
async fn verify_digests<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    key_digest_map: &HashMap<PubDataType, Vec<u8>>,
) -> anyhow::Result<()> {
    // TODO(dp): Why use contains_key here? Just look it up and do nothing if it's not there. Why even use a HashMap?
    // This code is all weird.
    if key_digest_map.contains_key(&PubDataType::PublicKey) {
        let public_key_exists = storage
            .data_exists(id, &PubDataType::PublicKey.to_string())
            .await?;
        let server_key_exists = storage
            .data_exists(id, &PubDataType::ServerKey.to_string())
            .await?;

        if !(public_key_exists && server_key_exists)
            && storage
                .data_exists(id, &PubDataType::CompressedXofKeySet.to_string())
                .await?
        {
            tracing::warn!(
                "Public material for id={id} still references legacy PublicKey/ServerKey metadata, \
                 but only CompressedXofKeySet is present. Falling back to compressed readability."
            );
            read_versioned_at_request_id::<_, tfhe::xof_key_set::CompressedXofKeySet>(
                storage,
                id,
                &PubDataType::CompressedXofKeySet.to_string(),
            )
            .await?;
            // TODO(dp): this shortcutting is burried. Lift it.
            return Ok(());
        }

        let public_key_bytes = storage
            .load_bytes(id, &PubDataType::PublicKey.to_string())
            .await?;
        // TODO(dp): this is potentially enormous. Figure out why we're doing this and if we can stop. Is `verify_digests` called from production code? Loading gigabytes of data
        // and then hashing it is silly for tests. Let the tests fail instead.
        let server_key_bytes = storage
            .load_bytes(id, &PubDataType::ServerKey.to_string())
            .await?;

        let expected_server_key_digest = key_digest_map
            .get(&PubDataType::ServerKey)
            .ok_or_else(|| anyhow::anyhow!("missing digest for server key, id={id}"))?;
        let expected_public_key_digest = key_digest_map
            .get(&PubDataType::PublicKey)
            .ok_or_else(|| anyhow::anyhow!("missing digest for public key, id={id}"))?;

        verify_key_digest_from_bytes(
            &server_key_bytes,
            &public_key_bytes,
            expected_server_key_digest,
            expected_public_key_digest,
        )
    } else if key_digest_map.contains_key(&PubDataType::CompressedXofKeySet) {
        let compressed_keyset_bytes = storage
            .load_bytes(id, &PubDataType::CompressedXofKeySet.to_string())
            .await?;

        let expected_digest = key_digest_map
            .get(&PubDataType::CompressedXofKeySet)
            .ok_or_else(|| anyhow::anyhow!("missing digest for compressed xof keyset, id={id}"))?;

        verify_compressed_key_digest_from_bytes(&compressed_keyset_bytes, expected_digest)
    } else {
        anyhow::bail!(
            "Inconsistent storage state for id={id}: pub data types {:?} \
             contains neither PublicKey nor CompressedXofKeySet",
            key_digest_map.keys().collect::<Vec<_>>()
        );
    }
}

/// Deserialize public key materials from storage to verify they are readable.
/// Used for legacy metadata that lacks digest information.
async fn check_readability<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    pub_data_types: &HashSet<PubDataType>,
) -> anyhow::Result<()> {
    if pub_data_types.contains(&PubDataType::PublicKey) {
        let public_key_exists = storage
            .data_exists(id, &PubDataType::PublicKey.to_string())
            .await?;
        let server_key_exists = storage
            .data_exists(id, &PubDataType::ServerKey.to_string())
            .await?;

        if !(public_key_exists && server_key_exists)
            && storage
                .data_exists(id, &PubDataType::CompressedXofKeySet.to_string())
                .await?
        {
            tracing::warn!(
                "Legacy public metadata for id={id} points to PublicKey/ServerKey, \
                 but only CompressedXofKeySet is present. Falling back to compressed readability."
            );
            read_versioned_at_request_id::<_, tfhe::xof_key_set::CompressedXofKeySet>(
                storage,
                id,
                &PubDataType::CompressedXofKeySet.to_string(),
            )
            .await?;
            return Ok(());
        }

        read_versioned_at_request_id::<_, tfhe::CompactPublicKey>(
            storage,
            id,
            &PubDataType::PublicKey.to_string(),
        )
        .await?;
        read_versioned_at_request_id::<_, tfhe::ServerKey>(
            storage,
            id,
            &PubDataType::ServerKey.to_string(),
        )
        .await?;
    } else if pub_data_types.contains(&PubDataType::CompressedXofKeySet) {
        read_versioned_at_request_id::<_, tfhe::xof_key_set::CompressedXofKeySet>(
            storage,
            id,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await?;
    } else {
        anyhow::bail!(
            "Inconsistent storage state for id={id}: pub data types {:?} \
             contains neither PublicKey nor CompressedXofKeySet",
            pub_data_types
        );
    }
    Ok(())
}

/// Sanity check that public key materials can be read from storage and verify their integrity.
///
/// For each entry, verifies that the public key materials can be successfully retrieved
/// from public storage. When `KeyGenMetadata::Current` metadata is available, also verifies
/// the integrity of the loaded data by comparing digests. For `KeyGenMetadata::LegacyV0`
/// entries (which lack digest information), only readability is checked.
pub async fn sanity_check_public_materials<S>(
    public_storage: &S,
    entries: &[(RequestId, KeyGenMetadata)],
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    for (id, metadata) in entries {
        match metadata {
            KeyGenMetadata::Current(inner) => {
                verify_digests(public_storage, id, &inner.key_digest_map).await?;
            }
            KeyGenMetadata::LegacyV0(hash_map) => {
                tracing::info!(
                    "Legacy metadata for id={id}, performing readability check only (no digest verification)"
                );
                let pub_data_types: HashSet<PubDataType> = hash_map.keys().cloned().collect();
                check_readability(public_storage, id, &pub_data_types).await?;
            }
        }
    }
    Ok(())
}

/// Sanity check that CRS materials can be read from storage and verify their integrity.
///
/// For each entry, verifies that the CRS can be successfully retrieved from public storage.
/// When `CrsGenMetadata::Current` metadata is available, also verifies the integrity of the
/// loaded data by comparing digests. For `CrsGenMetadata::LegacyV0` entries (which lack digest
/// information), only readability is checked.
pub async fn sanity_check_crs_materials<S>(
    public_storage: &S,
    crs_entries: &HashMap<RequestId, CrsGenMetadata>,
) -> anyhow::Result<()>
where
    S: StorageReader + Sync,
{
    for (id, metadata) in crs_entries {
        match metadata {
            CrsGenMetadata::Current(inner) => {
                let crs_bytes = public_storage
                    .load_bytes(id, &PubDataType::CRS.to_string())
                    .await?;
                verify_crs_digest_from_bytes(&crs_bytes, &inner.crs_digest)?;
            }
            CrsGenMetadata::LegacyV0(_) => {
                tracing::info!(
                    "Legacy CRS metadata for id={id}, performing readability check only (no digest verification)"
                );
                read_versioned_at_request_id::<_, tfhe::zk::CompactPkeCrs>(
                    public_storage,
                    id,
                    &PubDataType::CRS.to_string(),
                )
                .await?;
            }
        }
    }
    Ok(())
}

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
        let error_string = format!(
            "Failure on requestID {} with metric {}. Error: {}",
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
            #[cfg(test)]
            HANDLE_ERROR_CALL_COUNT.with(|c| c.set(c.get() + 1));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::engine::base::{KeyGenMetadataInner, safe_serialize_hash_element_versioned};
    use crate::engine::centralized::central_kms::gen_centralized_crs;
    use crate::vault::storage::ram::RamStorage;
    use crate::vault::storage::store_versioned_at_request_id;
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::PubDataType;
    use rand::SeedableRng;
    use std::collections::HashMap;
    use tfhe::core_crypto::prelude::NormalizedHammingWeightBound;
    use tfhe::shortint::ClassicPBSParameters;
    use tfhe::xof_key_set::CompressedXofKeySet;

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

    #[tokio::test]
    async fn sanity_check_current_standard_keys_valid_digests() {
        let mut rng = AesRng::seed_from_u64(69);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let digests = setup_standard_keys(&mut storage, &key_id).await;

        let metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: preproc_id,
            key_digest_map: digests,
            external_signature: vec![],
            extra_data: None,
        });

        let entries = vec![(key_id, metadata)];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_standard_keys_invalid_digest() {
        let mut rng = AesRng::seed_from_u64(69);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let mut digests = setup_standard_keys(&mut storage, &key_id).await;
        // Corrupt the server key digest
        if let Some(digest) = digests.get_mut(&PubDataType::ServerKey) {
            digest[0] ^= 0xFF;
        }

        let metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: preproc_id,
            key_digest_map: digests,
            external_signature: vec![],
            extra_data: None,
        });

        let entries = vec![(key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_SERVER_KEY_DIGEST_MISMATCH),
            "expected server key digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_valid_digests() {
        let mut rng = AesRng::seed_from_u64(44);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let digests = setup_compressed_keys(&mut storage, &key_id).await;

        let metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: preproc_id,
            key_digest_map: digests,
            external_signature: vec![],
            extra_data: None,
        });

        let entries = vec![(key_id, metadata)];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_invalid_digest() {
        let mut rng = AesRng::seed_from_u64(45);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let mut digests = setup_compressed_keys(&mut storage, &key_id).await;
        // Corrupt the digest
        if let Some(digest) = digests.get_mut(&PubDataType::CompressedXofKeySet) {
            digest[0] ^= 0xFF;
        }

        let metadata = KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id: preproc_id,
            key_digest_map: digests,
            external_signature: vec![],
            extra_data: None,
        });

        let entries = vec![(key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_COMPRESSED_KEYSET_DIGEST_MISMATCH),
            "expected compressed keyset digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_readability_only() {
        let mut rng = AesRng::seed_from_u64(46);
        let key_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        // Set up standard keys (we won't use the digests — legacy has no digest info)
        let _digests = setup_standard_keys(&mut storage, &key_id).await;

        // Create legacy metadata with empty handles — we just need the keys present
        use kms_grpc::rpc_types::SignedPubDataHandleInternal;
        let legacy_map: HashMap<PubDataType, SignedPubDataHandleInternal> = HashMap::from_iter([
            (
                PubDataType::PublicKey,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
            (
                PubDataType::ServerKey,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
        ]);
        let metadata = KeyGenMetadata::LegacyV0(legacy_map);

        let entries = vec![(key_id, metadata)];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("legacy readability check should pass");
    }

    #[tokio::test]
    async fn sanity_check_crs_valid_digest() {
        let mut rng = AesRng::seed_from_u64(70);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let (_crs, digest) = setup_crs(&mut storage, &crs_id).await;

        let metadata = CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest: digest,
            max_num_bits: 64,
            extra_data: None,
            external_signature: vec![],
        });

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        sanity_check_crs_materials(&storage, &entries)
            .await
            .expect("valid CRS digest should pass");
    }

    #[tokio::test]
    async fn sanity_check_crs_invalid_digest() {
        let mut rng = AesRng::seed_from_u64(71);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        let (_crs, mut digest) = setup_crs(&mut storage, &crs_id).await;
        // Corrupt the digest
        digest[0] ^= 0xFF;

        let metadata = CrsGenMetadata::Current(crate::engine::base::CrsGenMetadataInner {
            crs_id,
            crs_digest: digest,
            max_num_bits: 64,
            extra_data: None,
            external_signature: vec![],
        });

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        let err = sanity_check_crs_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_CRS_DIGEST_MISMATCH),
            "expected CRS digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_crs_legacy_readability_only() {
        let mut rng = AesRng::seed_from_u64(72);
        let crs_id = RequestId::new_random(&mut rng);
        let mut storage = RamStorage::new();

        // Set up CRS in storage (we won't use the digest — legacy has no digest info)
        let _crs_and_digest = setup_crs(&mut storage, &crs_id).await;

        use kms_grpc::rpc_types::SignedPubDataHandleInternal;
        let legacy_handle = SignedPubDataHandleInternal::new(String::new(), vec![], vec![]);
        let metadata = CrsGenMetadata::LegacyV0(legacy_handle);

        let entries = HashMap::from_iter([(crs_id, metadata)]);
        sanity_check_crs_materials(&storage, &entries)
            .await
            .expect("legacy CRS readability check should pass");
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

    async fn setup_standard_keys(
        storage: &mut RamStorage,
        key_id: &RequestId,
    ) -> HashMap<PubDataType, Vec<u8>> {
        let params = crate::consts::TEST_PARAM;
        let pbs_params: ClassicPBSParameters = params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let config = tfhe::ConfigBuilder::with_custom_parameters(pbs_params);
        let client_key = tfhe::ClientKey::generate(config);
        let server_key = client_key.generate_server_key();
        let public_key = tfhe::CompactPublicKey::new(&client_key);

        let server_key_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &server_key,
        )
        .unwrap();
        let public_key_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &public_key,
        )
        .unwrap();

        store_versioned_at_request_id(
            storage,
            key_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            storage,
            key_id,
            &server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();

        HashMap::from_iter([
            (PubDataType::ServerKey, server_key_digest),
            (PubDataType::PublicKey, public_key_digest),
        ])
    }

    async fn setup_compressed_keys(
        storage: &mut RamStorage,
        key_id: &RequestId,
    ) -> HashMap<PubDataType, Vec<u8>> {
        let params = crate::consts::TEST_PARAM;
        let config = params.to_tfhe_config();
        let max_norm_hwt = params
            .get_params_basics_handle()
            .get_sk_deviations()
            .map(|x| x.pmax)
            .unwrap_or(1.0);
        let max_norm_hwt = NormalizedHammingWeightBound::new(max_norm_hwt).unwrap();
        let tag = key_id.into();

        let (_client_key, compressed_keyset) = CompressedXofKeySet::generate(
            config,
            vec![42, 43, 44, 45],
            params.get_params_basics_handle().get_sec() as u32,
            max_norm_hwt,
            tag,
        )
        .unwrap();

        let digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &compressed_keyset,
        )
        .unwrap();

        store_versioned_at_request_id(
            storage,
            key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();

        HashMap::from_iter([(PubDataType::CompressedXofKeySet, digest)])
    }

    async fn setup_crs(
        storage: &mut RamStorage,
        crs_id: &RequestId,
    ) -> (tfhe::zk::CompactPkeCrs, Vec<u8>) {
        let mut rng = AesRng::seed_from_u64(42);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let params = crate::consts::TEST_PARAM;
        let domain = crate::dummy_domain();
        let max_num_bits = 64u32;

        let (crs, metadata) = gen_centralized_crs(
            &sk,
            &params,
            Some(max_num_bits),
            &domain,
            vec![],
            crs_id,
            &mut rng,
        )
        .unwrap();

        let digest = match &metadata {
            CrsGenMetadata::Current(inner) => inner.crs_digest.clone(),
            _ => panic!("expected Current metadata"),
        };

        store_versioned_at_request_id(storage, crs_id, &crs, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        (crs, digest)
    }
}
