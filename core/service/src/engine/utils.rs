use crate::engine::base::{CrsGenMetadata, DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, KeyGenMetadata};
use crate::vault::storage::{StorageExt, StorageReader, read_versioned_at_request_id};
use hashing::hash_element;
use kms_grpc::RequestId;
use kms_grpc::kms::v1::KeyMaterialAvailabilityResponse;
use kms_grpc::rpc_types::{KMSType, PrivDataType, PubDataType};
use kms_grpc::utils::tonic_result::top_1k_chars;
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
const ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE: &str = "Invalid current public key metadata shape";
const ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE: &str = "Invalid legacy public key metadata shape";

#[derive(Clone, Copy)]
enum CurrentPublicMaterialLayout {
    Standard,
    Compressed,
}

fn classify_current_public_material(
    pub_data_types: &HashSet<PubDataType>,
) -> anyhow::Result<CurrentPublicMaterialLayout> {
    let has_public_key = pub_data_types.contains(&PubDataType::PublicKey);
    let has_server_key = pub_data_types.contains(&PubDataType::ServerKey);
    let has_compressed_keyset = pub_data_types.contains(&PubDataType::CompressedXofKeySet);

    match (
        has_public_key,
        has_server_key,
        has_compressed_keyset,
        pub_data_types.len(),
    ) {
        (true, true, false, 2) => Ok(CurrentPublicMaterialLayout::Standard),
        (true, false, true, 2) => Ok(CurrentPublicMaterialLayout::Compressed),
        _ => anyhow::bail!(
            "{ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE}: expected either \
             {{PublicKey, ServerKey}} or {{PublicKey, CompressedXofKeySet}}, got {:?}",
            pub_data_types
        ),
    }
}

fn validate_legacy_public_material_shape(
    pub_data_types: &HashSet<PubDataType>,
) -> anyhow::Result<()> {
    let has_public_key = pub_data_types.contains(&PubDataType::PublicKey);
    let has_server_key = pub_data_types.contains(&PubDataType::ServerKey);

    if has_public_key && has_server_key && pub_data_types.len() == 2 {
        return Ok(());
    }

    anyhow::bail!(
        "{ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE}: expected exactly {{PublicKey, ServerKey}}, got {:?}",
        pub_data_types
    );
}

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

/// Verify a standalone public key digest using raw bytes from storage.
/// This avoids re-serializing the key, which would produce different bytes
/// if there was a version upgrade since the original digest was computed.
pub(crate) fn verify_public_key_digest_from_bytes(
    public_key_bytes: &[u8],
    expected_digest: &[u8],
) -> anyhow::Result<()> {
    let actual_digest = hash_element(&DSEP_PUBDATA_KEY, public_key_bytes);
    if actual_digest != expected_digest {
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
    let pub_data_types: HashSet<_> = key_digest_map.keys().cloned().collect();
    match classify_current_public_material(&pub_data_types)? {
        CurrentPublicMaterialLayout::Standard => {
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
        }
        CurrentPublicMaterialLayout::Compressed => {
            let public_key_bytes = storage
                .load_bytes(id, &PubDataType::PublicKey.to_string())
                .await?;
            let compressed_keyset_bytes = storage
                .load_bytes(id, &PubDataType::CompressedXofKeySet.to_string())
                .await?;

            let expected_public_key_digest = key_digest_map
                .get(&PubDataType::PublicKey)
                .ok_or_else(|| anyhow::anyhow!("missing digest for public key, id={id}"))?;
            let expected_compressed_keyset_digest = key_digest_map
                .get(&PubDataType::CompressedXofKeySet)
                .ok_or_else(|| {
                    anyhow::anyhow!("missing digest for compressed xof keyset, id={id}")
                })?;

            verify_public_key_digest_from_bytes(&public_key_bytes, expected_public_key_digest)?;
            verify_compressed_key_digest_from_bytes(
                &compressed_keyset_bytes,
                expected_compressed_keyset_digest,
            )
        }
    }
}

/// Deserialize public key materials from storage to verify they are readable.
/// Used for legacy metadata that lacks digest information.
async fn check_readability<S: StorageReader + Sync>(
    storage: &S,
    id: &RequestId,
    pub_data_types: &HashSet<PubDataType>,
) -> anyhow::Result<()> {
    validate_legacy_public_material_shape(pub_data_types)?;

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
    use crate::vault::storage::{delete_at_request_id, store_versioned_at_request_id};
    use aes_prng::AesRng;
    use kms_grpc::rpc_types::{PubDataType, SignedPubDataHandleInternal};
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

    #[derive(Clone)]
    struct TestStoredMaterial {
        key_id: RequestId,
        preproc_id: RequestId,
        key_digest_map: HashMap<PubDataType, Vec<u8>>,
    }

    impl TestStoredMaterial {
        fn current_metadata(&self) -> KeyGenMetadata {
            KeyGenMetadata::Current(KeyGenMetadataInner {
                key_id: self.key_id,
                preprocessing_id: self.preproc_id,
                key_digest_map: self.key_digest_map.clone(),
                external_signature: vec![],
            })
        }

        fn legacy_standard_metadata(&self) -> KeyGenMetadata {
            KeyGenMetadata::LegacyV0(HashMap::from_iter([
                (
                    PubDataType::PublicKey,
                    SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
                ),
                (
                    PubDataType::ServerKey,
                    SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
                ),
            ]))
        }

        fn current_metadata_with_types(&self, pub_data_types: &[PubDataType]) -> KeyGenMetadata {
            let key_digest_map = pub_data_types
                .iter()
                .filter_map(|data_type| {
                    self.key_digest_map
                        .get(data_type)
                        .cloned()
                        .map(|digest| (*data_type, digest))
                })
                .collect();
            KeyGenMetadata::Current(KeyGenMetadataInner {
                key_id: self.key_id,
                preprocessing_id: self.preproc_id,
                key_digest_map,
                external_signature: vec![],
            })
        }
    }

    #[tokio::test]
    async fn sanity_check_current_standard_keys_valid_digests() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 69).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_standard_keys_invalid_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_standard_keys(&mut storage, 70).await;
        if let Some(digest) = material.key_digest_map.get_mut(&PubDataType::ServerKey) {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
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
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 44).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("valid digests should pass");
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_invalid_public_key_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_compressed_keys(&mut storage, 45).await;
        if let Some(digest) = material.key_digest_map.get_mut(&PubDataType::PublicKey) {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(ERR_PUBLIC_KEY_DIGEST_MISMATCH),
            "expected public key digest mismatch, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keys_invalid_compressed_keyset_digest() {
        let mut storage = RamStorage::new();
        let mut material = setup_compressed_keys(&mut storage, 46).await;
        if let Some(digest) = material
            .key_digest_map
            .get_mut(&PubDataType::CompressedXofKeySet)
        {
            digest[0] ^= 0xFF;
        }

        let entries = vec![(material.key_id, material.current_metadata())];
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
    async fn sanity_check_current_compressed_keys_missing_public_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 47).await;
        delete_data(&mut storage, &material.key_id, PubDataType::PublicKey).await;

        let entries = vec![(material.key_id, material.current_metadata())];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(&PubDataType::PublicKey.to_string()),
            "expected missing public key error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_current_compressed_keyset_without_public_key_fails_as_inconsistent() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 48).await;
        let metadata = material.current_metadata_with_types(&[PubDataType::CompressedXofKeySet]);

        let entries = vec![(material.key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_CURRENT_PUBLIC_KEY_SHAPE),
            "expected invalid current shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_standard_metadata_readability_only() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 49).await;

        let entries = vec![(material.key_id, material.legacy_standard_metadata())];
        sanity_check_public_materials(&storage, &entries)
            .await
            .expect("legacy readability check should pass");
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_compressed_keyset_fails() {
        let mut storage = RamStorage::new();
        let material = setup_compressed_keys(&mut storage, 50).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([
            (
                PubDataType::PublicKey,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
            (
                PubDataType::CompressedXofKeySet,
                SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
            ),
        ]));

        let entries = vec![(material.key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_only_public_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 51).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([(
            PubDataType::PublicKey,
            SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
        )]));

        let entries = vec![(material.key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
    }

    #[tokio::test]
    async fn sanity_check_legacy_metadata_with_only_server_key_fails() {
        let mut storage = RamStorage::new();
        let material = setup_standard_keys(&mut storage, 52).await;
        let metadata = KeyGenMetadata::LegacyV0(HashMap::from_iter([(
            PubDataType::ServerKey,
            SignedPubDataHandleInternal::new(String::new(), vec![], vec![]),
        )]));

        let entries = vec![(material.key_id, metadata)];
        let err = sanity_check_public_materials(&storage, &entries)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(ERR_INVALID_LEGACY_PUBLIC_KEY_SHAPE),
            "expected invalid legacy shape error, got: {err}"
        );
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

    async fn setup_standard_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
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
            &key_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();

        TestStoredMaterial {
            key_id,
            preproc_id,
            key_digest_map: HashMap::from_iter([
                (PubDataType::ServerKey, server_key_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
        }
    }

    async fn setup_compressed_keys(storage: &mut RamStorage, seed: u64) -> TestStoredMaterial {
        let mut rng = AesRng::seed_from_u64(seed);
        let key_id = RequestId::new_random(&mut rng);
        let preproc_id = RequestId::new_random(&mut rng);
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
        let compact_public_key = compressed_keyset
            .clone()
            .decompress()
            .unwrap()
            .into_raw_parts()
            .0;

        let compressed_keyset_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &compressed_keyset,
        )
        .unwrap();
        let public_key_digest = safe_serialize_hash_element_versioned(
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &compact_public_key,
        )
        .unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        .unwrap();

        store_versioned_at_request_id(
            storage,
            &key_id,
            &compact_public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();

        TestStoredMaterial {
            key_id,
            preproc_id,
            key_digest_map: HashMap::from_iter([
                (PubDataType::CompressedXofKeySet, compressed_keyset_digest),
                (PubDataType::PublicKey, public_key_digest),
            ]),
        }
    }

    async fn delete_data(storage: &mut RamStorage, key_id: &RequestId, data_type: PubDataType) {
        delete_at_request_id(storage, key_id, &data_type.to_string())
            .await
            .unwrap();
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
            _ => panic!("expected Current metadata, instead got {:?}", metadata),
        };

        store_versioned_at_request_id(storage, crs_id, &crs, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        (crs, digest)
    }
}
