//! Utility functions for cryptographic material management in the KMS.
//!
//! This module provides various utility functions that support cryptographic operations,
//! storage management, and common operations needed by the cryptographic material
//! storage system.

use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
use crate::vault::storage::StorageReader;
use crate::{
    anyhow_error_and_warn_log,
    client::client_non_wasm::ClientDataType,
    vault::storage::{read_all_data_versioned, Storage},
};
use aes_prng::AesRng;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_grpc::RequestId;
use rand::SeedableRng;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Display;
use tfhe::{named::Named, Unversionize};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::zk::ceremony::max_num_messages;

/// Creates a new random number generator instance.
///
/// # Arguments
/// * `deterministic` - If true, the RNG will be seeded with the provided seed (or a default of 42 if None).
///   If false, a cryptographically secure random seed will be used.
/// * `seed` - Optional seed value for deterministic RNG generation.
///
/// # Returns
/// A new instance of `AesRng` configured according to the specified parameters.
///
/// # Examples
/// ```rust,ignore
/// // Create a deterministic RNG with default seed
/// let rng = get_rng(true, None);
///
/// // Create a non-deterministic RNG
/// let rng = get_rng(false, None);
/// ```
pub fn get_rng(deterministic: bool, seed: Option<u64>) -> AesRng {
    if deterministic {
        AesRng::seed_from_u64(seed.map_or(42, |seed| seed))
    } else {
        AesRng::from_entropy()
    }
}

/// Checks if data of the specified type exists in the provided storage.
///
/// # Arguments
/// * `storage` - The storage backend to check for data existence
/// * `req_id` - The request ID used to compute the storage URL
/// * `data_type` - Type of the data to check (used for URL computation)
///
/// # Returns
/// `Ok(true)` if data exists, `Ok(false)` if it doesn't, or an error if the check fails.
///
/// # Errors
/// Returns an error if URL computation or storage access fails.
pub async fn data_exists<S: Storage>(
    storage: &S,
    req_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<bool> {
    storage
        .data_exists(req_id, data_type)
        .await
        .map_err(|e| anyhow_error_and_warn_log(format!("Failed to check if data exists: {e}")))
}

/// Checks if both public and private data exist in their respective storages.
///
/// This is a convenience function that verifies the existence of related public
/// and private data in a single operation.
///
/// # Arguments
/// * `pub_storage` - Storage backend for public data
/// * `priv_storage` - Storage backend for private data
/// * `req_id` - The request ID used to compute storage URLs
/// * `pub_data_type` - Type of the public data
/// * `priv_data_type` - Type of the private data
///
/// # Returns
/// `Ok(true)` if both public and private data exist, `Ok(false)` if either is missing,
/// or an error if any check fails.
///
/// # Note
/// This function short-circuits and returns `Ok(false)` if public data is not found,
/// without checking for private data.
pub async fn check_data_exists<PubS: Storage, PrivS: Storage>(
    pub_storage: &PubS,
    priv_storage: &PrivS,
    req_id: &RequestId,
    pub_data_type: &str,
    priv_data_type: &str,
) -> anyhow::Result<bool> {
    let pub_exists = data_exists(pub_storage, req_id, pub_data_type).await?;

    if !pub_exists {
        return Ok(false);
    }

    data_exists(priv_storage, req_id, priv_data_type).await
}

/// Logs a message indicating that data already exists and generation is being skipped.
///
/// # Arguments
/// * `storage_info` - Information about the storage where data exists
/// * `pub_storage_info` - Optional information about the public storage (if applicable)
/// * `id` - Identifier for the data item
/// * `data_type` - Type of the data that already exists
///
/// # Note
/// The log level is set to `info` as this is a normal condition that doesn't indicate an error.
pub fn log_data_exists<T: Display, U: Display, V: Display>(
    storage_info: T,
    pub_storage_info: Option<U>,
    id: V,
    data_type: &str,
) {
    match pub_storage_info {
        Some(pub_info) => tracing::info!(
            "{} with ID {} already exist for private storage \"{}\" and public storage \"{}\", skipping generation",
            data_type, id, storage_info, pub_info
        ),
        None => tracing::info!(
            "{} with ID {} already exist, skipping generation",
            data_type, id
        ),
    }
}

/// Logs a message indicating successful storage of data.
///
/// # Arguments
/// * `req_id` - The request ID associated with the stored data
/// * `storage_info` - Information about the storage where data was stored
/// * `data_type` - Type of the data that was stored
/// * `is_public` - Whether the stored data is public or private
/// * `is_threshold` - Whether this is related to threshold cryptography
///
/// # Note
/// The log level is set to `info` to track successful storage operations.
pub fn log_storage_success<T: Display, U: Display>(
    req_id: T,
    storage_info: U,
    data_type: &str,
    is_public: bool,
    is_threshold: bool,
) {
    log_storage_success_optional_variant(
        req_id,
        storage_info,
        data_type,
        is_public,
        Some(is_threshold),
    );
}

/// Logs a message indicating successful storage of data.
///
/// # Arguments
/// * `req_id` - The request ID associated with the stored data
/// * `storage_info` - Information about the storage where data was stored
/// * `data_type` - Type of the data that was stored
/// * `is_public` - Whether the stored data is public or private
/// * `is_threshold` - If this is None, then no variant is logged.
///   If Some(true), threshold is logged, if Some(false), centralized is logged.
///
/// # Note
/// The log level is set to `info` to track successful storage operations.
pub fn log_storage_success_optional_variant<T: Display, U: Display>(
    req_id: T,
    storage_info: U,
    data_type: &str,
    is_public: bool,
    is_threshold: Option<bool>,
) {
    let visibility = if is_public { "public" } else { "private" };
    let variant = match is_threshold {
        Some(true) => "threshold ",
        Some(false) => "centralized",
        None => "",
    };

    tracing::info!(
        "Successfully stored {} {}{} under the handle {} in storage \"{}\"",
        visibility,
        variant,
        data_type,
        req_id,
        storage_info
    );
}

/// Calculates the maximum number of bits based on DKG (Distributed Key Generation) parameters.
///
/// This function determines the appropriate bit length for cryptographic operations
/// based on the provided DKG parameters. It includes fallback mechanisms to ensure
/// a valid value is always returned.
///
/// # Arguments
/// * `dkg_params` - The DKG parameters used for the calculation
///
/// # Returns
/// The calculated maximum number of bits, or a fallback value if calculation fails.
///
/// # Note
/// This function logs warnings if fallback values are used, which may indicate
/// suboptimal cryptographic parameters.
pub fn calculate_max_num_bits(dkg_params: &DKGParams) -> usize {
    // Extract constant to improve readability
    const DEFAULT_MAX_NUM_BITS: usize =
        threshold_fhe::execution::zk::constants::ZK_DEFAULT_MAX_NUM_BITS;
    const FALLBACK_BITS: usize = 16;

    // Cache the params_basics_handle to avoid calling it twice
    let params_basics = dkg_params.get_params_basics_handle();

    // Try to calculate max_messages, but fall back to default if it fails
    let max_messages = match max_num_messages(
        &params_basics.get_compact_pk_enc_params(),
        DEFAULT_MAX_NUM_BITS,
    ) {
        Ok(messages) => messages,
        Err(e) => {
            tracing::error!("Failed to calculate max_num_messages: {}", e);
            return FALLBACK_BITS;
        }
    };

    if params_basics.lwe_dimension().0 < max_messages.0 {
        tracing::warn!(
            "lwe dimension is too small, using max num bits: {}",
            FALLBACK_BITS
        );
        FALLBACK_BITS
    } else {
        tracing::warn!("Using max num bits: {}", DEFAULT_MAX_NUM_BITS);
        DEFAULT_MAX_NUM_BITS
    }
}

/// Generalizes `get_core_signing_key`, `get_client_verification_key` and
/// `get_core_ca_cert`. Can be used to implement a getter for any per-entity
/// (core or client) data.
///
/// # Arguments
/// * `storage` - The storage backend containing the per-entity data, such as signing keys, representable as `T`
/// * `data_type` - The type tag for the per-entity data used in storage URLs (one of `ClientDataType`, `PrivDataType`, `PubDataType`)
///
/// # Returns
/// The `T` value if found and valid, or an error if:
/// - The key data cannot be read from storage
/// - No key or multiple keys are found when exactly one is expected
///
/// # Errors
/// Returns an error if the storage operation fails, no key is found, or multiple keys are found.
async fn get_unique<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
    U: Display,
>(
    storage: &S,
    data_type: U,
) -> anyhow::Result<T> {
    let data_map: HashMap<RequestId, T> = read_all_data_versioned(storage, &data_type.to_string())
        .await
        .map_err(|e| {
            anyhow_error_and_warn_log(format!(
                "Failed to read {} from \"{}\": {e}",
                &data_type.to_string(),
                storage.info()
            ))
        })?;

    if data_map.values().len() != 1 {
        return Err(anyhow_error_and_warn_log(format!(
            "{} storage should contain exactly one entry, but contains {} entries for storage \"{}\"",
            data_type,
            data_map.values().len(),
            storage.info()
        )));
    }

    let value = data_map.into_values().next().unwrap(); // Safe unwrap since we checked length above
    Ok(value)
}

pub async fn get_core_signing_key<S: StorageReader>(storage: &S) -> anyhow::Result<PrivateSigKey> {
    get_unique::<S, PrivateSigKey, PrivDataType>(storage, PrivDataType::SigningKey).await
}

pub async fn get_core_verification_key<S: StorageReader>(
    storage: &S,
) -> anyhow::Result<PublicSigKey> {
    get_unique::<S, PublicSigKey, PubDataType>(storage, PubDataType::VerfKey).await
}

pub async fn get_client_signing_key<S: Storage>(storage: &S) -> anyhow::Result<PrivateSigKey> {
    get_unique::<S, PrivateSigKey, ClientDataType>(storage, ClientDataType::SigningKey).await
}

pub async fn get_client_verification_key<S: Storage>(storage: &S) -> anyhow::Result<PublicSigKey> {
    get_unique::<S, PublicSigKey, ClientDataType>(storage, ClientDataType::VerfKey).await
}
