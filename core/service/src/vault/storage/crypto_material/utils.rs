//! Utility functions for cryptographic material management in the KMS.
//!
//! This module provides various utility functions that support cryptographic operations,
//! storage management, and common operations needed by the cryptographic material
//! storage system.

use crate::consts::{SIGNING_KEY_ID, signing_material_id};
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, RootSigningSeed};
use crate::cryptography::signing::{
    Ed25519VerfKey, MlDsaVerfKey, SigningSchemeType, UnifiedPublicSigKey,
};
use crate::vault::storage::crypto_material::base::StorageError;
use crate::vault::storage::{StorageExt, StorageReader, StorageReaderExt};
use crate::{
    anyhow_error_and_warn_log,
    client::client_non_wasm::ClientDataType,
    vault::storage::{Storage, read_all_data_versioned},
};
use aes_prng::AesRng;
use kms_grpc::RequestId;
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use rand::SeedableRng;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fmt::Display;
use tfhe::{Unversionize, named::Named};
use threshold_execution::tfhe_internals::parameters::DKGParams;
use threshold_execution::zk::ceremony::max_num_messages;

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
        AesRng::seed_from_u64(seed.unwrap_or(42))
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
pub async fn data_exists<S: StorageReader>(
    storage: &S,
    req_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<bool> {
    storage
        .data_exists(req_id, data_type)
        .await
        .map_err(|e| anyhow_error_and_warn_log(format!("Failed to check if data exists: {e}")))
}

/// Checks if data of the specified type exists in the provided storage.
///
/// # Arguments
/// * `storage` - The storage backend to check for data existence
/// * `req_id` - The request ID used to compute the storage URL
/// * `epoch_id` - The epoch ID used to compute the storage URL
/// * `data_type` - Type of the data to check (used for URL computation)
///
/// # Returns
/// `Ok(true)` if data exists, `Ok(false)` if it doesn't, or an error if the check fails.
///
/// # Errors
/// Returns an error if URL computation or storage access fails.
pub async fn data_exists_at_epoch<S: StorageReaderExt>(
    storage: &S,
    req_id: &RequestId,
    epoch_id: &EpochId,
    data_type: &str,
) -> anyhow::Result<bool> {
    storage
        .data_exists_at_epoch(req_id, epoch_id, data_type)
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
#[cfg(test)]
pub(in crate::vault::storage::crypto_material) async fn check_data_exists<
    PubS: Storage,
    PrivS: Storage,
>(
    pub_storage: &PubS,
    priv_storage: &PrivS,
    req_id: &RequestId,
    pub_data_type: &PubDataType,
    priv_data_type: &PrivDataType,
) -> anyhow::Result<bool> {
    // No need to use epoch for public data existence check
    let pub_exists = data_exists(pub_storage, req_id, &pub_data_type.to_string()).await?;

    if !pub_exists {
        return Ok(false);
    }

    data_exists(priv_storage, req_id, &priv_data_type.to_string()).await
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
/// * `epoch_id` - The epoch ID used to compute storage URLs for the private data
/// * `pub_data_type` - Type of the public data to check
/// * `priv_data_type` - Type of the private data to check
///
/// # Returns
/// `Ok(true)` if both the public and private data exist, `Ok(false)` if either is missing,
/// or an error if any check fails or an error occurs.
/// `Err(StorageError::ReadingError)` is returned if there is an error accessing the storage, with an error log indicating the failure.
///
/// # Note
/// This function short-circuits and returns `Ok(false)` if public data is not found,
/// without checking for private data.
pub async fn check_data_exists_at_epoch<PubS: Storage, PrivS: StorageExt>(
    pub_storage: &PubS,
    priv_storage: &PrivS,
    req_id: &RequestId,
    epoch_id: &EpochId,
    pub_data_type: &PubDataType,
    priv_data_type: &PrivDataType,
) -> Result<bool, StorageError> {
    // No need to use epoch for public data existence check
    if !data_exists(pub_storage, req_id, &pub_data_type.to_string())
        .await
        .map_err(|_| StorageError::Reading)?
    {
        let msg = format!(
            "Some public data (at least one of {pub_data_type:?}) not found for request {req_id} and epoch {epoch_id}"
        );
        tracing::warn!(msg);
        return Ok(false);
    }
    if !data_exists_at_epoch(priv_storage, req_id, epoch_id, &priv_data_type.to_string())
        .await
        .map_err(|_| StorageError::Reading)?
    {
        let msg = format!(
            "Some private data (at least one of {priv_data_type:?}) not found for request {req_id} and epoch {epoch_id}"
        );
        tracing::warn!(msg);
        return Ok(false);
    }
    Ok(true)
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
            data_type,
            id,
            storage_info,
            pub_info
        ),
        None => tracing::warn!(
            "{} with ID {} already exist, skipping generation",
            data_type,
            id
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
        Some(false) => "centralized ",
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
    const DEFAULT_MAX_NUM_BITS: usize = threshold_execution::zk::constants::ZK_DEFAULT_MAX_NUM_BITS;
    const FALLBACK_BITS: usize = 16;

    // Try to calculate max_messages, but fall back to default if it fails
    let max_messages =
        match max_num_messages(&dkg_params.compact_pk_enc_params(), DEFAULT_MAX_NUM_BITS) {
            Ok(messages) => messages,
            Err(e) => {
                tracing::error!("Failed to calculate max_num_messages: {}", e);
                return FALLBACK_BITS;
            }
        };

    if dkg_params.lwe_dimension().0 < max_messages.0 {
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
                data_type,
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

/// The node's signing identity: its ECDSA key with the root seed attached.
///
/// A node that has not yet had `kms-gen-keys` generate a seed simply has none
/// attached: that is ECDSA-only operation, not a failure, and must not stop the
/// server from booting.
pub async fn get_core_signing_key<S: StorageReader>(storage: &S) -> anyhow::Result<PrivateSigKey> {
    let sk =
        get_unique::<S, PrivateSigKey, PrivDataType>(storage, PrivDataType::SigningKey).await?;
    match get_core_root_signing_seed(storage).await? {
        Some(seed) => Ok(sk.with_root_seed(seed)),
        None => {
            tracing::warn!(
                "No root signing seed found in storage \"{}\"; this node can only sign under \
                 ECDSA. Run kms-gen-keys to generate one.",
                storage.info()
            );
            Ok(sk)
        }
    }
}

/// The node's root signing seed, if it has one.
///
/// Absence is a normal state — a node that predates the seed, or one that has not
/// yet run `kms-gen-keys` — so this returns `None` rather than failing.
pub async fn get_core_root_signing_seed<S: StorageReader>(
    storage: &S,
) -> anyhow::Result<Option<RootSigningSeed>> {
    let mut seeds: HashMap<RequestId, RootSigningSeed> =
        read_all_data_versioned(storage, &PrivDataType::SigningSeed.to_string())
            .await
            .map_err(|e| {
                anyhow_error_and_warn_log(format!(
                    "Failed to read the root signing seed from \"{}\": {e}",
                    storage.info()
                ))
            })?;
    let seed = seeds.remove(&SIGNING_KEY_ID);
    if !seeds.is_empty() {
        tracing::warn!(
            "Ignoring {} root signing seed(s) under handles other than {} in storage \"{}\": {}. \
             Only the seed under {} is ever used.",
            seeds.len(),
            *SIGNING_KEY_ID,
            storage.info(),
            seeds
                .keys()
                .map(|id| id.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            *SIGNING_KEY_ID
        );
    }
    Ok(seed)
}

pub async fn get_client_signing_key<S: Storage>(storage: &S) -> anyhow::Result<PrivateSigKey> {
    get_unique::<S, PrivateSigKey, ClientDataType>(storage, ClientDataType::SigningKey).await
}

pub async fn get_client_verification_key<S: Storage>(storage: &S) -> anyhow::Result<PublicSigKey> {
    get_unique::<S, PublicSigKey, ClientDataType>(storage, ClientDataType::VerfKey).await
}

/// Read the verification key that [`store_scheme_verification_key`] wrote for
/// `scheme`, and tag it back up into a [`UnifiedPublicSigKey`].
pub async fn read_scheme_verification_key<S: StorageReader>(
    storage: &S,
    scheme: SigningSchemeType,
) -> anyhow::Result<UnifiedPublicSigKey> {
    read_verification_key_at(
        storage,
        &signing_material_id(scheme),
        PubDataType::TypedVerfKey,
        scheme,
    )
    .await
}

/// Read a `scheme` verification key from an explicit handle and folder, and tag it
/// back up into a [`UnifiedPublicSigKey`]. The inverse of
/// [`store_verification_key_at`].
pub async fn read_verification_key_at<S: StorageReader>(
    storage: &S,
    req_id: &RequestId,
    folder: PubDataType,
    scheme: SigningSchemeType,
) -> anyhow::Result<UnifiedPublicSigKey> {
    let req_id = *req_id;
    let data_type = folder.to_string();
    Ok(match scheme {
        SigningSchemeType::Ecdsa256k1 => {
            let vk: PublicSigKey = storage.read_data(&req_id, &data_type).await?;
            UnifiedPublicSigKey::Ecdsa256k1(vk)
        }
        SigningSchemeType::Ed25519 => {
            let vk: Ed25519VerfKey = storage.read_data(&req_id, &data_type).await?;
            UnifiedPublicSigKey::Ed25519(vk)
        }
        SigningSchemeType::MlDsa44 => {
            let vk: MlDsaVerfKey<MlDsa44> = storage.read_data(&req_id, &data_type).await?;
            UnifiedPublicSigKey::MlDsa44(Box::new(vk))
        }
        SigningSchemeType::MlDsa65 => {
            let vk: MlDsaVerfKey<MlDsa65> = storage.read_data(&req_id, &data_type).await?;
            UnifiedPublicSigKey::MlDsa65(Box::new(vk))
        }
        SigningSchemeType::MlDsa87 => {
            let vk: MlDsaVerfKey<MlDsa87> = storage.read_data(&req_id, &data_type).await?;
            UnifiedPublicSigKey::MlDsa87(Box::new(vk))
        }
    })
}
