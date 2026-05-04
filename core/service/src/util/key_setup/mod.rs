cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        pub mod test_tools;

        use crate::dummy_domain;
        use crate::engine::base::INSECURE_PREPROCESSING_ID;
        use crate::engine::base::{
            compute_info_compressed_keygen_from_digests, compute_info_crs_from_digest,
            CrsGenMetadata,
        };
        use crate::engine::base::{DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, safe_serialize_hash_element_versioned};
        use crate::engine::centralized::central_kms::{gen_centralized_crs, generate_fhe_keys};
        use crate::engine::threshold::service::{PublicKeyMaterial, ThresholdFheKeys};
        use crate::vault::storage::crypto_material::{
            calculate_max_num_bits,  data_exists, get_core_signing_key,
        };
        use crate::vault::storage::{delete_at_request_and_epoch_id, delete_at_request_id, store_versioned_at_request_and_epoch_id, StorageExt};
        use futures_util::future;
        use kms_grpc::identifiers::EpochId;
        use std::sync::Arc;
        use tfhe::Seed;
        use threshold_execution::keyset_config::StandardKeySetConfig;
        use threshold_execution::tfhe_internals::parameters::DKGParams;
        use threshold_execution::tfhe_internals::test_feature::gen_key_set;
        use threshold_execution::tfhe_internals::test_feature::keygen_all_party_shares_from_keyset;
        use threshold_execution::zk::ceremony::{max_num_bits_from_crs, public_parameters_by_trusted_setup};
        use threshold_types::session_id::SessionId;
    }
}

use crate::client::client_non_wasm::ClientDataType;
use crate::cryptography::signatures::{PrivateSigKey, gen_sig_keys};
use crate::engine::base::compute_handle;
use crate::vault::storage::crypto_material::{get_rng, log_data_exists, log_storage_success};
use crate::vault::storage::{
    Storage, StorageReader, StorageType, file::FileStorage, read_all_data_versioned,
    store_text_at_request_id, store_versioned_at_request_id,
};
use itertools::Itertools;
use k256::pkcs8::EncodePrivateKey;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use std::collections::HashMap;
use std::path::Path;

/// Compact public key for FHE operations
pub type FhePublicKey = tfhe::CompactPublicKey;

/// Client key for FHE operations (contains private parameters)
pub type FhePrivateKey = tfhe::ClientKey;

/// Generates and stores client signing and verification keys if they don't exist.
///
/// This function handles the complete key setup workflow for clients:
/// 1. Initializes client storage
/// 2. Checks for existing keys
/// 3. Generates new keys if needed
/// 4. Stores private and public keys
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed or an error occurred
///
/// # Note
/// Primarily used for testing and debugging via the [Client].
///
/// # Panics
/// - If storage initiation fails
/// - If key generation or storage operations fail
/// - If handle computation fails
pub async fn ensure_client_keys_exist(
    optional_path: Option<&Path>,
    req_id: &RequestId,
    deterministic: bool,
) -> bool {
    // Initialize client storage with error handling
    let mut client_storage = match FileStorage::new(optional_path, StorageType::CLIENT, None) {
        Ok(storage) => storage,
        Err(e) => {
            panic!("Failed to create client storage: {e}");
        }
    };

    // Check if keys already exist with error handling
    let temp: HashMap<RequestId, PrivateSigKey> =
        match read_all_data_versioned(&client_storage, &ClientDataType::SigningKey.to_string())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!("Failed to read existing client signing keys: {}", e);
                return false;
            }
        };

    if !temp.is_empty() {
        // If signing keys already exist, then do nothing
        let storage_path = client_storage.root_dir().to_string_lossy();
        tracing::info!(
            "Client signing keys already exist at {}, skipping generation",
            storage_path
        );
        return false;
    }

    // Generate new signing key pair
    let mut rng = get_rng(deterministic, None);
    let (client_pk, client_sk) = gen_sig_keys(&mut rng);

    // Store private client key with error handling
    if let Err(e) = store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_sk,
        &ClientDataType::SigningKey.to_string(),
    )
    .await
    {
        panic!("Failed to store private client key: {e}");
    }
    log_storage_success(req_id, client_storage.info(), "client key", false, false);

    // Compute handle with error handling
    let pk_handle = match compute_handle(&client_pk) {
        Ok(handle) => handle,
        Err(e) => {
            panic!("Failed to compute handle for client public key: {e}");
        }
    };

    // Store public client key with error handling
    if let Err(e) = store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_pk,
        &ClientDataType::VerfKey.to_string(),
    )
    .await
    {
        panic!("Failed to store public client key: {e}");
    }
    log_storage_success(pk_handle, client_storage.info(), "client key", true, false);

    true
}

/// Ensures central server signing and verification keys exist.
///
/// This function follows a fail-fast approach:
/// 1. Validates storage consistency
/// 2. Checks for existing keys
/// 3. Generates and stores new keys if needed
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed
///
/// # Panics
/// - If storage validation fails (inconsistent state)
/// - If key generation or storage operations fail
pub async fn ensure_central_server_signing_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    req_id: &RequestId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: Storage,
{
    // Check if keys already exist with error handling
    let temp: HashMap<RequestId, PrivateSigKey> =
        match read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string()).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!("Failed to read existing server signing keys: {}", e);
                return false;
            }
        };

    if !temp.is_empty() {
        // If signing keys already exist, check if VerfAddress/VerfKey need regeneration
        log_data_exists(
            priv_storage.info(),
            None::<String>,
            "",
            "Server signing keys",
        );

        // Even if signing keys exist, VerfAddress and VerfKey might not
        if let Some(sk) = temp.get(req_id) {
            let pk = sk.verf_key();

            // Regenerate VerfAddress if missing
            let verf_address_exists = match pub_storage
                .data_exists(req_id, &PubDataType::VerfAddress.to_string())
                .await
            {
                Ok(exists) => exists,
                Err(e) => {
                    tracing::warn!(
                        "Failed to check VerfAddress existence: {}, will attempt regeneration",
                        e
                    );
                    false
                }
            };
            if !verf_address_exists {
                let ethereum_address = pk.address();
                if let Err(store_err) = store_text_at_request_id(
                    pub_storage,
                    req_id,
                    &ethereum_address.to_string(),
                    &PubDataType::VerfAddress.to_string(),
                )
                .await
                {
                    tracing::error!("Failed to regenerate VerfAddress: {}", store_err);
                } else {
                    tracing::info!(
                        "Regenerated VerfAddress {} from existing signing key",
                        ethereum_address
                    );
                }
            }

            // Regenerate VerfKey if missing
            let verf_key_exists = match pub_storage
                .data_exists(req_id, &PubDataType::VerfKey.to_string())
                .await
            {
                Ok(exists) => exists,
                Err(e) => {
                    tracing::warn!(
                        "Failed to check VerfKey existence: {}, will attempt regeneration",
                        e
                    );
                    false
                }
            };
            if !verf_key_exists {
                if let Err(store_err) = store_versioned_at_request_id(
                    pub_storage,
                    req_id,
                    &pk,
                    &PubDataType::VerfKey.to_string(),
                )
                .await
                {
                    tracing::error!("Failed to regenerate VerfKey: {}", store_err);
                } else {
                    tracing::info!("Regenerated VerfKey from existing signing key");
                }
            }
        }

        return false;
    }

    let mut rng = get_rng(deterministic, Some(0));
    let (pk, sk) = gen_sig_keys(&mut rng);

    // Store public verification key
    if let Err(e) =
        store_versioned_at_request_id(pub_storage, req_id, &pk, &PubDataType::VerfKey.to_string())
            .await
    {
        tracing::error!("Failed to store public verification key: {}", e);
        return false;
    }
    log_storage_success(
        req_id,
        pub_storage.info(),
        "server signing key",
        true,
        false,
    );

    let ethereum_address = pk.address();

    // Store ethereum address (derived from public key), needed for KMS signature verification
    if let Err(e) = store_text_at_request_id(
        pub_storage,
        req_id,
        &ethereum_address.to_string(),
        &PubDataType::VerfAddress.to_string(),
    )
    .await
    {
        tracing::error!("Failed to store ethereum address: {}", e);
        return false;
    }
    tracing::info!(
        "Successfully stored ethereum address {} under the handle {} in storage \"{}\"",
        ethereum_address,
        req_id,
        pub_storage.info()
    );

    // Store private signing key
    if let Err(e) = store_versioned_at_request_id(
        priv_storage,
        req_id,
        &sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    {
        tracing::error!("Failed to store private signing key: {}", e);
        return false;
    }
    log_storage_success(
        req_id,
        priv_storage.info(),
        "server signing key",
        false,
        false,
    );

    true
}

/// Generates and stores a Common Reference String (CRS) if it doesn't exist.
///
/// Handles the complete CRS lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing CRS
/// 3. Generates new CRS with the given parameters
/// 4. Stores both public CRS and private metadata
///
/// # Returns
/// - `true` if new CRS was generated
/// - `false` if CRS already existed
///
/// # Panics
/// - If storage validation fails
/// - If CRS generation fails
/// - If storage operations fail
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_central_crs_exists<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    crs_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Check if data already exists in both storages

    use crate::vault::storage::crypto_material::check_data_exists_at_epoch;

    match check_data_exists_at_epoch(
        pub_storage,
        priv_storage,
        crs_id,
        epoch_id,
        &[PubDataType::CRS.to_string()],
        &[PrivDataType::CrsInfo.to_string()],
    )
    .await
    {
        Ok(true) => {
            log_data_exists(priv_storage.info(), Some(pub_storage.info()), crs_id, "CRS");
            return false;
        }
        Ok(false) => {} // Continue with generation
        Err(e) => {
            tracing::warn!("Error checking if CRS exists: {}", e);
            // Continue with generation, assuming data doesn't exist
        }
    }

    // Get signing key with proper error handling
    let sk = match get_core_signing_key(priv_storage).await {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Failed to get signing key: {}", e);
            return false; // Cannot proceed without signing key
        }
    };
    let mut rng = get_rng(deterministic, Some(0));

    // Calculate max_num_bits based on DKG parameters - now handles errors internally
    let max_num_bits = calculate_max_num_bits(&dkg_params);

    // Convert usize to Option<u32> for gen_centralized_crs
    let max_num_bits_u32 = Some(max_num_bits as u32);

    // Use proper error handling instead of unwrap
    let domain = dummy_domain();
    let (pp, crs_info) = match gen_centralized_crs(
        &sk,
        &dkg_params,
        max_num_bits_u32,
        &domain,
        vec![],
        crs_id,
        &mut rng,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate centralized CRS: {}", e);
            return false; // Cannot proceed without CRS
        }
    };

    // Store private CRS info with proper error handling
    if let Err(e) = store_versioned_at_request_and_epoch_id(
        priv_storage,
        crs_id,
        epoch_id,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    {
        tracing::error!("Failed to store private CRS info: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_id, priv_storage.info(), "CRS data", false, false);

    // Store public CRS with proper error handling
    if let Err(e) =
        store_versioned_at_request_id(pub_storage, crs_id, &pp, &PubDataType::CRS.to_string()).await
    {
        tracing::error!("Failed to store public CRS: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_id, pub_storage.info(), "CRS data", true, false);

    true
}

/// Ensures central server FHE keys exist.
///
/// Manages the complete FHE key lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing keys
/// 3. Generates new key pairs with the given parameters
/// 4. Stores both public and private keys with metadata
/// 5. Manages two distinct key sets under [key_id] and [other_key_id]
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed
///
/// # Panics
/// - If storage validation fails
/// - If key generation fails
/// - If storage operations fail
#[cfg(any(test, feature = "testing"))]
#[allow(clippy::too_many_arguments)]
pub async fn ensure_central_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    key_id: &RequestId,
    other_key_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
    write_privkey: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Check if PUBLIC data already exists. If so, skip regeneration entirely.
    //
    // Key generation uses seed-based XOF expansion, making it non-deterministic
    // across calls unless the same seed is used. If PUB keys exist but PRIV was
    // purged (e.g., for backup recovery tests), regenerating would create keys
    // with different digests that don't match the existing PUB data (since
    // store_data doesn't overwrite). The missing PRIV data will be restored
    // from backup.
    let pub_type = PubDataType::CompressedXofKeySet.to_string();
    let pub_types_to_purge = [
        PubDataType::CompressedXofKeySet.to_string(),
        PubDataType::PublicKey.to_string(),
        PubDataType::ServerKey.to_string(),
    ];
    let pub_complete = data_exists(pub_storage, key_id, &pub_type)
        .await
        .unwrap_or(false)
        && data_exists(pub_storage, other_key_id, &pub_type)
            .await
            .unwrap_or(false);
    if pub_complete {
        log_data_exists(
            priv_storage.info(),
            Some(pub_storage.info()),
            key_id,
            "FHE keys",
        );
        return false;
    }

    // PUB data is incomplete — purge any leftover fragments and regenerate everything.
    for existing_pub_type in &pub_types_to_purge {
        let _ = delete_at_request_id(pub_storage, key_id, existing_pub_type).await;
        let _ = delete_at_request_id(pub_storage, other_key_id, existing_pub_type).await;
    }
    let _ = delete_at_request_and_epoch_id(
        priv_storage,
        key_id,
        epoch_id,
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await;

    // Get signing key with proper error handling
    let sk = match get_core_signing_key(priv_storage).await {
        Ok(key) => key,
        Err(e) => {
            tracing::error!("Failed to get signing key: {}", e);
            return false; // Cannot proceed without signing key
        }
    };

    let seed = match deterministic {
        true => Some(Seed(42)),
        false => None,
    };

    // Generate the two FHE key sets in parallel on the rayon pool.
    let key_id_1 = *key_id;
    let key_id_2 = *other_key_id;
    let sk_1 = sk.clone();
    let sk_2 = sk;
    let (fhekey1, fhekey2) = tokio::task::spawn_blocking(move || {
        rayon::join(
            || {
                generate_fhe_keys(
                    &sk_1,
                    dkg_params,
                    StandardKeySetConfig::default().secret_key_config,
                    &key_id_1,
                    &INSECURE_PREPROCESSING_ID,
                    seed,
                    &dummy_domain(),
                    vec![],
                )
            },
            || {
                generate_fhe_keys(
                    &sk_2,
                    dkg_params,
                    StandardKeySetConfig::default().secret_key_config,
                    &key_id_2,
                    &INSECURE_PREPROCESSING_ID,
                    seed,
                    &dummy_domain(),
                    vec![],
                )
            },
        )
    })
    .await
    .expect("FHE keygen task panicked");

    let (compressed_keyset_1, public_key_1, key_info_1) = match fhekey1 {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate first set of FHE keys: {}", e);
            return false;
        }
    };
    let (compressed_keyset_2, public_key_2, key_info_2) = match fhekey2 {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate second set of FHE keys: {}", e);
            return false;
        }
    };

    let priv_fhe_map = HashMap::from([(*key_id, key_info_1), (*other_key_id, key_info_2)]);
    let pub_fhe_map = HashMap::from([
        (*key_id, (compressed_keyset_1, public_key_1)),
        (*other_key_id, (compressed_keyset_2, public_key_2)),
    ]);

    // Store private key data
    for (req_id, key_info) in &priv_fhe_map {
        // Store key info
        if let Err(e) = store_versioned_at_request_and_epoch_id(
            priv_storage,
            req_id,
            epoch_id,
            key_info,
            &PrivDataType::FhePrivateKey.to_string(),
        )
        .await
        {
            tracing::error!("Failed to store key info for request ID {}: {}", req_id, e);
            continue; // Skip this key but try others
        }
        log_storage_success(req_id, priv_storage.info(), "key data", false, false);

        // When the flag [write_privkey] is set, store the private key separately
        if write_privkey {
            if let Err(e) = store_versioned_at_request_and_epoch_id(
                priv_storage,
                req_id,
                epoch_id,
                &key_info.client_key,
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await
            {
                tracing::error!(
                    "Failed to store private key for request ID {}: {}",
                    req_id,
                    e
                );
                continue; // Skip this key but try others
            }
            log_storage_success(
                req_id,
                priv_storage.info(),
                "individual private key",
                false,
                false,
            );
        }
    }

    // Store compressed keyset and the public key derived from it as public key data
    for (req_id, (compressed_keyset, public_key)) in pub_fhe_map {
        tracing::info!("Storing compressed keyset");
        if let Err(e) = store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &compressed_keyset,
            &PubDataType::CompressedXofKeySet.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store compressed keyset for request ID {}: {}",
                req_id,
                e
            );
            continue; // Skip this key but try others
        }
        log_storage_success(req_id, pub_storage.info(), "compressed keyset", true, false);

        if let Err(e) = store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store public key for request ID {}: {}",
                req_id,
                e
            );
            continue;
        }
        log_storage_success(req_id, pub_storage.info(), "public key", true, false);
    }
    true
}

/// Configuration for threshold signing key generation.
///
/// Defines the signing participation model for the threshold system.
pub enum ThresholdSigningKeyConfig {
    /// All parties participate in signing (requires list of party identifiers)
    AllParties(Vec<String>),
    /// Only one designated party participates in signing (party index, party identifier)
    OneParty(usize, String),
}

/// Generates and stores threshold server signing and verification keys.
///
/// Implements the complete threshold key setup workflow:
/// 1. Validates storage consistency
/// 2. Checks for existing keys
/// 3. Generates new keys based on configuration
/// 4. Stores keys for each server under [request_id]
///
/// # Returns
/// - `true` if new keys were generated
/// - `false` if keys already existed
/// - `Err` if an operation failed
///
/// # Panics
/// - If storage validation fails
/// - If key generation fails with invalid parameters
pub async fn ensure_threshold_server_signing_keys_exist<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    request_id: &RequestId,
    deterministic: bool,
    config: ThresholdSigningKeyConfig,
    tls_wildcard: bool,
) -> anyhow::Result<bool>
where
    PubS: Storage,
    PrivS: Storage,
{
    // Validate input parameters
    if pub_storages.len() != priv_storages.len() {
        let msg = format!(
            "Number of public storages ({}) and private storages ({}) must be equal",
            pub_storages.len(),
            priv_storages.len()
        );
        tracing::error!(msg);
        panic!("{}", msg);
    }
    let parties = match config {
        ThresholdSigningKeyConfig::AllParties(parties) => {
            (1..=parties.len()).zip_eq(parties).collect_vec()
        }
        ThresholdSigningKeyConfig::OneParty(i, subject) => {
            std::iter::once((i, subject)).collect_vec()
        }
    };

    // Validate party indices
    for &(i, _) in &parties {
        if i == 0 || i > pub_storages.len() {
            let msg = format!(
                "Invalid party index: {} (must be between 1 and {})",
                i,
                pub_storages.len()
            );
            tracing::error!(msg);
            panic!("{}", msg);
        }
    }

    for (i, subject_str) in parties {
        let mut rng = get_rng(deterministic, Some(i as u64));

        // Check if keys already exist with error handling
        let temp: HashMap<RequestId, PrivateSigKey> = match read_all_data_versioned(
            &priv_storages[i - 1],
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!(
                    "Failed to read existing server signing keys for party {}: {}",
                    { i },
                    e
                );
                continue; // Skip this party but try others
            }
        };

        if !temp.is_empty() {
            // If signing keys already exist, then do nothing
            log_data_exists(
                priv_storages[i - 1].info(),
                None::<String>,
                "",
                "Threshold server signing keys",
            );
            // Even if signing keys exist, CA certificates and VerfAddress might not
            if let Some(sk) = temp.get(request_id) {
                // Regenerate VerfAddress if missing
                if !pub_storages[i - 1]
                    .data_exists(request_id, &PubDataType::VerfAddress.to_string())
                    .await?
                {
                    let pk = sk.verf_key();
                    let ethereum_address = pk.address();
                    if let Err(store_err) = store_text_at_request_id(
                        &mut pub_storages[i - 1],
                        request_id,
                        &ethereum_address.to_string(),
                        &PubDataType::VerfAddress.to_string(),
                    )
                    .await
                    {
                        tracing::error!(
                            "Failed to regenerate VerfAddress for party {}: {}",
                            i,
                            store_err
                        );
                    } else {
                        tracing::info!(
                            "Regenerated VerfAddress {} for party {} from existing signing key",
                            ethereum_address,
                            i
                        );
                    }
                }

                // Regenerate VerfKey if missing
                if !pub_storages[i - 1]
                    .data_exists(request_id, &PubDataType::VerfKey.to_string())
                    .await?
                {
                    let pk = sk.verf_key();
                    if let Err(store_err) = store_versioned_at_request_id(
                        &mut pub_storages[i - 1],
                        request_id,
                        &pk,
                        &PubDataType::VerfKey.to_string(),
                    )
                    .await
                    {
                        tracing::error!(
                            "Failed to regenerate VerfKey for party {}: {}",
                            i,
                            store_err
                        );
                    } else {
                        tracing::info!(
                            "Regenerated VerfKey for party {} from existing signing key",
                            i
                        );
                    }
                }

                // Regenerate CA certificate if missing
                if !pub_storages[i - 1]
                    .data_exists(request_id, &PubDataType::CACert.to_string())
                    .await?
                {
                    ensure_ca_cert_exists(
                        &mut pub_storages[i - 1],
                        sk,
                        request_id,
                        subject_str,
                        tls_wildcard,
                    )
                    .await?;
                }
            } else {
                tracing::error!(
                    "Failed to regenerate CA certificate from existing server signing key for party {i}"
                )
            };

            continue;
        }

        let (pk, sk) = gen_sig_keys(&mut rng);

        // Store public verification key
        if let Err(store_err) = store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store public verification key for party {}: {}",
                { i },
                store_err
            );
            continue; // Skip this party but try others
        }
        log_storage_success(
            request_id,
            pub_storages[i - 1].info(),
            "server signing key",
            true,
            true,
        );

        let ethereum_address = pk.address();

        // Store ethereum address (derived from public key), needed for KMS signature verification
        if let Err(store_err) = store_text_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &ethereum_address.to_string(),
            &PubDataType::VerfAddress.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store ethereum address for party {}: {}",
                i,
                store_err
            );
            continue; // Skip this party but try others
        }
        tracing::info!(
            "Successfully stored ethereum address {} under the handle {} in storage \"{}\"",
            ethereum_address,
            request_id,
            pub_storages[i - 1].info()
        );

        // Store private signing key
        if let Err(store_err) = store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            request_id,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store private signing key for party {}: {}",
                i,
                store_err
            );
            continue; // Skip this party but try others
        }
        log_storage_success(
            request_id,
            priv_storages[i - 1].info(),
            "server signing key",
            false,
            true,
        );

        // Generate CA certificate
        ensure_ca_cert_exists(
            &mut pub_storages[i - 1],
            &sk,
            request_id,
            subject_str,
            tls_wildcard,
        )
        .await?;
    }
    Ok(true)
}

/// Generates stores CA certificates that are used to issue ephemeral mTLS
/// certificates in the enclave.
async fn ensure_ca_cert_exists<PubS: Storage>(
    pub_storage: &mut PubS,
    sk: &PrivateSigKey,
    req_id: &RequestId,
    subject: String,
    tls_wildcard: bool,
) -> anyhow::Result<()> {
    // self-sign a CA certificate with the private signing key
    let sk_der = {
        // Will be fixed as part of [#2781](https://github.com/zama-ai/kms-internal/issues/2781).
        #[expect(deprecated)]
        let ecdsa_sk = sk.sk();
        ecdsa_sk.to_pkcs8_der()?
    };
    let ca_keypair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
        &sk_der.as_bytes().into(),
        &rcgen::PKCS_ECDSA_P256K1_SHA256,
    )?;
    let (ca_cert_ki, ca_cert, _ca_params) =
        threshold_networking::tls_certs::create_ca_cert_from_ca_keypair(
            subject.as_str(),
            tls_wildcard,
            &ca_keypair,
        )?;

    // Store self-signed CA certificate
    if let Err(store_err) = store_text_at_request_id(
        pub_storage,
        req_id,
        &ca_cert.pem(),
        &PubDataType::CACert.to_string(),
    )
    .await
    {
        tracing::error!(
            "Failed to store CA certificate for party {}: {}",
            subject,
            store_err
        );
    }
    tracing::info!(
        "Successfully stored CA certificate {} under the handle {} in storage \"{}\"",
        ca_cert_ki,
        req_id,
        pub_storage.info()
    );

    Ok(())
}

/// Generates and stores threshold FHE key shares and metadata.
///
/// Manages the complete threshold FHE key lifecycle:
/// 1. Validates input parameters and storage consistency
/// 2. Checks for existing keys
/// 3. Generates key shares with the given threshold parameters
/// 4. Computes and stores metadata for each party
/// 5. Distributes keys to all parties
///
/// # Returns
/// - `true` if new keys were generated and distributed
/// - `false` if keys already existed or an error occurred
///
/// # Panics
/// - If storage access fails
/// - If threshold parameters are invalid
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_threshold_keys_exist<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    dkg_params: DKGParams,
    key_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    // Validate input parameters
    if pub_storages.len() != priv_storages.len() {
        tracing::error!(
            "Number of public storages ({}) and private storages ({}) must be equal",
            pub_storages.len(),
            priv_storages.len()
        );
        return false;
    }

    let amount_parties = pub_storages.len();
    if amount_parties == 0 {
        tracing::error!("Cannot generate threshold keys with zero parties");
        return false;
    }

    // Compute threshold < amount_parties/3
    let threshold = max_threshold(amount_parties);

    // Check if PUBLIC data already exists for all parties. If so, skip entirely.
    // See comment in ensure_central_keys_exist for why we only check PUB.
    let pub_type = PubDataType::CompressedXofKeySet.to_string();
    let legacy_pub_types = [
        PubDataType::CompressedXofKeySet.to_string(),
        PubDataType::PublicKey.to_string(),
        PubDataType::ServerKey.to_string(),
    ];

    let mut all_data_exists = true;
    for pub_storage in pub_storages.iter() {
        all_data_exists &= data_exists(pub_storage, key_id, &pub_type)
            .await
            .unwrap_or(false);
    }
    if all_data_exists {
        tracing::info!("Threshold FHE keys exists, skipping generation");
        return false;
    }
    // Purge obsolete data
    for (pub_storage, priv_storage) in pub_storages.iter_mut().zip_eq(priv_storages.iter_mut()) {
        use crate::vault::storage::delete_at_request_and_epoch_id;

        for existing_pub_type in &legacy_pub_types {
            let _ = delete_at_request_id(pub_storage, key_id, existing_pub_type).await;
        }
        let _ = delete_at_request_and_epoch_id(
            priv_storage,
            key_id,
            epoch_id,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await;
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Collect signing keys from all private storages with proper error handling
    let mut signing_keys = Vec::new();
    for (i, cur_storage) in priv_storages.iter().enumerate() {
        match get_core_signing_key(cur_storage).await {
            Ok(key) => signing_keys.push(key),
            Err(e) => {
                tracing::error!("Failed to get signing key for party {}: {}", i + 1, e);
                return false; // Cannot proceed without signing keys
            }
        }
    }

    // Generate compressed key set and shares
    let (keyset, compressed_keyset) = match gen_key_set(dkg_params, key_id.into(), &mut rng) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate compressed key set: {}", e);
            return false;
        }
    };

    // Generate key shares with error handling
    let key_shares = match keygen_all_party_shares_from_keyset(
        &keyset,
        dkg_params
            .get_params_basics_handle()
            .to_classic_pbs_parameters(),
        &mut rng,
        amount_parties,
        threshold,
    ) {
        Ok(shares) => shares,
        Err(e) => {
            tracing::error!("Failed to generate key shares: {}", e);
            return false;
        }
    };

    // Hash the compressed keyset once; reuse per party.
    let compressed_digest =
        match safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &compressed_keyset) {
            Ok(digest) => digest,
            Err(e) => {
                tracing::error!("Failed to hash compressed keyset: {}", e);
                return false;
            }
        };

    // Derive the CompactPublicKey from the compressed keyset once; store and sign it
    // along with the compressed keyset for each party.
    let compact_public_key = match compressed_keyset.decompress() {
        Ok(ks) => ks.into_raw_parts().0,
        Err(e) => {
            tracing::error!("Failed to decompress compressed keyset: {}", e);
            return false;
        }
    };

    // Hash the compact public key once; reuse per party.
    let public_key_digest =
        match safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &compact_public_key) {
            Ok(digest) => digest,
            Err(e) => {
                tracing::error!("Failed to hash compact public key: {}", e);
                return false;
            }
        };

    // Wrap the compressed keyset, public key, and per-party shares once; futures hold cheap Arc clones.
    let compressed_keyset = Arc::new(compressed_keyset);
    let compact_public_key = Arc::new(compact_public_key);
    let key_shares: Vec<_> = key_shares.into_iter().map(Arc::new).collect();

    let domain = dummy_domain();
    let store_futs = pub_storages
        .iter_mut()
        .zip(priv_storages.iter_mut())
        .zip(signing_keys.iter())
        .zip(key_shares)
        .enumerate()
        .map(|(idx, (((pub_s, priv_s), sk), share))| {
            let party = idx + 1;
            let compressed_digest = compressed_digest.clone();
            let public_key_digest = public_key_digest.clone();
            let compressed_keyset = compressed_keyset.clone();
            let compact_public_key = compact_public_key.clone();
            let domain = &domain;

            async move {
                let info = match compute_info_compressed_keygen_from_digests(
                    sk,
                    &INSECURE_PREPROCESSING_ID,
                    key_id,
                    compressed_digest,
                    public_key_digest,
                    domain,
                    vec![],
                ) {
                    Ok(result) => result,
                    Err(e) => {
                        tracing::error!("Failed to compute key info for party {}: {}", party, e);
                        return;
                    }
                };
                let threshold_fhe_keys = ThresholdFheKeys::new(
                    share,
                    PublicKeyMaterial::Compressed {
                        keyset: compressed_keyset.clone(),
                    },
                    info,
                );

                tracing::info!("Storing compressed keyset for party {}", party);
                if let Err(store_err) = store_versioned_at_request_id(
                    pub_s,
                    key_id,
                    &*compressed_keyset,
                    &PubDataType::CompressedXofKeySet.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store compressed keyset for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, pub_s.info(), "compressed keyset", true, true);

                // Store the compact public key alongside the compressed keyset
                if let Err(store_err) = store_versioned_at_request_id(
                    pub_s,
                    key_id,
                    &*compact_public_key,
                    &PubDataType::PublicKey.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store public key for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, pub_s.info(), "public key", true, true);

                if let Err(store_err) = store_versioned_at_request_and_epoch_id(
                    priv_s,
                    key_id,
                    epoch_id,
                    &threshold_fhe_keys,
                    &PrivDataType::FheKeyInfo.to_string(),
                )
                .await
                {
                    tracing::error!(
                        "Failed to store private key data for party {}: {}",
                        party,
                        store_err
                    );
                    return;
                }
                log_storage_success(key_id, priv_s.info(), "key data", false, true);
            }
        });

    future::join_all(store_futs).await;
    true
}

/// Generates and stores a threshold CRS with metadata.
///
/// Implements the complete threshold CRS lifecycle:
/// 1. Validates storage consistency
/// 2. Checks for existing CRS
/// 3. Collects signing keys from all parties
/// 4. Generates centralized parameters with proper security
/// 5. Distributes CRS to all parties with signatures
///
/// # Returns
/// - `true` if new CRS was generated and distributed
/// - `false` if CRS already existed
///
/// # Panics
/// - If storage validation fails (inconsistent counts)
/// - If signing key collection fails
/// - If parameter generation fails
/// - If CRS distribution fails
#[cfg(any(test, feature = "testing"))]
pub async fn ensure_threshold_crs_exists<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    dkg_params: DKGParams,
    crs_id: &RequestId,
    epoch_id: &EpochId,
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: StorageExt,
{
    if pub_storages.len() != priv_storages.len() {
        panic!("Number of public storages and private storages must be equal");
    }

    let amount_parties = pub_storages.len();

    // Check if the all parties have the CRS. If so, we can stop, otherwise we need to generate it.
    // PANICS: If storage access fails or if no storage is available
    let mut all_data_exists = true;
    for (pub_storage, priv_storage) in pub_storages.iter().zip_eq(priv_storages.iter()) {
        use crate::vault::storage::crypto_material::check_data_exists_at_epoch;

        match check_data_exists_at_epoch(
            pub_storage,
            priv_storage,
            crs_id,
            epoch_id,
            &[PubDataType::CRS.to_string()],
            &[PrivDataType::CrsInfo.to_string()],
        )
        .await
        {
            Ok(true) => {
                continue; // Data exists for this party, check next
            }
            Ok(false) => {
                all_data_exists = false;
                break;
            }
            Err(e) => {
                tracing::warn!("Error checking if threshold FHE keys exist: {}", e);
                // Continue with generation, assuming data doesn't exist
                all_data_exists = false;
                break;
            }
        }
    }
    if all_data_exists {
        tracing::info!("Threshold CRS exist, skipping generation");
        return false;
    }

    // Collect signing keys from all private storages
    // PANICS: If any signing key cannot be retrieved - critical for security
    let signing_keys: Vec<_> = future::join_all(
        priv_storages
            .iter()
            .map(|storage| get_core_signing_key(storage)),
    )
    .await
    .into_iter()
    .collect::<Result<_, _>>()
    .unwrap_or_else(|e| panic!("Failed to get signing key: {e}"));

    // Calculate max_num_bits based on DKG parameters
    // PANICS: If parameters are invalid and yield zero bits (security critical)
    let max_num_bits = calculate_max_num_bits(&dkg_params);
    if max_num_bits == 0 {
        panic!("Invalid max_num_bits calculated from DKG parameters");
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Generate the public parameters - foundation for the entire cryptographic system
    // PANICS: If parameter generation fails - cannot proceed with insecure parameters
    let pke_params = dkg_params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();

    // Any sid will work for testing
    let sid = SessionId::from(0u128);
    let internal_pp =
        public_parameters_by_trusted_setup(&pke_params, Some(max_num_bits), sid, &mut rng)
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to make centralized public parameters (max_bits: {max_num_bits}): {e}"
                );
            });

    // Convert internal parameters to zero-knowledge proof compatible format
    // PANICS: If conversion fails - cryptographic integrity would be compromised
    let pp = internal_pp
        .try_into_tfhe_zk_pok_pp(&pke_params, sid)
        .unwrap_or_else(|e| {
            panic!("Failed to convert internal_pp to tfhe_zk_pok_pp: {e}");
        });

    // Hash pp once; reused per party.
    let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &pp)
        .expect("serializing and hashing a CompactPkCrs works");
    let crs_max_num_bits = max_num_bits_from_crs(&pp);

    // Store the CRS for each party. Per-party signing + writes run concurrently.
    let domain = dummy_domain();
    let pp_ref = &pp;
    let store_futs = pub_storages
        .iter_mut()
        .zip_eq(priv_storages.iter_mut().zip_eq(signing_keys.iter()))
        .map(|(cur_pub, (cur_priv, cur_sk))| {
            let crs_digest = crs_digest.clone();
            let domain = &domain;
            async move {
                // PANICS: If signature generation fails - would compromise security model
                let crs_info = compute_info_crs_from_digest(
                    cur_sk,
                    crs_id,
                    crs_digest,
                    crs_max_num_bits,
                    domain,
                    vec![],
                )
                .unwrap_or_else(|e| panic!("Failed to compute CRS info for party: {e}"));

                // PANICS: If storage fails - system would be in inconsistent state
                store_versioned_at_request_and_epoch_id::<PrivS, CrsGenMetadata>(
                    cur_priv,
                    crs_id,
                    epoch_id,
                    &crs_info,
                    &PrivDataType::CrsInfo.to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("Failed to store private CRS info for party: {e}"));
                log_storage_success(crs_id, cur_priv.info(), "CRS data", false, true);

                // PANICS: If storage fails - system would be unable to perform cryptographic operations
                store_versioned_at_request_id::<PubS, tfhe::zk::CompactPkeCrs>(
                    cur_pub,
                    crs_id,
                    pp_ref,
                    &PubDataType::CRS.to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("Failed to store public CRS for party: {e}"));
                log_storage_success(crs_id, cur_pub.info(), "CRS data", true, true);
            }
        });

    future::join_all(store_futs).await;
    true
}

/// Calculates the maximum secure threshold for a given number of parties.
///
/// Uses the formula: ⌈n/3⌉ - 1, which ensures security in the presence of malicious parties.
///
/// # Arguments
/// * `amount_parties` - The total number of parties in the threshold system
///
/// # Returns
/// The maximum secure threshold value
pub fn max_threshold(amount_parties: usize) -> usize {
    usize::div_ceil(amount_parties, 3) - 1
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use kms_grpc::RequestId;
    use rand::SeedableRng;
    use threshold_execution::zk::ceremony::max_num_bits_from_crs;

    use crate::{
        consts::DEFAULT_PARAM, cryptography::signatures::gen_sig_keys, dummy_domain,
        engine::centralized::central_kms::gen_centralized_crs,
    };

    #[test]
    fn test_max_num_bits() {
        let mut rng = AesRng::seed_from_u64(123);
        let req_id = RequestId::new_random(&mut rng);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let params = &DEFAULT_PARAM;
        let eip712_domain = dummy_domain();
        for max_num_bits in [64, 128, 256, 1024, 2048] {
            let (crs, _) = gen_centralized_crs(
                &sk,
                params,
                Some(max_num_bits),
                &eip712_domain,
                vec![],
                &req_id,
                &mut rng,
            )
            .unwrap();
            assert_eq!(max_num_bits as usize, max_num_bits_from_crs(&crs));
        }
    }
}
