cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        pub mod test_tools;

        use crate::dummy_domain;
        use crate::engine::base::{DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY};
        use crate::engine::base::INSECURE_PREPROCESSING_ID;
        use crate::engine::base::{compute_info_crs, CrsGenMetadata};
        use crate::engine::centralized::central_kms::{gen_centralized_crs, generate_fhe_keys};
        use crate::engine::threshold::service::{ThresholdFheKeys};
        use crate::vault::storage::crypto_material::{
            calculate_max_num_bits, check_data_exists, get_core_signing_key,
        };
        use crate::vault::storage::{store_pk_at_request_id, Storage};
        use futures_util::future;
        use kms_grpc::rpc_types::WrappedPublicKey;
        use tfhe::Seed;
        use threshold_fhe::execution::keyset_config::StandardKeySetConfig;
        use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
        use threshold_fhe::execution::tfhe_internals::test_feature::gen_key_set;
        use threshold_fhe::execution::tfhe_internals::test_feature::keygen_all_party_shares_from_keyset;
        use threshold_fhe::execution::zk::ceremony::public_parameters_by_trusted_setup;
        use threshold_fhe::session_id::SessionId;
        use std::sync::Arc;

    }
}

use crate::client::client_non_wasm::ClientDataType;
use crate::cryptography::internal_crypto_types::gen_sig_keys;
use crate::engine::base::compute_handle;
use crate::vault::storage::crypto_material::{get_rng, log_data_exists, log_storage_success};
use crate::vault::storage::{
    file::FileStorage, read_all_data_versioned, store_text_at_request_id,
    store_versioned_at_request_id, StorageForBytes, StorageReader, StorageType,
};
use itertools::Itertools;
use k256::pkcs8::EncodePrivateKey;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_grpc::RequestId;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256K1_SHA256,
};
use std::collections::HashMap;
use std::path::Path;
use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;

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
    let temp: HashMap<RequestId, crate::cryptography::internal_crypto_types::PrivateSigKey> =
        match read_all_data_versioned(&client_storage, &ClientDataType::SigningKey.to_string())
            .await
        {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!("Failed to read existing client keys: {}", e);
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
    PubS: StorageForBytes,
    PrivS: StorageForBytes,
{
    // Check if keys already exist with error handling
    let temp: HashMap<RequestId, crate::cryptography::internal_crypto_types::PrivateSigKey> =
        match read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string()).await {
            Ok(keys) => keys,
            Err(e) => {
                tracing::error!("Failed to read existing server signing keys: {}", e);
                return false;
            }
        };

    if !temp.is_empty() {
        // If signing keys already exist, then do nothing
        log_data_exists(
            priv_storage.info(),
            None::<String>,
            "",
            "Server signing keys",
        );
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

    let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

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
        "central server signing key",
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
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: Storage,
{
    // Check if data already exists in both storages
    match check_data_exists(
        pub_storage,
        priv_storage,
        crs_id,
        &PubDataType::CRS.to_string(),
        &PrivDataType::CrsInfo.to_string(),
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
    if let Err(e) = store_versioned_at_request_id(
        priv_storage,
        crs_id,
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
pub async fn ensure_central_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    key_id: &RequestId,
    other_key_id: &RequestId,
    deterministic: bool,
    write_privkey: bool,
) -> bool
where
    PubS: Storage,
    PrivS: Storage,
{
    // Check if data already exists in both storages
    match check_data_exists(
        pub_storage,
        priv_storage,
        key_id,
        &PubDataType::PublicKey.to_string(),
        &PrivDataType::FhePrivateKey.to_string(),
    )
    .await
    {
        Ok(true) => {
            log_data_exists(
                priv_storage.info(),
                Some(pub_storage.info()),
                key_id,
                "FHE keys",
            );
            return false;
        }
        Ok(false) => {} // Continue with generation
        Err(e) => {
            tracing::warn!("Error checking if FHE keys exist: {}", e);
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

    let seed = match deterministic {
        true => Some(Seed(42)),
        false => None,
    };

    // Generate two sets of FHE keys with proper error handling
    let domain = dummy_domain();
    let (fhe_pub_keys_1, key_info_1) = match generate_fhe_keys(
        &sk,
        dkg_params,
        StandardKeySetConfig::default(),
        None,
        key_id,
        &INSECURE_PREPROCESSING_ID,
        seed,
        &domain,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate first set of FHE keys: {}", e);
            return false; // Cannot proceed without keys
        }
    };

    let (fhe_pub_keys_2, key_info_2) = match generate_fhe_keys(
        &sk,
        dkg_params,
        StandardKeySetConfig::default(),
        None,
        other_key_id,
        &INSECURE_PREPROCESSING_ID,
        seed,
        &domain,
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to generate second set of FHE keys: {}", e);
            return false; // Cannot proceed without keys
        }
    };

    let priv_fhe_map = HashMap::from([(*key_id, key_info_1), (*other_key_id, key_info_2)]);
    let pub_fhe_map = HashMap::from([(*key_id, fhe_pub_keys_1), (*other_key_id, fhe_pub_keys_2)]);

    // Store private key data
    for (req_id, key_info) in &priv_fhe_map {
        // Store key info
        if let Err(e) = store_versioned_at_request_id(
            priv_storage,
            req_id,
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
            if let Err(e) = store_versioned_at_request_id(
                priv_storage,
                req_id,
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

    // Store public key data with proper error handling
    for (req_id, cur_keys) in pub_fhe_map {
        // Store public key
        if let Err(e) = store_pk_at_request_id(
            pub_storage,
            &req_id,
            WrappedPublicKey::Compact(&cur_keys.public_key),
        )
        .await
        {
            tracing::error!(
                "Failed to store public key for request ID {}: {}",
                req_id,
                e
            );
            continue; // Skip this key but try others
        }
        log_storage_success(req_id, pub_storage.info(), "key", true, false);

        // Store server key
        if let Err(e) = store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &cur_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store server key for request ID {}: {}",
                req_id,
                e
            );
            continue; // Skip this key but try others
        }
        log_storage_success(
            req_id,
            pub_storage.info(),
            "server signing key",
            true,
            false,
        );
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
    PubS: StorageForBytes,
    PrivS: StorageForBytes,
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
        ThresholdSigningKeyConfig::AllParties(parties) => (1..=parties.len())
            .zip_eq(parties.into_iter())
            .collect_vec(),
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
        let temp: HashMap<RequestId, crate::cryptography::internal_crypto_types::PrivateSigKey> =
            match read_all_data_versioned(
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
            continue;
        }

        let (pk, sk) = gen_sig_keys(&mut rng);

        // self-sign a CA certificate with the private signing key
        let subject = subject_str.as_str();

        let sans_vec = [
            if tls_wildcard {
                vec![format!("*.{}", subject)]
            } else {
                vec![]
            },
            vec![
                subject.to_string(),
                "localhost".to_string(),
                "192.168.0.1".to_string(),
                "127.0.0.1".to_string(),
                "0:0:0:0:0:0:0:1".to_string(),
            ],
        ]
        .concat();

        let mut ca_cp = CertificateParams::new(sans_vec)?;
        ca_cp.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, subject);
        ca_cp.distinguished_name = distinguished_name;
        ca_cp.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let sk_der = sk.sk().to_pkcs8_der()?;
        let ca_keypair = KeyPair::from_pkcs8_der_and_sign_algo(
            &PrivatePkcs8KeyDer::from(sk_der.as_bytes()),
            &PKCS_ECDSA_P256K1_SHA256,
        )?;

        let ca_cert = ca_cp.self_signed(&ca_keypair)?;

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

        let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

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

        // Store self-signed CA certificate
        if let Err(store_err) = store_text_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &ca_cert.pem(),
            &PubDataType::CACert.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store CA certificate for party {}: {}",
                i,
                store_err
            );
            continue; // Skip this party but try others
        }
        tracing::info!(
            "Successfully stored CA certificate {} under the handle {} in storage \"{}\"",
            hex::encode(ca_cp.key_identifier(&ca_keypair)),
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
    }
    Ok(true)
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
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: Storage,
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

    let mut all_data_exists = true;
    for (pub_storage, priv_storage) in pub_storages.iter().zip_eq(priv_storages.iter()) {
        match check_data_exists(
            pub_storage,
            priv_storage,
            key_id,
            &PubDataType::PublicKey.to_string(),
            &PrivDataType::FheKeyInfo.to_string(),
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
        tracing::info!("Threshold FHE keys exists, skipping generation");
        return false;
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

    // Generate key set and shares
    let keyset = gen_key_set(dkg_params, &mut rng);

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

    let (integer_server_key, _, _, decompression_key, sns_key, _, _, _) =
        keyset.public_keys.server_key.clone().into_raw_parts();

    // Store keys for each party
    let domain = dummy_domain();
    for i in 1..=amount_parties {
        // Get signing key for this party

        let sk = &signing_keys[i - 1];
        // Compute info with proper error handling
        let info = match crate::engine::base::compute_info_standard_keygen(
            sk,
            &DSEP_PUBDATA_KEY,
            &INSECURE_PREPROCESSING_ID,
            key_id,
            &keyset.public_keys,
            &domain,
        ) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to compute key info for party {}: {}", i, e);
                continue; // Skip this party but try others
            }
        };
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: Arc::new(key_shares[i - 1].to_owned()),
            integer_server_key: Arc::new(integer_server_key.clone()),
            sns_key: sns_key.clone().map(Arc::new),
            decompression_key: decompression_key.clone().map(Arc::new),
            meta_data: info,
        };

        // Store public key
        if let Err(store_err) = store_pk_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            WrappedPublicKey::Compact(&keyset.public_keys.public_key),
        )
        .await
        {
            tracing::error!(
                "Failed to store public key for party {}: {}",
                { i },
                store_err
            );
            continue; // Skip this party but try others
        }
        log_storage_success(key_id, pub_storages[i - 1].info(), "key data", true, true);

        // Store public server key
        if let Err(store_err) = store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            &keyset.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store public server key for party {}: {}",
                { i },
                store_err
            );
            continue; // Skip this party but try others
        }
        log_storage_success(
            key_id,
            pub_storages[i - 1].info(),
            "server key data",
            true,
            true,
        );

        // Store private key data
        if let Err(store_err) = store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            key_id,
            &threshold_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        {
            tracing::error!(
                "Failed to store private key data for party {}: {}",
                { i },
                store_err
            );
            continue; // Skip this party but try others
        }
        log_storage_success(key_id, priv_storages[i - 1].info(), "key data", false, true);
    }
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
    deterministic: bool,
) -> bool
where
    PubS: Storage,
    PrivS: Storage,
{
    if pub_storages.len() != priv_storages.len() {
        panic!("Number of public storages and private storages must be equal");
    }

    let amount_parties = pub_storages.len();

    // Check if the all parties have the CRS. If so, we can stop, otherwise we need to generate it.
    // PANICS: If storage access fails or if no storage is available
    let mut all_data_exists = true;
    for (pub_storage, priv_storage) in pub_storages.iter().zip_eq(priv_storages.iter()) {
        match check_data_exists(
            pub_storage,
            priv_storage,
            crs_id,
            &PubDataType::CRS.to_string(),
            &PrivDataType::CrsInfo.to_string(),
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

    // Store the CRS for each party
    // PANICS: if the private and public storage and signing keys are not of equal length
    let domain = dummy_domain();
    for (cur_pub, (cur_priv, cur_sk)) in pub_storages
        .iter_mut()
        .zip_eq(priv_storages.iter_mut().zip_eq(signing_keys.iter()))
    {
        // Compute signed metadata for CRS verification
        // PANICS: If signature generation fails - would compromise security model

        let crs_info = compute_info_crs(cur_sk, &DSEP_PUBDATA_CRS, crs_id, &pp, &domain)
            .unwrap_or_else(|e| {
                panic!("Failed to compute CRS info for party: {e}");
            });

        // Store private CRS info with signature - essential for verification chain
        // PANICS: If storage fails - system would be in inconsistent state
        store_versioned_at_request_id::<PrivS, CrsGenMetadata>(
            cur_priv,
            crs_id,
            &crs_info,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to store private CRS info for party: {e}");
        });

        log_storage_success(crs_id, cur_priv.info(), "CRS data", false, true);

        // Store public CRS parameters - must be available for all cryptographic operations
        // PANICS: If storage fails - system would be unable to perform cryptographic operations
        store_versioned_at_request_id::<PubS, tfhe::zk::CompactPkeCrs>(
            cur_pub,
            crs_id,
            &pp,
            &PubDataType::CRS.to_string(),
        )
        .await
        .unwrap_or_else(|e| {
            panic!("Failed to store public CRS for party: {e}");
        });
        log_storage_success(crs_id, cur_pub.info(), "CRS data", true, true);
    }
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
    use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;

    use crate::{
        consts::DEFAULT_PARAM, cryptography::internal_crypto_types::gen_sig_keys, dummy_domain,
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
                &req_id,
                &mut rng,
            )
            .unwrap();
            assert_eq!(max_num_bits as usize, max_num_bits_from_crs(&crs));
        }
    }
}
