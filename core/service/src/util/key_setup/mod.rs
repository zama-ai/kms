#[cfg(any(test, feature = "testing"))]
pub mod test_tools;
use crate::client::ClientDataType;
use crate::cryptography::internal_crypto_types::{gen_sig_keys, PrivateSigKey};
use crate::engine::base::{compute_handle, compute_info, DSEP_PUBDATA_CRS};
use crate::engine::centralized::central_kms::{gen_centralized_crs, generate_fhe_keys};
use crate::engine::threshold::service::{compute_all_info, ThresholdFheKeys};
use crate::vault::storage::crypto_material::{
    calculate_max_num_bits, check_data_exists, get_rng, get_signing_key, log_data_exists,
    log_storage_success,
};
use crate::vault::storage::{
    file::FileStorage, read_all_data_versioned, store_pk_at_request_id, store_text_at_request_id,
    store_versioned_at_request_id, Storage, StorageForText, StorageReader, StorageType,
};
use itertools::Itertools;
use kms_grpc::rpc_types::{PrivDataType, PubDataType, WrappedPublicKey};
use kms_grpc::RequestId;
use std::collections::HashMap;
use std::path::Path;
use tfhe::Seed;
use threshold_fhe::execution::keyset_config::StandardKeySetConfig;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::{
    tfhe_internals::test_feature::{gen_key_set, keygen_all_party_shares},
    zk::ceremony::make_centralized_public_parameters,
};

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

/// Generates a new client signing and verification keys and stores them in the given storage if they do not already exist.
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
/// This is only used for testing and debug purposes through the [Client].
pub async fn ensure_client_keys_exist(
    optional_path: Option<&Path>,
    req_id: &RequestId,
    deterministic: bool,
) -> bool {
    let mut client_storage = FileStorage::new(optional_path, StorageType::CLIENT, None).unwrap();
    let temp: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(&client_storage, &ClientDataType::SigningKey.to_string())
            .await
            .unwrap();

    if !temp.is_empty() {
        // If signing keys already exist, then do nothing
        tracing::info!(
            "Client signing keys already exist at {}, skipping generation",
            client_storage.root_dir().to_str().unwrap()
        );
        return false;
    }

    let mut rng = get_rng(deterministic, None);
    let (client_pk, client_sk) = gen_sig_keys(&mut rng);

    // Store private client key
    store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_sk,
        &ClientDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    log_storage_success(req_id, client_storage.info(), "client key", false, false);

    // Store public client key
    store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_pk,
        &ClientDataType::VerfKey.to_string(),
    )
    .await
    .unwrap();
    log_storage_success(
        compute_handle(&client_pk).unwrap(),
        client_storage.info(),
        "client key",
        true,
        false,
    );

    true
}

/// Ensure that the central server signing and verification keys exist.
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
pub async fn ensure_central_server_signing_keys_exist<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    req_id: &RequestId,
    deterministic: bool,
) -> bool
where
    PubS: StorageForText,
    PrivS: StorageForText,
{
    let temp: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
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
    store_versioned_at_request_id(pub_storage, req_id, &pk, &PubDataType::VerfKey.to_string())
        .await
        .unwrap();
    log_storage_success(
        req_id,
        pub_storage.info(),
        "server signing key",
        true,
        false,
    );

    let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

    // Store ethereum address (derived from public key), needed for KMS signature verification
    store_text_at_request_id(
        pub_storage,
        req_id,
        &ethereum_address.to_string(),
        &PubDataType::VerfAddress.to_string(),
    )
    .await
    .unwrap();
    tracing::info!(
        "Successfully stored ethereum address {} under the handle {} in storage \"{}\"",
        ethereum_address,
        req_id,
        pub_storage.info()
    );

    // Store private signing key
    store_versioned_at_request_id(
        priv_storage,
        req_id,
        &sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    log_storage_success(
        req_id,
        priv_storage.info(),
        "central server signing key",
        false,
        false,
    );

    true
}

/// Generates a CRS and stores it in the given storage if it does not already exist.
/// This involves both generating the public CRS and storing the private CRS.
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
// TODO refactor this to use CryptoMaterialStorage
pub async fn ensure_central_crs_exists<PubS, PrivS>(
    pub_storage: &mut PubS,
    priv_storage: &mut PrivS,
    dkg_params: DKGParams,
    crs_handle: &RequestId,
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
        crs_handle,
        &PubDataType::CRS.to_string(),
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    {
        Ok(true) => {
            log_data_exists(
                priv_storage.info(),
                Some(pub_storage.info()),
                crs_handle,
                "CRS",
            );
            return false;
        }
        Ok(false) => {} // Continue with generation
        Err(e) => {
            tracing::warn!("Error checking if CRS exists: {}", e);
            // Continue with generation, assuming data doesn't exist
        }
    }

    // Get signing key with proper error handling
    let sk = match get_signing_key(priv_storage).await {
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
    let (pp, crs_info) =
        match gen_centralized_crs(&sk, &dkg_params, max_num_bits_u32, &mut rng, None) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to generate centralized CRS: {}", e);
                return false; // Cannot proceed without CRS
            }
        };

    // Store private CRS info with proper error handling
    if let Err(e) = store_versioned_at_request_id(
        priv_storage,
        crs_handle,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    {
        tracing::error!("Failed to store private CRS info: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_handle, priv_storage.info(), "CRS data", false, false);

    // Store public CRS with proper error handling
    if let Err(e) =
        store_versioned_at_request_id(pub_storage, crs_handle, &pp, &PubDataType::CRS.to_string())
            .await
    {
        tracing::error!("Failed to store public CRS: {}", e);
        return false; // Storage operation failed
    }
    log_storage_success(crs_handle, pub_storage.info(), "CRS data", true, false);

    true
}

/// Ensure that the central server fhe keys exist.
/// This involves generating and storing both the public and private keys and the private meta information.
/// More specifically this method does so for two distinct sets of keys under [key_id] and [other_key_id].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
// TODO refactor this to use CryptoMaterialStorage
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
        &PrivDataType::FheKeyInfo.to_string(),
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
    let sk = match get_signing_key(priv_storage).await {
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
    let (fhe_pub_keys_1, key_info_1) = match generate_fhe_keys(
        &sk,
        dkg_params,
        StandardKeySetConfig::default(),
        None,
        seed,
        None,
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
        seed,
        None,
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
        store_versioned_at_request_id(
            priv_storage,
            req_id,
            key_info,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        log_storage_success(req_id, priv_storage.info(), "key data", false, false);

        // When the flag [write_privkey] is set, store the private key separately
        if write_privkey {
            store_versioned_at_request_id(
                priv_storage,
                req_id,
                &key_info.client_key,
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await
            .unwrap();
            log_storage_success(
                req_id,
                priv_storage.info(),
                "individual private key",
                false,
                false,
            );
        }
    }

    // Store public key data
    for (req_id, cur_keys) in pub_fhe_map {
        // Store public key
        store_pk_at_request_id(
            pub_storage,
            &req_id,
            WrappedPublicKey::Compact(&cur_keys.public_key),
        )
        .await
        .unwrap();
        log_storage_success(req_id, pub_storage.info(), "key", true, false);

        // Store server key
        store_versioned_at_request_id(
            pub_storage,
            &req_id,
            &cur_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
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

pub enum ThresholdSigningKeyConfig {
    AllParties(usize),
    OneParty(usize),
}

/// Generates signing and verification keys for _each_ of the servers
/// and stores them in the storages if they don't already exist under [request_id].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
pub async fn ensure_threshold_server_signing_keys_exist<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    request_id: &RequestId,
    deterministic: bool,
    config: ThresholdSigningKeyConfig,
) -> bool
where
    PubS: StorageForText,
    PrivS: StorageForText,
{
    let parties = match config {
        ThresholdSigningKeyConfig::AllParties(amount) => (1..=amount).collect_vec(),
        ThresholdSigningKeyConfig::OneParty(i) => std::iter::once(i).collect_vec(),
    };

    for i in parties {
        let mut rng = get_rng(deterministic, Some(i as u64));
        let temp: HashMap<RequestId, PrivateSigKey> =
            read_all_data_versioned(&priv_storages[i - 1], &PrivDataType::SigningKey.to_string())
                .await
                .unwrap();

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

        // Store public verification key
        store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        log_storage_success(
            request_id,
            pub_storages[i - 1].info(),
            "server signing key",
            true,
            true,
        );

        let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

        // Store ethereum address (derived from public key), needed for KMS signature verification
        store_text_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &ethereum_address.to_string(),
            &PubDataType::VerfAddress.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored ethereum address {} under the handle {} in storage \"{}\"",
            ethereum_address,
            request_id,
            pub_storages[i - 1].info()
        );

        // Store private signing key
        store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            request_id,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        log_storage_success(
            request_id,
            priv_storages[i - 1].info(),
            "server signing key",
            false,
            true,
        );
    }
    true
}
/// Generates threshold key shares, meta data and public keys for an FHE keyset
/// and stores them in the storages if they don't already exist under [key_id].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
// TODO refactor this to use CryptoMaterialStorage
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
    assert_eq!(
        pub_storages.len(),
        priv_storages.len(),
        "Number of public storages and private storages must be equal"
    );

    let amount_parties = pub_storages.len();
    // Compute threshold < amount_parties/3
    let threshold = max_threshold(amount_parties);

    // For simplicity just test if the last party has the keys
    match check_data_exists(
        pub_storages.last().unwrap(),
        priv_storages.last().unwrap(),
        key_id,
        &PubDataType::PublicKey.to_string(),
        &PrivDataType::FheKeyInfo.to_string(),
    )
    .await
    {
        Ok(true) => {
            log_data_exists(
                priv_storages.last().unwrap().info(),
                Some(pub_storages.last().unwrap().info()),
                key_id,
                "Threshold FHE keys",
            );
            return false;
        }
        Ok(false) => {} // Continue with generation
        Err(e) => {
            tracing::warn!("Error checking if threshold FHE keys exist: {}", e);
            // Continue with generation, assuming data doesn't exist
        }
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Collect signing keys from all private storages with proper error handling
    let mut signing_keys = Vec::new();
    for cur_storage in priv_storages.iter() {
        match get_signing_key(cur_storage).await {
            Ok(key) => signing_keys.push(key),
            Err(e) => {
                tracing::error!("Failed to get signing key: {}", e);
                return false; // Cannot proceed without signing keys
            }
        }
    }

    // Generate key set and shares
    let key_set = gen_key_set(dkg_params, &mut rng);
    let key_shares = keygen_all_party_shares(
        key_set.get_raw_lwe_client_key(),
        key_set.get_raw_glwe_client_key(),
        key_set.get_raw_glwe_client_sns_key_as_lwe().unwrap(),
        dkg_params
            .get_params_basics_handle()
            .to_classic_pbs_parameters(),
        &mut rng,
        amount_parties,
        threshold,
    )
    .unwrap();

    let (integer_server_key, _, _, decompression_key, sns_key, _) =
        key_set.public_keys.server_key.clone().into_raw_parts();

    // Store keys for each party
    for i in 1..=amount_parties {
        // Get signing key for this party
        let sk = &signing_keys[i - 1];
        // Compute info with proper error handling
        let info = match compute_all_info(sk, &key_set.public_keys, None) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to compute key info: {}", e);
                continue; // Skip this party but try others
            }
        };
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[i - 1].to_owned(),
            integer_server_key: integer_server_key.clone(),
            sns_key: sns_key.clone(),
            decompression_key: decompression_key.clone(),
            pk_meta_data: info,
        };

        // Store public key
        store_pk_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            WrappedPublicKey::Compact(&key_set.public_keys.public_key),
        )
        .await
        .unwrap();
        log_storage_success(key_id, pub_storages[i - 1].info(), "key data", true, true);

        // Store public server key
        store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            &key_set.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
        log_storage_success(
            key_id,
            pub_storages[i - 1].info(),
            "server key data",
            true,
            true,
        );

        // Store private key data
        store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            key_id,
            &threshold_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        log_storage_success(key_id, priv_storages[i - 1].info(), "key data", false, true);
    }
    true
}

/// Generates a public CRS along with private metedata (containing the signature on the public CRS)
/// and stores the information in the storage if CRS does not already exist for [crs_handle].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
// TODO refactor this to use CryptoMaterialStorage
pub async fn ensure_threshold_crs_exists<PubS, PrivS>(
    pub_storages: &mut [PubS],
    priv_storages: &mut [PrivS],
    dkg_params: DKGParams,
    crs_handle: &RequestId,
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

    // Check if the last party has the CRS. If so, we can stop, otherwise we need to generate it.
    match check_data_exists(
        pub_storages.last().unwrap(),
        priv_storages.last().unwrap(),
        crs_handle,
        &PubDataType::CRS.to_string(),
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    {
        Ok(true) => {
            log_data_exists(
                priv_storages.last().unwrap().info(),
                Some(pub_storages.last().unwrap().info()),
                crs_handle,
                "Threshold CRS",
            );
            return false;
        }
        Ok(false) => {} // Continue with generation
        Err(e) => {
            tracing::warn!("Error checking if threshold CRS exists: {}", e);
            // Continue with generation, assuming data doesn't exist
        }
    }

    // Collect signing keys from all private storages with proper error handling
    let mut signing_keys = Vec::new();
    for cur_storage in priv_storages.iter() {
        match get_signing_key(cur_storage).await {
            Ok(key) => signing_keys.push(key),
            Err(e) => {
                tracing::error!("Failed to get signing key: {}", e);
                return false; // Cannot proceed without signing keys
            }
        }
    }

    // Calculate max_num_bits based on DKG parameters - now handles errors internally
    let max_num_bits = calculate_max_num_bits(&dkg_params);

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    // Generate the public parameters with proper error handling
    let internal_pp = match make_centralized_public_parameters(
        &dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params(),
        Some(max_num_bits), // Wrap in Some() as the function expects Option<usize>
        &mut rng,
    ) {
        Ok(pp) => pp,
        Err(e) => {
            tracing::error!("Failed to make centralized public parameters: {}", e);
            return false; // Cannot proceed without public parameters
        }
    };
    let pke_params = dkg_params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();

    // Convert internal_pp to tfhe_zk_pok_pp with proper error handling
    let pp = match internal_pp.try_into_tfhe_zk_pok_pp(&pke_params) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Failed to convert internal_pp to tfhe_zk_pok_pp: {}", e);
            return false; // Cannot proceed without proper conversion
        }
    };

    // Store the CRS for each party
    for (cur_pub, (cur_priv, cur_sk)) in pub_storages
        .iter_mut()
        .zip(priv_storages.iter_mut().zip(signing_keys.iter()))
    {
        // Compute info with proper error handling
        let crs_info = match compute_info(cur_sk, &DSEP_PUBDATA_CRS, &pp, None) {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("Failed to compute CRS info: {}", e);
                continue; // Skip this party but try others
            }
        };

        // Store private CRS info with proper error handling
        if let Err(e) = store_versioned_at_request_id(
            cur_priv,
            crs_handle,
            &crs_info,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        {
            tracing::error!("Failed to store private CRS info: {}", e);
            continue; // Skip this party but try others
        }
        log_storage_success(crs_handle, cur_priv.info(), "CRS data", false, true);

        // Store public CRS with proper error handling
        if let Err(e) =
            store_versioned_at_request_id(cur_pub, crs_handle, &pp, &PubDataType::CRS.to_string())
                .await
        {
            tracing::error!("Failed to store public CRS: {}", e);
            continue; // Skip this party but try others
        }
        log_storage_success(crs_handle, cur_pub.info(), "CRS data", true, true);
    }
    true
}

pub fn max_threshold(amount_parties: usize) -> usize {
    usize::div_ceil(amount_parties, 3) - 1
}
