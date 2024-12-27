#[cfg(any(test, feature = "testing"))]
pub mod test_tools;
use crate::client::ClientDataType;
use crate::cryptography::central_kms::compute_info;
use crate::cryptography::central_kms::{
    compute_handle, gen_centralized_crs, gen_sig_keys, generate_fhe_keys,
};
use crate::cryptography::internal_crypto_types::PrivateSigKey;
use crate::threshold::threshold_kms::{compute_all_info, ThresholdFheKeys};
use crate::vault::storage::{
    file::FileStorage, read_all_data_versioned, store_pk_at_request_id, store_text_at_request_id,
    store_versioned_at_request_id, Storage, StorageForText, StorageReader, StorageType,
};
use aes_prng::AesRng;
use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
use distributed_decryption::execution::{
    tfhe_internals::test_feature::{gen_key_set, keygen_all_party_shares},
    zk::ceremony::make_centralized_public_parameters,
};
use itertools::Itertools;
use kms_grpc::kms::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType, WrappedPublicKey};
use rand::SeedableRng;
use std::collections::HashMap;
use std::path::Path;
use tfhe::Seed;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

fn get_rng(deterministic: bool, seed: Option<u64>) -> AesRng {
    if deterministic {
        AesRng::seed_from_u64(seed.map_or(42, |seed| seed))
    } else {
        AesRng::from_entropy()
    }
}

async fn get_signing_key<S: Storage>(priv_storage: &S) -> PrivateSigKey {
    let mut sk_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data_versioned(priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if sk_map.values().len() != 1 {
        panic!(
            "Server signing key map should contain exactly one entry, but contains {} entries for storage \"{}\"",
            sk_map.values().len(), priv_storage.info()
        );
    }
    let req_id = sk_map.keys().last().unwrap().clone();
    sk_map.remove(&req_id).unwrap()
}

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
        // If signing keys already exit, then do nothing
        tracing::warn!(
            "Client signing keys already exist at {}, skipping generation",
            client_storage.root_dir().to_str().unwrap()
        );
        return false;
    }
    let mut rng = get_rng(deterministic, None);
    let (client_pk, client_sk) = gen_sig_keys(&mut rng);
    store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_sk,
        &ClientDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    tracing::info!(
        "Successfully stored private client key under the handle {} in storage {}",
        req_id,
        client_storage.info()
    );
    store_versioned_at_request_id(
        &mut client_storage,
        req_id,
        &client_pk,
        &ClientDataType::VerfKey.to_string(),
    )
    .await
    .unwrap();
    tracing::info!(
        "Successfully stored public client key under the handle {} in storage {}",
        compute_handle(&client_pk).unwrap(),
        client_storage.info()
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
        // If signing keys already exit, then do nothing
        tracing::warn!(
            "Server signing keys already exist for private storage \"{}\", skipping generation",
            priv_storage.info()
        );
        return false;
    }
    let mut rng = get_rng(deterministic, Some(0));
    let (pk, sk) = gen_sig_keys(&mut rng);

    // store public verification key
    store_versioned_at_request_id(pub_storage, req_id, &pk, &PubDataType::VerfKey.to_string())
        .await
        .unwrap();
    tracing::info!(
        "Successfully stored public server signing key under the handle {} in storage \"{}\"",
        req_id,
        pub_storage.info()
    );

    let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

    // store ethereum address (derived from public key), needed for KMS signature verification
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

    // store private signing key
    store_versioned_at_request_id(
        priv_storage,
        req_id,
        &sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    tracing::info!(
        "Successfully stored private central server signing key under the handle {} in storage \"{}\"",
        req_id,
        priv_storage.info()
    );
    true
}

/// Generates a CRS and stores it in the given storage if it does not already exist.
/// This involves both generating the public CRS and storing the private CRS.
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
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
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&crs_handle.to_string(), &PubDataType::CRS.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
        && priv_storage
            .data_exists(
                &priv_storage
                    .compute_url(&crs_handle.to_string(), &PrivDataType::CrsInfo.to_string())
                    .unwrap(),
            )
            .await
            .unwrap()
    {
        tracing::warn!(
            "CRS already exist for private storage \"{}\" and public storage \"{}\" for ID {}, skipping generation",
            priv_storage.info(), pub_storage.info(), crs_handle
        );
        return false;
    }
    let sk = get_signing_key(priv_storage).await;
    let mut rng = get_rng(deterministic, Some(0));
    let (pp, crs_info) = gen_centralized_crs(&sk, &dkg_params, None, &mut rng, None).unwrap();

    store_versioned_at_request_id(
        priv_storage,
        crs_handle,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    .unwrap();
    tracing::info!(
        "Successfully stored private CRS data under the handle {} in storage {}",
        crs_handle,
        priv_storage.info()
    );
    store_versioned_at_request_id(pub_storage, crs_handle, &pp, &PubDataType::CRS.to_string())
        .await
        .unwrap();
    tracing::info!(
        "Successfully stored public CRS data under the handle {} in storage {}",
        crs_handle,
        pub_storage.info()
    );
    true
}

/// Ensure that the central server fhe keys exist.
/// This involves generating and storing both the public and private keys and the private meta information.
/// More specifically this method does so for two distinct sets of keys under [key_id] and [other_key_id].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
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
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&key_id.to_string(), &PubDataType::PublicKey.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
        && priv_storage
            .data_exists(
                &priv_storage
                    .compute_url(&key_id.to_string(), &PrivDataType::FheKeyInfo.to_string())
                    .unwrap(),
            )
            .await
            .unwrap()
    {
        tracing::warn!(
            "FHE keys already exist for private storage \"{}\" and public storage \"{}\" with ID {}, skipping generation",
            priv_storage.info(), pub_storage.info(), key_id
        );
        return false;
    }

    let sk = get_signing_key(priv_storage).await;
    let seed = match deterministic {
        true => Some(Seed(42)),
        false => None,
    };

    let (fhe_pub_keys_1, key_info_1) = generate_fhe_keys(&sk, dkg_params, seed, None).unwrap();
    let (fhe_pub_keys_2, key_info_2) = generate_fhe_keys(&sk, dkg_params, seed, None).unwrap();
    let priv_fhe_map = HashMap::from([
        (key_id.clone(), key_info_1),
        (other_key_id.clone(), key_info_2),
    ]);
    let pub_fhe_map = HashMap::from([
        (key_id.clone(), fhe_pub_keys_1),
        (other_key_id.clone(), fhe_pub_keys_2),
    ]);
    for (req_id, key_info) in &priv_fhe_map {
        store_versioned_at_request_id(
            priv_storage,
            req_id,
            key_info,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored private key data under the handle {} in storage {}",
            req_id,
            priv_storage.info()
        );
        // when the flag [write_privkey] is set, store the private key separately
        if write_privkey {
            store_versioned_at_request_id(
                priv_storage,
                req_id,
                &key_info.client_key,
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await
            .unwrap();
            tracing::info!(
                "Successfully stored individual private key under the handle {} in storage {}",
                req_id,
                priv_storage.info()
            );
        }
    }
    for (req_id, cur_keys) in &pub_fhe_map {
        store_pk_at_request_id(
            pub_storage,
            req_id,
            WrappedPublicKey::Compact(&cur_keys.public_key),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored public key under the handle {} in storage {}",
            req_id,
            pub_storage.info()
        );
        store_versioned_at_request_id(
            pub_storage,
            req_id,
            &cur_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored public server key under the handle {} in storage {}",
            req_id,
            pub_storage.info()
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
            // If signing keys already exit, then do nothing
            tracing::warn!(
                "Threshold server signing keys already exist for private storage \"{}\", skipping generation",
                priv_storages[i-1].info()
            );
            continue;
        }
        let (pk, sk) = gen_sig_keys(&mut rng);

        // store public verification key
        store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            request_id,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored public threshold server signing key under the handle {} in storage {}",
            request_id,
            pub_storages[i - 1].info()
        );

        let ethereum_address = alloy_signer::utils::public_key_to_address(pk.pk());

        // store ethereum address (derived from public key), needed for KMS signature verification
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

        // store private signing key
        store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            request_id,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored private threshold server signing key under the handle {} in storage {}",
            request_id,
            priv_storages[i - 1].info()
        );
    }
    true
}
/// Generates threshold key shares, meta data and public keys for an FHE keyset
/// and stores them in the storages if they don't already exist under [key_id].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
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
    if pub_storages
        .last()
        .unwrap()
        .data_exists(
            &pub_storages
                .last()
                .unwrap()
                .compute_url(&key_id.to_string(), &PubDataType::PublicKey.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
        && priv_storages
            .last()
            .unwrap()
            .data_exists(
                &priv_storages
                    .last()
                    .unwrap()
                    .compute_url(&key_id.to_string(), &PrivDataType::FheKeyInfo.to_string())
                    .unwrap(),
            )
            .await
            .unwrap()
    {
        tracing::warn!(
            "Threshold FHE keys already exist for private storage \"{}\" and public storage \"{}\" with ID {}, skipping generation",
            priv_storages.last().unwrap().info(), pub_storages.last().unwrap().info(), key_id
        );
        return false;
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    let mut signing_keys = Vec::new();
    for cur_storage in priv_storages.iter() {
        signing_keys.push(get_signing_key(cur_storage).await);
    }

    let key_set = gen_key_set(dkg_params, &mut rng);
    let key_shares = keygen_all_party_shares(
        key_set.get_raw_lwe_client_key(),
        key_set.get_raw_glwe_client_key(),
        key_set.sns_secret_key.key,
        dkg_params
            .get_params_basics_handle()
            .to_classic_pbs_parameters(),
        &mut rng,
        amount_parties,
        threshold,
    )
    .unwrap();

    let sns_key = key_set.public_keys.sns_key.to_owned().unwrap();
    let decompression_key = key_set.public_keys.server_key.to_owned().into_raw_parts().3;

    for i in 1..=amount_parties {
        // Get first signing key
        let sk = &signing_keys[i - 1];
        let info = compute_all_info(sk, &key_set.public_keys, None).unwrap();
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[i - 1].to_owned(),
            sns_key: sns_key.clone(),
            decompression_key: decompression_key.clone(),
            pk_meta_data: info,
        };
        store_pk_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            WrappedPublicKey::Compact(&key_set.public_keys.public_key),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored public threshold key data under the handle {} in storage {}",
            key_id,
            pub_storages[i - 1].info()
        );
        store_versioned_at_request_id(
            &mut pub_storages[i - 1],
            key_id,
            &key_set.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored public threshold server key data under the handle {} in storage {}",
            key_id,
            pub_storages[i-1].info()
        );
        store_versioned_at_request_id(
            &mut priv_storages[i - 1],
            key_id,
            &threshold_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
        tracing::info!(
            "Successfully stored private threshold key data under the handle {} in storage {}",
            key_id,
            priv_storages[i - 1].info()
        );
    }
    true
}

/// Generates a public CRS along with private metedata (containing the signature on the public CRS)
/// and stores the information in the storage if CRS does not already exist for [crs_handle].
///
/// Returns true if the keys were generated and false if they already existed and hence were not generated.
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
    // Check if the last party has the CRS. If  so, we can stop, otherwise we need to generate it.
    if pub_storages
        .last()
        .unwrap()
        .data_exists(
            &pub_storages
                .last()
                .unwrap()
                .compute_url(&crs_handle.to_string(), &PubDataType::CRS.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
        && priv_storages
            .last()
            .unwrap()
            .data_exists(
                &priv_storages
                    .last()
                    .unwrap()
                    .compute_url(&crs_handle.to_string(), &PrivDataType::CrsInfo.to_string())
                    .unwrap(),
            )
            .await
            .unwrap()
    {
        tracing::warn!(
            "Threshold CRS already exist for private storage \"{}\" and public storage \"{}\" for ID {}, skipping generation",
            priv_storages.last().unwrap().info(), pub_storages.last().unwrap().info(), crs_handle
        );
        return false;
    }
    let mut signing_keys = Vec::new();
    for cur_storage in priv_storages.iter() {
        signing_keys.push(get_signing_key(cur_storage).await);
    }

    let mut rng = get_rng(deterministic, Some(amount_parties as u64));

    let internal_pp = make_centralized_public_parameters(
        &dkg_params
            .get_params_basics_handle()
            .get_compact_pk_enc_params(),
        None,
        &mut rng,
    )
    .unwrap();
    let pke_params = dkg_params
        .get_params_basics_handle()
        .get_compact_pk_enc_params();
    let pp = internal_pp.try_into_tfhe_zk_pok_pp(&pke_params).unwrap();

    for (cur_pub, (cur_priv, cur_sk)) in pub_storages
        .iter_mut()
        .zip(priv_storages.iter_mut().zip(signing_keys.iter()))
    {
        let crs_info = compute_info(cur_sk, &pp, None).unwrap();

        store_versioned_at_request_id(
            cur_priv,
            crs_handle,
            &crs_info,
            &PrivDataType::CrsInfo.to_string(),
        )
        .await
        .unwrap();
        println!(
            "Successfully stored private threshold CRS data under the handle {} in storage {}",
            crs_handle,
            cur_priv.info()
        );
        store_versioned_at_request_id(cur_pub, crs_handle, &pp, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        println!(
            "Successfully stored public threshold CRS data under the handle {} in storage {}",
            crs_handle,
            cur_pub.info()
        );
    }
    true
}

pub fn max_threshold(amount_parties: usize) -> usize {
    usize::div_ceil(amount_parties, 3) - 1
}
