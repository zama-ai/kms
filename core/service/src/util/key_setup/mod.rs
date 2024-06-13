#[cfg(any(test, feature = "testing"))]
pub mod test_tools;

use crate::client::ClientDataType;
use crate::cryptography::central_kms::{
    compute_handle, gen_centralized_crs, gen_sig_keys, generate_fhe_keys,
};
use crate::cryptography::der_types::PrivateSigKey;
use crate::kms::RequestId;
use crate::rpc::rpc_types::PrivDataType;
use crate::rpc::rpc_types::PubDataType;
use crate::storage::Storage;
use crate::storage::{read_all_data, StorageReader};
use crate::storage::{store_at_request_id, FileStorage, StorageType};
use crate::util::file_handling::read_as_json;
use aes_prng::AesRng;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use itertools::Itertools;
use rand::SeedableRng;
use std::collections::HashMap;
use std::path::Path;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub async fn ensure_client_keys_exist(optional_path: Option<&Path>, deterministic: bool) {
    let mut client_storage =
        FileStorage::new_centralized(optional_path, StorageType::CLIENT).unwrap();
    let temp: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&client_storage, &ClientDataType::SigningKey.to_string())
            .await
            .unwrap();
    if !temp.is_empty() {
        // If signing keys already exit, then do nothing
        return;
    }
    let mut rng = if deterministic {
        AesRng::seed_from_u64(42)
    } else {
        AesRng::from_entropy()
    };
    let (client_pk, client_sk) = gen_sig_keys(&mut rng);
    // TODO is this how we want to compute the handles? Do we instead want to compute them from a static string
    // since we only ever expect there to be one?
    store_at_request_id(
        &mut client_storage,
        &compute_handle(&client_sk).unwrap().try_into().unwrap(),
        &client_sk,
        &ClientDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    store_at_request_id(
        &mut client_storage,
        &compute_handle(&client_pk).unwrap().try_into().unwrap(),
        &client_pk,
        &ClientDataType::VerfKey.to_string(),
    )
    .await
    .unwrap();
}

/// Ensure that the central server signing keys exist.
/// If they already exist, then return false, otherwise create them and return true.
pub async fn ensure_central_server_signing_keys_exist(
    priv_path: Option<&Path>,
    pub_path: Option<&Path>,
    deterministic: bool,
) -> bool {
    let mut priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    let mut pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    let temp: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if !temp.is_empty() {
        // If signing keys already exit, then do nothing
        return false;
    }
    let mut rng = if deterministic {
        AesRng::seed_from_u64(1337)
    } else {
        AesRng::from_entropy()
    };
    let (pk, sk) = gen_sig_keys(&mut rng);
    store_at_request_id(
        &mut pub_storage,
        &compute_handle(&sk).unwrap().try_into().unwrap(),
        &pk,
        &PubDataType::VerfKey.to_string(),
    )
    .await
    .unwrap();
    store_at_request_id(
        &mut priv_storage,
        &compute_handle(&sk).unwrap().try_into().unwrap(),
        &sk,
        &PrivDataType::SigningKey.to_string(),
    )
    .await
    .unwrap();
    true
}

pub async fn ensure_threshold_server_signing_keys_exist(
    priv_path: Option<&Path>,
    pub_path: Option<&Path>,
    deterministic: bool,
    amount: usize,
) -> Vec<HashMap<RequestId, PrivateSigKey>> {
    let mut signing_keys = Vec::with_capacity(amount);
    for i in 1..=amount {
        let mut priv_storage = FileStorage::new_threshold(priv_path, StorageType::PRIV, i).unwrap();
        let mut pub_storage = FileStorage::new_threshold(pub_path, StorageType::PUB, i).unwrap();
        let temp: HashMap<RequestId, PrivateSigKey> =
            read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
                .await
                .unwrap();
        if !temp.is_empty() {
            // If signing keys already exit, then do nothing
            signing_keys.push(temp);
            continue;
        }
        let mut rng = if deterministic {
            AesRng::seed_from_u64(i as u64)
        } else {
            AesRng::from_entropy()
        };
        let (pk, sk) = gen_sig_keys(&mut rng);
        let handle = compute_handle(&sk).unwrap().try_into().unwrap();
        store_at_request_id(
            &mut pub_storage,
            &handle,
            &pk,
            &PubDataType::VerfKey.to_string(),
        )
        .await
        .unwrap();
        store_at_request_id(
            &mut priv_storage,
            &handle,
            &sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .await
        .unwrap();
        signing_keys.push(HashMap::from([(handle, sk)]));
    }
    signing_keys
}

/// Ensure that the central server crs exist.
/// If they already exist, then return false, otherwise create them and return true.
pub async fn ensure_central_crs_store_exists(
    priv_path: Option<&Path>,
    pub_path: Option<&Path>,
    param_path: &str,
    crs_handle: &RequestId,
    deterministic: bool,
) -> bool {
    let mut priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    let mut pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    ensure_crs_store_exists(
        &mut priv_storage,
        &mut pub_storage,
        param_path,
        crs_handle,
        deterministic,
    )
    .await
}

/// This is the helper function for creating CRS stores,
/// it can be used for both the centralized and threshold setting (in an insecure way).
async fn ensure_crs_store_exists<S>(
    priv_storage: &mut S,
    pub_storage: &mut S,
    param_path: &str,
    crs_handle: &RequestId,
    deterministic: bool,
) -> bool
where
    S: Storage,
{
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&crs_handle.to_string(), &PubDataType::CRS.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
    {
        return false;
    }
    println!("Generating new CRS store",);
    let sk_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data(priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if sk_map.values().cloned().collect_vec().len() != 1 {
        panic!("Server signing key map should only contain one entry");
    }
    let sk = sk_map
        .values()
        .cloned()
        .collect_vec()
        .first()
        .unwrap()
        .to_owned();

    let params: NoiseFloodParameters = read_as_json(param_path).await.unwrap();
    let mut rng = if deterministic {
        AesRng::seed_from_u64(42)
    } else {
        AesRng::from_entropy()
    };
    let (pp, crs_info) = gen_centralized_crs(&sk, &params, &mut rng).unwrap();

    store_at_request_id(
        priv_storage,
        crs_handle,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    .unwrap();
    store_at_request_id(pub_storage, crs_handle, &pp, &PubDataType::CRS.to_string())
        .await
        .unwrap();
    true
}

/// Ensure that the central server fhe keys exist.
/// If they already exist, then return false, otherwise create them and return true.
pub async fn ensure_central_keys_exist(
    priv_path: Option<&Path>,
    pub_path: Option<&Path>,
    param_path: &str,
    key_id: &RequestId,
    other_key_id: &RequestId,
    deterministic: bool,
    write_privkey: bool,
) -> bool {
    ensure_central_server_signing_keys_exist(priv_path, pub_path, deterministic).await;
    let mut priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    let mut pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&key_id.to_string(), &PubDataType::PublicKey.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
    {
        return false;
    }
    println!("Generating new centralized multiple keys. The default key has handle {key_id}");
    let params: NoiseFloodParameters = read_as_json(param_path).await.unwrap();
    let sk_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if sk_map.values().len() != 1 {
        panic!(
            "Client signing key map must contain exactly one entry, but contains {}",
            sk_map.values().len()
        );
    }
    let sk = sk_map
        .values()
        .cloned()
        .collect_vec()
        .first()
        .unwrap()
        .to_owned();

    let (fhe_pub_keys_1, key_info_1) = generate_fhe_keys(&sk, params).unwrap();
    let (fhe_pub_keys_2, key_info_2) = generate_fhe_keys(&sk, params).unwrap();
    let priv_fhe_map = HashMap::from([
        (key_id.clone(), key_info_1),
        (other_key_id.clone(), key_info_2),
    ]);
    let pub_fhe_map = HashMap::from([
        (key_id.clone(), fhe_pub_keys_1),
        (other_key_id.clone(), fhe_pub_keys_2),
    ]);
    for (req_id, key_info) in &priv_fhe_map {
        store_at_request_id(
            &mut priv_storage,
            req_id,
            key_info,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();

        // when the flag [write_privkey] is set, store the private key separately
        if write_privkey {
            store_at_request_id(
                &mut priv_storage,
                req_id,
                &key_info.client_key,
                &PrivDataType::FhePrivateKey.to_string(),
            )
            .await
            .unwrap();
        }
    }
    for (req_id, cur_keys) in &pub_fhe_map {
        store_at_request_id(
            &mut pub_storage,
            req_id,
            &cur_keys.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_at_request_id(
            &mut pub_storage,
            req_id,
            &cur_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
    }
    true
}
