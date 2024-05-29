#[cfg(test)]
use crate::consts::{KEY_PATH_PREFIX, TMP_PATH_PREFIX};
use crate::cryptography::central_kms::{
    compute_handle, gen_centralized_crs, gen_sig_keys, generate_fhe_keys,
};
use crate::cryptography::der_types::PrivateSigKey;
use crate::kms::{FheType, RequestId};
use crate::rpc::rpc_types::PrivDataType;
use crate::rpc::rpc_types::PubDataType;
use crate::storage::PublicStorage;
use crate::storage::{read_all_data, PublicStorageReader};
use crate::storage::{store_at_request_id, FileStorage, StorageType};
use crate::threshold::threshold_kms::compute_all_info;
use crate::threshold::threshold_kms::ThresholdFheKeys;
use crate::util::file_handling::read_as_json;
use crate::{
    client::ClientDataType,
    consts::{AMOUNT_PARTIES, THRESHOLD},
};
use aes_prng::AesRng;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::execution::tfhe_internals::test_feature::{
    gen_key_set, keygen_all_party_shares,
};
use itertools::Itertools;
use rand::SeedableRng;
use std::collections::HashMap;
use std::path::Path;
use strum::IntoEnumIterator;
use tfhe::prelude::*;
use tfhe::FheUint8;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

// TODD The code here should be split s.t. that generation code stays in production and everything else goes to the test package

pub fn compute_cipher(msg: u8, pk: &FhePublicKey) -> (Vec<u8>, FheType) {
    let ct = FheUint8::encrypt(msg, pk);
    let mut serialized_ct = Vec::new();
    bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
    (serialized_ct, FheType::Euint8)
}

/// This function should be used for testing only and it can panic.
pub async fn compute_cipher_from_storage(
    pub_path: Option<&Path>,
    msg: u8,
    key_id: &str,
) -> (Vec<u8>, FheType) {
    // Try first with centralized storage
    let storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    let url = storage
        .compute_url(key_id, &PubDataType::PublicKey.to_string())
        .unwrap();
    let pk = if storage.data_exists(&url).await.unwrap() {
        storage.read_data(&url).await.unwrap()
    } else {
        // Try with the threshold storage
        let storage = FileStorage::new_threshold(pub_path, StorageType::PUB, 1).unwrap();
        let url = storage
            .compute_url(key_id, &PubDataType::PublicKey.to_string())
            .unwrap();
        storage.read_data(&url).await.unwrap()
    };
    compute_cipher(msg, &pk)
}

/// Purge any kind of data, regardless of type, for a specific request ID.
///
/// This function should be used for testing only and it can panic.
pub async fn purge(pub_path: Option<&Path>, priv_path: Option<&Path>, id: &str) {
    let mut pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    for cur_type in PubDataType::iter() {
        let _ = pub_storage
            .delete_data(&pub_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }

    let mut priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    for cur_type in PrivDataType::iter() {
        let _ = priv_storage
            .delete_data(&priv_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }
    for i in 1..=AMOUNT_PARTIES {
        let mut threshold_pub = FileStorage::new_threshold(pub_path, StorageType::PUB, i).unwrap();
        let mut threshold_priv =
            FileStorage::new_threshold(priv_path, StorageType::PRIV, i).unwrap();
        for cur_type in PrivDataType::iter() {
            let _ = threshold_priv
                .delete_data(
                    &threshold_priv
                        .compute_url(id, &cur_type.to_string())
                        .unwrap(),
                )
                .await;
        }
        for cur_type in PubDataType::iter() {
            let _ = threshold_pub
                .delete_data(
                    &threshold_pub
                        .compute_url(id, &cur_type.to_string())
                        .unwrap(),
                )
                .await;
        }
    }
}

#[cfg(test)]
pub async fn ensure_dir_exist() {
    tokio::fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
    tokio::fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
}

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
    println!("Generating new centralized multiple keys");
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
) -> Vec<HashMap<RequestId, PrivateSigKey>> {
    let mut signing_keys = Vec::with_capacity(AMOUNT_PARTIES);
    for i in 1..=AMOUNT_PARTIES {
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

/// NOTE: this is insecure!
pub async fn ensure_threshold_keys_exist(
    priv_path: Option<&Path>,
    pub_path: Option<&Path>,
    param_path: &str,
    key_id: &RequestId,
    deterministic: bool,
) {
    // TODO generalize setup for multiple keys
    let mut rng = if deterministic {
        AesRng::seed_from_u64(AMOUNT_PARTIES as u64)
    } else {
        AesRng::from_entropy()
    };
    let signing_keys =
        ensure_threshold_server_signing_keys_exist(priv_path, pub_path, deterministic).await;
    let pub_storage = FileStorage::new_threshold(pub_path, StorageType::PUB, 1).unwrap();
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&key_id.to_string(), &PubDataType::PublicKey.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
    {
        return;
    }

    let params: NoiseFloodParameters = read_as_json(param_path).await.unwrap();
    let key_set = gen_key_set(params, &mut rng);
    let key_shares = keygen_all_party_shares(
        key_set.get_raw_lwe_client_key(),
        key_set.get_raw_glwe_client_key(),
        key_set.sns_secret_key.key,
        params.ciphertext_parameters,
        &mut rng,
        AMOUNT_PARTIES,
        THRESHOLD,
    )
    .unwrap();
    let sns_key = key_set.public_keys.sns_key.to_owned().unwrap();
    for i in 1..=AMOUNT_PARTIES {
        println!("Generating key for party {i}");
        // Get first signing key
        let sk = signing_keys[i - 1]
            .values()
            .collect_vec()
            .first()
            .unwrap()
            .to_owned()
            .to_owned();
        let info = compute_all_info(&sk, &key_set.public_keys).unwrap();
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[i - 1].to_owned(),
            sns_key: sns_key.clone(),
            pk_meta_data: info,
        };
        let mut pub_storage = FileStorage::new_threshold(pub_path, StorageType::PUB, i).unwrap();
        store_at_request_id(
            &mut pub_storage,
            key_id,
            &key_set.public_keys.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .await
        .unwrap();
        store_at_request_id(
            &mut pub_storage,
            key_id,
            &key_set.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .await
        .unwrap();
        let mut priv_storage = FileStorage::new_threshold(priv_path, StorageType::PRIV, i).unwrap();
        store_at_request_id(
            &mut priv_storage,
            key_id,
            &threshold_fhe_keys,
            &PrivDataType::FheKeyInfo.to_string(),
        )
        .await
        .unwrap();
    }
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

/// Ensure that the central server crs exist.
/// If they already exist, then return false, otherwise create them and return true.
async fn ensure_crs_store_exists<S>(
    priv_storage: &mut S,
    pub_storage: &mut S,
    param_path: &str,
    crs_handle: &RequestId,
    deterministic: bool,
) -> bool
where
    S: PublicStorage,
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
    let params: NoiseFloodParameters = read_as_json(param_path).await.unwrap();
    let sk_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if sk_map.values().cloned().collect_vec().len() != 1 {
        panic!("Client signing key map should only contain one entry");
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

#[cfg(test)]
mod tests {
    use crate::consts::TEST_CENTRAL_KEY_ID;
    use crate::consts::{
        OTHER_CENTRAL_TEST_ID, TEST_CRS_ID, TEST_PARAM_PATH, TEST_THRESHOLD_KEY_ID,
    };
    use crate::util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist, ensure_client_keys_exist,
        ensure_dir_exist, ensure_threshold_keys_exist,
    };

    #[tokio::test]
    #[ctor::ctor]
    async fn ensure_testing_material_exists() {
        ensure_dir_exist().await;
        ensure_client_keys_exist(None, true).await;
        ensure_central_keys_exist(
            None,
            None,
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            true,
        )
        .await;
        ensure_central_crs_store_exists(None, None, TEST_PARAM_PATH, &TEST_CRS_ID, true).await;
        ensure_threshold_keys_exist(None, None, TEST_PARAM_PATH, &TEST_THRESHOLD_KEY_ID, true)
            .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[ctor::ctor]
    async fn ensure_default_material_exists() {
        use crate::consts::{
            DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_PARAM_PATH, DEFAULT_THRESHOLD_KEY_ID,
            OTHER_CENTRAL_DEFAULT_ID,
        };

        ensure_dir_exist().await;
        ensure_client_keys_exist(None, true).await;
        ensure_central_keys_exist(
            None,
            None,
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_DEFAULT_ID,
            true,
        )
        .await;
        ensure_central_crs_store_exists(None, None, DEFAULT_PARAM_PATH, &DEFAULT_CRS_ID, true)
            .await;
        ensure_threshold_keys_exist(
            None,
            None,
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID,
            true,
        )
        .await;
    }
}
