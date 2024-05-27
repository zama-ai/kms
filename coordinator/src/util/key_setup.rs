use crate::cryptography::central_kms::{
    compute_handle, compute_info, gen_centralized_crs, gen_sig_keys, generate_fhe_keys,
    BaseKmsStruct, KmsFheKeyHandles,
};
use crate::cryptography::der_types::PrivateSigKey;
use crate::kms::{FheType, RequestId};
use crate::rpc::rpc_types::PrivDataType;
use crate::rpc::rpc_types::PubDataType;
use crate::storage::PublicStorage;
use crate::storage::{read_all_data, PublicStorageReader};
use crate::storage::{store_at_request_id, FileStorage, StorageType};
use crate::threshold::threshold_kms::ThresholdFheKeys;
use crate::util::file_handling::read_as_json;
use crate::{
    client::ClientDataType,
    consts::{AMOUNT_PARTIES, KEY_PATH_PREFIX, THRESHOLD, TMP_PATH_PREFIX},
};
use aes_prng::AesRng;
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
use distributed_decryption::execution::tfhe_internals::test_feature::{
    gen_key_set, keygen_all_party_shares,
};
use itertools::Itertools;
use rand::SeedableRng;
use std::collections::HashMap;
use strum::IntoEnumIterator;
use tfhe::prelude::*;
use tfhe::FheUint8;
use tokio::fs;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

// TODD The code here should be split s.t. that generation code stays in production and everything else goes to the test package

pub fn compute_cipher(msg: u8, pk: &FhePublicKey) -> (Vec<u8>, FheType) {
    let ct = FheUint8::encrypt(msg, pk);
    let mut serialized_ct = Vec::new();
    bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
    (serialized_ct, FheType::Euint8)
}

pub async fn compute_cipher_from_storage(msg: u8, key_id: &str) -> (Vec<u8>, FheType) {
    // Try first with centralized storage
    let storage = FileStorage::new_central(StorageType::PUB);
    let url = storage
        .compute_url(key_id, &PubDataType::PublicKey.to_string())
        .unwrap();
    let pk = if storage.data_exists(&url).await.unwrap() {
        storage.read_data(&url).await.unwrap()
    } else {
        // Try with the threshold storage
        let storage = FileStorage::new_threshold(StorageType::PUB, 1);
        let url = storage
            .compute_url(key_id, &PubDataType::PublicKey.to_string())
            .unwrap();
        storage.read_data(&url).await.unwrap()
    };
    compute_cipher(msg, &pk)
}

// Purge any kind of data, regardless of type, for a specific request ID
pub async fn purge(id: &str) {
    let mut pub_storage = FileStorage::new_central(StorageType::PUB);
    for cur_type in PubDataType::iter() {
        let _ = pub_storage
            .delete_data(&pub_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }

    let mut priv_storage = FileStorage::new_central(StorageType::PRIV);
    for cur_type in PrivDataType::iter() {
        let _ = priv_storage
            .delete_data(&priv_storage.compute_url(id, &cur_type.to_string()).unwrap())
            .await;
    }
    for i in 1..=AMOUNT_PARTIES {
        let mut threshold_pub = FileStorage::new_threshold(StorageType::PUB, i);
        let mut threshold_priv = FileStorage::new_threshold(StorageType::PRIV, i);
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

pub async fn ensure_dir_exist() {
    fs::create_dir_all(TMP_PATH_PREFIX).await.unwrap();
    fs::create_dir_all(KEY_PATH_PREFIX).await.unwrap();
}

pub async fn ensure_client_keys_exist(deterministic: bool) {
    let mut client_storage = FileStorage::new_central(StorageType::CLIENT);
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

pub async fn ensure_central_server_signing_keys_exist(deterministic: bool) {
    let mut priv_storage = FileStorage::new_central(StorageType::PRIV);
    let mut pub_storage = FileStorage::new_central(StorageType::PUB);
    let temp: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
    if !temp.is_empty() {
        // If signing keys already exit, then do nothing
        return;
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
}

pub async fn ensure_threshold_server_signing_keys_exist(deterministic: bool) {
    for i in 1..=AMOUNT_PARTIES {
        let mut priv_storage = FileStorage::new_threshold(StorageType::PRIV, i);
        let mut pub_storage = FileStorage::new_threshold(StorageType::PUB, i);
        let temp: HashMap<RequestId, PrivateSigKey> =
            read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
                .await
                .unwrap();
        if !temp.is_empty() {
            // If signing keys already exit, then do nothing
            return;
        }
        let mut rng = if deterministic {
            AesRng::seed_from_u64(i as u64)
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
    }
}

pub async fn ensure_threshold_keys_exist(
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
    ensure_threshold_server_signing_keys_exist(deterministic).await;
    let pub_storage = FileStorage::new_threshold(StorageType::PUB, 1);
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
    let sns_key = key_set.public_keys.sns_key.unwrap();
    for i in 1..=AMOUNT_PARTIES {
        println!("Generating key for party {i}");
        let threshold_fhe_keys = ThresholdFheKeys {
            private_keys: key_shares[i - 1].to_owned(),
            sns_key: sns_key.clone(),
        };
        let mut pub_storage = FileStorage::new_threshold(StorageType::PUB, i);
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
        let mut priv_storage = FileStorage::new_threshold(StorageType::PRIV, i);
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

pub async fn ensure_central_crs_store_exists(
    param_path: &str,
    crs_handle: &RequestId,
    deterministic: bool,
) {
    ensure_central_server_signing_keys_exist(deterministic).await;
    let mut priv_storage = FileStorage::new_central(StorageType::PRIV);
    let mut pub_storage = FileStorage::new_central(StorageType::PUB);
    if pub_storage
        .data_exists(
            &pub_storage
                .compute_url(&crs_handle.to_string(), &PubDataType::CRS.to_string())
                .unwrap(),
        )
        .await
        .unwrap()
    {
        return;
    }
    println!("Generating new centralized CRS store",);
    let sk_map: HashMap<RequestId, PrivateSigKey> =
        read_all_data(&priv_storage, &PrivDataType::SigningKey.to_string())
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
    let crs = gen_centralized_crs(&params, &mut rng).unwrap();

    let kms = BaseKmsStruct::new(sk);
    let crs_info = compute_info(&kms, &crs).unwrap();

    store_at_request_id(
        &mut priv_storage,
        crs_handle,
        &crs_info,
        &PrivDataType::CrsInfo.to_string(),
    )
    .await
    .unwrap();
    store_at_request_id(
        &mut pub_storage,
        crs_handle,
        &crs,
        &PubDataType::CRS.to_string(),
    )
    .await
    .unwrap();
}

pub async fn ensure_central_keys_exist(
    param_path: &str,
    key_id: &RequestId,
    other_key_id: &RequestId,
    deterministic: bool,
) {
    ensure_central_server_signing_keys_exist(deterministic).await;
    let mut priv_storage = FileStorage::new_central(StorageType::PRIV);
    let mut pub_storage = FileStorage::new_central(StorageType::PUB);
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

    let kms = BaseKmsStruct::new(sk.clone());
    let (client_key_1, fhe_pub_keys_1) = generate_fhe_keys(params);
    let key_info_1 = KmsFheKeyHandles::new(&kms, client_key_1, &fhe_pub_keys_1).unwrap();
    let (client_key_2, fhe_pub_keys_2) = generate_fhe_keys(params);
    let key_info_2 = KmsFheKeyHandles::new(&kms, client_key_2, &fhe_pub_keys_2).unwrap();
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
        ensure_client_keys_exist(true).await;
        ensure_central_keys_exist(
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_TEST_ID,
            true,
        )
        .await;
        ensure_central_crs_store_exists(TEST_PARAM_PATH, &TEST_CRS_ID, true).await;
        ensure_threshold_keys_exist(TEST_PARAM_PATH, &TEST_THRESHOLD_KEY_ID, true).await;
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
        ensure_client_keys_exist(true).await;
        ensure_central_keys_exist(
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID,
            &OTHER_CENTRAL_DEFAULT_ID,
            true,
        )
        .await;
        ensure_central_crs_store_exists(DEFAULT_PARAM_PATH, &DEFAULT_CRS_ID, true).await;
        ensure_threshold_keys_exist(DEFAULT_PARAM_PATH, &DEFAULT_THRESHOLD_KEY_ID, true).await;
    }
}
