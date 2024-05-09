use super::file_handling::read_element;
use crate::{
    consts::{
        AMOUNT_PARTIES, COMPRESSED, CRS_PATH_PREFIX, KEY_PATH_PREFIX, SEC_PAR, TEST_MSG, THRESHOLD,
        TMP_PATH_PREFIX,
    },
    cryptography::central_kms::{compute_handle, BaseKmsStruct},
    rpc::rpc_types::PubDataType,
    storage::StorageType,
};
use crate::{cryptography::central_kms::compute_info, storage::FileStorage};
use crate::{cryptography::central_kms::KmsFheKeyHandles, util::file_handling::read_as_json};
use crate::{
    cryptography::central_kms::{
        gen_centralized_crs, gen_default_kms_keys, gen_sig_keys, generate_fhe_keys, CrsHashMap,
        SoftwareKmsKeys,
    },
    util::file_handling::write_element,
};
use crate::{
    cryptography::der_types::{PrivateSigKey, PublicSigKey},
    threshold::threshold_kms::ThresholdFheKeys,
};
use crate::{
    kms::{FheType, RequestId},
    storage::store_request_id,
};
use crate::{rpc::rpc_types::PrivDataType, threshold::threshold_kms::ThresholdKmsKeys};
use aes_prng::AesRng;
use distributed_decryption::execution::zk::ceremony::PublicParameter;
use distributed_decryption::execution::{
    endpoints::keygen::FhePubKeySet,
    tfhe_internals::{
        parameters::{DKGParamsRegular, DKGParamsSnS, NoiseFloodParameters},
        test_feature::{gen_key_set, keygen_all_party_shares},
    },
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::HashMap, fs};
use tfhe::prelude::*;
use tfhe::FheUint8;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

// TODO this should all be replaced with an integration test using devstorage

#[derive(Serialize, Deserialize)]
pub struct ThresholdTestingKeys {
    pub params: DKGParamsSnS,
    pub fhe_pub: FhePublicKey,
    pub kms_keys: ThresholdKmsKeys,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

// TODO should be in test package
#[derive(Serialize, Deserialize)]
pub struct CentralizedTestingKeys {
    pub params: NoiseFloodParameters,
    pub software_kms_keys: SoftwareKmsKeys,
    pub pub_fhe_keys: HashMap<RequestId, FhePubKeySet>,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

#[derive(Serialize, Deserialize)]
pub struct CrsHandleStore {
    pub params: NoiseFloodParameters,
    pub crs: HashMap<RequestId, PublicParameter>,
    pub crs_info: CrsHashMap,
}

pub fn ensure_dir_exist() {
    fs::create_dir_all(TMP_PATH_PREFIX).unwrap();
    fs::create_dir_all(KEY_PATH_PREFIX).unwrap();
    fs::create_dir_all(CRS_PATH_PREFIX).unwrap();
}

pub fn ensure_threshold_keys_exist(param_path: &str, threshold_key_path: &str, key_id: &str) {
    if !Path::new(&format!("{}-1.bin", threshold_key_path))
        .try_exists()
        .unwrap()
    {
        println!("Generating new threshold keys at {}", threshold_key_path);
        // TODO generalize setup for multiple keys
        let key_req_id = RequestId {
            request_id: key_id.to_owned(),
        };
        let mut rng = AesRng::seed_from_u64(1);
        let noise_params: NoiseFloodParameters = read_as_json(param_path.to_owned()).unwrap();
        let params = DKGParamsSnS {
            regular_params: DKGParamsRegular {
                sec: SEC_PAR,
                ciphertext_parameters: noise_params.ciphertext_parameters,
                flag: COMPRESSED,
            },
            sns_params: noise_params.sns_parameters,
        };
        let key_set = gen_key_set(params.to_noiseflood_parameters(), &mut rng);
        let key_shares = keygen_all_party_shares(
            key_set.get_raw_lwe_client_key(),
            key_set.get_raw_glwe_client_key(),
            key_set.sns_secret_key.key,
            params.to_noiseflood_parameters().ciphertext_parameters,
            &mut rng,
            AMOUNT_PARTIES,
            THRESHOLD,
        )
        .unwrap();
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let mut pks = Vec::with_capacity(AMOUNT_PARTIES);
        let mut sks = Vec::with_capacity(AMOUNT_PARTIES);
        for _i in 1..=AMOUNT_PARTIES {
            let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
            pks.push(sig_pk);
            sks.push(sig_sk);
        }
        let sns_key = key_set.public_keys.sns_key.unwrap();
        let mut pub_storage = FileStorage::new(&StorageType::PUB.to_string());
        store_request_id(
            &mut pub_storage,
            &key_req_id,
            &key_set.public_keys.public_key,
            &PubDataType::PublicKey.to_string(),
        )
        .unwrap();
        store_request_id(
            &mut pub_storage,
            &key_req_id,
            &key_set.public_keys.server_key,
            &PubDataType::ServerKey.to_string(),
        )
        .unwrap();
        for i in 1..=AMOUNT_PARTIES {
            println!("Generating key for party {i}");
            let threshold_fhe_keys = ThresholdFheKeys {
                private_keys: key_shares[i - 1].to_owned(),
                sns_key: sns_key.clone(),
            };
            let kms_keys = ThresholdKmsKeys {
                fhe_keys: HashMap::from([(key_req_id.clone(), threshold_fhe_keys.clone())]),
                sig_sk: sks[i - 1].clone(),
                sig_pk: pks[i - 1].clone(),
            };
            let threshold_testing_keys = ThresholdTestingKeys {
                params,
                kms_keys,
                fhe_pub: key_set.public_keys.public_key.to_owned(),
                client_pk: client_pk.clone(),
                client_sk: client_sk.clone(),
                server_keys: pks.clone(),
            };
            let path = format!("{}-{}.bin", threshold_key_path, i);
            assert!(write_element(path, &threshold_testing_keys,).is_ok());
            store_request_id(
                &mut pub_storage,
                &RequestId {
                    request_id: compute_handle(&sks[i - 1]).unwrap(),
                },
                &pks[i - 1].clone(),
                &PubDataType::VerfKey.to_string(),
            )
            .unwrap();
            let mut priv_storage = FileStorage::new(&format!("priv-p{i}"));
            store_request_id(
                &mut priv_storage,
                &key_req_id,
                &sks[i - 1].clone(),
                &PrivDataType::SigningKey.to_string(),
            )
            .unwrap();
            store_request_id(
                &mut priv_storage,
                &key_req_id,
                &threshold_fhe_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .unwrap();
        }
    }
}

pub fn ensure_central_crs_store_exists(
    param_path: &str,
    central_crs_path: &str,
    central_key_path: &str,
    crs_handle: &RequestId,
) {
    if !Path::new(central_crs_path).try_exists().unwrap() {
        let central_keys: CentralizedTestingKeys = read_element(central_key_path).unwrap();

        println!(
            "Generating new centralized CRS store at {}",
            central_crs_path
        );
        let params: NoiseFloodParameters = read_as_json(param_path.to_owned()).unwrap();
        let mut rng = AesRng::seed_from_u64(42);
        let crs = gen_centralized_crs(&params, &mut rng).unwrap();

        let kms = BaseKmsStruct::new(central_keys.software_kms_keys.sig_sk.clone());
        let crs_info = compute_info(&kms, &crs).unwrap();

        let ccs = CrsHandleStore {
            params,
            crs: HashMap::from([(crs_handle.clone(), crs)]),
            crs_info: HashMap::from([(crs_handle.clone(), crs_info.clone())]),
        };
        assert!(write_element(central_crs_path.to_string(), &ccs,).is_ok());
        let mut storage = FileStorage::new(&StorageType::PRIV.to_string());
        store_request_id(
            &mut storage,
            crs_handle,
            &crs_info,
            &PrivDataType::CrsInfo.to_string(),
        )
        .unwrap();
    }
}

pub fn ensure_central_keys_exist(
    param_path: &str,
    central_keys_path: &str,
    key_id: &RequestId,
    other_key_id: &RequestId,
) {
    if !Path::new(central_keys_path).try_exists().unwrap() {
        println!(
            "Generating new centralized multiple keys at {}",
            central_keys_path
        );
        let params: NoiseFloodParameters = read_as_json(param_path.to_owned()).unwrap();
        let mut rng = AesRng::seed_from_u64(1);
        // Generate keys with default handle
        let (mut software_kms_keys, pub_fhe_keys) =
            gen_default_kms_keys(params, &mut rng, Some(key_id.to_owned()));
        let (other_client_key, other_pub_keys) = generate_fhe_keys(params);
        let kms = BaseKmsStruct::new(software_kms_keys.sig_sk.clone());
        let other_key_info =
            KmsFheKeyHandles::new(&kms, other_client_key, &other_pub_keys).unwrap();
        // Insert a key with another handle to setup a KMS with multiple keys
        software_kms_keys
            .key_info
            .insert(other_key_id.clone(), other_key_info);
        let pub_fhe_map = HashMap::from([
            (key_id.clone(), pub_fhe_keys),
            (other_key_id.clone(), other_pub_keys),
        ]);
        let server_keys = vec![software_kms_keys.sig_pk.clone()];
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params,
            software_kms_keys,
            client_pk,
            client_sk,
            server_keys,
            pub_fhe_keys: pub_fhe_map,
        };
        assert!(write_element(central_keys_path.to_string(), &centralized_test_keys,).is_ok());
        let mut priv_storage = FileStorage::new(&StorageType::PRIV.to_string());
        let mut pub_storage = FileStorage::new(&StorageType::PUB.to_string());
        store_request_id(
            &mut pub_storage,
            &RequestId {
                request_id: compute_handle(&centralized_test_keys.software_kms_keys.sig_sk)
                    .unwrap(),
            },
            &centralized_test_keys.software_kms_keys.sig_pk.clone(),
            &PubDataType::VerfKey.to_string(),
        )
        .unwrap();
        store_request_id(
            &mut priv_storage,
            key_id,
            &centralized_test_keys.software_kms_keys.sig_sk,
            &PrivDataType::SigningKey.to_string(),
        )
        .unwrap();
        for (req_id, key_info) in &centralized_test_keys.software_kms_keys.key_info {
            store_request_id(
                &mut priv_storage,
                req_id,
                key_info,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .unwrap();
        }
        for (req_id, cur_keys) in &centralized_test_keys.pub_fhe_keys {
            store_request_id(
                &mut pub_storage,
                req_id,
                &cur_keys.public_key,
                &PubDataType::PublicKey.to_string(),
            )
            .unwrap();
            store_request_id(
                &mut pub_storage,
                req_id,
                &cur_keys.server_key,
                &PubDataType::ServerKey.to_string(),
            )
            .unwrap();
        }
    }
}

pub fn ensure_ciphertext_exist(ciphertext_path: &str, fhe_pk: &FhePublicKey) {
    if !Path::new(ciphertext_path).try_exists().unwrap() {
        println!("Generating a new ciphertext at {}", ciphertext_path);
        let ct = FheUint8::encrypt(TEST_MSG, fhe_pk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        assert!(write_element(
            ciphertext_path.to_string(),
            &(serialized_ct, FheType::Euint8)
        )
        .is_ok());
    }
}
