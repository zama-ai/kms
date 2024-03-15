use crate::core::der_types::{PrivateSigKey, PublicSigKey};
use crate::core::kms_core::{
    gen_centralized_crs, gen_default_kms_keys, gen_sig_keys, generate_fhe_keys, CrsHashMap,
    SoftwareKmsKeys,
};
use crate::file_handling::read_as_json;
use crate::kms::FheType;
use crate::threshold::threshold_kms::ThresholdKmsKeys;
use aes_prng::AesRng;
use distributed_decryption::file_handling::{read_element, write_element};
use distributed_decryption::lwe::{gen_key_set, keygen_all_party_shares, ThresholdLWEParameters};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tfhe::prelude::FheEncrypt;
use tfhe::FheUint8;

pub type FhePublicKey = tfhe::CompactPublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub const KEY_PATH_PREFIX: &str = "keys";
pub const CRS_PATH_PREFIX: &str = "crs";
pub const TMP_PATH_PREFIX: &str = "temp";

pub const DEFAULT_PARAM_PATH: &str = "parameters/default_params.json";
pub const DEFAULT_THRESHOLD_KEYS_PATH: &str = "temp/default-threshold-keys";
pub const DEFAULT_THRESHOLD_CT_PATH: &str = "temp/default-threshold-ciphertext.bin";
pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";
pub const DEFAULT_SOFTWARE_CENTRAL_KEY_PATH: &str = "temp/default-software-keys.bin";
pub const DEFAULT_CENTRAL_CRS_PATH: &str = "crs/default-crs-store.bin";
pub const DEFAULT_CENTRAL_MULTI_KEYS_PATH: &str = "temp/default-central-multi-keys.bin";
pub const DEFAULT_CENTRAL_CT_PATH: &str = "temp/default-central-ciphertext.bin";
pub const DEFAULT_CENTRAL_MULTI_CT_PATH: &str = "temp/default-central-multi-keys-ciphertext.bin";
pub const KEY_HANDLE: &str = "default";

pub const DEFAULT_CRS_HANDLE: &str = "default";
pub const TEST_CRS_HANDLE: &str = "test";

// TODO Test should be in a test module, however I have spend an hour trying to refactor this
// without success. Someone with good rust skills are very welcome to try this
pub const BASE_PORT: u16 = 50050;
pub const DEFAULT_URL: &str = "127.0.0.1";
pub const DEFAULT_PROT: &str = "http";
pub const TEST_MSG: u8 = 42;
pub const TEST_FHE_TYPE: FheType = FheType::Euint8;
pub const AMOUNT_PARTIES: usize = 4;
pub const THRESHOLD: usize = 1;

pub const TEST_PARAM_PATH: &str = "parameters/small_test_params.json";
pub const TEST_THRESHOLD_KEYS_PATH: &str = "temp/test-threshold-keys";
pub const TEST_THRESHOLD_CT_PATH: &str = "temp/test-threshold-ciphertext.bin";
pub const TEST_CENTRAL_KEYS_PATH: &str = "temp/test-central-keys.bin";
pub const TEST_CENTRAL_CRS_PATH: &str = "crs/test-crs-store.bin";
pub const TEST_CENTRAL_MULTI_KEYS_PATH: &str = "temp/test-central-multi-keys.bin";
pub const TEST_CENTRAL_CT_PATH: &str = "temp/test-central-ciphertext.bin";
pub const TEST_CENTRAL_MULTI_CT_PATH: &str = "temp/test-central-multi-keys-ciphertext.bin";
pub const OTHER_KEY_HANDLE: &str = "otherKeyHandle";

#[derive(Serialize, Deserialize)]
pub struct ThresholdTestingKeys {
    pub params: ThresholdLWEParameters,
    pub fhe_pub: FhePublicKey,
    pub kms_keys: ThresholdKmsKeys,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

#[derive(Serialize, Deserialize)]
pub struct CentralizedTestingKeys {
    pub params: ThresholdLWEParameters,
    pub software_kms_keys: SoftwareKmsKeys,
    pub client_pk: PublicSigKey,
    pub client_sk: PrivateSigKey,
    pub server_keys: Vec<PublicSigKey>,
}

pub fn ensure_dir_exist() {
    fs::create_dir_all(TMP_PATH_PREFIX).unwrap();
    fs::create_dir_all(KEY_PATH_PREFIX).unwrap();
    fs::create_dir_all(CRS_PATH_PREFIX).unwrap();
}

fn ensure_threshold_keys_exist(param_path: &str, threshold_key_path: &str) {
    if !Path::new(threshold_key_path).exists() {
        tracing::info!("Generating new threshold keys");
        let mut rng = AesRng::seed_from_u64(1);
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let key_set = gen_key_set(params, &mut rng);
        let key_shares =
            keygen_all_party_shares(&key_set, &mut rng, AMOUNT_PARTIES, THRESHOLD).unwrap();
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let mut pks = Vec::with_capacity(AMOUNT_PARTIES);
        let mut sks = Vec::with_capacity(AMOUNT_PARTIES);
        for _i in 1..=AMOUNT_PARTIES {
            let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
            pks.push(sig_pk);
            sks.push(sig_sk);
        }
        for i in 1..=AMOUNT_PARTIES {
            tracing::info!("Generating ket for party {i}");
            let kms_keys = ThresholdKmsKeys {
                params,
                fhe_dec_key_share: key_shares[i - 1].to_owned(),
                conversion_key: key_set.conversion_key.clone(),
                sig_sk: sks[i - 1].clone(),
                sig_pk: pks[i - 1].clone(),
            };
            let threshold_testing_keys = ThresholdTestingKeys {
                params,
                kms_keys,
                fhe_pub: key_set.public_key.to_owned(),
                client_pk: client_pk.clone(),
                client_sk: client_sk.clone(),
                server_keys: pks.clone(),
            };
            let path = format!("{}-{}.bin", threshold_key_path, i);
            assert!(write_element(path, &threshold_testing_keys,).is_ok());
        }
    }
}

fn ensure_central_keys_exist(param_path: &str, central_key_path: &str, key_handle: Option<String>) {
    if !Path::new(central_key_path).exists() {
        tracing::info!("Generating new centralized keys");
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let mut rng = AesRng::seed_from_u64(1);
        let software_kms_keys = gen_default_kms_keys(params, &mut rng, key_handle);
        let server_keys = vec![software_kms_keys.sig_pk.clone()];
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params,
            software_kms_keys,
            client_pk,
            client_sk,
            server_keys,
        };
        assert!(write_element(central_key_path.to_string(), &centralized_test_keys,).is_ok());
    }
}

pub fn ensure_central_crs_store_exists(
    param_path: &str,
    central_crs_path: &str,
    crs_handle: Option<String>,
) {
    if !Path::new(central_crs_path).exists() {
        tracing::info!("Generating new centralized CRS store");
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let mut rng = AesRng::seed_from_u64(42);
        let crs = gen_centralized_crs(&params, &mut rng);
        let handle = crs_handle.unwrap_or(DEFAULT_CRS_HANDLE.to_string());
        let crs_store = CrsHashMap::from([(handle, crs)]);
        assert!(write_element(central_crs_path.to_string(), &crs_store,).is_ok());
    }
}

pub fn ensure_central_multiple_keys_ct_exist(
    param_path: &str,
    central_keys_path: &str,
    other_key_handle: &str,
    ciphertext_path: &str,
) {
    if !Path::new(central_keys_path).exists() {
        tracing::info!("Generating new centralized multiple keys");
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let mut rng = AesRng::seed_from_u64(1);
        // Generate keys with default handle
        let mut software_kms_keys =
            gen_default_kms_keys(params, &mut rng, Some(KEY_HANDLE.to_string()));
        let other_fhe_keys = generate_fhe_keys(params);
        // Insert a key with another handle to setup a KMS with multiple keys
        software_kms_keys
            .fhe_keys
            .insert(other_key_handle.to_string(), other_fhe_keys);
        let server_keys = vec![software_kms_keys.sig_pk.clone()];
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params,
            software_kms_keys,
            client_pk,
            client_sk,
            server_keys,
        };
        assert!(write_element(central_keys_path.to_string(), &centralized_test_keys,).is_ok());
    }
    if !Path::new(ciphertext_path).exists() {
        let central_keys: CentralizedTestingKeys =
            read_element(central_keys_path.to_string()).unwrap();
        let client_key = &central_keys
            .software_kms_keys
            .fhe_keys
            .get(OTHER_KEY_HANDLE)
            .unwrap()
            .client_key;
        ensure_ciphertext_exist(ciphertext_path, FhePublicKey::new(client_key));
    }
}

pub fn ensure_ciphertext_exist(ciphertext_path: &str, fhe_pk: FhePublicKey) {
    if !Path::new(ciphertext_path).exists() {
        tracing::info!("Generating a new ciphertext");
        let ct = FheUint8::encrypt(TEST_MSG, &fhe_pk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        assert!(write_element(
            ciphertext_path.to_string(),
            &(serialized_ct, FheType::Euint8)
        )
        .is_ok());
    }
}

pub fn ensure_central_key_ct_exist(
    param_path: &str,
    central_key_path: &str,
    ciphertext_path: &str,
) {
    if !Path::new(central_key_path).exists() {
        ensure_central_keys_exist(param_path, central_key_path, Some(KEY_HANDLE.to_string()));
    }
    if !Path::new(ciphertext_path).exists() {
        let central_keys: CentralizedTestingKeys =
            read_element(central_key_path.to_string()).unwrap();
        let client_key = &central_keys
            .software_kms_keys
            .fhe_keys
            .get(KEY_HANDLE)
            .unwrap()
            .client_key;
        ensure_ciphertext_exist(ciphertext_path, FhePublicKey::new(client_key));
    }
}

pub fn ensure_threshold_key_ct_exist(
    param_path: &str,
    threshold_key_path: &str,
    ciphertext_path: &str,
) {
    // Observe we just test for the first key for simplicity
    if !Path::new(&format!("{threshold_key_path}-1.bin")).exists() {
        ensure_threshold_keys_exist(param_path, threshold_key_path);
    }
    if !Path::new(ciphertext_path).exists() {
        let threshold_keys: ThresholdTestingKeys =
            read_element(format!("{threshold_key_path}-1.bin")).unwrap();
        ensure_ciphertext_exist(ciphertext_path, threshold_keys.fhe_pub);
    }
}
