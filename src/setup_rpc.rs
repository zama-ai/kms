use crate::core::der_types::{PrivateSigKey, PublicSigKey};
use crate::{
    core::kms_core::{gen_sig_keys, SoftwareKmsKeys},
    file_handling::read_as_json,
    kms::FheType,
    threshold::threshold_kms::ThresholdKmsKeys,
};
use aes_prng::AesRng;
use distributed_decryption::lwe::{SecretKey, ThresholdLWEParameters};
use distributed_decryption::{
    file_handling::{read_element, write_element},
    lwe::{gen_key_set, keygen_all_party_shares},
};
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use tfhe::prelude::FheEncrypt;
use tfhe::shortint::{CarryModulus, ClassicPBSParameters, EncryptionKeyChoice, MessageModulus};
use tfhe::FheUint8;
use tfhe::PublicKey;
use tfhe::CompactPublicKey;

pub type FhePublicKey = tfhe::PublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub const DEFAULT_CENTRAL_CIPHER_PATH: &str = "temp/default-central-cipher.bin";
pub const DEFAULT_THRESHOLD_CIPHER_PATH: &str = "temp/default-threshold-cipher.bin";
pub const DEFAULT_THRESHOLD_KEYS_PATH: &str = "temp/default-threshold-keys";
pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys";
pub const DEFAULT_PARAM_PATH: &str = "parameters/default_params.json";

// TODO Test  should be in a test module, however I have spend an hour trying to refactor this without success.
// Someone with good rust skills are very welcome to try this
pub const BASE_PORT: u16 = 50050;
pub const DEFAULT_URL: &str = "0.0.0.0";
pub const DEFAULT_PROT: &str = "http";
pub const TEST_MSG: u8 = 42;
pub const TEST_FHE_TYPE: FheType = FheType::Euint8;
pub const AMOUNT_PARTIES: usize = 4;
pub const THRESHOLD: usize = 1;

pub const TEST_PARAM_PATH: &str = "parameters/small_test_params.json";
pub const TEST_THRESHOLD_KEYS_PATH: &str = "temp/test-threshold-keys";
pub const TEST_THRESHOLD_CIPHER_PATH: &str = "temp/test-threshold-cipher.bin";
pub const TEST_CENTRAL_KEYS_PATH: &str = "temp/test-central-keys";
pub const TEST_CENTRAL_CIPHER_PATH: &str = "temp/test-central-cipher.bin";

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

pub fn recover_bsk(sk: &tfhe::ClientKey) -> tfhe::ServerKey {
    sk.generate_server_key()
}

pub fn recover_compact_pk(ddec_sk: SecretKey) -> tfhe::CompactPublicKey {
    let hl_sk = recover_sk(ddec_sk);
    CompactPublicKey::new(&hl_sk)
}

pub fn recover_pk(ddec_sk: SecretKey) -> FhePublicKey {
    let hl_sk = recover_sk(ddec_sk);
    FhePublicKey::new(&hl_sk)
}

pub fn recover_sk(ddec_sk: SecretKey) -> tfhe::ClientKey {
    let threshold_params = ddec_sk.threshold_lwe_parameters.input_cipher_parameters;
    let carry_mod = CarryModulus(
        1 << (threshold_params.message_modulus_log.0
            - threshold_params.usable_message_modulus_log.0),
    );
    let classic_params = ClassicPBSParameters {
        lwe_dimension: threshold_params.lwe_dimension,
        glwe_dimension: threshold_params.glwe_dimension,
        polynomial_size: threshold_params.polynomial_size,
        lwe_modular_std_dev: threshold_params.lwe_modular_std_dev,
        glwe_modular_std_dev: threshold_params.glwe_modular_std_dev,
        pbs_base_log: threshold_params.pbs_base_log,
        pbs_level: threshold_params.pbs_level,
        ks_base_log: threshold_params.ks_base_log,
        ks_level: threshold_params.ks_level,
        message_modulus: MessageModulus(1 << threshold_params.usable_message_modulus_log.0),
        carry_modulus: carry_mod,
        ciphertext_modulus: threshold_params.ciphertext_modulus,
        encryption_key_choice: EncryptionKeyChoice::Small,
    };
    let raw_shortint = tfhe::shortint::ClientKey::from_raw_parts(
        ddec_sk.glwe_secret_key_64,
        ddec_sk.lwe_secret_key_64,
        classic_params.into(),
    );
    let raw = tfhe::integer::ClientKey::from_raw_parts(raw_shortint);
    tfhe::ClientKey::from_raw_parts(raw, None)
}

fn ensure_dir_exist() {
    fs::create_dir_all("temp").unwrap();
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
                bsk: key_set.ck.clone(),
                sig_sk: sks[i - 1].clone(),
                sig_pk: pks[i - 1].clone(),
            };
            let threshold_testing_keys = ThresholdTestingKeys {
                params,
                kms_keys,
                fhe_pub: recover_pk(key_set.sk.to_owned()),
                client_pk: client_pk.clone(),
                client_sk: client_sk.clone(),
                server_keys: pks.clone(),
            };
            let path = format!("{}-{}.bin", threshold_key_path, i);
            assert!(write_element(path.to_string(), &threshold_testing_keys,).is_ok());
        }
    }
}

fn ensure_central_keys_exist(param_path: &str, central_key_path: &str) {
    if !Path::new(central_key_path).exists() {
        tracing::info!("Generating new centralized keys");
        let mut rng = AesRng::seed_from_u64(1);
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let key_set = gen_key_set(params, &mut rng);
        let fhe_sk = recover_sk(key_set.sk);
        let mut rng = AesRng::seed_from_u64(1);
        let (server_pk, server_sk) = gen_sig_keys(&mut rng);
        let software_kms_keys = SoftwareKmsKeys {
            fhe_sk,
            sig_sk: server_sk,
            sig_pk: server_pk.clone(),
        };
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        let centralized_test_keys = CentralizedTestingKeys {
            params,
            software_kms_keys,
            client_pk,
            client_sk,
            server_keys: vec![server_pk],
        };
        assert!(write_element(central_key_path.to_string(), &centralized_test_keys,).is_ok());
    }
}

fn ensure_cipher_exist(cipher_path: &str, fhe_pk: FhePublicKey) {
    if !Path::new(cipher_path).exists() {
        tracing::info!("Generating a new ciphertext");
        let ct = FheUint8::encrypt(TEST_MSG, &fhe_pk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        assert!(write_element(cipher_path.to_string(), &(serialized_ct, FheType::Euint8)).is_ok());
    }
}

pub fn ensure_central_key_cipher_exist(
    param_path: &str,
    central_key_path: &str,
    cipher_path: &str,
) {
    ensure_dir_exist();
    if !Path::new(central_key_path).exists() {
        ensure_central_keys_exist(param_path, central_key_path);
    }
    if !Path::new(cipher_path).exists() {
        let central_keys: CentralizedTestingKeys =
            read_element(central_key_path.to_string()).unwrap();
        ensure_cipher_exist(
            cipher_path,
            PublicKey::new(&central_keys.software_kms_keys.fhe_sk),
        );
    }
}

pub fn ensure_threshold_key_cipher_exist(
    param_path: &str,
    threshold_key_path: &str,
    cipher_path: &str,
) {
    ensure_dir_exist();
    // Observe we just test for the first key for simplicity
    if !Path::new(&format!("{threshold_key_path}-1.bin")).exists() {
        ensure_threshold_keys_exist(param_path, threshold_key_path);
    }
    if !Path::new(cipher_path).exists() {
        let threshold_keys: ThresholdTestingKeys =
            read_element(format!("{threshold_key_path}-1.bin")).unwrap();
        ensure_cipher_exist(cipher_path, threshold_keys.fhe_pub);
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_PARAM_PATH, TEST_PARAM_PATH};
    use crate::{
        kms::FheType,
        setup_rpc::{recover_pk, recover_sk, FhePublicKey, TEST_MSG},
    };
    use aes_prng::AesRng;
    use distributed_decryption::{
        algebra::base_ring::Z128,
        file_handling::read_as_json,
        lwe::{
            combine128, gen_key_set, to_large_ciphertext_block, BootstrappingKey, SecretKey,
            ThresholdLWEParameters,
        },
    };
    use itertools::Itertools;
    use rand::SeedableRng;
    use tfhe::{
        prelude::{FheDecrypt, FheEncrypt},
        FheUint8,
    };

    /// Validate the keys by testing all the possible combination of high level, 64 bit and 128 bit ciphers decrypt correctly
    /// This involves regenerating default FHE keys which can take several minutes. Only use as needed.
    // #[test]
    // #[ignore]
    #[allow(dead_code)]
    fn validate_default_keys() {
        validate_keys(DEFAULT_PARAM_PATH);
    }

    #[test]
    fn validate_test_keys() {
        validate_keys(TEST_PARAM_PATH);
    }

    fn validate_keys(param_path: &str) {
        let mut rng = AesRng::seed_from_u64(1);
        let params: ThresholdLWEParameters = read_as_json(param_path.to_owned()).unwrap();
        let key_set = gen_key_set(params, &mut rng);
        let sk = recover_sk(key_set.sk.clone());
        // Two different ways to recover public key
        let pk = recover_pk(key_set.sk.clone());
        let (hl_ct, res_64_1, res_128_1) = decrypt(&pk, &key_set.ck, &key_set.sk);
        // First decrypt using HL keys
        let hl_res: u8 = hl_ct.decrypt(&sk);
        assert_eq!(TEST_MSG, hl_res);
        let bit_in_block = params.output_cipher_parameters.usable_message_modulus_log.0 as u32;
        let res_combined_64 = combine128(bit_in_block, res_64_1).unwrap();
        let res_combined_128 = combine128(bit_in_block, res_128_1).unwrap();
        assert_eq!(TEST_MSG as u128, res_combined_64);
        assert_eq!(TEST_MSG as u128, res_combined_128);
    }

    fn decrypt(
        pk: &FhePublicKey,
        ck: &BootstrappingKey,
        sk: &SecretKey,
    ) -> (FheUint8, Vec<Z128>, Vec<Z128>) {
        let hl_ct: FheUint8 = FheUint8::encrypt(TEST_MSG, pk);
        let mut res_64 = Vec::new();
        let mut res_128 = Vec::new();
        let mut serialized_hl_ct = Vec::new();
        bincode::serialize_into(&mut serialized_hl_ct, &hl_ct).unwrap();
        let ll_ct = FheType::Euint8
            .deserialize_to_low_level(&serialized_hl_ct)
            .unwrap();
        let ct_large = ll_ct
            .iter()
            .map(|ct_block| to_large_ciphertext_block(ck, ct_block))
            .collect_vec();

        for cur_block in ll_ct {
            res_64.push(sk.decrypt_block_64(&cur_block));
        }
        for cur_block in ct_large {
            res_128.push(sk.decrypt_block_128(&cur_block));
        }
        (hl_ct, res_64, res_128)
    }
}
