#[allow(dead_code)]
pub const DEFAULT_KMS_KEY_PATH: &str = "temp/kms-keys.bin";
#[allow(dead_code)]
pub const DEFAULT_SERVER_KEYS_PATH: &str = "temp/pub-server-keys.bin";
#[allow(dead_code)]
pub const DEFAULT_FHE_KEY_PATH: &str = "temp/fhe-key.bin";
#[allow(dead_code)]
pub const DEFAULT_CLIENT_KEY_PATH: &str = "temp/priv-client-key.bin";
#[allow(dead_code)]
pub const DEFAULT_HL_CIPHER_PATH: &str = "temp/HL-cipher.bin";
#[allow(dead_code)]
pub const DEFAULT_LL_CIPHER_PATH: &str = "temp/LL-cipher.bin";
#[allow(dead_code)]
pub const KEY_SET_PATH: &str = "temp/key-set.bin";
#[allow(dead_code)]
pub const THRESHOLD_KMS_KEY_PATH: &str = "temp/threshold-kms-keys";
#[allow(dead_code)]
pub const PARAM_PATH: &str = "parameters/default_fhe.json";
#[allow(dead_code)]
pub const BASE_PORT: u16 = 50050;
#[allow(dead_code)]
pub const DEFAULT_URL: &str = "0.0.0.0";
#[allow(dead_code)]
pub const DEFAULT_PROT: &str = "http";

#[cfg(test)]
pub(crate) mod tests {
    use crate::setup_rpc::{
        DEFAULT_CLIENT_KEY_PATH, DEFAULT_FHE_KEY_PATH, DEFAULT_HL_CIPHER_PATH,
        DEFAULT_KMS_KEY_PATH, DEFAULT_SERVER_KEYS_PATH, PARAM_PATH,
    };
    use ctor::ctor;
    use distributed_decryption::lwe::{
        gen_key_set, keygen_all_party_shares, KeySet, ThresholdLWEParameters,
    };
    use kms::core::kms_core::{gen_sig_keys, FhePublicKey, SoftwareKmsKeys};
    use kms::file_handling::{read_as_json, read_element, write_element};
    use kms::kms::FheType;
    use kms::threshold::threshold_kms::ThresholdKmsKeys;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::path::Path;
    use tfhe::prelude::FheEncrypt;
    use tfhe::{generate_keys, ConfigBuilder, FheUint8, PublicKey};

    use super::{DEFAULT_LL_CIPHER_PATH, KEY_SET_PATH, THRESHOLD_KMS_KEY_PATH};

    pub const DEFAULT_MSG: u8 = 42;
    #[allow(dead_code)]
    pub const DEFAULT_FHE_TYPE: FheType = FheType::Euint8;
    pub const AMOUNT_PARTIES: usize = 5;
    pub const THRESHOLD: usize = 1;

    #[ctor]
    #[test]
    fn ensure_kms_keys_exist() {
        if !Path::new(DEFAULT_KMS_KEY_PATH).exists() {
            let config = ConfigBuilder::default().build();
            let (fhe_sk, _fhe_server_key) = generate_keys(config.clone());
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
            let kms_keys = SoftwareKmsKeys {
                config,
                fhe_sk,
                sig_sk,
                sig_pk,
            };
            assert!(write_element(DEFAULT_KMS_KEY_PATH.to_string(), &kms_keys,).is_ok());
        }
        if !Path::new(DEFAULT_FHE_KEY_PATH).exists() {
            let kms_keys: SoftwareKmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
            let fhe = PublicKey::new(&kms_keys.fhe_sk);
            assert!(write_element(DEFAULT_FHE_KEY_PATH.to_string(), &fhe).is_ok());
        }
    }

    #[ctor]
    #[test]
    fn ensure_client_keys_exist() {
        if !Path::new(DEFAULT_CLIENT_KEY_PATH).exists() {
            let mut rng = ChaCha20Rng::seed_from_u64(2);
            let client_keys = gen_sig_keys(&mut rng);
            assert!(write_element(DEFAULT_CLIENT_KEY_PATH.to_string(), &client_keys).is_ok());
        }
    }

    #[ctor]
    #[test]
    fn ensure_hl_cipher_exist() {
        if !Path::new(DEFAULT_HL_CIPHER_PATH).exists() {
            if !Path::new(DEFAULT_FHE_KEY_PATH).exists() {
                ensure_kms_keys_exist();
            }
            let fhe_pk: FhePublicKey = read_element(DEFAULT_FHE_KEY_PATH.to_string()).unwrap();
            let ct = FheUint8::encrypt(DEFAULT_MSG, &fhe_pk);
            let mut serialized_ct = Vec::new();
            bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
            assert!(write_element(
                DEFAULT_HL_CIPHER_PATH.to_string(),
                &(serialized_ct, FheType::Euint8)
            )
            .is_ok());
        }
    }

    #[ctor]
    #[test]
    fn ensure_ll_cipher_exist() {
        if !Path::new(DEFAULT_LL_CIPHER_PATH).exists() {
            ensure_all_threshold_kms_keys_exist();
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let full_path = format!("{}-1.bin", THRESHOLD_KMS_KEY_PATH);
            let kms_keys: ThresholdKmsKeys = read_element(full_path.to_string()).unwrap();
            let ct = kms_keys.fhe_pk.encrypt(&mut rng, DEFAULT_MSG);

            let serialized_ct = serde_asn1_der::to_vec(&ct).unwrap();
            assert!(write_element(
                DEFAULT_LL_CIPHER_PATH.to_string(),
                &(serialized_ct, FheType::Euint8)
            )
            .is_ok());
        }
    }

    #[ctor]
    #[test]
    fn ensure_all_threshold_kms_keys_exist() {
        let mut recompute: bool = false;
        for i in 1..=AMOUNT_PARTIES {
            let full_path = format!("{}-{}.bin", THRESHOLD_KMS_KEY_PATH, i);
            if !Path::new(&full_path).exists() {
                recompute = true;
            }
        }
        if recompute || !Path::new(DEFAULT_SERVER_KEYS_PATH).exists() {
            write_threshold_kms_keys_exist();
        }
    }

    fn write_threshold_kms_keys_exist() {
        if !Path::new(KEY_SET_PATH).exists() {
            ensure_key_set_exist();
        }
        let (key_set, params): (KeySet, ThresholdLWEParameters) =
            read_element(KEY_SET_PATH.to_string()).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let key_shares =
            keygen_all_party_shares(&key_set, &mut rng, AMOUNT_PARTIES, THRESHOLD).unwrap();
        let mut pks = Vec::with_capacity(AMOUNT_PARTIES);

        // TODO hack to ensure that we generate the same signing keys for both the small and large ciphertext key-pairs. Should be updated with task 292 https://github.com/zama-ai/distributed-decryption/issues/292
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for i in 1..=AMOUNT_PARTIES {
            let (sig_pk, sig_sk) = gen_sig_keys(&mut rng);
            let kms_keys = ThresholdKmsKeys {
                params,
                fhe_dec_key_share: key_shares[i - 1].to_owned(),
                bsk: key_set.ck.clone(),
                fhe_pk: key_set.pk.clone(),
                sig_sk,
                sig_pk: sig_pk.clone(),
            };
            let path = format!("{}-{}.bin", THRESHOLD_KMS_KEY_PATH, i);
            assert!(write_element(path.to_string(), &kms_keys,).is_ok());
            pks.push(sig_pk)
        }
        assert!(write_element(DEFAULT_SERVER_KEYS_PATH.to_string(), &pks).is_ok());
    }

    fn ensure_key_set_exist() {
        if !Path::new(KEY_SET_PATH).exists() {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let default_params: ThresholdLWEParameters =
                read_as_json(PARAM_PATH.to_owned()).unwrap();
            let key_set = gen_key_set(default_params, &mut rng);
            assert!(write_element(KEY_SET_PATH.to_string(), &(key_set, default_params)).is_ok());
        }
    }
}
