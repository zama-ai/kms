#[allow(dead_code)]
pub const DEFAULT_KMS_KEY_PATH: &str = "temp/kms-keys.bin";
#[allow(dead_code)]
pub const DEFAULT_SERVER_KEY_PATH: &str = "temp/pub-server-key.bin";
#[allow(dead_code)]
pub const DEFAULT_FHE_KEY_PATH: &str = "temp/fhe-key.bin";
#[allow(dead_code)]
pub const DEFAULT_CLIENT_KEY_PATH: &str = "temp/priv-client-key.bin";
#[allow(dead_code)]
pub const DEFAULT_CIPHER_PATH: &str = "temp/cipher.bin";

#[cfg(test)]
mod tests {
    use crate::key_setup::{
        DEFAULT_CIPHER_PATH, DEFAULT_CLIENT_KEY_PATH, DEFAULT_FHE_KEY_PATH, DEFAULT_KMS_KEY_PATH,
        DEFAULT_SERVER_KEY_PATH,
    };
    use ctor::ctor;
    use kms::file_handling::{read_element, write_element};
    use kms::{
        core::kms_core::{gen_kms_keys, gen_sig_keys, FhePublicKey, KmsKeys},
        kms::FheType,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use std::path::Path;
    use tfhe::{prelude::FheEncrypt, ConfigBuilder, FheUint8, PublicKey};

    #[ctor]
    #[test]
    fn ensure_kms_keys_exist() {
        if !Path::new(DEFAULT_KMS_KEY_PATH).exists() {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let config = ConfigBuilder::all_disabled()
                .enable_default_integers()
                .build();
            let kms_keys = gen_kms_keys(config, &mut rng);
            assert!(write_element(DEFAULT_KMS_KEY_PATH.to_string(), &kms_keys,).is_ok());
        }
        if !Path::new(DEFAULT_SERVER_KEY_PATH).exists() {
            let kms_keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
            assert!(write_element(DEFAULT_SERVER_KEY_PATH.to_string(), &kms_keys.sig_pk).is_ok());
        }
        if !Path::new(DEFAULT_FHE_KEY_PATH).exists() {
            let kms_keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
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
    fn ensure_cipher_exist() {
        if !Path::new(DEFAULT_CIPHER_PATH).exists() {
            if !Path::new(DEFAULT_FHE_KEY_PATH).exists() {
                ensure_kms_keys_exist();
            }
            let fhe_pk: FhePublicKey = read_element(DEFAULT_FHE_KEY_PATH.to_string()).unwrap();
            let ct = FheUint8::encrypt(42_u8, &fhe_pk);
            let mut serialized_ct = Vec::new();
            bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
            assert!(write_element(
                DEFAULT_CIPHER_PATH.to_string(),
                &(serialized_ct, FheType::Euint8)
            )
            .is_ok());
        }
    }
}
