use kms::{
    core::kms_core::{KmsKeys, SoftwareKms},
    file_handling::read_element,
    kms::kms_endpoint_server::KmsEndpointServer,
};
use tonic::transport::Server;

#[allow(dead_code)]
pub const DEFAULT_KMS_KEY_PATH: &str = "temp/kms-keys.bin";
#[allow(dead_code)]
pub const DEFAULT_SERVER_KEYS_PATH: &str = "temp/pub-server-keys.bin";
#[allow(dead_code)]
pub const DEFAULT_FHE_KEY_PATH: &str = "temp/fhe-key.bin";
#[allow(dead_code)]
pub const DEFAULT_CLIENT_KEY_PATH: &str = "temp/priv-client-key.bin";
#[allow(dead_code)]
pub const DEFAULT_CIPHER_PATH: &str = "temp/cipher.bin";

#[allow(dead_code)]
pub async fn server_handle(url: String, key_path: String) {
    let socket: std::net::SocketAddr = url.parse().unwrap();
    let keys: KmsKeys = read_element(key_path.to_string()).unwrap();
    let kms = SoftwareKms::new(keys.config, keys.fhe_sk, keys.sig_sk);
    tracing::info!("Starting KMS server ...");
    Server::builder()
        .add_service(KmsEndpointServer::new(kms))
        .serve(socket)
        .await
        .unwrap();
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::setup_rpc::{
        DEFAULT_CIPHER_PATH, DEFAULT_CLIENT_KEY_PATH, DEFAULT_FHE_KEY_PATH, DEFAULT_KMS_KEY_PATH,
        DEFAULT_SERVER_KEYS_PATH,
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

    pub const DEFAULT_MSG: u8 = 42;
    #[allow(dead_code)]
    pub const DEFAULT_FHE_TYPE: FheType = FheType::Euint8;

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
        if !Path::new(DEFAULT_SERVER_KEYS_PATH).exists() {
            let kms_keys: KmsKeys = read_element(DEFAULT_KMS_KEY_PATH.to_string()).unwrap();
            assert!(
                write_element(DEFAULT_SERVER_KEYS_PATH.to_string(), &vec![kms_keys.sig_pk]).is_ok()
            );
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
            let ct = FheUint8::encrypt(DEFAULT_MSG, &fhe_pk);
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
