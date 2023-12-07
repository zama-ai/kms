use crate::{kms::FheType, rpc_types::Kms};

use super::{
    der_types::{KeyAddress, PrivateSigKey, PublicEncKey, PublicSigKey},
    signcryption::{sign, signcrypt, verify_sig},
};

use k256::ecdsa::SigningKey;
use rand::SeedableRng;
use rand_chacha::{rand_core::CryptoRngCore, ChaCha20Rng};
use serde::{Deserialize, Serialize};
use serde_asn1_der::to_vec;
use std::{
    fmt,
    sync::{Arc, Mutex},
};
use tfhe::{
    generate_keys, prelude::FheDecrypt, ClientKey, Config, FheBool, FheUint16, FheUint32, FheUint8,
    PublicKey, ServerKey,
};

pub type FhePublicKey = tfhe::PublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub fn gen_sig_keys(rng: &mut impl CryptoRngCore) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
}

pub fn gen_kms_keys(config: Config, rng: &mut impl CryptoRngCore) -> KmsKeys {
    let (fhe_sk, fhe_server_key) = generate_keys(config.clone());
    let fhe_pk = PublicKey::new(&fhe_sk);
    let (sig_pk, sig_sk) = gen_sig_keys(rng);
    KmsKeys {
        config,
        fhe_pk,
        fhe_sk,
        sig_pk,
        sig_sk,
        fhe_server_key,
    }
}

#[derive(Serialize, Deserialize)]
pub struct KmsKeys {
    pub config: Config,
    pub fhe_pk: FhePublicKey,
    pub fhe_sk: FhePrivateKey,
    pub fhe_server_key: ServerKey,
    pub sig_pk: PublicSigKey,
    pub sig_sk: PrivateSigKey,
}

/// Software based KMS where keys are stored in a local file
#[derive(Debug)]
pub struct SoftwareKms {
    pub config: Config,
    fhe_dec_key: ClientKey,
    sig_key: PrivateSigKey,
    rng: Arc<Mutex<ChaCha20Rng>>,
}

impl Kms for SoftwareKms {
    fn validate_and_reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        client_enc_key: &PublicEncKey,
        address: &KeyAddress,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // TODO validate
        Kms::reencrypt(self, ct, fhe_type, client_enc_key, address)
    }

    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<(Vec<u8>, u32)> {
        let plaintext = self.raw_decryption(ct, fhe_type)?;
        // TODO sign type as well!!!
        let sig = sign(&plaintext_to_vec(plaintext, fhe_type), &self.sig_key)?;
        Ok((to_vec(&sig)?, plaintext))
    }

    fn reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        client_enc_key: &PublicEncKey,
        address: &KeyAddress,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let (sig, plaintext) = Kms::decrypt(self, ct, fhe_type)?;
        let msg = plaintext_to_vec(plaintext, fhe_type);
        // TODO what is the right way of doing this without panic
        let mut current_rng = self.rng.lock().unwrap();
        let mut rng_clone = current_rng.clone();
        let enc_res = signcrypt(&mut rng_clone, &msg, client_enc_key, address, &self.sig_key)?;
        *current_rng = rng_clone;

        Ok(Some(to_vec(&enc_res)?))
    }

    fn verify_sig<T>(
        &self,
        payload: &T,
        signature: &super::der_types::Signature,
        address: &KeyAddress,
    ) -> bool
    where
        T: fmt::Debug + Serialize,
    {
        let msg = match to_vec(&payload) {
            Ok(msg) => msg,
            Err(e) => {
                tracing::warn!("Could not encode payload {:?}", payload);
                return false;
            }
        };
        // TODO refactor
        verify_sig(&msg, signature, &signature.pk)
    }

    fn sign(&self, msg: &[u8]) -> anyhow::Result<super::der_types::Signature> {
        sign(&msg.to_vec(), &self.sig_key)
    }
}

impl SoftwareKms {
    pub fn new(config: Config, fhe_dec_key: ClientKey, sig_key: PrivateSigKey) -> Self {
        SoftwareKms {
            config,
            rng: Arc::new(Mutex::new(ChaCha20Rng::from_entropy())),
            fhe_dec_key,
            sig_key,
        }
    }

    fn raw_decryption(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<u32> {
        Ok(match fhe_type {
            FheType::Bool => {
                let cipher: FheBool = bincode::deserialize(ct)?;
                let plaintext: bool = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint8 => {
                let cipher: FheUint8 = bincode::deserialize(ct)?;
                let plaintext: u8 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint16 => {
                let cipher: FheUint16 = bincode::deserialize(ct)?;
                let plaintext: u16 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
            FheType::Euint32 => {
                let cipher: FheUint32 = bincode::deserialize(ct)?;
                let plaintext: u32 = cipher.decrypt(&self.fhe_dec_key);
                plaintext as u32
            }
        })
    }
}
fn plaintext_to_vec(plaintext: u32, fhe_type: FheType) -> Vec<u8> {
    match fhe_type {
        FheType::Bool => {
            vec![plaintext as u8]
        }
        FheType::Euint8 => {
            vec![plaintext as u8]
        }
        FheType::Euint16 => plaintext.to_be_bytes().to_vec(),
        FheType::Euint32 => plaintext.to_be_bytes().to_vec(),
    }
}

#[allow(dead_code)]
fn vec_to_plaintext(msg: &[u8], fhe_type: FheType) -> anyhow::Result<u32> {
    Ok(match fhe_type {
        FheType::Bool => msg[0] as u32,
        FheType::Euint8 => msg[0] as u32,
        FheType::Euint16 => u16::from_be_bytes(msg.try_into()?) as u32,
        FheType::Euint32 => u32::from_be_bytes(msg.try_into()?),
    })
}

#[cfg(test)]
mod tests {
    use ctor::ctor;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serde_asn1_der::from_bytes;
    use std::path::Path;
    use tfhe::{prelude::FheEncrypt, ConfigBuilder, FheUint8};

    use crate::{
        core::{
            der_types::Cipher,
            kms_core::{gen_sig_keys, vec_to_plaintext, SoftwareKms},
            request::ephemeral_key_generation,
            signcryption::{address, validate_and_decrypt},
        },
        file_handling::{read_element, write_element},
        kms::FheType,
        rpc_types::Kms,
    };

    use super::{gen_kms_keys, KmsKeys};

    pub const TEST_KMS_KEY_PATH: &str = "temp/kms-keys.bin";

    #[ctor]
    #[test]
    fn ensure_keys_exist() {
        if !Path::new(TEST_KMS_KEY_PATH).exists() {
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let config = ConfigBuilder::all_disabled()
                .enable_default_integers()
                .build();
            write_element(
                TEST_KMS_KEY_PATH.to_string(),
                &gen_kms_keys(config, &mut rng),
            )
            .unwrap();
        }
    }

    #[test]
    fn sunshine_rencrypt() {
        let msg = 42_u8;
        let kms_keys: KmsKeys = read_element(TEST_KMS_KEY_PATH.to_string()).unwrap();
        let kms = SoftwareKms::new(kms_keys.config, kms_keys.fhe_sk.clone(), kms_keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &kms_keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = ephemeral_key_generation(&mut rng, &client_sig_key);

        let raw_cipher = kms
            .reencrypt(
                &serialized_ct,
                FheType::Euint8,
                &client_keys.pk.enc_key,
                &address(&client_keys.pk.verification_key),
            )
            .unwrap()
            .unwrap();

        let cipher: Cipher = from_bytes(&raw_cipher).unwrap();
        let decrypted_msg = vec_to_plaintext(
            &validate_and_decrypt(&cipher, &client_keys, &kms_keys.sig_pk)
                .unwrap()
                .unwrap(),
            FheType::Euint8,
        )
        .unwrap();
        assert_eq!(decrypted_msg as u8, msg);
    }

    #[test]
    fn sunshine_decrypt() {
        let msg = 42_u8;
        let keys: KmsKeys = read_element(TEST_KMS_KEY_PATH.to_string()).unwrap();
        let kms = SoftwareKms::new(keys.config, keys.fhe_sk.clone(), keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let (sig, plaintext) = kms.decrypt(&serialized_ct, FheType::Euint8).unwrap();
        assert_eq!(plaintext as u8, msg);
    }

    #[test]
    fn sunshine_validate_reencrypt() {
        let msg = 42_u8;
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let kms_keys: KmsKeys = read_element(TEST_KMS_KEY_PATH.to_string()).unwrap();
        let kms = SoftwareKms::new(kms_keys.config, kms_keys.fhe_sk.clone(), kms_keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &kms_keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();

        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = ephemeral_key_generation(&mut rng, &client_sig_key);
        let raw_cipher = kms
            .validate_and_reencrypt(
                &serialized_ct,
                FheType::Euint8,
                &client_keys.pk.enc_key,
                &address(&client_keys.pk.verification_key),
            )
            .unwrap()
            .unwrap();
        let cipher: Cipher = from_bytes(&raw_cipher).unwrap();
        let decrypted_msg = vec_to_plaintext(
            &validate_and_decrypt(&cipher, &client_keys, &kms_keys.sig_pk)
                .unwrap()
                .unwrap(),
            FheType::Euint8,
        )
        .unwrap();
        assert_eq!(decrypted_msg as u8, msg);
    }
}
