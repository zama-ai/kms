use super::{
    der_types::{KeyAddress, PrivateSigKey, PublicEncKey, PublicSigKey, BYTES_IN_ADDRESS},
    signcryption::{hash_element, sign, signcrypt, verify_sig},
};
use crate::{anyhow_error_and_warn_log, kms::FheType, rpc_types::Kms};
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
    // TODO do we need this to be a mutex as well to allow for parallel queries
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
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<u32> {
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

    // TODO add link so this can be linked to digest
    fn reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        client_enc_key: &PublicEncKey,
        address: &KeyAddress,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let plaintext = Kms::decrypt(self, ct, fhe_type)?;
        let msg = plaintext_to_vec(plaintext, fhe_type);
        // TODO what is the right way of doing this without panic
        let mut current_rng = self.rng.lock().unwrap();
        let mut rng_clone = current_rng.clone();
        let enc_res = signcrypt(&mut rng_clone, &msg, client_enc_key, address, &self.sig_key)?;
        *current_rng = rng_clone;
        let res = to_vec(&enc_res)?;
        // TODO make logs everywhere. In particular make sure to log errors before throwing the error back up
        tracing::info!("Completed renecyption of ciphertext {:?} with type {:?} to client with address {:?} under public key {:?}", ct, fhe_type, address, client_enc_key.0);
        Ok(Some(res))
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
            Err(_) => {
                tracing::warn!(
                    "Could not encode payload for signature verification {:?}",
                    payload
                );
                return false;
            }
        };
        // TODO refactor
        if !verify_sig(&msg, signature, &signature.pk) {
            return false;
        }
        address != &get_address(&signature.pk)
    }

    fn sign<T>(&self, msg: &T) -> anyhow::Result<super::der_types::Signature>
    where
        T: fmt::Debug + Serialize,
    {
        let to_sign = match to_vec(&msg) {
            Ok(to_sign) => to_sign,
            Err(_) => {
                return Err(anyhow_error_and_warn_log(format!(
                    "Could not encode message for signing {:?}",
                    msg
                )))
            }
        };
        sign(&to_sign, &self.sig_key)
    }

    fn digest<T>(&self, msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: fmt::Debug + Serialize,
    {
        let to_hash = match to_vec(&msg) {
            Ok(to_sign) => to_sign,
            Err(_) => {
                return Err(anyhow_error_and_warn_log(format!(
                    "Could not encode message for signing {:?}",
                    msg
                )))
            }
        };
        Ok(hash_element(&to_hash))
    }

    fn get_verf_key(&self) -> PublicSigKey {
        PublicSigKey {
            pk: SigningKey::verifying_key(&self.sig_key.sk).to_owned(),
        }
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
}

pub(crate) fn get_address(key: &PublicSigKey) -> KeyAddress {
    // TODO should this be updated to use keccak to make the address notion compatible with ethereum
    let mut digest = hash_element(&key.pk.to_sec1_bytes()[..]);
    digest.truncate(BYTES_IN_ADDRESS);
    let mut res = [0_u8; BYTES_IN_ADDRESS];
    res[..BYTES_IN_ADDRESS].copy_from_slice(&digest[..BYTES_IN_ADDRESS]);
    res
}

pub(crate) fn plaintext_to_vec(plaintext: u32, fhe_type: FheType) -> Vec<u8> {
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
            kms_core::{gen_sig_keys, get_address, vec_to_plaintext, SoftwareKms},
            request::ephemeral_key_generation,
            signcryption::validate_and_decrypt,
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
                &get_address(&client_keys.pk.verification_key),
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

        let plaintext = kms.decrypt(&serialized_ct, FheType::Euint8).unwrap();
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
            .reencrypt(
                &serialized_ct,
                FheType::Euint8,
                &client_keys.pk.enc_key,
                &get_address(&client_keys.pk.verification_key),
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
