use super::der_types::{Cipher, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair};
use super::signcryption::{
    hash_element, sign, signcrypt, validate_and_decrypt, verify_sig, RND_SIZE,
};
use crate::anyhow_error_and_warn_log;
use crate::kms::FheType;
use crate::rpc::kms_rpc::handle_potential_err;
use crate::rpc::rpc_types::{BaseKms, Kms, Plaintext, RawDecryption, SigncryptionPayload};
use aes_prng::AesRng;
use k256::ecdsa::SigningKey;
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use serde_asn1_der::{from_bytes, to_vec};
use std::fmt;
use std::sync::{Arc, Mutex};
use tfhe::prelude::FheDecrypt;
use tfhe::{generate_keys, ClientKey, Config, FheBool, FheUint16, FheUint32, FheUint8};

pub type FhePublicKey = tfhe::PublicKey;
pub type FhePrivateKey = tfhe::ClientKey;

pub fn gen_sig_keys(rng: &mut (impl CryptoRng + RngCore)) -> (PublicSigKey, PrivateSigKey) {
    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey { pk: *pk }, PrivateSigKey { sk })
}

pub fn gen_kms_keys(config: Config, rng: &mut (impl CryptoRng + RngCore)) -> SoftwareKmsKeys {
    let (fhe_sk, _fhe_server_key) = generate_keys(config.clone());
    let (sig_pk, sig_sk) = gen_sig_keys(rng);
    // TODO do we need this to be a mutex as well to allow for parallel queries
    SoftwareKmsKeys {
        config,
        fhe_sk,
        sig_sk,
        sig_pk,
    }
}

#[derive(Clone)]
pub struct BaseKmsStruct {
    pub(crate) sig_key: PrivateSigKey,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}
impl BaseKmsStruct {
    pub fn new(sig_sk: PrivateSigKey) -> Self {
        BaseKmsStruct {
            sig_key: sig_sk,
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        }
    }

    pub(crate) fn new_rng(&self) -> anyhow::Result<AesRng> {
        let mut seed = [0u8; RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng =
                handle_potential_err(self.rng.lock(), "Could not lock rng".to_owned())?;
            base_rng.try_fill_bytes(seed.as_mut())?;
        }
        Ok(AesRng::from_seed(seed))
    }
}

impl BaseKms for BaseKmsStruct {
    fn verify_sig<T>(
        payload: &T,
        signature: &super::der_types::Signature,
        key: &PublicSigKey,
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
        if !verify_sig(&msg, signature, key) {
            return false;
        }
        true
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

    fn get_verf_key(&self) -> PublicSigKey {
        PublicSigKey {
            pk: SigningKey::verifying_key(&self.sig_key.sk).to_owned(),
        }
    }

    fn digest<T>(msg: &T) -> anyhow::Result<Vec<u8>>
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
}

#[derive(Serialize, Deserialize)]
pub struct SoftwareKmsKeys {
    pub config: Config,
    pub fhe_sk: FhePrivateKey,
    pub sig_sk: PrivateSigKey,
    pub sig_pk: PublicSigKey,
}

/// Software based KMS where keys are stored in a local file
pub struct SoftwareKms {
    base_kms: BaseKmsStruct,
    fhe_dec_key: FhePrivateKey,
}

// impl fmt::Debug for SoftwareKms, we don't want to include the decryption key in the debug output
impl fmt::Debug for SoftwareKms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SoftwareKms")
            .field("sig_key", &self.base_kms.sig_key)
            .finish() // Don't include fhe_dec_key
    }
}

impl BaseKms for SoftwareKms {
    fn verify_sig<T: fmt::Debug + Serialize>(
        payload: &T,
        signature: &super::der_types::Signature,
        verification_key: &PublicSigKey,
    ) -> bool {
        BaseKmsStruct::verify_sig(payload, signature, verification_key)
    }

    fn sign<T: fmt::Debug + Serialize>(
        &self,
        msg: &T,
    ) -> anyhow::Result<super::der_types::Signature> {
        self.base_kms.sign(msg)
    }

    fn get_verf_key(&self) -> PublicSigKey {
        self.base_kms.get_verf_key()
    }

    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>> {
        BaseKmsStruct::digest(&msg)
    }
}
impl Kms for SoftwareKms {
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<Plaintext> {
        Ok(match fhe_type {
            FheType::Bool => {
                let cipher: FheBool = bincode::deserialize(ct)?;
                let plaintext: bool = cipher.decrypt(&self.fhe_dec_key);
                Plaintext::from_bool(plaintext)
            }
            FheType::Euint8 => {
                let cipher: FheUint8 = bincode::deserialize(ct)?;
                let plaintext: u8 = cipher.decrypt(&self.fhe_dec_key);
                Plaintext::from_u8(plaintext)
            }
            FheType::Euint16 => {
                let cipher: FheUint16 = bincode::deserialize(ct)?;
                let plaintext: u16 = cipher.decrypt(&self.fhe_dec_key);
                Plaintext::from_u16(plaintext)
            }
            FheType::Euint32 => {
                let cipher: FheUint32 = bincode::deserialize(ct)?;
                let plaintext: u32 = cipher.decrypt(&self.fhe_dec_key);
                Plaintext::from_u32(plaintext)
            }
        })
    }

    fn reencrypt(
        &self,
        ct: &[u8],
        fhe_type: FheType,
        req_digest: Vec<u8>,
        client_enc_key: &PublicEncKey,
        client_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        let plaintext = Kms::decrypt(self, ct, fhe_type)?;
        // Observe that we encrypt the plaintext itself, this is different from the threshold case
        // where it is first mapped to a Vec<Residuepoly<Z128>> element
        let raw_decryption = RawDecryption::new(plaintext.value.to_le_bytes().to_vec(), fhe_type);
        let signcryption_msg = SigncryptionPayload {
            raw_decryption,
            req_digest,
        };
        let enc_res = signcrypt(
            &mut self.base_kms.new_rng()?,
            &serde_asn1_der::to_vec(&signcryption_msg)?,
            client_enc_key,
            client_verf_key,
            &self.base_kms.sig_key,
        )?;
        let res = to_vec(&enc_res)?;
        tracing::info!("Completed reencyption of ciphertext {:?} with type {:?} to client verification key {:?} under client encryption key {:?}", ct, fhe_type, client_verf_key.pk, client_enc_key.0);
        Ok(Some(res))
    }
}

impl SoftwareKms {
    pub fn new(fhe_dec_key: ClientKey, sig_key: PrivateSigKey) -> Self {
        SoftwareKms {
            base_kms: BaseKmsStruct::new(sig_key),
            fhe_dec_key,
        }
    }
}

pub fn decrypt_signcryption(
    cipher: &[u8],
    link: &[u8],
    client_keys: &SigncryptionPair,
    server_verf_key: &PublicSigKey,
) -> anyhow::Result<Option<RawDecryption>> {
    let cipher: Cipher = from_bytes(cipher)?;
    let decrypted_signcryption = match validate_and_decrypt(&cipher, client_keys, server_verf_key)?
    {
        Some(decrypted_signcryption) => decrypted_signcryption,
        None => {
            tracing::warn!("Signcryption validation failed");
            return Ok(None);
        }
    };
    let signcrypted_msg: SigncryptionPayload = serde_asn1_der::from_bytes(&decrypted_signcryption)?;
    if link != signcrypted_msg.req_digest {
        tracing::warn!("Link validation for signcryption failed");
        return Ok(None);
    }
    Ok(Some(signcrypted_msg.raw_decryption))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{gen_kms_keys, SoftwareKmsKeys};
    use crate::core::kms_core::{decrypt_signcryption, gen_sig_keys, SoftwareKms};
    use crate::core::request::ephemeral_key_generation;
    use crate::file_handling::{read_element, write_element};
    use crate::kms::FheType;
    use crate::rpc::rpc_types::{Kms, Plaintext};
    use aes_prng::AesRng;
    use ctor::ctor;
    use rand::SeedableRng;
    use tfhe::prelude::FheEncrypt;
    use tfhe::{ConfigBuilder, FheUint8};

    pub const TEST_KMS_KEY_PATH: &str = "temp/kms-keys.bin";

    #[ctor]
    #[test]
    fn ensure_keys_exist() {
        if !Path::new(TEST_KMS_KEY_PATH).exists() {
            let mut rng = AesRng::seed_from_u64(1);
            let config = ConfigBuilder::default().build();
            write_element(
                TEST_KMS_KEY_PATH.to_string(),
                &gen_kms_keys(config, &mut rng),
            )
            .unwrap();
        }
    }

    #[test]
    fn sunshine_decrypt() {
        let msg = 42_u8;
        let keys: SoftwareKmsKeys = read_element(TEST_KMS_KEY_PATH.to_string()).unwrap();
        let kms = SoftwareKms::new(keys.fhe_sk.clone(), keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        let plaintext: Plaintext = kms.decrypt(&serialized_ct, FheType::Euint8).unwrap();
        assert_eq!(plaintext.as_u8(), msg);
    }

    #[test]
    fn sunshine_reencrypt() {
        let msg = 42_u8;
        let mut rng = AesRng::seed_from_u64(1);
        let kms_keys: SoftwareKmsKeys = read_element(TEST_KMS_KEY_PATH.to_string()).unwrap();
        let kms = SoftwareKms::new(kms_keys.fhe_sk.clone(), kms_keys.sig_sk);
        let ct = FheUint8::encrypt(msg, &kms_keys.fhe_sk);
        let mut serialized_ct = Vec::new();
        bincode::serialize_into(&mut serialized_ct, &ct).unwrap();
        let link = vec![42_u8, 42, 42];
        let (_client_verf_key, client_sig_key) = gen_sig_keys(&mut rng);
        let client_keys = ephemeral_key_generation(&mut rng, &client_sig_key);
        let raw_cipher = kms
            .reencrypt(
                &serialized_ct,
                FheType::Euint8,
                link.clone(),
                &client_keys.pk.enc_key,
                &client_keys.pk.verification_key,
            )
            .unwrap()
            .unwrap();
        let decrypted_msg =
            decrypt_signcryption(&raw_cipher, &link, &client_keys, &kms_keys.sig_pk)
                .unwrap()
                .unwrap();
        let plaintext: Plaintext = decrypted_msg.try_into().unwrap();
        assert_eq!(plaintext.as_u8(), msg);
        assert_eq!(plaintext.fhe_type(), FheType::Euint8);
    }
}
