use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, KeySizeUser};
use rand::{CryptoRng, Rng};
use rsa::sha2;
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;

use super::error::BackupError;

const NONCE_LEN: usize = 12;
const RSA_OUTPUT_LEN: usize = 512;
const RSA_KEY_BIT_SIZE: usize = 4096;

pub(crate) fn keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(rsa::RsaPrivateKey, rsa::RsaPublicKey), BackupError> {
    let rsa_private_key = rsa::RsaPrivateKey::new(rng, RSA_KEY_BIT_SIZE)?;
    let rsa_public_key = rsa_private_key.to_public_key();
    Ok((rsa_private_key, rsa_public_key))
}

struct InnerHybridRsaCt {
    pub nonce: [u8; NONCE_LEN],
    pub key_ct: [u8; RSA_OUTPUT_LEN],
    pub payload_ct: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum HybridRsaCtVersioned {
    V0(HybridRsaCt),
}

#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(HybridRsaCtVersioned)]
pub struct HybridRsaCt {
    pub nonce: [u8; NONCE_LEN],
    pub key_ct: Vec<u8>,
    pub payload_ct: Vec<u8>,
}

impl Named for HybridRsaCt {
    const NAME: &'static str = "backup::HybridRsaCt";
}

impl TryFrom<HybridRsaCt> for InnerHybridRsaCt {
    type Error = BackupError;

    fn try_from(value: HybridRsaCt) -> Result<Self, Self::Error> {
        if value.key_ct.len() != RSA_OUTPUT_LEN {
            return Err(BackupError::LengthError(
                "rsa ciphertext has the wrong length".to_string(),
            ));
        }
        let mut key_ct = [0u8; RSA_OUTPUT_LEN];
        key_ct.copy_from_slice(&value.key_ct);
        Ok(Self {
            nonce: value.nonce,
            key_ct,
            payload_ct: value.payload_ct,
        })
    }
}

impl From<InnerHybridRsaCt> for HybridRsaCt {
    fn from(value: InnerHybridRsaCt) -> Self {
        Self {
            nonce: value.nonce,
            key_ct: value.key_ct.to_vec(),
            payload_ct: value.payload_ct,
        }
    }
}

pub(crate) fn enc<R: Rng + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
    rsa_pk: &rsa::RsaPublicKey,
) -> Result<HybridRsaCt, BackupError> {
    // we need to do hybrid encryption, so generate a new symmetric keypair
    // note that we need to write `&mut *rng` so that it's not considered to be moved
    let aead_key = Aes256Gcm::generate_key(&mut *rng);

    // key_byte is used to encrypt msg using aead
    let cipher = Aes256Gcm::new(&aead_key);
    let nonce = Aes256Gcm::generate_nonce(&mut *rng);
    let payload_ct = cipher.encrypt(&nonce, msg)?;

    // and we encrypt the key using OAED RSA.
    // Observe that SHA2 is used to stay compatible with AWS KMS.
    let padding = rsa::Oaep::new::<sha2::Sha256>();
    let key_ct_vec = rsa_pk.encrypt(rng, padding, &aead_key)?;
    let mut key_ct = [0u8; RSA_OUTPUT_LEN];
    key_ct.copy_from_slice(&key_ct_vec);

    Ok(InnerHybridRsaCt {
        nonce: nonce.into(),
        key_ct,
        payload_ct,
    }
    .into())
}

pub(crate) fn dec(ct: HybridRsaCt, rsa_sk: &rsa::RsaPrivateKey) -> Result<Vec<u8>, BackupError> {
    // first decrypt RSA OAED ciphertext to obtain the AES key
    let ct: InnerHybridRsaCt = ct.try_into()?;
    let InnerHybridRsaCt {
        nonce,
        key_ct,
        payload_ct,
    } = ct;

    let padding = rsa::Oaep::new::<sha2::Sha256>();
    let aead_key = rsa_sk.decrypt(padding, &key_ct)?;
    let key_size = <Aes256Gcm as KeySizeUser>::key_size();

    if key_size > aead_key.len() {
        return Err(BackupError::LengthError(
            "aead key has the wrong length".to_string(),
        ));
    }
    let aead_key = Key::<Aes256Gcm>::from_slice(&aead_key[0..key_size]);

    // then use the key to decrypt the symmetric key
    let cipher = Aes256Gcm::new(aead_key);
    let out = cipher.decrypt(&nonce.into(), &*payload_ct)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use proptest::{collection, num, prelude::*};
    use rand::rngs::OsRng;

    const SERIALIZED_SIZE_LIMIT: u64 = 1024 * 1024;

    fn vec_strat() -> impl Strategy<Value = Vec<u8>> {
        collection::vec(num::u8::ANY, 0..2).prop_union(collection::vec(num::u8::ANY, 100..101))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]

        #[test]
        fn pke_sunshine(msg in vec_strat()) {
            let mut rng = OsRng;
            let (sk, pk) = keygen(&mut rng).unwrap();

            let ct = enc(&mut rng, &msg, &pk).unwrap();
            assert_eq!(RSA_OUTPUT_LEN, ct.key_ct.len());
            assert_eq!(NONCE_LEN, ct.nonce.len());

            let mut ct_buf = Vec::new();
            tfhe::safe_serialization::safe_serialize(&ct, &mut ct_buf, SERIALIZED_SIZE_LIMIT).unwrap();
            let ct_new: HybridRsaCt = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(ct_buf),
                SERIALIZED_SIZE_LIMIT,
            )
            .unwrap();

            let pt = dec(ct_new, &sk).unwrap();
            assert_eq!(msg, pt);
        }

        #[test]
        fn pke_wrong_key(msg in vec_strat()) {
            let mut rng = OsRng;
            let (_sk, pk) = keygen(&mut rng).unwrap();
            let (sk, _pk) = keygen(&mut rng).unwrap();
            let ct = enc(&mut rng, &msg, &pk).unwrap();
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, BackupError::RsaError(..)));
        }

        #[test]
        fn pke_wrong_ct(msg in vec_strat()) {
            let mut rng = OsRng;
            let (sk, pk) = keygen(&mut rng).unwrap();
            let mut ct = enc(&mut rng, &msg, &pk).unwrap();
            ct.payload_ct[0] ^= 1;
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, BackupError::AesGcmError(..)));
        }
    }
}
