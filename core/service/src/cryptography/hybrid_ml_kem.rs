use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, KeySizeUser};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    KemCore, MlKem512Params,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;

use super::error::CryptographyError;

pub(crate) type KemParam = MlKem512Params;

pub(crate) const ML_KEM_CT_LENGTH: usize = 768; // ciphertext size for MlKem512Params
pub(crate) const ML_KEM_PK_LENGTH: usize = 800; // encapsulation key size for MlKem512Params
pub(crate) const ML_KEM_SK_LEN: usize = 1632; // decapsulation key size for MlKem512Params
const NONCE_LEN: usize = 12;

pub(crate) fn keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> (DecapsulationKey<KemParam>, EncapsulationKey<KemParam>) {
    ml_kem::MlKem512::generate(rng)
}

struct InnerHybridKemCt {
    pub nonce: [u8; NONCE_LEN],
    pub kem_ct: [u8; ML_KEM_CT_LENGTH],
    pub payload_ct: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum HybridKemCtVersioned {
    V0(HybridKemCt),
}

// We prefer to use arrays like what is in [InnerHybridKemCt]
// but serde cannot derive Serialize/Deserialize for arrays
// larger than 32. So we have this [HybridKemCt] type where
// [kem_ct] is a Vec.
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(HybridKemCtVersioned)]
pub struct HybridKemCt {
    pub nonce: [u8; NONCE_LEN],
    // normally [kem_ct] is an array, but serde cannot serialize large arrays
    // so we use a Vec here.
    pub kem_ct: Vec<u8>,
    pub payload_ct: Vec<u8>,
}

impl Named for HybridKemCt {
    const NAME: &'static str = "backup::HybridKemCt";
}

impl TryFrom<HybridKemCt> for InnerHybridKemCt {
    type Error = CryptographyError;

    fn try_from(value: HybridKemCt) -> Result<Self, Self::Error> {
        if value.kem_ct.len() != ML_KEM_CT_LENGTH {
            return Err(CryptographyError::LengthError(
                "kem ciphertext has the wrong length".to_string(),
            ));
        }
        let mut kem_ct = [0u8; ML_KEM_CT_LENGTH];
        kem_ct.copy_from_slice(&value.kem_ct);
        Ok(Self {
            nonce: value.nonce,
            kem_ct,
            payload_ct: value.payload_ct,
        })
    }
}

impl From<InnerHybridKemCt> for HybridKemCt {
    fn from(value: InnerHybridKemCt) -> Self {
        Self {
            nonce: value.nonce,
            kem_ct: value.kem_ct.to_vec(),
            payload_ct: value.payload_ct,
        }
    }
}

pub(crate) fn enc<R: Rng + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
    enc_k: &EncapsulationKey<KemParam>,
) -> Result<HybridKemCt, CryptographyError> {
    let (kem_ct, kem_shared_secret) = enc_k
        .encapsulate(rng)
        .map_err(|_| CryptographyError::MlKemError)?;

    let key_size = <Aes256Gcm as KeySizeUser>::key_size();
    let aead_key = Key::<Aes256Gcm>::from_slice(&kem_shared_secret[0..key_size]);
    let cipher = Aes256Gcm::new(aead_key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let payload_ct = cipher.encrypt(&nonce, msg)?;

    Ok(InnerHybridKemCt {
        nonce: nonce.into(),
        kem_ct: kem_ct.0,
        payload_ct,
    }
    .into())
}

pub(crate) fn dec(
    ct: HybridKemCt,
    dec_k: &DecapsulationKey<KemParam>,
) -> Result<Vec<u8>, CryptographyError> {
    let ct: InnerHybridKemCt = ct.try_into()?;
    let InnerHybridKemCt {
        nonce,
        kem_ct,
        payload_ct,
    } = ct;

    // NOTE: this error never happens because there's implicit rejection,
    // meaning that some default value is returned when there's a decapsulation failure.
    // More information on implicit rejection here: https://eprint.iacr.org/2018/526.pdf
    let kem_shared_secret = dec_k
        .decapsulate(&kem_ct.into())
        .map_err(|_| CryptographyError::MlKemError)?;

    let key_size = <Aes256Gcm as KeySizeUser>::key_size();
    let aead_key = Key::<aes_gcm::Aes256Gcm>::clone_from_slice(&kem_shared_secret[0..key_size]);

    let cipher = aes_gcm::Aes256Gcm::new(&aead_key);
    let out = cipher.decrypt(&nonce.into(), &*payload_ct)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ml_kem::EncodedSizeUser;
    use proptest::prelude::*;
    use rand::rngs::OsRng;

    const SERIALIZED_SIZE_LIMIT: u64 = 1024 * 1024;

    proptest! {
        #[test]
        fn pke_sunshine(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (sk, pk) = keygen(&mut rng);
            assert_eq!(pk.as_bytes().len(), ML_KEM_PK_LENGTH);
            assert_eq!(sk.as_bytes().len(), ML_KEM_SK_LEN);

            let ct = enc(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_CT_LENGTH);
            assert_eq!(ct.nonce.len(), NONCE_LEN);

            let mut ct_buf = Vec::new();
            tfhe::safe_serialization::safe_serialize(&ct, &mut ct_buf, SERIALIZED_SIZE_LIMIT)
                .unwrap();
            let ct_new: HybridKemCt = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(ct_buf),
                SERIALIZED_SIZE_LIMIT,
            )
            .unwrap();

            let pt = dec(ct_new, &sk).unwrap();
            assert_eq!(msg, pt);
        }

        #[test]
        fn pke_wrong_key(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (_sk, pk) = keygen(&mut rng, );
            let (sk, _pk) = keygen(&mut rng, );
            let ct = enc(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_CT_LENGTH);
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }

        #[test]
        fn pke_wrong_ct(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (sk, pk) = keygen(&mut rng, );
            let mut ct = enc(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_CT_LENGTH);
            ct.payload_ct[0] ^= 1;
            let err = dec(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }
    }
}
