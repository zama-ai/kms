use super::error::CryptographyError;
use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit, KeySizeUser};
use ml_kem::{
    array::{typenum::Unsigned, Array},
    kem::{Decapsulate, Encapsulate},
    KemCore,
};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::{named::Named, Versionize};
use tfhe_versionable::VersionsDispatch;

#[cfg(test)]
pub(crate) const ML_KEM_512_CT_LENGTH: usize = 768; // ciphertext size for MlKem512Params
#[cfg(any(not(feature = "non-wasm"), test))]
pub(crate) const ML_KEM_512_PK_LENGTH: usize = 800; // encapsulation key size for MlKem512Params
#[cfg(any(not(feature = "non-wasm"), test))]
pub(crate) const ML_KEM_512_SK_LEN: usize = 1632; // decapsulation key size for MlKem512Params

const NONCE_LEN: usize = 12;

pub(crate) fn keygen<C: KemCore, R: Rng + CryptoRng>(
    rng: &mut R,
) -> (C::DecapsulationKey, C::EncapsulationKey) {
    C::generate(rng)
}

struct InnerHybridKemCt<C: KemCore> {
    pub nonce: [u8; NONCE_LEN],
    pub kem_ct: Array<u8, C::CiphertextSize>,
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
// TODO(#2782) implement a new version along with LegacySerialization to allow safe serialization of newer encryptions and only keep unversioned bincode for signcryption
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

impl<C: KemCore> TryFrom<HybridKemCt> for InnerHybridKemCt<C> {
    type Error = CryptographyError;

    fn try_from(value: HybridKemCt) -> Result<Self, Self::Error> {
        if value.kem_ct.len() != C::CiphertextSize::USIZE {
            return Err(CryptographyError::LengthError(
                "kem ciphertext has the wrong length".to_string(),
            ));
        }

        let mut kem_ct: Array<u8, C::CiphertextSize> = Array::default();
        kem_ct.copy_from_slice(&value.kem_ct);

        Ok(Self {
            nonce: value.nonce,
            kem_ct,
            payload_ct: value.payload_ct,
        })
    }
}

impl<C: KemCore> From<InnerHybridKemCt<C>> for HybridKemCt {
    fn from(value: InnerHybridKemCt<C>) -> Self {
        Self {
            nonce: value.nonce,
            kem_ct: value.kem_ct.to_vec(),
            payload_ct: value.payload_ct,
        }
    }
}

pub(crate) fn enc<C: KemCore, R: Rng + CryptoRng>(
    rng: &mut R,
    msg: &[u8],
    enc_k: &C::EncapsulationKey,
) -> Result<HybridKemCt, CryptographyError> {
    let (kem_ct, kem_shared_secret) = enc_k
        .encapsulate(rng)
        .map_err(|_| CryptographyError::MlKemError)?;

    let key_size = <Aes256Gcm as KeySizeUser>::key_size();
    let aead_key = Key::<Aes256Gcm>::from_slice(&kem_shared_secret[0..key_size]);
    let cipher = Aes256Gcm::new(aead_key);
    let nonce = Aes256Gcm::generate_nonce(rng);
    let payload_ct = cipher.encrypt(&nonce, msg)?;

    Ok(InnerHybridKemCt::<C> {
        nonce: nonce.into(),
        kem_ct,
        payload_ct,
    }
    .into())
}

pub(crate) fn dec<C: KemCore>(
    ct: HybridKemCt,
    dec_k: &C::DecapsulationKey,
) -> Result<Vec<u8>, CryptographyError> {
    let ct: InnerHybridKemCt<C> = ct.try_into()?;
    let InnerHybridKemCt {
        nonce,
        kem_ct,
        payload_ct,
    } = ct;

    // NOTE: this error never happens because there's implicit rejection,
    // meaning that some default value is returned when there's a decapsulation failure.
    // More information on implicit rejection here: https://eprint.iacr.org/2018/526.pdf
    let kem_shared_secret = dec_k
        .decapsulate(&kem_ct)
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
            let (sk, pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            assert_eq!(pk.as_bytes().len(), ML_KEM_512_PK_LENGTH);
            assert_eq!(sk.as_bytes().len(), ML_KEM_512_SK_LEN);

            let ct = enc::<ml_kem::MlKem512, _>(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_512_CT_LENGTH);
            assert_eq!(ct.nonce.len(), NONCE_LEN);

            let mut ct_buf = Vec::new();
            tfhe::safe_serialization::safe_serialize(&ct, &mut ct_buf, SERIALIZED_SIZE_LIMIT)
                .unwrap();
            let ct_new: HybridKemCt = tfhe::safe_serialization::safe_deserialize(
                std::io::Cursor::new(ct_buf),
                SERIALIZED_SIZE_LIMIT,
            )
            .unwrap();

            let pt = dec::<ml_kem::MlKem512>(ct_new, &sk).unwrap();
            assert_eq!(msg, pt);
        }

        #[test]
        fn pke_wrong_key(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (_sk, pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            let (sk, _pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            let ct = enc::<ml_kem::MlKem512, _>(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_512_CT_LENGTH);
            let err = dec::<ml_kem::MlKem512>(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }

        #[test]
        fn pke_wrong_ct(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (sk, pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            let mut ct = enc::<ml_kem::MlKem512, _>(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_512_CT_LENGTH);
            ct.payload_ct[0] ^= 1;
            let err = dec::<ml_kem::MlKem512>(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }

        #[test]
        fn pke_wrong_nonce(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (sk, pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            let mut ct = enc::<ml_kem::MlKem512, _>(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_512_CT_LENGTH);
            ct.nonce[ct.nonce.len()-1] ^= 1;
            let err = dec::<ml_kem::MlKem512>(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }

        #[test]
        fn pke_wrong_kem(msg: Vec<u8>) {
            let mut rng = OsRng;
            let (sk, pk) = keygen::<ml_kem::MlKem512, _>(&mut rng);
            let mut ct = enc::<ml_kem::MlKem512, _>(&mut rng, &msg, &pk).unwrap();
            assert_eq!(ct.kem_ct.len(), ML_KEM_512_CT_LENGTH);
            let len = ct.kem_ct.len();
            ct.kem_ct[len - 1] ^= 1;
            let err = dec::<ml_kem::MlKem512>(ct, &sk).unwrap_err();
            assert!(matches!(err, CryptographyError::AesGcmError(..)));
        }
    }
}
