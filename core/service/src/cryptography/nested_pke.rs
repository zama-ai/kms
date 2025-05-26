use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::EncodedSizeUser;
use rand::{CryptoRng, Rng};
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::hybrid_ml_kem::KemParam;
use crate::cryptography::hybrid_ml_kem::ML_KEM_SK_LEN;
use crate::cryptography::hybrid_ml_kem::{self, ML_KEM_CT_PK_LENGTH};

use super::error::CryptographyError;
use super::hybrid_rsa;

struct InnerNestedPrivateKey {
    // None of these types can be versioned,
    // so we need to make a wrapper
    decapsulation_key: DecapsulationKey<KemParam>,
    rsa_private_key: RsaPrivateKey,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum NestedPrivateKeyVersioned {
    V0(NestedPrivateKey),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(NestedPrivateKeyVersioned)]
pub struct NestedPrivateKey {
    decapsulation_key: Vec<u8>,
    rsa_private_key_der: Vec<u8>, // PKCS1 DER encoding
}

impl NestedPrivateKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let sk: InnerNestedPrivateKey = self.try_into()?;
        sk.decrypt(ciphertext)
    }
}

impl Named for NestedPrivateKey {
    const NAME: &'static str = "backup::NestedPrivateKey";
}

impl TryFrom<&NestedPrivateKey> for InnerNestedPrivateKey {
    type Error = CryptographyError;

    fn try_from(value: &NestedPrivateKey) -> Result<Self, Self::Error> {
        if value.decapsulation_key.len() != ML_KEM_SK_LEN {
            return Err(CryptographyError::LengthError(
                "decapsulation key has the wrong length".to_string(),
            ));
        }
        let mut decaps_key_buf = [0u8; ML_KEM_SK_LEN];
        decaps_key_buf.copy_from_slice(&value.decapsulation_key);
        let rsa_private_key = RsaPrivateKey::from_pkcs1_der(&value.rsa_private_key_der)?;
        Ok(Self {
            decapsulation_key: DecapsulationKey::<KemParam>::from_bytes(&decaps_key_buf.into()),
            rsa_private_key,
        })
    }
}

impl From<&InnerNestedPrivateKey> for NestedPrivateKey {
    fn from(value: &InnerNestedPrivateKey) -> Self {
        Self {
            decapsulation_key: value.decapsulation_key.as_bytes().to_vec(),
            rsa_private_key_der: value
                .rsa_private_key
                .to_pkcs1_der()
                .expect("unexpected failure: cannot perform to_pkcs2_der on private key")
                .as_bytes()
                .to_vec(),
        }
    }
}

impl InnerNestedPrivateKey {
    /// Perform nested decryption, outer layer is RSA OAEP,
    /// inner layer is the PQ scheme (hybrid with AEAD and ML-KEM).
    ///
    /// Note that we use tfhe::safe_serialize.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let ct = tfhe::safe_serialization::safe_deserialize::<hybrid_rsa::HybridRsaCt>(
            std::io::Cursor::new(ciphertext),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(CryptographyError::SafeDeserializationError)?;
        let outer_buf = hybrid_rsa::dec(ct, &self.rsa_private_key)?;
        let outer = tfhe::safe_serialization::safe_deserialize::<hybrid_ml_kem::HybridKemCt>(
            std::io::Cursor::new(outer_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(CryptographyError::SafeDeserializationError)?;
        hybrid_ml_kem::dec(outer, &self.decapsulation_key)
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum NestedPublicKeyVersioned {
    V0(NestedPublicKey),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(NestedPublicKeyVersioned)]
pub struct NestedPublicKey {
    encapsulation_key: Vec<u8>,
    rsa_public_key: Vec<u8>,
}

impl Named for NestedPublicKey {
    const NAME: &'static str = "backup::NestedPublicKey";
}

#[derive(Clone, Debug)]
struct InnerNestedPublicKey {
    // note we cannot serialize/deserialize EncapsulationKey
    // so a wrapper is needed
    encapsulation_key: EncapsulationKey<KemParam>,
    rsa_public_key: RsaPublicKey,
}

impl TryFrom<&NestedPublicKey> for InnerNestedPublicKey {
    type Error = CryptographyError;

    fn try_from(value: &NestedPublicKey) -> Result<Self, Self::Error> {
        if value.encapsulation_key.len() != ML_KEM_CT_PK_LENGTH {
            return Err(CryptographyError::LengthError(
                "encapsulation key has the wrong length".to_string(),
            ));
        }
        let mut encapsulation_key_buf = [0u8; ML_KEM_CT_PK_LENGTH];
        encapsulation_key_buf.copy_from_slice(&value.encapsulation_key);

        let rsa_public_key = RsaPublicKey::from_pkcs1_der(&value.rsa_public_key)?;
        Ok(Self {
            encapsulation_key: EncapsulationKey::<KemParam>::from_bytes(
                &encapsulation_key_buf.into(),
            ),
            rsa_public_key,
        })
    }
}

impl From<&InnerNestedPublicKey> for NestedPublicKey {
    fn from(value: &InnerNestedPublicKey) -> Self {
        Self {
            encapsulation_key: value.encapsulation_key.as_bytes().to_vec(),
            rsa_public_key: value
                .rsa_public_key
                .to_pkcs1_der()
                .expect("unexpected failure: cannot perform to_pkcs2_der on public key")
                .as_bytes()
                .to_vec(),
        }
    }
}

impl InnerNestedPublicKey {
    /// Perform nested encryption, first layer is using the PQ scheme (hybrid with AEAD and ML-KEM)
    /// the second layer is RSA OAEP.
    ///
    /// Note that we use safe_serialize to serialize first layer of ciphertext to be used in the second layer.
    /// The result is also safe_serialized.
    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptographyError> {
        let inner = hybrid_ml_kem::enc(rng, msg, &self.encapsulation_key).unwrap();
        let mut inner_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&inner, &mut inner_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;

        let ct = hybrid_rsa::enc(rng, &inner_buf, &self.rsa_public_key)?;
        let mut ct_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        Ok(ct_buf)
    }
}

impl NestedPublicKey {
    /// Perform nested encryption, first layer is using the PQ scheme (hybrid with AEAD and ML-KEM)
    /// the second layer is RSA OAEP.
    ///
    /// Note that we use safe_serialize to serialize first layer of ciphertext to be used in the second layer.
    /// The result is also safe_serialized.
    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptographyError> {
        let pk: InnerNestedPublicKey = self.try_into()?;
        pk.encrypt(rng, msg)
    }
}

pub fn keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(NestedPrivateKey, NestedPublicKey), CryptographyError> {
    let (decapsulation_key, encapsulation_key) = hybrid_ml_kem::keygen(rng);
    let (rsa_private_key, rsa_public_key) = hybrid_rsa::keygen(rng)?;

    let sk = InnerNestedPrivateKey {
        decapsulation_key,
        rsa_private_key,
    };
    let pk = InnerNestedPublicKey {
        encapsulation_key,
        rsa_public_key,
    };
    Ok(((&sk).into(), (&pk).into()))
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;

    use crate::cryptography::error::CryptographyError;

    use super::*;

    #[test]
    fn nested_pke_sunshine() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (sk, pk) = keygen(&mut rng).unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let pt = sk.decrypt(&ct).unwrap();
        assert_eq!(msg, pt);

        let mut pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&pk, &mut pk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let pk2: NestedPublicKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(pk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let ct2 = pk2.encrypt(&mut rng, &msg).unwrap();

        let mut sk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&sk, &mut sk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let sk2: NestedPrivateKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(sk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let pt2 = sk2.decrypt(&ct2).unwrap();
        assert_eq!(msg, pt2);
    }

    #[test]
    fn pke_wrong_rsa_key() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (sk_orig, pk) = keygen(&mut rng).unwrap();
        let (mut sk, _pk) = keygen(&mut rng).unwrap();

        // use the correct decapsulation key
        sk.decapsulation_key = sk_orig.decapsulation_key;

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt(&ct).unwrap_err();
        assert!(matches!(err, CryptographyError::RsaError(..)));
    }

    #[test]
    fn pke_wrong_kem_key() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (sk_orig, pk) = keygen(&mut rng).unwrap();
        let (mut sk, _pk) = keygen(&mut rng).unwrap();

        // use the right rsa key
        sk.rsa_private_key_der = sk_orig.rsa_private_key_der;

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt(&ct).unwrap_err();
        // We get an AesGcm error due to implicit rejection
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn pke_wrong_ct() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (sk, pk) = keygen(&mut rng).unwrap();
        let mut ct = pk.encrypt(&mut rng, &msg).unwrap();
        ct[0] ^= 1;
        let err = sk.decrypt(&ct).unwrap_err();
        assert!(matches!(
            err,
            CryptographyError::SafeDeserializationError(..)
        ));
    }
}
