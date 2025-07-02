use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::EncodedSizeUser;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::hybrid_ml_kem::KemParam;
use crate::cryptography::hybrid_ml_kem::ML_KEM_SK_LEN;
use crate::cryptography::hybrid_ml_kem::{self, ML_KEM_PK_LENGTH};

use super::error::CryptographyError;

struct InnerBackupPrivateKey {
    // None of these types can be versioned,
    // so we need to make a wrapper
    decapsulation_key: DecapsulationKey<KemParam>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupPrivateKeyVersioned {
    V0(BackupPrivateKey),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupPrivateKeyVersioned)]
pub struct BackupPrivateKey {
    decapsulation_key: Vec<u8>,
}

impl BackupPrivateKey {
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let sk: InnerBackupPrivateKey = self.try_into()?;
        sk.decrypt(ciphertext)
    }
}

impl Named for BackupPrivateKey {
    const NAME: &'static str = "cryptography::BackupPrivateKey";
}

impl TryFrom<&BackupPrivateKey> for InnerBackupPrivateKey {
    type Error = CryptographyError;

    fn try_from(value: &BackupPrivateKey) -> Result<Self, Self::Error> {
        if value.decapsulation_key.len() != ML_KEM_SK_LEN {
            return Err(CryptographyError::LengthError(
                "decapsulation key has the wrong length".to_string(),
            ));
        }
        let mut decaps_key_buf = [0u8; ML_KEM_SK_LEN];
        decaps_key_buf.copy_from_slice(&value.decapsulation_key);
        Ok(Self {
            decapsulation_key: DecapsulationKey::<KemParam>::from_bytes(&decaps_key_buf.into()),
        })
    }
}

impl From<&InnerBackupPrivateKey> for BackupPrivateKey {
    fn from(value: &InnerBackupPrivateKey) -> Self {
        Self {
            decapsulation_key: value.decapsulation_key.as_bytes().to_vec(),
        }
    }
}

impl InnerBackupPrivateKey {
    /// Decrypt the backup ciphertext.
    ///
    /// Note that we use tfhe::safe_serialize.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptographyError> {
        let buf = tfhe::safe_serialization::safe_deserialize::<hybrid_ml_kem::HybridKemCt>(
            std::io::Cursor::new(ciphertext),
            SAFE_SER_SIZE_LIMIT,
        )
        .map_err(CryptographyError::SafeDeserializationError)?;
        hybrid_ml_kem::dec(buf, &self.decapsulation_key)
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupPublicKeyVersioned {
    V0(BackupPublicKey),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(BackupPublicKeyVersioned)]
pub struct BackupPublicKey {
    encapsulation_key: Vec<u8>,
}

impl Named for BackupPublicKey {
    const NAME: &'static str = "cryptography::BackupPublicKey";
}

#[derive(Clone, Debug)]
struct InnerBackupPublicKey {
    // note we cannot serialize/deserialize EncapsulationKey
    // so a wrapper is needed
    encapsulation_key: EncapsulationKey<KemParam>,
}

impl TryFrom<&BackupPublicKey> for InnerBackupPublicKey {
    type Error = CryptographyError;

    fn try_from(value: &BackupPublicKey) -> Result<Self, Self::Error> {
        if value.encapsulation_key.len() != ML_KEM_PK_LENGTH {
            return Err(CryptographyError::LengthError(
                "encapsulation key has the wrong length".to_string(),
            ));
        }
        let mut encapsulation_key_buf = [0u8; ML_KEM_PK_LENGTH];
        encapsulation_key_buf.copy_from_slice(&value.encapsulation_key);

        Ok(Self {
            encapsulation_key: EncapsulationKey::<KemParam>::from_bytes(
                &encapsulation_key_buf.into(),
            ),
        })
    }
}

impl From<&InnerBackupPublicKey> for BackupPublicKey {
    fn from(value: &InnerBackupPublicKey) -> Self {
        Self {
            encapsulation_key: value.encapsulation_key.as_bytes().to_vec(),
        }
    }
}

impl InnerBackupPublicKey {
    /// Perform backup encryption.
    ///
    /// Note that the result is safe_serialized.
    fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptographyError> {
        let inner = hybrid_ml_kem::enc(rng, msg, &self.encapsulation_key).unwrap();
        let mut ct_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&inner, &mut ct_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        Ok(ct_buf)
    }
}

impl BackupPublicKey {
    /// Perform backup encryption.
    ///
    /// Note that the result is safe_serialized.
    pub fn encrypt<R: Rng + CryptoRng>(
        &self,
        rng: &mut R,
        msg: &[u8],
    ) -> Result<Vec<u8>, CryptographyError> {
        let pk: InnerBackupPublicKey = self.try_into()?;
        pk.encrypt(rng, msg)
    }
}

// We allow the following lints because we are fine with mutating the rng even if
// we end up returning an error when serializing the enc_pk.
#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
pub fn keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(BackupPrivateKey, BackupPublicKey), CryptographyError> {
    let (decapsulation_key, encapsulation_key) = hybrid_ml_kem::keygen(rng);

    let sk = InnerBackupPrivateKey { decapsulation_key };
    let pk = InnerBackupPublicKey { encapsulation_key };
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
        let pk2: BackupPublicKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(pk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let ct2 = pk2.encrypt(&mut rng, &msg).unwrap();

        let mut sk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&sk, &mut sk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let sk2: BackupPrivateKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(sk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let pt2 = sk2.decrypt(&ct2).unwrap();
        assert_eq!(msg, pt2);
    }

    #[test]
    fn pke_wrong_kem_key() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (_sk_orig, pk) = keygen(&mut rng).unwrap();
        let (sk, _pk) = keygen(&mut rng).unwrap();

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
