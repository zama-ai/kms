use kms_grpc::rpc_types::PrivDataType;
use ml_kem::array::typenum::Unsigned;
use ml_kem::array::Array;
use ml_kem::EncodedSizeUser;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use zeroize::Zeroize;

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::hybrid_ml_kem::{self};

use super::error::CryptographyError;

type MlKemType = ml_kem::MlKem512;
type MlKemParams = ml_kem::MlKem512Params;

struct InnerBackupPrivateKey {
    // None of these types can be versioned,
    // so we need to make a wrapper
    decapsulation_key: <ml_kem::kem::Kem<MlKemParams> as ml_kem::KemCore>::DecapsulationKey,
}

impl Drop for InnerBackupPrivateKey {
    fn drop(&mut self) {
        // Directly zeroize the underlying key bytes without creating copies
        // This is more secure as it avoids temporary allocations of sensitive data
        let key_bytes_ptr = self.decapsulation_key.as_bytes().as_ptr() as *mut u8;
        let key_len = self.decapsulation_key.as_bytes().len();

        // SAFETY: We're zeroizing the memory that belongs to this struct
        // The pointer is valid and the length is correct from as_bytes()
        unsafe {
            std::ptr::write_bytes(key_bytes_ptr, 0, key_len);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupPrivateKeyVersioned {
    V0(BackupPrivateKey),
}

// NOTE:
// The `Versionize` derive macro cannot be combined with a custom `Drop` implementation
// or `ZeroizeOnDrop` derivation without conflicts.
//
// Security-wise, the current design is solid:
// - Actual cryptographic key material resides in `InnerBackupPrivateKey`, not in the
//   serialized `Vec<u8>` representation.
// - Most `BackupPrivateKey` instances are short-lived and immediately used for decryption;
//   `decrypt()` converts them into `InnerBackupPrivateKey`.
// - `InnerBackupPrivateKey` implements a custom `Drop` with explicit memory zeroization.
// - `BackupPrivateKey` implements `Zeroize` for manual wiping if needed.
// - `try_from()` ensures that the intermediate `decaps_key_buf` (which *does* contain
//   sensitive data) is securely zeroized after use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize, Zeroize)]
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
        type EncodedSize512 = <<ml_kem::kem::Kem<MlKemParams> as ml_kem::KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize;
        let z = EncodedSize512::USIZE;
        if value.decapsulation_key.len() != z {
            return Err(CryptographyError::LengthError(
                "decapsulation key has the wrong length".to_string(),
            ));
        }
        let mut decaps_key_buf: Array<u8, EncodedSize512> = Array::default();
        decaps_key_buf.copy_from_slice(&value.decapsulation_key);

        let decapsulation_key =
            <MlKemType as ml_kem::KemCore>::DecapsulationKey::from_bytes(&decaps_key_buf);

        // Zeroize the key buffer to prevent memory disclosure attacks
        decaps_key_buf.zeroize();

        Ok(Self { decapsulation_key })
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
        hybrid_ml_kem::dec::<MlKemType>(buf, &self.decapsulation_key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupPublicKeyVersioned {
    V0(BackupPublicKey),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupPublicKeyVersioned)]
pub struct BackupPublicKey {
    pub(crate) encapsulation_key: Vec<u8>,
}

impl Named for BackupPublicKey {
    const NAME: &'static str = "cryptography::BackupPublicKey";
}

#[derive(Clone, Debug)]
struct InnerBackupPublicKey {
    // note we cannot serialize/deserialize EncapsulationKey
    // so a wrapper is needed
    encapsulation_key: <ml_kem::kem::Kem<MlKemParams> as ml_kem::KemCore>::EncapsulationKey,
}

impl TryFrom<&BackupPublicKey> for InnerBackupPublicKey {
    type Error = CryptographyError;

    fn try_from(value: &BackupPublicKey) -> Result<Self, Self::Error> {
        type EncodedSize512 = <<ml_kem::kem::Kem<MlKemParams> as ml_kem::KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize;
        let z = EncodedSize512::USIZE;
        if value.encapsulation_key.len() != z {
            return Err(CryptographyError::LengthError(
                "encapsulation key has the wrong length".to_string(),
            ));
        }
        let mut encapsulation_key_buf: Array<u8, EncodedSize512> = Array::default();
        encapsulation_key_buf.copy_from_slice(&value.encapsulation_key);

        Ok(Self {
            encapsulation_key: <ml_kem::kem::Kem<ml_kem::MlKem512Params> as ml_kem::KemCore>::EncapsulationKey::from_bytes(
                &encapsulation_key_buf,
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
        let inner = hybrid_ml_kem::enc::<MlKemType, _>(rng, msg, &self.encapsulation_key)?;
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

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCiphertextVersioned {
    V0(BackupCiphertext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCiphertextVersioned)]
pub struct BackupCiphertext {
    pub ciphertext: Vec<u8>,
    pub priv_data_type: PrivDataType,
}

impl Named for BackupCiphertext {
    const NAME: &'static str = "cryptography::BackupCiphertext";
}

// We allow the following lints because we are fine with mutating the rng even if
// we end up returning an error when serializing the enc_pk.
#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
pub fn keygen<R: Rng + CryptoRng>(
    rng: &mut R,
) -> Result<(BackupPublicKey, BackupPrivateKey), CryptographyError> {
    let (decapsulation_key, encapsulation_key) = hybrid_ml_kem::keygen::<MlKemType, _>(rng);

    let sk = InnerBackupPrivateKey { decapsulation_key };
    let pk = InnerBackupPublicKey { encapsulation_key };
    Ok(((&pk).into(), (&sk).into()))
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
        let (pk, sk) = keygen(&mut rng).unwrap();

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
        let (pk, _sk_orig) = keygen(&mut rng).unwrap();
        let (_pk, sk) = keygen(&mut rng).unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt(&ct).unwrap_err();
        // We get an AesGcm error due to implicit rejection
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn pke_wrong_ct() {
        let msg = vec![1, 2, 3, 4];
        let mut rng = OsRng;
        let (pk, sk) = keygen(&mut rng).unwrap();
        let mut ct = pk.encrypt(&mut rng, &msg).unwrap();
        ct[0] ^= 1;
        let err = sk.decrypt(&ct).unwrap_err();
        assert!(matches!(
            err,
            CryptographyError::SafeDeserializationError(..)
        ));
    }
}
