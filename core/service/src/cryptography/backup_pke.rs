use crate::cryptography::internal_crypto_types::UnifiedCipher;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCiphertextVersioned {
    V0(BackupCiphertext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCiphertextVersioned)]
pub struct BackupCiphertext {
    pub ciphertext: UnifiedCipher,
    pub priv_data_type: PrivDataType,
    pub backup_id: RequestId,
}

impl Named for BackupCiphertext {
    const NAME: &'static str = "cryptography::BackupCiphertext";
}

#[cfg(test)]
mod tests {
    use crate::{
        consts::SAFE_SER_SIZE_LIMIT,
        cryptography::{
            error::CryptographyError,
            internal_crypto_types::{
                Decrypt, Encrypt, Encryption, EncryptionScheme, EncryptionSchemeType,
                UnifiedPrivateEncKey, UnifiedPublicEncKey,
            },
        },
        vault::storage::tests::TestType,
    };
    use rand::rngs::OsRng;
    // TODO are these tests still needed or maybe in the wrong place
    #[test]
    fn nested_pke_sunshine() {
        let msg = TestType { i: 42 };
        let mut rng = OsRng;
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = enc.keygen().unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let pt = sk.decrypt(&ct).unwrap();
        assert_eq!(msg, pt);

        let mut pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&pk, &mut pk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let pk2: UnifiedPublicEncKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(pk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let ct2 = pk2.encrypt(&mut rng, &msg).unwrap();

        let mut sk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&sk, &mut sk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let sk2: UnifiedPrivateEncKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(sk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let pt2 = sk2.decrypt(&ct2).unwrap();
        assert_eq!(msg, pt2);
    }

    #[test]
    fn pke_wrong_kem_key() {
        let msg = TestType { i: 42 };
        let mut rng = OsRng;
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_sk_orig, pk) = enc.keygen().unwrap();
        let (sk, _pk) = enc.keygen().unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt::<TestType>(&ct).unwrap_err();
        // We get an AesGcm error due to implicit rejection
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn pke_wrong_ct() {
        let msg = TestType { i: 42 };
        let mut rng = OsRng;
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = enc.keygen().unwrap();
        let mut ct = pk.encrypt(&mut rng, &msg).unwrap();
        ct.cipher[0] ^= 1;
        let err = sk.decrypt::<TestType>(&ct).unwrap_err();
        assert!(matches!(err, CryptographyError::DeserializationError(..)));
    }
}
