use threshold_fhe::hashing::DomainSep;

use crate::cryptography::{internal_crypto_types::PrivateSigKey, signcryption};

use super::error::BackupError;

pub trait BackupSigner {
    fn sign(&self, dsep: &DomainSep, msg: &[u8]) -> Result<Vec<u8>, BackupError>;
}

impl BackupSigner for PrivateSigKey {
    fn sign(&self, dsep: &DomainSep, msg: &[u8]) -> Result<Vec<u8>, BackupError> {
        signcryption::sign(dsep, msg, self)
            .map(|sig| sig.sig.to_vec())
            .map_err(|_e| BackupError::SigningError)
    }
}

pub trait BackupDecryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BackupError>;
}
