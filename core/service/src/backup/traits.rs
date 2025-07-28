use std::sync::Arc;
use threshold_fhe::hashing::DomainSep;

use crate::cryptography::{
    backup_pke::BackupPrivateKey, internal_crypto_types::PrivateSigKey, signcryption,
};

use super::error::BackupError;

pub trait BackupSigner {
    fn sign(&self, dsep: &DomainSep, msg: &[u8]) -> Result<Vec<u8>, BackupError>;
}

impl BackupSigner for PrivateSigKey {
    fn sign(&self, dsep: &DomainSep, msg: &[u8]) -> Result<Vec<u8>, BackupError> {
        signcryption::internal_sign(dsep, msg, self)
            .map(|sig| sig.sig.to_vec())
            .map_err(|e| BackupError::SigningError(e.to_string()))
    }
}

impl BackupSigner for Arc<PrivateSigKey> {
    fn sign(&self, dsep: &DomainSep, msg: &[u8]) -> Result<Vec<u8>, BackupError> {
        signcryption::internal_sign(dsep, msg, self)
            .map(|sig| sig.sig.to_vec())
            .map_err(|e| BackupError::SigningError(e.to_string()))
    }
}

pub trait BackupDecryptor {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BackupError>;
}

impl BackupDecryptor for BackupPrivateKey {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BackupError> {
        BackupPrivateKey::decrypt(self, ciphertext).map_err(|e| e.into())
    }
}
