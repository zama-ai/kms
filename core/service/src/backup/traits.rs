use super::error::BackupError;
use crate::cryptography::{
    backup_pke::BackupPrivateKey, internal_crypto_types::PrivateSigKey, signcryption,
};
use std::sync::Arc;
use threshold_fhe::hashing::DomainSep;

pub trait BackupSigner {
    fn sign<T>(&self, dsep: &DomainSep, msg: &T) -> Result<Vec<u8>, BackupError>
    where
        T: AsRef<[u8]> + ?Sized;
}
// TODO(#2748) remove as it causes more issues than good
impl BackupSigner for PrivateSigKey {
    fn sign<T: AsRef<[u8]> + ?Sized>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<Vec<u8>, BackupError> {
        signcryption::internal_sign(dsep, msg, self)
            .map(|sig| sig.sig.to_vec())
            .map_err(|e| BackupError::SigningError(e.to_string()))
    }
}

impl BackupSigner for Arc<PrivateSigKey> {
    fn sign<T: AsRef<[u8]> + ?Sized>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<Vec<u8>, BackupError> {
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
