use super::{EnvelopeLoad, EnvelopeStore, Keychain};
use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::backup_pke::{BackupCiphertext, BackupPublicKey},
};
use kms_grpc::rpc_types::PrivDataType;
use rand::{CryptoRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tfhe::{named::Named, safe_serialization::safe_serialize, Unversionize, Versionize};

#[derive(Clone)]
pub struct SecretShareKeychain<R: Rng + CryptoRng> {
    rng: R,
    backup_enc_key: BackupPublicKey,
}

impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    pub fn new(rng: R, backup_enc_key: BackupPublicKey) -> Self {
        Self {
            rng,
            backup_enc_key,
        }
    }

    pub fn operator_public_key_bytes(&self) -> Vec<u8> {
        self.backup_enc_key.encapsulation_key.clone()
    }

    pub fn set_backup_enc_key(&mut self, backup_enc_key: BackupPublicKey) {
        self.backup_enc_key = backup_enc_key;
    }
}

impl<R: Rng + CryptoRng> Keychain for SecretShareKeychain<R> {
    async fn encrypt<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_type: &str,
    ) -> anyhow::Result<EnvelopeStore> {
        let priv_data_type: PrivDataType = data_type.try_into()?;
        let mut payload_bytes = Vec::new();
        safe_serialize(data, &mut payload_bytes, SAFE_SER_SIZE_LIMIT)?;
        let raw_ct = self
            .backup_enc_key
            .encrypt(&mut self.rng, &payload_bytes)
            .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt backup: {e}")))?;
        let ct = BackupCiphertext {
            ciphertext: raw_ct,
            priv_data_type,
        };
        Ok(EnvelopeStore::OperatorBackupOutput(ct))
    }

    async fn decrypt<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        _envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T> {
        anyhow::bail!("Decryption not supported for SecretShareKeychain; decryption key is purged after initial secret sharing");
    }
}
