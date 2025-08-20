use super::{EnvelopeLoad, EnvelopeStore, Keychain};
use crate::{
    anyhow_error_and_log,
    backup::operator::Operator,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::backup_pke::{BackupCiphertext, BackupPublicKey},
};
use kms_grpc::{rpc_types::PrivDataType, RequestId};
use rand::{CryptoRng, Rng};
use serde::{de::DeserializeOwned, Serialize};
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};

/// A keychain for managing secret shares.
/// This key chain is used for backups in order to securely store and retrieve sensitive information.
/// The [`backup_enc_key`] is the encryption key used for encrypting private data which can the be stored in the backup vault.
/// That is, the corresponding secret key share must have been secret shared among the custodians in order to allow recovery.
/// In order to decrypt this key must first be reconstructed and used to make an [`Operator`] that can decrypt the data.
/// For this reason the [`operator`] is optional, as it should _only_ be set as part of the recovery procedure
/// when the private decryption key has been reconstructed with the help of the custodians.
#[derive(Clone)]
pub struct SecretShareKeychain<R: Rng + CryptoRng> {
    rng: R,
    custodian_context_id: RequestId,
    backup_enc_key: BackupPublicKey,
    operator: Option<Operator>,
}

/// Create a new [`SecretShareKeychain`] used for backups in order to securely store and retrieve sensitive information.
impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    pub fn new(rng: R, custodian_context_id: RequestId, backup_enc_key: BackupPublicKey) -> Self {
        Self {
            rng,
            backup_enc_key,
            custodian_context_id,
            operator: None,
        }
    }

    pub fn operator_public_key_bytes(&self) -> Vec<u8> {
        self.backup_enc_key.encapsulation_key.clone()
    }

    pub fn set_backup_enc_key(
        &mut self,
        custodian_context_id: RequestId,
        backup_enc_key: BackupPublicKey,
    ) {
        self.backup_enc_key = backup_enc_key;
        self.custodian_context_id = custodian_context_id;
    }

    /// After recovery of the private decryption key has been carried out with the help of the custodians
    /// it is possible to set the backup operator in order to allow decryption
    pub fn set_decryptor(&mut self, operator: Operator) {
        self.operator = Some(operator);
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
        envelope: &mut EnvelopeLoad,
    ) -> anyhow::Result<T> {
        let EnvelopeLoad::OperatorRecoveryInput(rs, cs) = envelope else {
            anyhow::bail!("Expected multi-share encrypted data")
        };
        let payload_bytes = self
            .operator
            .as_ref()
            .ok_or_else(|| anyhow_error_and_log("Operator not set"))?
            .verify_and_recover(rs, cs, self.custodian_context_id)?;
        let mut buf = std::io::Cursor::new(&payload_bytes);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| anyhow_error_and_log(format!("Cannot decrypt backup: {e}")))
    }
}
