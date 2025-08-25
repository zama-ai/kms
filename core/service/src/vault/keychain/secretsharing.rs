use super::{EnvelopeLoad, EnvelopeStore, Keychain};
use crate::{
    anyhow_error_and_log,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::backup_pke::{self, BackupCiphertext, BackupPrivateKey, BackupPublicKey},
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
    dec_key: Option<BackupPrivateKey>,
}

/// Create a new [`SecretShareKeychain`] used for backups in order to securely store and retrieve sensitive information.
impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    pub fn new(rng: R, custodian_context_id: RequestId, backup_enc_key: BackupPublicKey) -> Self {
        Self {
            rng,
            backup_enc_key,
            custodian_context_id,
            dec_key: None,
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
    pub fn set_dec_key(&mut self, dec_key: Option<BackupPrivateKey>) {
        self.dec_key = dec_key;
    }

    pub fn get_current_backup_id(&self) -> RequestId {
        self.custodian_context_id
    }

    pub fn set_current_backup_id(&mut self, backup_id: RequestId) {
        self.custodian_context_id = backup_id;
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
        let EnvelopeLoad::OperatorRecoveryInput(backup_ct) = envelope else {
            anyhow::bail!("Expected backup ct encrypted data")
        };
        let unwrapped_dec_key = self
            .dec_key
            .as_ref()
            .ok_or_else(|| anyhow_error_and_log("Operator not set"))?;
        match backup_ct.priv_data_type {
            PrivDataType::SigningKey => read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key),
            PrivDataType::FheKeyInfo => read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key),
            PrivDataType::CrsInfo => read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key),
            PrivDataType::FhePrivateKey => {
                read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key)
            }
            PrivDataType::PrssSetup => {
                anyhow::bail!("PRSS backup is not supported")
            }
            PrivDataType::CustodianInfo => {
                read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key)
            }
            PrivDataType::ContextInfo => read_backup_data(&backup_ct.ciphertext, unwrapped_dec_key),
        }
    }
}

fn read_backup_data<
    T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named + Send,
>(
    ct: &[u8],
    priv_dec_key: &backup_pke::BackupPrivateKey,
) -> anyhow::Result<T> {
    let plain_text = priv_dec_key.decrypt(ct)?;
    let mut buf = std::io::Cursor::new(plain_text);
    safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow_error_and_log(format!("Cannot decrypt backup: {e}")))
}
