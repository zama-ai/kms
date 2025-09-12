use super::{EnvelopeLoad, EnvelopeStore, Keychain};
use crate::cryptography::backup_pke::{BackupPrivateKey, BackupPublicKey};
use crate::{
    anyhow_error_and_log,
    backup::operator::InnerRecoveryRequest,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::backup_pke::{self, BackupCiphertext},
    vault::storage::{read_versioned_at_request_id, StorageReader},
};
use itertools::Itertools;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_grpc::RequestId;
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
/// For this reason the [`dec_key`] is optional, as it should _only_ be set as part of the recovery procedure
/// when the private decryption key has been reconstructed with the help of the custodians.
#[derive(Clone)]
pub struct SecretShareKeychain<R: Rng + CryptoRng> {
    rng: R,
    custodian_context_id: Option<RequestId>,
    backup_enc_key: Option<BackupPublicKey>,
    dec_key: Option<BackupPrivateKey>,
}

/// Create a new [`SecretShareKeychain`] used for backups in order to securely store and retrieve sensitive information.
/// If the `pub_storage` is not provided, the keychain will be created without a backup key and must be set later.
impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    pub async fn new<PubS>(rng: R, pub_storage: Option<&PubS>) -> anyhow::Result<Self>
    where
        PubS: StorageReader,
    {
        let (backup_enc_key, custodian_context_id) = match pub_storage {
            Some(pub_storage) => {
                // Try to see if there is already a backup key set
                let all_backup_ids = pub_storage
                    .all_data_ids(&PubDataType::RecoveryRequest.to_string())
                    .await?;
                // Get the latest context ID which should be the most recent one
                match all_backup_ids.iter().sorted().last() {
                    Some(id) => {
                        let rec_req: InnerRecoveryRequest = read_versioned_at_request_id(
                            pub_storage,
                            id,
                            &PubDataType::RecoveryRequest.to_string(),
                        )
                        .await?;
                        (Some(rec_req.backup_enc_key), Some(id.to_owned()))
                    }
                    None => {
                        tracing::warn!(
                            "No custodian context found in public vault. Secret sharing keychain will be created without a backup key and must be set later."
                        );
                        (None, None)
                    }
                }
            }
            None => {
                tracing::warn!(
                    "Public vault not provided. Secret sharing keychain will be created without a backup key and must be set later."
                );
                (None, None)
            }
        };
        Ok(Self {
            rng,
            backup_enc_key,
            custodian_context_id,
            dec_key: None,
        })
    }

    pub fn operator_public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match &self.backup_enc_key {
            Some(backup_key) => Ok(backup_key.encapsulation_key.clone()),
            None => anyhow::bail!("Secret sharing keychain is not initialized"),
        }
    }

    pub fn get_backup_enc_key(&self) -> anyhow::Result<BackupPublicKey> {
        match &self.backup_enc_key {
            Some(backup_key) => Ok(backup_key.clone()),
            None => anyhow::bail!("Secret sharing keychain is not initialized"),
        }
    }

    pub fn set_backup_enc_key(
        &mut self,
        custodian_context_id: RequestId,
        backup_enc_key: BackupPublicKey,
    ) {
        self.backup_enc_key = Some(backup_enc_key);
        self.custodian_context_id = Some(custodian_context_id);
    }

    /// After recovery of the private decryption key has been carried out with the help of the custodians
    /// it is possible to set the backup operator in order to allow decryption
    pub fn set_dec_key(&mut self, dec_key: Option<BackupPrivateKey>) {
        self.dec_key = dec_key;
    }

    pub fn get_current_backup_id(&self) -> anyhow::Result<RequestId> {
        match self.custodian_context_id {
            Some(backup_id) => Ok(backup_id),
            None => anyhow::bail!("No custodian context has been set yet"),
        }
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
            .get_backup_enc_key()?
            .encrypt(&mut self.rng, &payload_bytes)
            .map_err(|e| anyhow_error_and_log(format!("Cannot encrypt backup: {e}")))?;
        let ct = BackupCiphertext {
            ciphertext: raw_ct,
            priv_data_type,
            backup_id: self.get_current_backup_id()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cryptography::internal_crypto_types::{gen_sig_keys, PrivateSigKey},
        engine::base::derive_request_id,
        vault::storage::ram::RamStorage,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_new_keychain_without_pub_storage() {
        let rng = AesRng::seed_from_u64(42);
        let keychain = SecretShareKeychain::<AesRng>::new::<RamStorage>(rng, None)
            .await
            .unwrap();
        assert!(keychain.backup_enc_key.is_none());
        assert!(keychain.custodian_context_id.is_none());
    }

    #[tokio::test]
    async fn test_set_and_get_backup_enc_key() {
        let rng = AesRng::seed_from_u64(42);
        let mut keychain = SecretShareKeychain::<AesRng>::new::<RamStorage>(rng, None)
            .await
            .unwrap();
        let backup_key = BackupPublicKey {
            encapsulation_key: vec![1, 2, 3],
        };
        let req_id = RequestId::zeros();
        keychain.set_backup_enc_key(req_id, backup_key.clone());
        assert_eq!(keychain.get_backup_enc_key().unwrap(), backup_key);
        assert_eq!(keychain.get_current_backup_id().unwrap(), req_id);
    }

    #[tokio::test]
    async fn test_operator_public_key_bytes_error() {
        let rng = AesRng::seed_from_u64(42);
        let keychain = SecretShareKeychain::<AesRng>::new::<RamStorage>(rng, None)
            .await
            .unwrap();
        let result = keychain.operator_public_key_bytes();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_encrypt_and_decrypt_roundtrip() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let (enc_key, dec_key) = backup_pke::keygen(&mut rng).unwrap();
        let mut keychain = SecretShareKeychain {
            rng,
            custodian_context_id: Some(derive_request_id("test").unwrap()),
            backup_enc_key: Some(enc_key.clone()),
            dec_key: Some(dec_key.clone()),
        };

        let envelope = keychain
            .encrypt(&sig_key, &PrivDataType::SigningKey.to_string())
            .await
            .unwrap();
        let mut envelope_load = match envelope {
            EnvelopeStore::OperatorBackupOutput(ct) => EnvelopeLoad::OperatorRecoveryInput(ct),
            _ => panic!("Unexpected envelope type"),
        };
        let decrypted_key: PrivateSigKey = keychain.decrypt(&mut envelope_load).await.unwrap();
        assert_eq!(decrypted_key, sig_key);
    }
}
