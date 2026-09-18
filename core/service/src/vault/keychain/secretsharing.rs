use super::{EnvelopeLoad, EnvelopeStore, Keychain, RootKeyMeasurements};
use crate::{
    anyhow_error_and_log,
    backup::BackupCiphertext,
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::encryption::{Decrypt, Encrypt, UnifiedPrivateEncKey, UnifiedPublicEncKey},
};
use kms_grpc::RequestId;
use kms_grpc::rpc_types::PrivDataType;
use rand::{CryptoRng, Rng};
use serde::{Serialize, de::DeserializeOwned};
use std::sync::Arc;
use tfhe::{Unversionize, Versionize, named::Named, safe_serialization::safe_serialize};

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
    backup_enc_key: Option<UnifiedPublicEncKey>,
    dec_key: Option<UnifiedPrivateEncKey>,
}

impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    /// The keychain starts uninitialized. Which custodian context it adopts is decided by
    /// [`crate::vault::adopt_custodian_context`] from the anchor in private storage, never by what
    /// the backup vault happens to hold.
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            custodian_context_id: None,
            backup_enc_key: None,
            dec_key: None,
        }
    }

    pub fn operator_public_key_bytes(&self) -> anyhow::Result<Vec<u8>> {
        match &self.backup_enc_key {
            Some(backup_key) => {
                let mut res = Vec::new();
                safe_serialize(backup_key, &mut res, SAFE_SER_SIZE_LIMIT)
                    .map_err(|e| anyhow::anyhow!("Cannot serialize operator public key: {e}"))?;
                Ok(res)
            }
            None => anyhow::bail!("Secret sharing keychain is not initialized"),
        }
    }

    pub fn get_backup_enc_key(&self) -> anyhow::Result<UnifiedPublicEncKey> {
        match &self.backup_enc_key {
            Some(backup_key) => Ok(backup_key.clone()),
            None => anyhow::bail!("Secret sharing keychain is not initialized"),
        }
    }

    pub fn set_backup_enc_key(
        &mut self,
        custodian_context_id: RequestId,
        backup_enc_key: UnifiedPublicEncKey,
    ) {
        self.restore_backup_enc_key(Some((custodian_context_id, backup_enc_key)));
    }

    /// Restore the backup encryption key and custodian context id to a previously
    /// captured `(context_id, backup_enc_key)` snapshot. Passing `None` resets the
    /// keychain to the uninitialized state (no backup key set).
    ///
    /// This is used to roll back a custodian-context setup that fails before its
    /// recovery material is persisted, so the keychain is never left pointing at a
    /// context whose recovery material does not exist — which would otherwise make
    /// any later backup encrypted under that key unrecoverable.
    pub fn restore_backup_enc_key(&mut self, state: Option<(RequestId, UnifiedPublicEncKey)>) {
        let (custodian_context_id, backup_enc_key) = match state {
            Some((id, key)) => (Some(id), Some(key)),
            None => (None, None),
        };
        self.custodian_context_id = custodian_context_id;
        self.backup_enc_key = backup_enc_key;
    }

    /// After recovery of the private decryption key has been carried out with the help of the custodians
    /// it is possible to set the backup operator in order to allow decryption
    pub fn set_dec_key(&mut self, dec_key: Option<UnifiedPrivateEncKey>) {
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
        let raw_ct = self
            .get_backup_enc_key()?
            .encrypt(&mut self.rng, data)
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
            PrivDataType::CustodianContextAnchor => {
                anyhow::bail!("The custodian context anchor is never backed up")
            }
            // Both halves of the node's signing identity, handled alike.
            PrivDataType::SigningKey | PrivDataType::SigningSeed => unwrapped_dec_key
                .decrypt(&backup_ct.ciphertext)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Could not decrypt backed up secret shared {} {e}",
                        backup_ct.priv_data_type
                    )
                }),
            PrivDataType::FheKeyInfo => {
                unwrapped_dec_key
                    .decrypt(&backup_ct.ciphertext)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Could not decrypt backed up secret shared fhe key info {e}"
                        )
                    })
            }
            PrivDataType::CrsInfo => {
                unwrapped_dec_key
                    .decrypt(&backup_ct.ciphertext)
                    .map_err(|e| {
                        anyhow::anyhow!("Could not decrypt backed up secret shared crs info {e}")
                    })
            }
            PrivDataType::FhePrivateKey => unwrapped_dec_key
                .decrypt(&backup_ct.ciphertext)
                .map_err(|e| {
                    anyhow::anyhow!("Could not decrypt backed up secret shared private fhe key {e}")
                }),
            #[expect(deprecated)]
            PrivDataType::PrssSetup => unwrapped_dec_key
                .decrypt(&backup_ct.ciphertext)
                .map_err(|e| anyhow::anyhow!("Could not decrypt backed up PRSS setup legacy {e}")),
            #[expect(deprecated)]
            PrivDataType::PrssSetupCombined => unwrapped_dec_key
                .decrypt(&backup_ct.ciphertext)
                .map_err(|e| {
                    anyhow::anyhow!("Could not decrypt backed up PRSS setup combined {e}")
                }),
            PrivDataType::ContextInfo => {
                unwrapped_dec_key
                    .decrypt(&backup_ct.ciphertext)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Could not decrypt backed up secret shared context info {e}"
                        )
                    })
            }
            PrivDataType::EpochData => {
                unwrapped_dec_key
                    .decrypt(&backup_ct.ciphertext)
                    .map_err(|e| {
                        anyhow::anyhow!("Could not decrypt backed up secret shared epoch data {e}")
                    })
            }
        }
    }

    fn root_key_measurements(&self) -> Arc<RootKeyMeasurements> {
        Arc::new(RootKeyMeasurements::SecretSharing {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{PrivateSigKey, gen_sig_keys},
        },
        engine::base::derive_request_id,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[tokio::test]
    async fn test_new_keychain_is_uninitialized() {
        let keychain = SecretShareKeychain::new(AesRng::seed_from_u64(42));
        assert!(keychain.backup_enc_key.is_none());
        assert!(keychain.custodian_context_id.is_none());
    }

    #[tokio::test]
    async fn test_set_and_get_backup_enc_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let mut keychain = SecretShareKeychain::new(rng);
        let req_id = RequestId::zeros();
        keychain.set_backup_enc_key(req_id, enc_key.clone());
        assert_eq!(keychain.get_backup_enc_key().unwrap(), enc_key);
        assert_eq!(keychain.get_current_backup_id().unwrap(), req_id);
    }

    #[tokio::test]
    async fn test_restore_backup_enc_key_restores_and_resets() {
        let mut rng = AesRng::seed_from_u64(42);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let mut keychain = SecretShareKeychain::new(rng);
        let req_id = RequestId::zeros();

        // Restoring to a captured snapshot initializes the keychain.
        keychain.restore_backup_enc_key(Some((req_id, enc_key.clone())));
        assert_eq!(keychain.get_backup_enc_key().unwrap(), enc_key);
        assert_eq!(keychain.get_current_backup_id().unwrap(), req_id);

        // Restoring `None` resets the keychain to the uninitialized state, so a failed
        // custodian setup never leaves it pointing at a context with no recovery material.
        keychain.restore_backup_enc_key(None);
        assert!(
            keychain.get_backup_enc_key().is_err(),
            "backup enc key must be cleared on reset"
        );
        assert!(
            keychain.get_current_backup_id().is_err(),
            "current backup id must be cleared on reset"
        );
    }

    #[tokio::test]
    async fn test_operator_public_key_bytes_error() {
        let keychain = SecretShareKeychain::new(AesRng::seed_from_u64(42));
        let result = keychain.operator_public_key_bytes();
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_encrypt_and_decrypt_roundtrip() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_verf_key, sig_key) = gen_sig_keys(&mut rng);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (dec_key, enc_key) = enc.keygen().unwrap();
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
