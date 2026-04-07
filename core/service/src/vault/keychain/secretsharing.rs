use super::{EnvelopeLoad, EnvelopeStore, Keychain, RootKeyMeasurements};
use crate::{
    anyhow_error_and_log,
    backup::{BackupCiphertext, operator::RecoveryValidationMaterial},
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{
        encryption::{Decrypt, Encrypt, UnifiedPrivateEncKey, UnifiedPublicEncKey},
        signatures::PublicSigKey,
    },
    vault::storage::{StorageReader, read_versioned_at_request_id},
};
use itertools::Itertools;
use kms_grpc::RequestId;
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
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
/// The [`loaded_recovery_material`] is loaded from public storage during initialization and is used by
/// [`SecretShareKeychain::validate_recovery_material`] to verify the recovery material signature once
/// the verification key becomes available. It is `None` on first startup before custodian setup,
/// in which case validation is skipped.
#[derive(Clone)]
pub struct SecretShareKeychain<R: Rng + CryptoRng> {
    rng: R,
    custodian_context_id: Option<RequestId>,
    backup_enc_key: Option<UnifiedPublicEncKey>,
    dec_key: Option<UnifiedPrivateEncKey>,
    loaded_recovery_material: Option<RecoveryValidationMaterial>,
}

/// Create a new [`SecretShareKeychain`] used for backups in order to securely store and retrieve sensitive information.
/// If the `pub_storage` is not provided, the keychain will be created without a backup key and must be set later.
impl<R: Rng + CryptoRng> SecretShareKeychain<R> {
    pub async fn new<PubS>(rng: R, pub_storage: Option<&PubS>) -> anyhow::Result<Self>
    where
        PubS: StorageReader,
    {
        let (backup_enc_key, custodian_context_id, loaded_recovery_material) = match pub_storage {
            Some(pub_storage) => {
                // Try to see if there is already a backup key set
                let all_backup_ids = pub_storage
                    .all_data_ids(&PubDataType::RecoveryMaterial.to_string())
                    .await?;
                // Get the latest context ID which should be the most recent one
                match all_backup_ids.iter().sorted().last() {
                    Some(id) => {
                        let rec_material: RecoveryValidationMaterial =
                            read_versioned_at_request_id(
                                pub_storage,
                                id,
                                &PubDataType::RecoveryMaterial.to_string(),
                            )
                            .await?;
                        let backup_enc_key = rec_material
                            .payload
                            .custodian_context
                            .backup_enc_key
                            .clone();
                        (
                            Some(backup_enc_key),
                            Some(id.to_owned()),
                            Some(rec_material),
                        )
                    }
                    None => {
                        tracing::warn!(
                            "No custodian context found in public vault. Secret sharing keychain will be created without a backup key and must be set later."
                        );
                        (None, None, None)
                    }
                }
            }
            None => {
                tracing::warn!(
                    "Public vault not provided. Secret sharing keychain will be created without a backup key and must be set later."
                );
                (None, None, None)
            }
        };
        Ok(Self {
            rng,
            backup_enc_key,
            custodian_context_id,
            dec_key: None,
            loaded_recovery_material,
        })
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
        self.backup_enc_key = Some(backup_enc_key);
        self.custodian_context_id = Some(custodian_context_id);
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

    /// Validate the recovery material loaded from public storage.
    /// Must be called once the verification key becomes available.
    /// If no recovery material was loaded (e.g. first startup before custodian setup),
    /// validation is skipped since there is nothing to verify.
    pub fn validate_recovery_material(&self, verf_key: &PublicSigKey) -> anyhow::Result<()> {
        match self.loaded_recovery_material {
            Some(ref material) => {
                if !material.validate(verf_key) {
                    Err(anyhow_error_and_log(format!(
                        "Recovery validation material for context {:?} has an invalid signature",
                        self.custodian_context_id
                    )))
                } else {
                    tracing::info!("Recovery material signature validated successfully");
                    Ok(())
                }
            }
            None => {
                tracing::info!(
                    "No recovery material loaded from public storage, skipping validation"
                );
                Ok(())
            }
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
            PrivDataType::SigningKey => {
                unwrapped_dec_key
                    .decrypt(&backup_ct.ciphertext)
                    .map_err(|e| {
                        anyhow::anyhow!("Could not decrypt backed up secret shared signing key {e}")
                    })
            }
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
        backup::{
            custodian::{CustodianSetupMessagePayload, HEADER, InternalCustodianContext},
            operator::InnerOperatorBackupOutput,
        },
        cryptography::{
            encryption::{Encryption, PkeScheme, PkeSchemeType},
            signatures::{PrivateSigKey, SigningSchemeType, gen_sig_keys},
            signcryption::UnifiedSigncryption,
        },
        engine::base::derive_request_id,
        vault::storage::{ram::RamStorage, store_versioned_at_request_id},
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::{CustodianContext, CustodianSetupMessage};
    use rand::SeedableRng;
    use std::collections::BTreeMap;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tfhe::safe_serialization::safe_serialize;
    use threshold_types::role::Role;

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
        let mut rng = AesRng::seed_from_u64(42);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let mut keychain = SecretShareKeychain::<AesRng>::new::<RamStorage>(rng, None)
            .await
            .unwrap();
        let req_id = RequestId::zeros();
        keychain.set_backup_enc_key(req_id, enc_key.clone());
        assert_eq!(keychain.get_backup_enc_key().unwrap(), enc_key);
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
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (dec_key, enc_key) = enc.keygen().unwrap();
        let mut keychain = SecretShareKeychain {
            rng,
            custodian_context_id: Some(derive_request_id("test").unwrap()),
            backup_enc_key: Some(enc_key.clone()),
            dec_key: Some(dec_key.clone()),
            loaded_recovery_material: None,
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

    #[tokio::test]
    async fn test_validate_recovery_material_valid_signature() {
        let (storage, verf_key, _wrong_verf_key) = setup_recovery_material_in_storage().await;
        let rng = AesRng::seed_from_u64(99);
        let keychain = SecretShareKeychain::new(rng, Some(&storage)).await.unwrap();
        keychain.validate_recovery_material(&verf_key).unwrap();
    }

    #[tokio::test]
    async fn test_validate_recovery_material_invalid_signature() {
        let (storage, _verf_key, wrong_verf_key) = setup_recovery_material_in_storage().await;
        let rng = AesRng::seed_from_u64(99);
        let keychain = SecretShareKeychain::new(rng, Some(&storage)).await.unwrap();
        let result = keychain.validate_recovery_material(&wrong_verf_key);
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid signature")
        );
    }

    #[tokio::test]
    async fn test_validate_recovery_material_no_material_is_ok() {
        let rng = AesRng::seed_from_u64(69);
        let mut rng2 = AesRng::seed_from_u64(69);
        let (verf_key, _sig_key) = gen_sig_keys(&mut rng2);
        let keychain = SecretShareKeychain::<AesRng>::new::<RamStorage>(rng, None)
            .await
            .unwrap();
        // No recovery material loaded yet (e.g. first startup before custodian setup)
        // should be OK since there is nothing to validate.
        keychain.validate_recovery_material(&verf_key).unwrap();
    }

    /// Helper: create a RecoveryValidationMaterial, store it in RamStorage, and return
    /// the storage, verification key, and a different verification key for negative tests.
    async fn setup_recovery_material_in_storage() -> (RamStorage, PublicSigKey, PublicSigKey) {
        let mut rng = AesRng::seed_from_u64(0);
        let (verf_key, sig_key) = gen_sig_keys(&mut rng);
        let (wrong_verf_key, _wrong_sig_key) = gen_sig_keys(&mut rng);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_dec_key, enc_key) = enc.keygen().unwrap();
        let backup_id = derive_request_id("test-backup").unwrap();

        // Build custodian setup messages
        let payload = CustodianSetupMessagePayload {
            header: HEADER.to_string(),
            random_value: [4_u8; 32],
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            public_enc_key: enc_key.clone(),
            verification_key: verf_key.clone(),
        };
        let mut payload_serial = Vec::new();
        safe_serialize(&payload, &mut payload_serial, SAFE_SER_SIZE_LIMIT).unwrap();
        let setup_msgs: Vec<_> = (1..=3)
            .map(|i| CustodianSetupMessage {
                custodian_role: i,
                name: format!("Custodian-{i}"),
                payload: payload_serial.clone(),
            })
            .collect();
        let custodian_context = CustodianContext {
            custodian_nodes: setup_msgs,
            custodian_context_id: Some(backup_id.into()),
            threshold: 1,
        };
        let internal_custodian_context =
            InternalCustodianContext::new(custodian_context, enc_key).unwrap();

        // Build dummy operator backup outputs and commitments
        let mut cts = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for i in 1..=3 {
            let role = Role::indexed_from_one(i);
            cts.insert(
                role,
                InnerOperatorBackupOutput {
                    signcryption: UnifiedSigncryption {
                        payload: vec![1, 2, 3],
                        pke_type: PkeSchemeType::MlKem512,
                        signing_type: SigningSchemeType::Ecdsa256k1,
                    },
                },
            );
            commitments.insert(role, vec![i as u8; 32]);
        }

        let rec_material =
            RecoveryValidationMaterial::new(
                cts,
                commitments,
                internal_custodian_context,
                &sig_key,
                kms_grpc::identifiers::ContextId::from_bytes([7u8; 32]),
            )
            .unwrap();

        // Store it in RamStorage
        let mut storage = RamStorage::default();
        store_versioned_at_request_id(
            &mut storage,
            &backup_id,
            &rec_material,
            &PubDataType::RecoveryMaterial.to_string(),
        )
        .await
        .unwrap();

        (storage, verf_key, wrong_verf_key)
    }
}
