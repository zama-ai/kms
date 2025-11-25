use anyhow::anyhow;
use keychain::{EnvelopeLoad, EnvelopeStore, Keychain, KeychainProxy};
use kms_grpc::rpc_types::BackupDataType;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use storage::{Storage, StorageForBytes, StorageProxy, StorageReader};
use tfhe::{named::Named, Unversionize, Versionize};

pub mod aws;
pub mod keychain;
pub mod storage;

pub struct Vault {
    pub storage: StorageProxy,
    pub keychain: Option<KeychainProxy>,
}

impl Vault {
    fn get_backup_type(&self, outer_data_type: &str) -> anyhow::Result<BackupDataType> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            Ok(BackupDataType::CustodianBackupData(
                secret_share_keychain.get_current_backup_id()?,
                outer_data_type.try_into()?,
            ))
        } else {
            Ok(BackupDataType::ExportData(outer_data_type.try_into()?))
        }
    }
}

#[cfg(feature = "non-wasm")]
impl StorageReader for Vault {
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, &backup_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, &backup_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::SecretSharing(_secret_share_keychain) => {
                        EnvelopeLoad::OperatorRecoveryInput(
                            self.storage
                                .read_data(data_id, &backup_type)
                                .await
                                .map_err(|e| anyhow!("Backup recovery input load failed: {e}"))?,
                        )
                    }
                };
                keychain_proxy
                    .decrypt(&mut envelope)
                    .await
                    .map_err(|e| anyhow!("Decryption failed during load: {e}"))
            }
            None => self
                .storage // TODO shoudl this be backuptype?
                .read_data(data_id, data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted load failed: {e}")),
        }
    }

    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        self.storage
            .data_exists(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Existence check failed: {e}"))
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            if secret_share_keychain.get_current_backup_id().is_err() {
                tracing::info!(
                    "No custodian context has been set yet! Returning empty set of data ids."
                );
                return Ok(HashSet::new());
            }
        }
        self.storage
            .all_data_ids(&backup_type)
            .await
            .map_err(|e| anyhow!("Getting all ids failed: {e}"))
    }

    fn info(&self) -> String {
        self.storage.info()
    }
}

#[cfg(feature = "non-wasm")]
impl Storage for Vault {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        match self.keychain.as_mut() {
            Some(kcp) => {
                let envelope = kcp
                    .encrypt(data, data_type)
                    .await
                    .map_err(|e| anyhow!("Encryption failed during store: {e}"))?;
                let backup_type = self.get_backup_type(data_type)?.to_string();
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => self
                        .storage
                        .store_data(&blob, data_id, data_type)
                        .await
                        .map_err(|e| anyhow!("Key blob store failed: {e}"))?,
                    EnvelopeStore::OperatorBackupOutput(ct) => {
                        self.storage
                            .store_data(&ct, data_id, &backup_type)
                            .await
                            .map_err(|e| anyhow!("Backup output store failed: {e}"))?;
                    }
                }
                Ok(())
            }
            None => self
                .storage
                .store_data(data, data_id, data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted store failed: {e}")),
        }
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        self.storage
            .delete_data(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Delete failed: {e}"))
    }
}

#[cfg(feature = "non-wasm")]
impl StorageForBytes for Vault {
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        self.storage
            .store_bytes(bytes, data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte store failed: {e}"))
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let backup_type = self.get_backup_type(data_type)?.to_string();
        self.storage
            .load_bytes(data_id, &backup_type)
            .await
            .map_err(|e| anyhow!("Byte load failed: {e}"))
    }
}
