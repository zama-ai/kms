use anyhow::anyhow;
use keychain::{EnvelopeLoad, EnvelopeStore, Keychain, KeychainProxy};
use kms_grpc::rpc_types::BackupDataType;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashSet;
use std::path::MAIN_SEPARATOR;
use storage::{Storage, StorageForBytes, StorageProxy, StorageReader};
use tfhe::{named::Named, Unversionize, Versionize};

pub mod aws;
pub mod keychain;
pub mod storage;

pub struct Vault {
    pub storage: StorageProxy,
    pub keychain: Option<KeychainProxy>,
}

#[cfg(feature = "non-wasm")]
impl StorageReader for Vault {
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage
                            .read_data(data_id, data_type)
                            .await
                            .map_err(|e| anyhow!("Key blob load failed: {e}"))?,
                    ),
                    KeychainProxy::SecretSharing(secret_share_keychain) => {
                        // We only use the coerced backup type for secret sharing
                        let inner_type =
                            BackupDataType::PrivData(data_type.try_into()?).to_string();
                        let coerced_backup_type = format!(
                            "{}{MAIN_SEPARATOR}{inner_type}",
                            secret_share_keychain.get_current_backup_id()?
                        );
                        EnvelopeLoad::OperatorRecoveryInput(
                            self.storage
                                .read_data(data_id, &coerced_backup_type)
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
                .storage
                .read_data(data_id, data_type)
                .await
                .map_err(|e| anyhow!("Unencrypted load failed: {e}")),
        }
    }

    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .data_exists(data_id, &coerced_backup_type)
                .await
                .map_err(|e| anyhow!("Existence check failed: {e}"));
        }
        self.storage
            .data_exists(data_id, data_type)
            .await
            .map_err(|e| anyhow!("Existence check failed: {e}"))
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            match secret_share_keychain.get_current_backup_id() {
                Ok(backup_id) => {
                    let coerced_backup_type = format!("{}{MAIN_SEPARATOR}{inner_type}", backup_id);
                    return self
                        .storage
                        .all_data_ids(&coerced_backup_type)
                        .await
                        .map_err(|e| anyhow!("Getting all ids failed: {e}"));
                }
                Err(_) => {
                    tracing::info!(
                        "No custodian context has been set yet! Returning empty set of data ids."
                    );
                    return Ok(HashSet::new());
                }
            }
        }
        self.storage
            .all_data_ids(data_type)
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
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => self
                        .storage
                        .store_data(&blob, data_id, data_type)
                        .await
                        .map_err(|e| anyhow!("Key blob store failed: {e}"))?,
                    EnvelopeStore::OperatorBackupOutput(ct) => {
                        let coerced_backup_type =
                            if let KeychainProxy::SecretSharing(secret_share_keychain) = kcp {
                                secret_share_keychain.get_current_backup_id()?;
                                let inner_type =
                                    BackupDataType::PrivData(data_type.try_into()?).to_string();
                                &format!(
                                    "{}{MAIN_SEPARATOR}{inner_type}",
                                    secret_share_keychain.get_current_backup_id()?
                                )
                            } else {
                                data_type
                            };
                        self.storage
                            .store_data(&ct, data_id, coerced_backup_type)
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
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .delete_data(data_id, &coerced_backup_type)
                .await
                .map_err(|e| anyhow!("Delete failed: {e}"));
        }
        self.storage
            .delete_data(data_id, data_type)
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
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .store_bytes(bytes, data_id, &coerced_backup_type)
                .await
                .map_err(|e| anyhow!("Byte store failed: {e}"));
        }
        self.storage
            .store_bytes(bytes, data_id, data_type)
            .await
            .map_err(|e| anyhow!("Byte store failed: {e}"))
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .load_bytes(data_id, &coerced_backup_type)
                .await
                .map_err(|e| anyhow!("Byte load failed: {e}"));
        }
        self.storage
            .load_bytes(data_id, data_type)
            .await
            .map_err(|e| anyhow!("Byte load failed: {e}"))
    }
}
