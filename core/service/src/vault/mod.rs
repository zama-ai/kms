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

#[derive(Clone)]
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
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage.read_data(data_id, &inner_type).await?,
                    ),
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => EnvelopeLoad::AppKeyBlob(
                        self.storage.read_data(data_id, &inner_type).await?,
                    ),
                    KeychainProxy::SecretSharing(secret_share_keychain) => {
                        // TODO we likely want to change this but for now let us keep all back ups even though we only care about the latest
                        let coerced_backup_type = format!(
                            "{}{MAIN_SEPARATOR}{inner_type}",
                            secret_share_keychain.get_current_backup_id()?
                        );
                        EnvelopeLoad::OperatorRecoveryInput(
                            self.storage
                                .read_data(data_id, &coerced_backup_type)
                                .await?,
                        )
                    }
                };
                keychain_proxy.decrypt(&mut envelope).await
            }
            None => self.storage.read_data(data_id, &inner_type).await,
        }
    }

    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .data_exists(data_id, &coerced_backup_type)
                .await;
        }
        self.storage.data_exists(data_id, &inner_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            match secret_share_keychain.get_current_backup_id() {
                Ok(backup_id) => {
                    let coerced_backup_type = format!("{}{MAIN_SEPARATOR}{inner_type}", backup_id);
                    return self.storage.all_data_ids(&coerced_backup_type).await;
                }
                Err(_) => {
                    tracing::warn!(
                        "No custodian context has been set yet! Returning empty set of data ids."
                    );
                    return Ok(HashSet::new());
                }
            }
        }
        self.storage.all_data_ids(&inner_type).await
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
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        match self.keychain.as_mut() {
            Some(kcp) => {
                let coerced_backup_type =
                    if let KeychainProxy::SecretSharing(secret_share_keychain) = kcp {
                        if secret_share_keychain.get_current_backup_id().is_err() {
                            tracing::warn!(
                            "No custodian context has been set yet! NO BACKUP WILL BE PRODUCED!!!"
                        );
                            return Ok(());
                        }
                        &format!(
                            "{}{MAIN_SEPARATOR}{inner_type}",
                            secret_share_keychain.get_current_backup_id()?
                        )
                    } else {
                        &inner_type
                    };
                let envelope = kcp.encrypt(data, data_type).await?;
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => {
                        self.storage
                            .store_data(&blob, data_id, coerced_backup_type)
                            .await?
                    }
                    EnvelopeStore::OperatorBackupOutput(ct) => {
                        self.storage
                            .store_data(&ct, data_id, coerced_backup_type)
                            .await?;
                    }
                }
                Ok(())
            }
            None => self.storage.store_data(data, data_id, &inner_type).await,
        }
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            println!("path {}", coerced_backup_type);
            return self
                .storage
                .delete_data(data_id, &coerced_backup_type)
                .await;
        }
        self.storage.delete_data(data_id, &inner_type).await
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
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self
                .storage
                .store_bytes(bytes, data_id, &coerced_backup_type)
                .await;
        }
        self.storage.store_bytes(bytes, data_id, &inner_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self.storage.load_bytes(data_id, &coerced_backup_type).await;
        }
        self.storage.load_bytes(data_id, &inner_type).await
    }
}
