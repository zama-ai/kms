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
        match self.keychain.as_ref() {
            Some(keychain_proxy) => {
                let mut envelope = match keychain_proxy {
                    KeychainProxy::AwsKmsSymm(_awskmskeychain) => {
                        EnvelopeLoad::AppKeyBlob(self.storage.read_data(data_id, data_type).await?)
                    }
                    KeychainProxy::AwsKmsAsymm(_awskmskeychain) => {
                        EnvelopeLoad::AppKeyBlob(self.storage.read_data(data_id, data_type).await?)
                    }
                    KeychainProxy::SecretSharing(secret_share_keychain) => {
                        // We only use the coerced backup type for secret sharing
                        // TODO is this what we actually want to do? Is it really needed? Should it be forced to only be private data?
                        // And more crucially does it make sense to change the file structure? Would it be better to always just have the most recent back up in the root and if others are present to them into a folder called old backup?
                        let inner_type =
                            BackupDataType::PrivData(data_type.try_into()?).to_string();
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
            None => self.storage.read_data(data_id, data_type).await,
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
                .await;
        }
        self.storage.data_exists(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
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
        self.storage.all_data_ids(data_type).await
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
                let envelope = kcp.encrypt(data, data_type).await?;
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => {
                        self.storage.store_data(&blob, data_id, data_type).await?
                    }
                    EnvelopeStore::OperatorBackupOutput(ct) => {
                        let coerced_backup_type = if let KeychainProxy::SecretSharing(
                            secret_share_keychain,
                        ) = kcp
                        {
                            if secret_share_keychain.get_current_backup_id().is_err() {
                                tracing::warn!("No custodian context has been set yet! NO BACKUP WILL BE PRODUCED!!!");
                                return Ok(());
                            }
                            let inner_type =
                                BackupDataType::PrivData(data_type.try_into()?).to_string();
                            &format!(
                                "{}{MAIN_SEPARATOR}{inner_type}",
                                secret_share_keychain.get_current_backup_id()?
                            )
                        } else {
                            data_type
                        };
                        println!(
                            "Storing data type {}, req {} name {}",
                            coerced_backup_type,
                            data_id,
                            T::NAME
                        );
                        self.storage
                            .store_data(&ct, data_id, coerced_backup_type)
                            .await?;
                    }
                }
                Ok(())
            }
            None => self.storage.store_data(data, data_id, data_type).await,
        }
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
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
        self.storage.delete_data(data_id, data_type).await
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
                .await;
        }
        self.storage.store_bytes(bytes, data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        if let Some(KeychainProxy::SecretSharing(secret_share_keychain)) = self.keychain.as_ref() {
            let inner_type = BackupDataType::PrivData(data_type.try_into()?).to_string();
            let coerced_backup_type = format!(
                "{}{MAIN_SEPARATOR}{inner_type}",
                secret_share_keychain.get_current_backup_id()?
            );
            return self.storage.load_bytes(data_id, &coerced_backup_type).await;
        }
        self.storage.load_bytes(data_id, data_type).await
    }
}
