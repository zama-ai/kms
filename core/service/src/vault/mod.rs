use futures_util::future::try_join;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, HashSet};
use tfhe::{named::Named, Unversionize, Versionize};

use crate::backup::operator::BackupCommitments;
use keychain::{EnvelopeLoad, EnvelopeStore, Keychain, KeychainProxy};
use storage::{Storage, StorageForBytes, StorageProxy, StorageReader};

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
            Some(k) => {
                let mut envelope = match k.envelope_share_ids() {
                    Some(ids) => {
                        let mut rs = BTreeMap::new();
                        let mut cs = BTreeMap::new();
                        for id in &ids {
                            let (recovery, commitment) = try_join(
                                self.storage.read_data(
                                    data_id,
                                    format!("{data_type}-recovery-{id}").as_str(),
                                ),
                                self.storage.load_bytes(
                                    data_id,
                                    format!("{data_type}-commitment-{id}").as_str(),
                                ),
                            )
                            .await?;
                            rs.insert(*id, recovery);
                            cs.insert(*id, commitment);
                        }
                        EnvelopeLoad::OperatorRecoveryInput(rs, BackupCommitments::from_btree(cs))
                    }
                    None => {
                        EnvelopeLoad::AppKeyBlob(self.storage.read_data(data_id, data_type).await?)
                    }
                };
                k.decrypt(data_id, &mut envelope).await
            }
            None => self.storage.read_data(data_id, data_type).await,
        }
    }

    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        self.storage.data_exists(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
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
            Some(k) => {
                let envelope = k.encrypt(data_id, data).await?;
                match envelope {
                    EnvelopeStore::AppKeyBlob(blob) => {
                        self.storage.store_data(&blob, data_id, data_type).await?
                    }
                    EnvelopeStore::OperatorBackupOutput(backup_outputs) => {
                        for (id, backup_output) in &backup_outputs {
                            self.storage
                                .store_data(
                                    backup_output,
                                    data_id,
                                    format!("{data_type}-backup-{id}").as_str(),
                                )
                                .await?;
                            self.storage
                                .store_bytes(
                                    backup_output.commitment.as_slice(),
                                    data_id,
                                    format!("{data_type}- commitment-{id}").as_str(),
                                )
                                .await?;
                        }
                    }
                }
                Ok(())
            }
            None => self.storage.store_data(data, data_id, data_type).await,
        }
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
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
        self.storage.store_bytes(bytes, data_id, data_type).await
    }
    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.storage.load_bytes(data_id, data_type).await
    }
}
