use super::{Storage, StorageReader};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::vault::storage::{all_data_ids_from_all_epochs_impl, StorageExt};
use crate::{anyhow_error_and_log, vault::storage::StorageReaderExt};
use anyhow::anyhow;
use kms_grpc::{identifiers::EpochId, RequestId};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RamStorage {
    // Store data_id, data_type to serialized data
    #[allow(clippy::type_complexity)]
    internal_storage: HashMap<((RequestId, Option<EpochId>), String), Vec<u8>>,
}

impl RamStorage {
    // Aggregate with devstorage to make an object that loads from files but don't store
    pub fn new() -> Self {
        Self {
            internal_storage: HashMap::new(),
        }
    }
}

impl StorageReader for RamStorage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        Ok(self
            .internal_storage
            .contains_key(&((*data_id, None), data_type.to_string())))
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let raw_data = match self
            .internal_storage
            .get(&((*data_id, None), data_type.to_string()))
        {
            Some(raw_data) => raw_data,
            None => {
                return Err(anyhow!(
                    "Could not find data at ({}, {})",
                    data_type,
                    data_id
                ))
            }
        };
        let mut buf = std::io::Cursor::new(raw_data);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let raw_data = match self
            .internal_storage
            .get(&((*data_id, None), data_type.to_string()))
        {
            Some(raw_data) => raw_data,
            None => {
                return Err(anyhow!(
                    "Could not decode data at ({}, {})",
                    data_id,
                    data_type
                ))
            }
        };
        Ok(raw_data.clone())
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let mut res = HashSet::new();
        for ((cur_data_id, cur_epoch_id), cur_data_type) in self.internal_storage.keys() {
            // Only return IDs stored without an epoch (non-epoch storage)
            if cur_data_type == data_type && cur_epoch_id.is_none() {
                res.insert(*cur_data_id);
            }
        }
        Ok(res)
    }

    fn info(&self) -> String {
        "memory storage".to_string()
    }
}

impl StorageReaderExt for RamStorage {
    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let raw_data = match self
            .internal_storage
            .get(&((*data_id, Some(*epoch_id)), data_type.to_string()))
        {
            Some(raw_data) => raw_data,
            None => {
                return Err(anyhow!(
                    "Could not find data at (RequestId: {}, Epoch_id: {}, data type: {})",
                    data_type,
                    data_id,
                    epoch_id
                ))
            }
        };
        let mut buf = std::io::Cursor::new(raw_data);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let mut res = HashSet::new();
        for ((_cur_data_id, cur_epoch_id), cur_data_type) in self.internal_storage.keys() {
            if let Some(epoch_id) = cur_epoch_id {
                if cur_data_type == data_type {
                    res.insert(*epoch_id);
                }
            }
        }
        Ok(res)
    }

    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        Ok(self
            .internal_storage
            .contains_key(&((*data_id, Some(*epoch_id)), data_type.to_string())))
    }

    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        let mut res = HashSet::new();
        for ((cur_data_id, cur_epoch_id), cur_data_type) in self.internal_storage.keys() {
            if cur_data_type == data_type && cur_epoch_id.as_ref() == Some(epoch_id) {
                res.insert(*cur_data_id);
            }
        }
        Ok(res)
    }

    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        all_data_ids_from_all_epochs_impl(self, data_type).await
    }

    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>> {
        let raw_data = match self
            .internal_storage
            .get(&((*data_id, Some(*epoch_id)), data_type.to_string()))
        {
            Some(raw_data) => raw_data,
            None => {
                return Err(anyhow!(
                    "Could not find data at ({}, {}, {})",
                    data_id,
                    epoch_id,
                    data_type
                ))
            }
        };
        Ok(raw_data.clone())
    }
}

impl Storage for RamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(());
        }
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        self.internal_storage
            .insert(((*data_id, None), data_type.to_string()), serialized);
        Ok(())
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(());
        }
        self.internal_storage
            .insert(((*data_id, None), data_type.to_string()), bytes.to_vec());
        Ok(())
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        match self
            .internal_storage
            .remove(&((*data_id, None), data_type.to_string()))
        {
            Some(_) => Ok(()),
            None => Err(anyhow_error_and_log("Could not delete data")),
        }
    }
}

impl StorageExt for RamStorage {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await?
        {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(());
        }
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        self.internal_storage.insert(
            ((*data_id, Some(*epoch_id)), data_type.to_string()),
            serialized,
        );
        println!(
            "Stored data at epoch: ({}, {}, {})",
            data_id, epoch_id, data_type
        );
        Ok(())
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await?
        {
            tracing::warn!(
                "The data {}-{} at epoch {} already exists. Keeping the data without overwriting",
                data_id,
                data_type,
                epoch_id
            );
            return Ok(());
        }
        self.internal_storage.insert(
            ((*data_id, Some(*epoch_id)), data_type.to_string()),
            bytes.to_vec(),
        );
        Ok(())
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        match self
            .internal_storage
            .remove(&((*data_id, Some(*epoch_id)), data_type.to_string()))
        {
            Some(_) => Ok(()),
            None => Err(anyhow_error_and_log("Could not delete data")),
        }
    }
}

/// This is a storage that fails after a predetermined number of writes.
///
/// It uses a [RamStorage] internally
/// and make it fail after a configurable number of operations.
#[cfg(test)]
pub struct FailingRamStorage {
    available_writes: usize,
    inner: RamStorage,
}

#[cfg(test)]
impl FailingRamStorage {
    pub fn new(writes_before_failure: usize) -> Self {
        Self {
            available_writes: writes_before_failure,
            inner: RamStorage::new(),
        }
    }

    pub fn set_available_writes(&mut self, available_writes: usize) {
        self.available_writes = available_writes
    }
}

#[cfg(test)]
impl StorageReader for FailingRamStorage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        self.inner.data_exists(data_id, data_type).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.inner.read_data(data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.inner.load_bytes(data_id, data_type).await
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids(data_type).await
    }

    fn info(&self) -> String {
        "FailingRamStorage".to_string()
    }
}

#[cfg(test)]
impl Storage for FailingRamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        if self.available_writes < 1 {
            anyhow::bail!("storage failed!")
        } else {
            self.available_writes -= 1;
            self.inner.store_data(data, data_id, data_type).await
        }
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        self.inner.store_bytes(bytes, data_id, data_type).await
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        self.inner.delete_data(data_id, data_type).await
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vault::storage::tests::*;

    #[tokio::test]
    async fn storage_helper_methods() {
        let mut storage = RamStorage::new();
        test_storage_read_store_methods(&mut storage).await;
        test_batch_helper_methods(&mut storage).await;
    }

    #[tokio::test]
    async fn test_all_data_ids_from_all_epochs_ram() {
        let mut storage = RamStorage::new();
        test_all_data_ids_from_all_epochs(&mut storage).await;
    }

    #[tokio::test]
    async fn test_store_load_bytes_at_epoch_ram() {
        let mut storage = RamStorage::new();
        test_store_load_bytes_at_epoch(&mut storage).await;
    }

    /// Test that files don't get silently overwritten
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_overwrite_logic_ram() {
        let mut storage = RamStorage::new();
        test_store_bytes_does_not_overwrite_existing_bytes(&mut storage).await;
        test_store_data_does_not_overwrite_existing_data(&mut storage).await;
        assert!(logs_contain(
            "already exists. Keeping the data without overwriting"
        ));
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_overwrite_logic_ram_on_epoch() {
        let mut storage = RamStorage::new();
        test_store_bytes_at_epoch_does_not_overwrite(&mut storage).await;
        assert!(logs_contain(
            "already exists. Keeping the data without overwriting"
        ));
    }
}
