use super::{Storage, StorageForBytes, StorageReader};
use crate::anyhow_error_and_log;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use anyhow::anyhow;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{HashMap, HashSet};
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};

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

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids(data_type).await
    }

    fn info(&self) -> String {
        "FailingRamStorage".to_string()
    }
}

#[cfg(test)]
impl StorageForBytes for FailingRamStorage {
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        self.inner.store_bytes(bytes, data_id, data_type).await
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        self.inner.load_bytes(data_id, data_type).await
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

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        self.inner.delete_data(data_id, data_type).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RamStorage {
    // Store data_id, data_type to serialized data
    internal_storage: HashMap<(RequestId, String), Vec<u8>>,
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
            .contains_key(&(*data_id, data_type.to_string())))
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let raw_data = match self
            .internal_storage
            .get(&(*data_id, data_type.to_string()))
        {
            Some(raw_data) => raw_data,
            None => {
                return Err(anyhow!(
                    "Could not decode data at ({}, {})",
                    data_type,
                    data_id
                ))
            }
        };
        let mut buf = std::io::Cursor::new(raw_data);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }

    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let mut res = HashSet::new();
        for (cur_data_id, cur_data_type) in self.internal_storage.keys() {
            if cur_data_type == data_type {
                res.insert(*cur_data_id);
            }
        }
        Ok(res)
    }

    fn info(&self) -> String {
        "memory storage".to_string()
    }
}

impl StorageForBytes for RamStorage {
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        self.internal_storage
            .insert((*data_id, data_type.to_string()), bytes.to_vec());
        Ok(())
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let raw_data = match self
            .internal_storage
            .get(&(*data_id, data_type.to_string()))
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
}

impl Storage for RamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        self.internal_storage
            .insert((*data_id, data_type.to_string()), serialized);
        Ok(())
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        match self
            .internal_storage
            .remove(&(*data_id, data_type.to_string()))
        {
            Some(_) => Ok(()),
            None => Err(anyhow_error_and_log("Could not delete data")),
        }
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
}
