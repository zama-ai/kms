use super::{Storage, StorageReader, StoreWriteOutcome};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::vault::storage::{StorageExt, all_data_ids_from_all_epochs_impl};
use crate::{anyhow_error_and_log, vault::storage::StorageReaderExt};
use anyhow::anyhow;
use kms_grpc::{RequestId, identifiers::EpochId};
use serde::{Serialize, de::DeserializeOwned};
use std::collections::{HashMap, HashSet};
use tfhe::{
    Unversionize, Versionize,
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
};

#[cfg(test)]
use super::test_support::{
    EntryFingerprint, StorageEntry, StorageFault, StorageMutation, StorageOp, StorageState,
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RamStorage {
    // Store data_id, data_type to serialized data
    #[expect(clippy::type_complexity)]
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
                    "Could not find data at (data_type: {}, data_id: {})",
                    data_type,
                    data_id
                ));
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
                ));
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
                    "Could not find data at (data_type: {}, data_id: {}, epoch_id: {})",
                    data_type,
                    data_id,
                    epoch_id
                ));
            }
        };
        let mut buf = std::io::Cursor::new(raw_data);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let mut res = HashSet::new();
        for ((_cur_data_id, cur_epoch_id), cur_data_type) in self.internal_storage.keys() {
            if let Some(epoch_id) = cur_epoch_id
                && cur_data_type == data_type
            {
                res.insert(*epoch_id);
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
        all_data_ids_from_all_epochs_impl(self, data_type)
            .await
            .map(|(ids, _)| ids)
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
                    "Could not find data at (data_type: {}, data_id: {}, epoch_id: {})",
                    data_id,
                    epoch_id,
                    data_type
                ));
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
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        // Record the persisted payload size, keyed by the element's type name (see `observe_size`).
        let size = serialized.len() as f64;
        self.internal_storage
            .insert(((*data_id, None), data_type.to_string()), serialized);
        observability::metrics::METRICS.observe_size(<T as Named>::NAME, size);
        Ok(StoreWriteOutcome::Created)
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The data {}-{} already exists. Keeping the data without overwriting",
                data_id,
                data_type
            );
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        self.internal_storage
            .insert(((*data_id, None), data_type.to_string()), bytes.to_vec());
        Ok(StoreWriteOutcome::Created)
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
    ) -> anyhow::Result<StoreWriteOutcome> {
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
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        // Record the persisted payload size, keyed by the element's type name (see `observe_size`).
        let size = serialized.len() as f64;
        self.internal_storage.insert(
            ((*data_id, Some(*epoch_id)), data_type.to_string()),
            serialized,
        );
        observability::metrics::METRICS.observe_size(<T as Named>::NAME, size);
        Ok(StoreWriteOutcome::Created)
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
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
            return Ok(StoreWriteOutcome::SkippedExisting);
        }
        self.internal_storage.insert(
            ((*data_id, Some(*epoch_id)), data_type.to_string()),
            bytes.to_vec(),
        );
        Ok(StoreWriteOutcome::Created)
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

/// Test-only [`RamStorage`] wrapper with entry-specific fault injection and side-effect recording.
///
/// Store and delete fail points name the exact storage entry to reject. Both can be active at the
/// same time and remain active until replaced or cleared. Successful mutations and failed
/// operations are recorded separately, and [`Self::state`] snapshots the stored entries. Reads
/// pass through to the wrapped storage and are not recorded.
#[cfg(test)]
pub struct FailingRamStorage {
    fail_store_at: Option<StorageEntry>,
    fail_delete_at: Option<StorageEntry>,
    mutations: Vec<StorageMutation>,
    faults: Vec<StorageFault>,
    inner: RamStorage,
}

#[cfg(test)]
impl FailingRamStorage {
    pub fn new() -> Self {
        Self {
            fail_store_at: None,
            fail_delete_at: None,
            mutations: Vec::new(),
            faults: Vec::new(),
            inner: RamStorage::new(),
        }
    }

    pub(crate) fn set_fail_store_at(&mut self, entry: StorageEntry) {
        self.fail_store_at = Some(entry);
    }

    pub(crate) fn set_fail_delete_at(&mut self, entry: StorageEntry) {
        self.fail_delete_at = Some(entry);
    }

    pub(crate) fn clear_fail_points(&mut self) {
        self.fail_store_at = None;
        self.fail_delete_at = None;
    }

    pub(crate) fn clear_events(&mut self) {
        self.mutations.clear();
        self.faults.clear();
    }

    pub(crate) fn mutations(&self) -> &[StorageMutation] {
        &self.mutations
    }

    pub(crate) fn faults(&self) -> &[StorageFault] {
        &self.faults
    }

    pub(crate) fn state(&self) -> StorageState {
        self.inner
            .internal_storage
            .iter()
            .map(|(((data_id, epoch_id), data_type), bytes)| {
                (
                    StorageEntry::new(*data_id, *epoch_id, data_type),
                    EntryFingerprint::from_bytes(bytes),
                )
            })
            .collect()
    }

    fn should_fail_store(&self, entry: &StorageEntry) -> bool {
        self.fail_store_at.as_ref() == Some(entry)
    }

    fn should_fail_delete(&self, entry: &StorageEntry) -> bool {
        self.fail_delete_at.as_ref() == Some(entry)
    }

    fn record_store_result(
        &mut self,
        entry: StorageEntry,
        result: anyhow::Result<StoreWriteOutcome>,
    ) -> anyhow::Result<StoreWriteOutcome> {
        match result {
            Ok(StoreWriteOutcome::Created) => {
                self.mutations
                    .push(StorageMutation::new(entry, StorageOp::Store));
                Ok(StoreWriteOutcome::Created)
            }
            Ok(StoreWriteOutcome::SkippedExisting) => Ok(StoreWriteOutcome::SkippedExisting),
            Err(error) => {
                self.record_fault(entry, StorageOp::Store);
                Err(error)
            }
        }
    }

    fn record_delete_result(
        &mut self,
        entry: StorageEntry,
        result: anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        match result {
            Ok(()) => {
                self.mutations
                    .push(StorageMutation::new(entry, StorageOp::Delete));
                Ok(())
            }
            Err(error) => {
                self.record_fault(entry, StorageOp::Delete);
                Err(error)
            }
        }
    }

    fn record_fault(&mut self, entry: StorageEntry, operation: StorageOp) {
        self.faults.push(StorageFault::new(entry, operation));
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
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.should_fail_store(&entry) {
            self.record_fault(entry, StorageOp::Store);
            anyhow::bail!("storage failed!")
        }
        let result = self.inner.store_data(data, data_id, data_type).await;
        self.record_store_result(entry, result)
    }

    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.should_fail_store(&entry) {
            self.record_fault(entry, StorageOp::Store);
            anyhow::bail!("storage failed!")
        }
        let result = self.inner.store_bytes(bytes, data_id, data_type).await;
        self.record_store_result(entry, result)
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let entry = StorageEntry::new(*data_id, None, data_type);
        if self.should_fail_delete(&entry) {
            self.record_fault(entry, StorageOp::Delete);
            anyhow::bail!("storage delete failed!")
        }
        let result = self.inner.delete_data(data_id, data_type).await;
        self.record_delete_result(entry, result)
    }
}

#[cfg(test)]
impl StorageReaderExt for FailingRamStorage {
    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        self.inner
            .read_data_at_epoch(data_id, epoch_id, data_type)
            .await
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        self.inner.all_epoch_ids_for_data(data_type).await
    }

    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        self.inner
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await
    }

    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids_at_epoch(epoch_id, data_type).await
    }

    async fn all_data_ids_from_all_epochs(
        &self,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        self.inner.all_data_ids_from_all_epochs(data_type).await
    }

    async fn load_bytes_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner
            .load_bytes_at_epoch(data_id, epoch_id, data_type)
            .await
    }
}

#[cfg(test)]
impl StorageExt for FailingRamStorage {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.should_fail_store(&entry) {
            self.record_fault(entry, StorageOp::Store);
            anyhow::bail!("storage failed!")
        }
        let result = self
            .inner
            .store_data_at_epoch(data, data_id, epoch_id, data_type)
            .await;
        self.record_store_result(entry, result)
    }

    async fn store_bytes_at_epoch(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<StoreWriteOutcome> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.should_fail_store(&entry) {
            self.record_fault(entry, StorageOp::Store);
            anyhow::bail!("storage failed!")
        }
        let result = self
            .inner
            .store_bytes_at_epoch(bytes, data_id, epoch_id, data_type)
            .await;
        self.record_store_result(entry, result)
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let entry = StorageEntry::new(*data_id, Some(*epoch_id), data_type);
        if self.should_fail_delete(&entry) {
            self.record_fault(entry, StorageOp::Delete);
            anyhow::bail!("storage delete failed!")
        }
        let result = self
            .inner
            .delete_data_at_epoch(data_id, epoch_id, data_type)
            .await;
        self.record_delete_result(entry, result)
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
    async fn test_store_data_records_payload_size_ram() {
        let mut storage = RamStorage::new();
        test_store_data_records_payload_size(&mut storage).await;
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
    #[tokio::test]
    async fn test_overwrite_logic_ram() {
        let mut storage = RamStorage::new();
        test_store_bytes_does_not_overwrite_existing_bytes(&mut storage).await;
        test_store_data_does_not_overwrite_existing_data(&mut storage).await;
    }

    #[tokio::test]
    async fn test_mixed_epoch_and_non_epoch_data_ram() {
        let mut storage = RamStorage::new();
        test_all_epoch_ids_and_data_ids_with_mixed_storage(&mut storage).await;
    }

    #[tokio::test]
    async fn test_epoch_ids_with_only_non_epoch_data_ram() {
        let mut storage = RamStorage::new();
        test_all_epoch_ids_for_data_with_only_non_epoch_data(&mut storage).await;
    }

    #[tokio::test]
    async fn test_data_ids_with_only_epoch_data_ram() {
        let mut storage = RamStorage::new();
        test_all_data_ids_with_only_epoch_data(&mut storage).await;
    }

    #[tokio::test]
    async fn test_overwrite_logic_ram_on_epoch() {
        let mut storage = RamStorage::new();
        test_store_bytes_at_epoch_does_not_overwrite(&mut storage).await;
    }
}
