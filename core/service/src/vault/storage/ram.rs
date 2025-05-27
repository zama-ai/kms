use super::{Storage, StorageForText, StorageReader, StorageType};
use crate::anyhow_error_and_log;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use anyhow::anyhow;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use tfhe::{
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
    Unversionize, Versionize,
};
use url::Url;

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
    pub fn new(storage_type: StorageType, writes_before_failure: usize) -> Self {
        Self {
            available_writes: writes_before_failure,
            inner: RamStorage::new(storage_type),
        }
    }

    pub fn set_available_writes(&mut self, available_writes: usize) {
        self.available_writes = available_writes
    }
}

#[cfg(test)]
#[tonic::async_trait]
impl StorageReader for FailingRamStorage {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        self.inner.data_exists(url).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        self.inner.read_data(url).await
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        self.inner.compute_url(data_id, data_type)
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        self.inner.all_urls(data_type).await
    }

    fn info(&self) -> String {
        "FailingRamStorage".to_string()
    }
}

#[cfg(test)]
#[tonic::async_trait]
impl StorageForText for FailingRamStorage {
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        self.inner.store_text(text, url).await
    }

    async fn read_text(&mut self, url: &Url) -> anyhow::Result<String> {
        self.inner.read_text(url).await
    }
}

#[cfg(test)]
#[tonic::async_trait]
impl Storage for FailingRamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        if self.available_writes < 1 {
            anyhow::bail!("storage failed!")
        } else {
            self.available_writes -= 1;
            self.inner.store_data(data, url).await
        }
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        self.inner.delete_data(url).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RamStorage {
    extra_prefix: String,
    // Store Url to data_id, data_type, serialized data
    internal_storage: HashMap<Url, (String, String, Vec<u8>)>,
}

impl RamStorage {
    // Aggregate with devstorage to make an object that loads from files but don't store
    pub fn new(storage_type: StorageType) -> Self {
        Self {
            extra_prefix: storage_type.to_string(),
            internal_storage: HashMap::new(),
        }
    }
}

#[tonic::async_trait]
impl StorageReader for RamStorage {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        Ok(self.internal_storage.contains_key(url))
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        let raw_data = match self.internal_storage.get(url) {
            Some((_data_id, _data_type, raw_data)) => raw_data,
            None => return Err(anyhow!("Could not decode data at url {}", url)),
        };
        let mut buf = std::io::Cursor::new(raw_data);
        safe_deserialize(&mut buf, SAFE_SER_SIZE_LIMIT).map_err(|e| anyhow::anyhow!(e))
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        if data_id.contains('/') || data_type.contains('/') {
            return Err(anyhow_error_and_log(
                "Could not store data, data_id or data_type contains '/'".to_string(),
            ));
        }

        Ok(Url::parse(
            format!("ram://{}/{}/{}", self.extra_prefix, data_type, data_id).as_str(),
        )?)
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        let mut res = HashMap::new();
        for key in self.internal_storage.keys() {
            let (cur_data_id, cur_data_type, _cur_raw_data) =
                self.internal_storage.get(key).unwrap();
            if cur_data_type == data_type {
                res.insert(cur_data_id.to_string(), key.clone());
            }
        }
        Ok(res)
    }

    fn info(&self) -> String {
        "memory storage".to_string()
    }
}

#[tonic::async_trait]
impl StorageForText for RamStorage {
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        let url_string = url.to_owned().to_string();
        let components: Vec<&str> = url_string.split('/').collect();
        let data_type = components
            .get(components.len() - 2)
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data id"))?
            .to_string();
        let data_id = components
            .last()
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data type"))?
            .to_string();
        let serialized = text.as_bytes().to_vec();
        self.internal_storage
            .insert(url.to_owned(), (data_id, data_type, serialized));
        Ok(())
    }

    async fn read_text(&mut self, url: &Url) -> anyhow::Result<String> {
        let raw_data = match self.internal_storage.get(url) {
            Some((_data_id, _data_type, raw_data)) => raw_data,
            None => return Err(anyhow!("Could not decode data at url {}", url)),
        };
        String::from_utf8(raw_data.clone())
            .map_err(|e| anyhow_error_and_log(e.utf8_error().to_string()))
    }
}

#[tonic::async_trait]
impl Storage for RamStorage {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let url_string = url.to_owned().to_string();
        let components: Vec<&str> = url_string.split('/').collect();
        let data_type = components
            .get(components.len() - 2)
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data id"))?
            .to_string();
        let data_id = components
            .last()
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data type"))?
            .to_string();
        let mut serialized = Vec::new();
        safe_serialize(data, &mut serialized, SAFE_SER_SIZE_LIMIT)?;
        self.internal_storage
            .insert(url.to_owned(), (data_id, data_type, serialized));
        Ok(())
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        match self.internal_storage.remove(url) {
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
        let mut storage = RamStorage::new(StorageType::PUB);
        test_storage_read_store_methods(&mut storage).await;
        test_batch_helper_methods(&mut storage).await;
    }

    #[ignore]
    #[tokio::test]
    async fn ram_storage_url() {
        let storage = RamStorage::new(StorageType::PUB);
        let url = storage.compute_url("id", "type").unwrap();
        assert_eq!(url, Url::parse("ram://PUB/type/id").unwrap());

        assert!(storage.compute_url("as/df", "type").is_err());
        assert!(storage.compute_url("id", "as/df").is_err());
    }
}
