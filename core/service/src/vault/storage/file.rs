use super::{Storage, StorageForBytes, StorageReader, StorageType};
use crate::consts::KEY_PATH_PREFIX;
use crate::util::file_handling::{
    safe_read_element_versioned, safe_write_element_versioned, write_bytes,
};
use crate::vault::storage::{StorageExt, StorageReaderExt};
use crate::vault::storage_prefix_safety;
use crate::{anyhow_error_and_log, some_or_err};
use kms_grpc::identifiers::EpochId;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use tfhe::{named::Named, Unversionize, Versionize};

#[derive(Default, Clone, Debug)]
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    /// current_dir/keys/extra_prefix
    pub fn root_dir(&self) -> &Path {
        self.path.as_path()
    }

    /// Create a new storage directory.
    ///
    /// If [path] is None, set the storage directory to be
    /// {current_dir}/keys/{extra_prefix}
    /// Otherwise, set the storage directory to be
    /// {path}/{extra_prefix}
    /// {extra_prefix} is {storage_prefix} if it is Some,
    /// otherwise it is set to {storage_type}.
    /// All missing paths are created during this process.
    pub fn new(
        path: Option<&Path>,
        storage_type: StorageType,
        storage_prefix: Option<&str>,
    ) -> anyhow::Result<Self> {
        let extra_prefix = match storage_prefix {
            Some(prefix) => {
                storage_prefix_safety(storage_type, prefix)?;
                prefix.to_string()
            }
            None => storage_type.to_string(),
        };
        let path = match path {
            Some(path) => path.join(extra_prefix),
            None => env::current_dir()?.join(KEY_PATH_PREFIX).join(extra_prefix),
        };
        fs::create_dir_all(&path)?;
        Ok(Self {
            path: path.canonicalize()?,
        })
    }

    // Check if a path already exists and create it if not.
    pub async fn setup_dirs(&self, url_path: &Path) -> anyhow::Result<()> {
        if url_path.try_exists().is_ok_and(|res| res) {
            // If the path exists, then trace a warning
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                url_path
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("Could not convert path to string"))?
            );
            return Ok(());
        }
        // Create the directory
        tokio::fs::create_dir_all(self.root_dir())
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Could not create directory {}: {}",
                    self.root_dir().display(),
                    e
                );
                e
            })?;

        Ok(())
    }

    fn item_path(&self, data_id: &RequestId, data_type: &str) -> PathBuf {
        self.root_dir().join(data_type).join(data_id.to_string())
    }

    fn item_path_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> PathBuf {
        self.root_dir()
            .join(data_type)
            .join(epoch_id.to_string())
            .join(data_id.to_string())
    }

    async fn item_exists_at_path(&self, path: &Path) -> anyhow::Result<bool> {
        tokio::fs::try_exists(path)
            .await
            .map_err(|_| anyhow_error_and_log(format!("Path {} does not exist", path.display())))
    }

    async fn all_data_from_path(
        &self,
        path: &Path,
        ensure_file: bool,
    ) -> anyhow::Result<HashSet<RequestId>> {
        if !path.try_exists()? {
            // If the path does not exist, then return an empty hashmap.
            tracing::info!(
                "The path {} does not exist, returning an empty map of URLs",
                path.display(),
            );
            return Ok(HashSet::new());
        }

        let mut res = HashSet::new();
        let mut files = tokio::fs::read_dir(path)
            .await
            .map_err(|e| anyhow::anyhow!("Could not read directory due to error {}!", e))?;
        while let Some(cur_file) = files.next_entry().await? {
            let cur_path = cur_file.path();

            // if ensure_file is true, only consider files, else only consider directories
            if (ensure_file && !cur_path.is_file()) || !ensure_file && !cur_path.is_dir() {
                continue;
            }

            let data_ptr = some_or_err(
                some_or_err(
                    cur_path.file_name(),
                    "Could not convert path to OsStr".to_string(),
                )?
                .to_str(),
                "Could not convert OsStr to string".to_string(),
            )?
            .to_string();
            if data_ptr.starts_with('.') {
                // Ignore hidden files
                continue;
            }
            res.insert(RequestId::from_str(&data_ptr)?);
        }
        Ok(res)
    }
}

impl StorageReader for FileStorage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let path = self.item_path(data_id, data_type);
        self.item_exists_at_path(path.as_path()).await
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let path = self.item_path(data_id, data_type);
        let res: T = safe_read_element_versioned(&path).await?;
        Ok(res)
    }

    /// Return all elements stored of a specific type as a hashmap of the `data_ptr` as key and the
    /// `url` as value.
    async fn all_data_ids(&self, data_type: &str) -> anyhow::Result<HashSet<RequestId>> {
        let path = self.root_dir().join(data_type);
        self.all_data_from_path(path.as_path(), true).await
    }

    fn info(&self) -> String {
        format!(
            "file storage with root_path \'{}\'",
            self.root_dir().display()
        )
    }
}

impl StorageReaderExt for FileStorage {
    async fn data_exists_at_epoch(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<bool> {
        let path = self.item_path_at_epoch(data_id, epoch_id, data_type);
        self.item_exists_at_path(path.as_path()).await
    }

    async fn read_data_at_epoch<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<T> {
        let path = self.item_path_at_epoch(data_id, epoch_id, data_type);
        let res: T = safe_read_element_versioned(&path).await?;
        Ok(res)
    }

    async fn all_data_ids_at_epoch(
        &self,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<HashSet<RequestId>> {
        let path = self.root_dir().join(data_type).join(epoch_id.to_string());
        self.all_data_from_path(path.as_path(), true).await
    }

    async fn all_epoch_ids_for_data(&self, data_type: &str) -> anyhow::Result<HashSet<EpochId>> {
        let path = self.root_dir().join(data_type);
        Ok(self
            .all_data_from_path(path.as_path(), false)
            .await?
            .into_iter()
            .map(|inner| inner.into())
            .collect())
    }
}

impl StorageForBytes for FileStorage {
    /// Store bytes with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_bytes(
        &mut self,
        bytes: &[u8],
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let path = self.item_path(data_id, data_type);
        self.setup_dirs(&path).await?;
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                path.display()
            );
            return Ok(());
        }
        write_bytes(path.as_path(), bytes).await.map_err(|e| {
            tracing::warn!("Could not write to path {}: {}", path.display(), e);
            e
        })?;
        Ok(())
    }

    async fn load_bytes(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.item_path(data_id, data_type);
        tokio::fs::read(&path).await.map_err(|e| {
            anyhow_error_and_log(format!(
                "Could not read from path {}: {}",
                path.display(),
                e
            ))
        })
    }
}

impl Storage for FileStorage {
    /// Store data with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let path = self.item_path(data_id, data_type);
        self.setup_dirs(&path).await?;
        if self.data_exists(data_id, data_type).await? {
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                path.display()
            );
            return Ok(());
        }
        safe_write_element_versioned(&path, data)
            .await
            .map_err(|e| {
                tracing::warn!("Could not write to path {}: {}", path.display(), e);
                e
            })?;
        Ok(())
    }

    async fn delete_data(&mut self, data_id: &RequestId, data_type: &str) -> anyhow::Result<()> {
        let path = self.item_path(data_id, data_type);
        Ok(tokio::fs::remove_file(&path).await?)
    }
}

impl StorageExt for FileStorage {
    async fn store_data_at_epoch<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let path = self.item_path_at_epoch(data_id, epoch_id, data_type);
        self.setup_dirs(&path).await?;
        if self
            .data_exists_at_epoch(data_id, epoch_id, data_type)
            .await?
        {
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                path.display()
            );
            return Ok(());
        }
        println!(
            "storing data {} at epoch {:?} at path {}",
            data_type,
            epoch_id,
            path.display()
        );
        safe_write_element_versioned(&path, data)
            .await
            .map_err(|e| {
                tracing::warn!("Could not write to path {}: {}", path.display(), e);
                e
            })?;
        Ok(())
    }

    async fn delete_data_at_epoch(
        &mut self,
        data_id: &RequestId,
        epoch_id: &EpochId,
        data_type: &str,
    ) -> anyhow::Result<()> {
        let path = self.item_path_at_epoch(data_id, epoch_id, data_type);
        tokio::fs::remove_file(&path).await?;

        // Remove the epoch directory if it's now empty
        if let Some(epoch_dir) = path.parent() {
            if let Ok(mut entries) = tokio::fs::read_dir(epoch_dir).await {
                if entries.next_entry().await?.is_none() {
                    let _ = tokio::fs::remove_dir(epoch_dir).await;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{
        consts::PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL, engine::base::derive_request_id,
        vault::storage::tests::*,
    };
    use kms_grpc::rpc_types::PubDataType;
    use strum::IntoEnumIterator;

    #[ignore]
    #[tokio::test]
    async fn threshold_dev_storage() {
        let path1 = tempfile::tempdir().unwrap();
        let path2 = tempfile::tempdir().unwrap();
        let mut storage1 = FileStorage { path: path1.keep() };
        let storage2 = FileStorage { path: path2.keep() };

        // clear out storage
        let _ = fs::remove_dir_all(storage1.root_dir());
        let _ = fs::remove_dir_all(storage2.root_dir());

        // urls should be empty
        for data_type in PubDataType::iter() {
            assert!(storage1
                .all_data_ids(&data_type.to_string())
                .await
                .unwrap()
                .is_empty());
            assert!(storage2
                .all_data_ids(&data_type.to_string())
                .await
                .unwrap()
                .is_empty());
        }

        let data = TestType { i: 13 };
        let id = derive_request_id("ID").unwrap();
        let wrong_id = derive_request_id("WRONG_ID").unwrap();
        // make sure we can put it in storage1
        assert!(storage1
            .store_data(&data, &id, &PubDataType::CRS.to_string())
            .await
            .is_ok());
        assert!(storage1
            .data_exists(&id, &PubDataType::CRS.to_string())
            .await
            .unwrap());
        assert!(!storage1
            .data_exists(&wrong_id, &PubDataType::CRS.to_string())
            .await
            .unwrap());
    }

    #[ignore]
    #[tokio::test]
    async fn threshold_file_storage_with_path() {
        file_storage_with_path(true).await
    }

    #[ignore]
    #[tokio::test]
    async fn centralized_file_storage_with_path() {
        file_storage_with_path(false).await
    }

    async fn file_storage_with_path(threshold: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = if threshold {
            FileStorage::new(
                Some(path),
                StorageType::PUB,
                PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
            )
            .unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PUB, None).unwrap()
        };

        let data = TestType { i: 23 };
        let data_id = derive_request_id("ID").unwrap();
        storage
            .store_data(&data, &data_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();

        // manually check that the file actually exists
        let data_path = if threshold {
            path.join(format!("{}-p1", StorageType::PUB))
                .join(PubDataType::CRS.to_string())
                .join(data_id.to_string())
        } else {
            path.join(StorageType::PUB.to_string())
                .join(PubDataType::CRS.to_string())
                .join(data_id.to_string())
        };
        assert!(data_path.exists());

        // drop the tempdir and it should disappear
        drop(temp_dir);
        assert!(!data_path.exists());
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn storage_helper_methods(#[values(true, false)] threshold: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut pub_storage = if threshold {
            FileStorage::new(
                Some(path),
                StorageType::PUB,
                PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
            )
            .unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PUB, None).unwrap()
        };
        let mut priv_storage = if threshold {
            FileStorage::new(
                Some(path),
                StorageType::PRIV,
                crate::consts::PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
            )
            .unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PRIV, None).unwrap()
        };
        test_storage_read_store_methods(&mut pub_storage).await;
        test_storage_read_store_methods(&mut priv_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut priv_storage).await;
    }

    /// Test that files don't get silently overwritten
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_overwrite_logic_files() {
        // Setup temporary directory and storage
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = FileStorage::new(Some(path), StorageType::PUB, None).unwrap();
        test_store_bytes_does_not_overwrite_existing_bytes(&mut storage).await;
        test_store_data_does_not_overwrite_existing_data(&mut storage).await;
        assert!(logs_contain(
            "already exists. Keeping the data without overwriting"
        ));
    }

    #[tokio::test]
    async fn test_epoch_storage() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = FileStorage::new(Some(path), StorageType::PRIV, None).unwrap();
        test_epoch_methods(&mut storage).await;
    }

    #[tokio::test]
    async fn test_delete_at_epoch_removes_empty_epoch_dir() {
        use aes_prng::AesRng;
        use kms_grpc::rpc_types::PrivDataType;
        use rand::SeedableRng;

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = FileStorage::new(Some(path), StorageType::PRIV, None).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        let epoch_id = kms_grpc::identifiers::EpochId::new_random(&mut rng);
        let data_id = derive_request_id("TEST_DATA").unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let data = TestType { i: 99 };

        // Store data at epoch
        storage
            .store_data_at_epoch(&data, &data_id, &epoch_id, &data_type)
            .await
            .unwrap();

        // Verify the epoch directory exists
        let epoch_dir = storage
            .root_dir()
            .join(&data_type)
            .join(epoch_id.to_string());
        assert!(
            epoch_dir.exists(),
            "Epoch directory should exist after storing data"
        );

        // Delete the data
        storage
            .delete_data_at_epoch(&data_id, &epoch_id, &data_type)
            .await
            .unwrap();

        // Verify the epoch directory is removed since it's now empty
        assert!(
            !epoch_dir.exists(),
            "Epoch directory should be removed after deleting the last file"
        );
    }

    #[tokio::test]
    async fn test_delete_at_epoch_keeps_dir_when_not_empty() {
        use aes_prng::AesRng;
        use kms_grpc::rpc_types::PrivDataType;
        use rand::SeedableRng;

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = FileStorage::new(Some(path), StorageType::PRIV, None).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        let epoch_id = kms_grpc::identifiers::EpochId::new_random(&mut rng);
        let data_id_1 = derive_request_id("TEST_DATA_1").unwrap();
        let data_id_2 = derive_request_id("TEST_DATA_2").unwrap();
        let data_type = PrivDataType::FheKeyInfo.to_string();

        let data1 = TestType { i: 1 };
        let data2 = TestType { i: 2 };

        // Store two items at the same epoch
        storage
            .store_data_at_epoch(&data1, &data_id_1, &epoch_id, &data_type)
            .await
            .unwrap();
        storage
            .store_data_at_epoch(&data2, &data_id_2, &epoch_id, &data_type)
            .await
            .unwrap();

        let epoch_dir = storage
            .root_dir()
            .join(&data_type)
            .join(epoch_id.to_string());
        assert!(epoch_dir.exists(), "Epoch directory should exist");

        // Delete only the first item
        storage
            .delete_data_at_epoch(&data_id_1, &epoch_id, &data_type)
            .await
            .unwrap();

        // Epoch directory should still exist because data_id_2 is still there
        assert!(
            epoch_dir.exists(),
            "Epoch directory should still exist when other files remain"
        );

        // Verify data_id_2 still exists and is readable
        let retrieved: TestType = storage
            .read_data_at_epoch(&data_id_2, &epoch_id, &data_type)
            .await
            .unwrap();
        assert_eq!(retrieved.i, 2);

        // Now delete the second item
        storage
            .delete_data_at_epoch(&data_id_2, &epoch_id, &data_type)
            .await
            .unwrap();

        // Now the epoch directory should be removed
        assert!(
            !epoch_dir.exists(),
            "Epoch directory should be removed after deleting the last file"
        );
    }
}
