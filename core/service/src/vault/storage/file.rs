use super::{Storage, StorageForBytes, StorageReader, StorageType};
use crate::consts::KEY_PATH_PREFIX;
use crate::util::file_handling::{
    safe_read_element_versioned, safe_write_element_versioned, write_bytes,
};
use crate::{anyhow_error_and_log, some_or_err};
use anyhow::anyhow;
use kms_grpc::RequestId;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashSet,
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
};
use tfhe::{named::Named, Unversionize, Versionize};
use threshold_fhe::execution::runtime::party::Role;

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
    /// {path}/{extra_pefix}
    /// {extra_prefix} is {storage_type} if [party_id] is None,
    /// otherwise it is set to {storage_type}-p{party_id}
    /// All missing paths are created during this process.
    pub fn new(
        path: Option<&Path>,
        storage_type: StorageType,
        party_role: Option<Role>,
    ) -> anyhow::Result<Self> {
        let extra_prefix = match party_role {
            Some(party_role) => format!("{storage_type}-p{party_role}"),
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

    /// Return the default path for the storage type.
    pub fn default_path(
        storage_type: StorageType,
        party_role: Option<Role>,
    ) -> anyhow::Result<PathBuf> {
        let extra_prefix = match party_role {
            Some(party_role) => format!("{storage_type}-p{party_role}"),
            None => storage_type.to_string(),
        };
        Ok(env::current_dir()?.join(KEY_PATH_PREFIX).join(extra_prefix))
    }

    // Check if a path already exists and create it if not.
    pub async fn setup_dirs(&self, url_path: &Path) -> anyhow::Result<()> {
        if url_path.try_exists().is_ok_and(|res| res) {
            // If the path exists, then trace a warning
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                url_path
                    .to_str()
                    .ok_or_else(|| anyhow!("Could not convert path to string"))?
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

    pub fn item_path(&self, data_id: &RequestId, data_type: &str) -> PathBuf {
        self.root_dir().join(data_type).join(data_id.to_string())
    }
}

impl StorageReader for FileStorage {
    async fn data_exists(&self, data_id: &RequestId, data_type: &str) -> anyhow::Result<bool> {
        let path = self.item_path(data_id, data_type);
        let res = path
            .as_path()
            .try_exists()
            .map_err(|_| anyhow_error_and_log(format!("Path {} does not exist", path.display())))?;
        Ok(res)
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
            .map_err(|e| anyhow!("Could not read directory due to error {}!", e))?;
        while let Some(cur_file) = files.next_entry().await? {
            let cur_path = cur_file.path();
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

    fn info(&self) -> String {
        format!(
            "file storage with root_path \'{}\'",
            self.root_dir().display()
        )
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::{engine::base::derive_request_id, vault::storage::tests::*};
    use kms_grpc::rpc_types::PubDataType;
    use strum::IntoEnumIterator;
    use threshold_fhe::execution::runtime::party::Role;

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
                Some(Role::indexed_from_one(1)),
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
                Some(Role::indexed_from_one(1)),
            )
            .unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PUB, None).unwrap()
        };
        let mut priv_storage = if threshold {
            FileStorage::new(
                Some(path),
                StorageType::PRIV,
                Some(Role::indexed_from_one(1)),
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
}
