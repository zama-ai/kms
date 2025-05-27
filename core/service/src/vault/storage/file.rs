use super::{Storage, StorageForText, StorageReader, StorageType};
use crate::consts::KEY_PATH_PREFIX;
use crate::util::file_handling::{
    safe_read_element_versioned, safe_write_element_versioned, write_text,
};
use crate::{anyhow_error_and_log, some_or_err};
use anyhow::anyhow;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf, MAIN_SEPARATOR},
};
use tfhe::{named::Named, Unversionize, Versionize};
use url::Url;

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
        party_id: Option<usize>,
    ) -> anyhow::Result<Self> {
        let extra_prefix = match party_id {
            Some(party_id) => format!("{storage_type}-p{party_id}"),
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
    async fn setup_dirs(&self, url_path: &Path) -> anyhow::Result<()> {
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
}

#[tonic::async_trait]
impl StorageReader for FileStorage {
    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        if data_id.contains(MAIN_SEPARATOR) || data_type.contains(MAIN_SEPARATOR) {
            return Err(anyhow_error_and_log(format!(
                "Could not store data, data_id or data_type contains {MAIN_SEPARATOR}",
            )));
        }
        let root_path = self.root_dir();
        let path = root_path.join(data_type).join(data_id);
        let url = Url::from_file_path(path)
            .map_err(|_e| anyhow_error_and_log("Could not turn path into URL"))?;
        Ok(url)
    }

    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        let res = url_to_pathbuf(url)
            .as_path()
            .try_exists()
            .map_err(|_| anyhow_error_and_log(format!("The url {} does not exist", url)))?;
        Ok(res)
    }

    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        let res: T = safe_read_element_versioned(
            url_to_pathbuf(url)
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert path to string"))?,
        )
        .await?;
        Ok(res)
    }

    /// Return all elements stored of a specific type as a hashmap of the `data_ptr` as key and the
    /// `url` as value.
    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        let root = self.root_dir();
        let path = root.join(data_type);
        if !path.try_exists()? {
            // If the path does not exist, then return an empty hashmap.
            tracing::info!(
                "The path {} does not exist, returning an empty map of URLs",
                path.display(),
            );
            return Ok(HashMap::new());
        }

        let mut res = HashMap::new();
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
            let url = Url::from_file_path(cur_path)
                .map_err(|_| anyhow!("Could not convert path to URL"))?;
            res.insert(data_ptr, url);
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

#[tonic::async_trait]
impl StorageForText for FileStorage {
    /// Store text with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        let url_path = url_to_pathbuf(url);

        self.setup_dirs(&url_path).await?;

        write_text(
            url_path
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert path to string"))?,
            text,
        )
        .await
        .map_err(|e| {
            tracing::warn!("Could not write to URL {}: {}", url, e);
            e
        })?;
        Ok(())
    }

    async fn read_text(&mut self, url: &Url) -> anyhow::Result<String> {
        let url_path = url_to_pathbuf(url);
        tokio::fs::read_to_string(
            url_path
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert path to string"))?,
        )
        .await
        .map_err(|e| anyhow_error_and_log(format!("Could not read from URL {}: {}", url, e)))
    }
}

#[tonic::async_trait]
impl Storage for FileStorage {
    /// Store data with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let url_path = url_to_pathbuf(url);

        self.setup_dirs(&url_path).await?;

        safe_write_element_versioned(
            url_path
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert path to string"))?,
            data,
        )
        .await
        .map_err(|e| {
            tracing::warn!("Could not write to URL {}: {}", url, e);
            e
        })?;
        Ok(())
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        let url_path = url_to_pathbuf(url);
        Ok(tokio::fs::remove_file(
            url_path
                .to_str()
                .ok_or_else(|| anyhow!("Could not convert path to string"))?,
        )
        .await?)
    }
}

/// Converts a file:// URL into a PathBuf. Doesn't check the URL scheme though,
/// if it's not file://, it won't make a lot of sense to use this
/// function. Unlike Url::to_file_path, it accepts relative paths.
pub fn url_to_pathbuf(url: &Url) -> PathBuf {
    PathBuf::from(format!("{}{}", url.host_str().map_or("", |x| { x }), url.path()).as_str())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::vault::storage::tests::*;
    use kms_grpc::rpc_types::PubDataType;
    use strum::IntoEnumIterator;

    #[ignore]
    #[tokio::test]
    async fn threshold_dev_storage() {
        let path1 = tempfile::tempdir().unwrap();
        let path2 = tempfile::tempdir().unwrap();
        let path1_str = path1.path().to_str().unwrap().to_string();
        let mut storage1 = FileStorage { path: path1.keep() };
        assert_eq!(
            Url::parse(&format!("file://{}/type/id", path1_str)).unwrap(),
            storage1.compute_url("id", "type").unwrap()
        );
        let storage2 = FileStorage { path: path2.keep() };

        // clear out storage
        let _ = fs::remove_dir_all(storage1.root_dir());
        let _ = fs::remove_dir_all(storage2.root_dir());

        // urls should be empty
        for data_type in PubDataType::iter() {
            assert!(storage1
                .all_urls(&data_type.to_string())
                .await
                .unwrap()
                .is_empty());
            assert!(storage2
                .all_urls(&data_type.to_string())
                .await
                .unwrap()
                .is_empty());
        }

        let data = TestType { i: 13 };
        let url = storage1
            .compute_url("ID", &PubDataType::CRS.to_string())
            .unwrap();

        // make sure we can put it in storage1
        assert!(storage1.store_data(&data, &url).await.is_ok());
        assert!(storage1.data_exists(&url).await.unwrap());
        let wrong = Url::from_file_path(format!(
            "{MAIN_SEPARATOR}some{MAIN_SEPARATOR}wrong{MAIN_SEPARATOR}path{MAIN_SEPARATOR}file.txt"
        ))
        .unwrap();
        assert!(!storage1.data_exists(&wrong).await.unwrap());

        let url2 = storage2
            .compute_url("ID", &PubDataType::CRS.to_string())
            .unwrap();
        // check that URLs are different on storage1 and storage2
        assert!(url != url2);
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
            FileStorage::new(Some(path), StorageType::PUB, Some(1)).unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PUB, None).unwrap()
        };

        let data = TestType { i: 23 };
        let data_id = "ID";
        let url = storage
            .compute_url(data_id, &PubDataType::CRS.to_string())
            .unwrap();
        storage.store_data(&data, &url).await.unwrap();

        // manually check that the file actually exists
        let data_path = if threshold {
            path.join(format!("{}-p1", StorageType::PUB))
                .join(PubDataType::CRS.to_string())
                .join(data_id)
        } else {
            path.join(StorageType::PUB.to_string())
                .join(PubDataType::CRS.to_string())
                .join(data_id)
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
            FileStorage::new(Some(path), StorageType::PUB, Some(1)).unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PUB, None).unwrap()
        };
        let mut priv_storage = if threshold {
            FileStorage::new(Some(path), StorageType::PRIV, Some(1)).unwrap()
        } else {
            FileStorage::new(Some(path), StorageType::PRIV, None).unwrap()
        };
        test_storage_read_store_methods(&mut pub_storage).await;
        test_storage_read_store_methods(&mut priv_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut priv_storage).await;
    }
}
