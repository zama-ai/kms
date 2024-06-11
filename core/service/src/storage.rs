use crate::consts::KEY_PATH_PREFIX;
use crate::cryptography::central_kms::{compute_handle, SoftwareKmsKeys};
use crate::kms::RequestId;
use crate::rpc::rpc_types::PrivDataType;
use crate::util::file_handling::{read_element, write_element};
use crate::{anyhow_error_and_log, some_or_err};
use anyhow::anyhow;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{self};
use std::path::{Path, PathBuf};
use std::{env, fs, path::MAIN_SEPARATOR};
use strum::EnumIter;
use url::Url;

// TODO add a wrapper struct for both public and private storage.

/// Trait for public KMS storage reading
#[tonic::async_trait]
pub trait PublicStorageReader {
    /// Validate if data exists at a given `url`.
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool>;

    /// Read some data from a given `url`.
    async fn read_data<Ser: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<Ser>;

    /// Compute an URL for some specific data given its `data_id` and of a given `data_type`.
    /// Depending on how the underlying functionality is realized one of these parameters might not
    /// be used.
    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url>; // TODO should be based on StorageType as generic

    /// Return all URLs stored of a specific data type
    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>>;

    /// Output some information on the storage instance.
    fn info(&self) -> String;
}

// Trait for KMS public storage reading and writing
// TODO rename away from public
#[tonic::async_trait]
pub trait PublicStorage: PublicStorageReader {
    async fn store_data<Ser: Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &Ser,
        url: &Url,
    ) -> anyhow::Result<()>;
    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()>;
}

// Helper method for storing data based on a data type and request ID.
// An error will be returned if the data already exists.
pub async fn store_at_request_id<S: PublicStorage, Ser: Serialize + Send + Sync + ?Sized>(
    storage: &mut S,
    request_id: &RequestId,
    data: &Ser,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.store_data(data, &url).await.map_err(|_| {
        anyhow_error_and_log(format!(
            "Could not store data with ID {} and type {}!",
            request_id, data_type,
        ))
    })
}

// Helper method to remove data based on a data type and request ID.
pub async fn delete_at_request_id<S: PublicStorage>(
    storage: &mut S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.delete_data(&url).await.map_err(|_| {
        anyhow_error_and_log(format!(
            "Could not delete data with ID {} and type {}!",
            request_id, data_type,
        ))
    })
}

/// Helper method for reading data based on a data type and request ID.
pub async fn read_request_id<S: PublicStorage, Ser: DeserializeOwned + Send>(
    storage: &S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<Ser> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.read_data(&url).await
}

/// Helper method for reading all data of a specific type.
pub async fn read_all_data<S: PublicStorageReader, Ser: DeserializeOwned + Serialize + Send>(
    storage: &S,
    data_type: &str,
) -> anyhow::Result<HashMap<RequestId, Ser>> {
    let url_map = storage.all_urls(data_type).await?;
    let mut res = HashMap::with_capacity(url_map.len());
    for (data_ptr, url) in url_map.iter() {
        let data: Ser = storage
            .read_data(url)
            .await
            .map_err(|e| anyhow!("reading failed on url {url} with error {e}"))?;
        let req_id: RequestId = data_ptr.to_owned().try_into()?;
        if !req_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "Request ID {} is not valid",
                data_ptr
            )));
        }
        res.insert(req_id, data);
    }
    Ok(res)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, EnumIter)]
pub enum StorageType {
    PUB,
    PRIV,
    CLIENT,
}
impl fmt::Display for StorageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Default, Clone)]
pub struct FileStorage {
    path: PathBuf,
}

impl FileStorage {
    /// current_dir/keys/extra_prefix
    pub fn root_dir(&self) -> &Path {
        self.path.as_path()
    }

    fn default_path_with_prefix(extra_prefix: &str) -> anyhow::Result<PathBuf> {
        let cur = env::current_dir()?;
        let path = cur.join(KEY_PATH_PREFIX).join(extra_prefix);
        // ensure the directory exists
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    /// Create a new directory for centralized storage.
    ///
    /// If [optional_path] is None, set the storage directory to be
    /// {current_dir}/keys/{storage_type}
    /// Otherwise, set the storage directory to be
    /// {path}/{storage_type}
    /// All missing paths are created during this process.
    pub fn new_centralized(
        optional_path: Option<&Path>,
        storage_type: StorageType,
    ) -> anyhow::Result<Self> {
        let path = match optional_path {
            Some(path) => {
                let path = path.join(storage_type.to_string());
                fs::create_dir_all(&path)?;
                path.canonicalize()?
            }
            None => Self::default_path_with_prefix(&storage_type.to_string())?,
        };
        Ok(Self { path })
    }

    /// Create a new directory for threshold storage.
    ///
    /// If [optional_path] is None, set the storage directory to be
    /// {current_dir}/keys/{storage_type}-p{party_id}
    /// Otherwise, set the storage directory to be
    /// {path}/{storage_type}-p{party_id}
    /// All missing paths are created during this process.
    pub fn new_threshold(
        optional_path: Option<&Path>,
        storage_type: StorageType,
        party_id: usize,
    ) -> anyhow::Result<Self> {
        let path = match optional_path {
            Some(path) => {
                let path = path.join(format!("{storage_type}-p{party_id}"));
                fs::create_dir_all(&path)?;
                path.canonicalize()?
            }
            None => Self::default_path_with_prefix(&format!("{storage_type}-p{party_id}"))?,
        };
        Ok(Self { path })
    }

    /// Delete everything stored in the file storage system at the given path for a centralized system's storage.
    pub fn purge_centralized(
        optional_path: Option<&Path>,
        storage_type: StorageType,
    ) -> anyhow::Result<()> {
        match optional_path {
            Some(path) => {
                let path = path.join(storage_type.to_string());
                fs::create_dir_all(path)?;
            }
            None => {
                let default_path = Self::default_path_with_prefix(&storage_type.to_string())?;
                fs::remove_dir_all(default_path)?;
            }
        }
        Ok(())
    }

    /// Delete everything stored in the file storage system at the given path for a threshold system's storage.
    pub fn purge_threshold(
        optional_path: Option<&Path>,
        storage_type: StorageType,
        party_id: usize,
    ) -> anyhow::Result<()> {
        match optional_path {
            Some(path) => {
                let path = path.join(format!("{storage_type}-p{party_id}"));
                fs::remove_dir_all(path)?;
            }
            None => {
                let default_path =
                    Self::default_path_with_prefix(&format!("{storage_type}-p{party_id}"))?;
                fs::remove_dir_all(default_path)?;
            }
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl PublicStorageReader for FileStorage {
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
        let res = Path::new(&url.path())
            .try_exists()
            .map_err(|_| anyhow_error_and_log(format!("The url {} does not exist", url)))?;
        Ok(res)
    }

    async fn read_data<T: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<T> {
        let res: T = read_element(url.path()).await?;
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
impl PublicStorage for FileStorage {
    /// Store data with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_data<T: Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let url_path = Path::new(url.path());
        if url_path.try_exists().is_ok_and(|res| res) {
            // If the path exists, then trace a warning
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                url.path()
            );
            return Ok(());
        }
        tokio::fs::create_dir_all(self.root_dir())
            .await
            .map_err(|e| {
                tracing::warn!(
                    "Could not create directory {}, error {}",
                    self.root_dir().display(),
                    e
                );
                e
            })?;
        write_element(url.path(), &data).await.map_err(|e| {
            tracing::warn!("Could not write to URL {}, error {}", url, e);
            e
        })?;
        Ok(())
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        let url_path = Path::new(url.path());
        Ok(tokio::fs::remove_file(url_path).await?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RamStorage {
    extra_prefix: String,
    // Store Url to data_id, data_type, serialized data
    internal_storage: HashMap<Url, (String, String, Vec<u8>)>,
}

impl RamStorage {
    // Aggregate with devstorage to make an objevt that loads from files but don't store
    pub fn new(storage_type: StorageType) -> Self {
        Self {
            extra_prefix: storage_type.to_string(),
            internal_storage: HashMap::new(),
        }
    }

    // Construct a storage for private keys
    pub async fn from_existing_keys(keys: &SoftwareKmsKeys) -> anyhow::Result<Self> {
        let mut res = Self::new(StorageType::PRIV);
        for (cur_req_id, cur_keys) in &keys.key_info {
            store_at_request_id(
                &mut res,
                cur_req_id,
                &cur_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await?;
        }
        let sk_handle = compute_handle(&keys.sig_sk)?;
        res.store_data(
            &keys.sig_sk,
            &res.compute_url(&sk_handle, &PrivDataType::SigningKey.to_string())?,
        )
        .await?;
        Ok(res)
    }
}

#[tonic::async_trait]
impl PublicStorageReader for RamStorage {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        Ok(self.internal_storage.contains_key(url))
    }

    async fn read_data<Ser: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<Ser> {
        let raw_data = match self.internal_storage.get(url) {
            Some((_data_id, _data_type, raw_data)) => raw_data,
            None => return Err(anyhow!("Could not decode data at url {}", url)),
        };
        let res: Ser = bincode::deserialize(raw_data)?;
        Ok(res)
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        let url_string = format!(
            "{MAIN_SEPARATOR}{}{MAIN_SEPARATOR}{}{MAIN_SEPARATOR}{}",
            self.extra_prefix, data_id, data_type
        );
        if data_id.contains(MAIN_SEPARATOR) || data_type.contains(MAIN_SEPARATOR) {
            return Err(anyhow_error_and_log(format!(
                "Could not store data, data_id or data_type contains {MAIN_SEPARATOR}",
            )));
        }
        let url = Url::from_file_path(url_string)
            .map_err(|_e| anyhow_error_and_log("Could not turn path into URL"))?;
        Ok(url)
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
impl PublicStorage for RamStorage {
    async fn store_data<T: serde::Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        let url_string = url.to_owned().to_string();
        let components: Vec<&str> = url_string.split(MAIN_SEPARATOR).collect();
        let data_id = components
            .get(components.len() - 2)
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data id"))?
            .to_string();
        let data_type = components
            .last()
            .ok_or_else(|| anyhow_error_and_log("URL does not contain data type"))?
            .to_string();
        let serialized = bincode::serialize(&data)?;
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

#[allow(dead_code)]
pub enum StorageVersion {
    Dev,
    Ram,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::rpc_types::PubDataType;

    #[tokio::test]
    async fn threshold_dev_storage() {
        let path1 = tempfile::tempdir().unwrap();
        let path2 = tempfile::tempdir().unwrap();
        let mut storage1 = FileStorage {
            path: path1.into_path(),
        };
        let storage2 = FileStorage {
            path: path2.into_path(),
        };

        // clear out storage
        let _ = fs::remove_dir_all(storage1.root_dir());
        let _ = fs::remove_dir_all(storage2.root_dir());

        // urls should be empty
        for data_type in [
            PubDataType::PublicKey,
            PubDataType::ServerKey,
            PubDataType::SnsKey,
            PubDataType::CRS,
            PubDataType::VerfKey,
        ] {
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

        let data = "data";
        let url = storage1
            .compute_url("ID", &PubDataType::CRS.to_string())
            .unwrap();

        // make sure we can put it in storage1
        assert!(storage1.store_data(data, &url).await.is_ok());
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

    async fn file_storage_with_path(threshold: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = if threshold {
            FileStorage::new_threshold(Some(path), StorageType::PUB, 1).unwrap()
        } else {
            FileStorage::new_centralized(Some(path), StorageType::PUB).unwrap()
        };

        let data = vec![1, 2, 3];
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

    #[tokio::test]
    async fn threshold_file_storage_with_path() {
        file_storage_with_path(true).await
    }

    #[tokio::test]
    async fn centralized_file_storage_with_path() {
        file_storage_with_path(false).await
    }
}
