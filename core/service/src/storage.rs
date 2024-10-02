use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::central_kms::{compute_handle, SoftwareKmsKeys};
use crate::kms::RequestId;
use crate::rpc::rpc_types::{PrivDataType, PublicKeyType, WrappedPublicKey, WrappedPublicKeyOwned};
use crate::util::file_handling::{
    safe_read_element_versioned, safe_write_element_versioned, write_text,
};
use crate::{anyhow_error_and_log, some_or_err};
use crate::{consts::KEY_PATH_PREFIX, rpc::rpc_types::PubDataType};
use anyhow::anyhow;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt::{self};
use std::path::{Path, PathBuf};
use std::{env, fs, path::MAIN_SEPARATOR};
use strum::{EnumIter, IntoEnumIterator};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{Unversionize, Versionize};
use url::Url;

// TODO add a wrapper struct for both public and private storage.

/// Trait for public KMS storage reading
#[tonic::async_trait]
pub trait StorageReader {
    /// Validate if data exists at a given `url`.
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool>;

    /// Read some data from a given `url`.
    /// On return, the data is unversioned.
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T>;

    /// Compute an URL for some specific data given its `data_id` and of a given `data_type`.
    /// Depending on how the underlying functionality is realized one of these parameters might not
    /// be used.
    ///
    /// The implementation should prefix the URL with the storage backend type. For example,
    /// file-based storage should start with file://, S3 based storage should start with s3://, etc.
    /// Further, in the URL, the type should come before the ID, i.e., file://<metadata>/<type>/<id>.
    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url>;

    /// Return all URLs stored of a specific data type
    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>>;

    /// Output some information on the storage instance.
    fn info(&self) -> String;
}

// Trait for KMS public storage reading and writing
// Warning: There is no compiler validation that the data being stored are of a versioned type!
#[tonic::async_trait]
pub trait Storage: StorageReader {
    /// Store the given `data` at the given `url`
    /// Under the hood, the versioned data is stored.
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()>;

    /// Delete the given `data` stored at `url`.
    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()>;
}

#[tonic::async_trait]
pub trait StorageForText: Storage {
    /// Store the given `text` at the given `url`
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()>;
}

/// Store some data at a location defined by `request_id` and `data_type`.
/// Under the hood, the versioned data will be stored.
pub async fn store_versioned_at_request_id<
    'a,
    S: Storage,
    T: Serialize + Versionize + Named + Send + Sync,
>(
    storage: &mut S,
    request_id: &RequestId,
    data: &'a T,
    data_type: &str,
) -> anyhow::Result<()>
where
    <T as Versionize>::Versioned<'a>: Send + Sync,
{
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.store_data(data, &url).await.map_err(|e| {
        anyhow_error_and_log(format!(
            "Could not store data with ID {} and type {}: {}",
            request_id, data_type, e
        ))
    })
}

// Helper method for storing text under a request ID.
// An error will be returned if the data already exists.
pub async fn store_text_at_request_id<S: StorageForText>(
    storage: &mut S,
    request_id: &RequestId,
    data: &str,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.store_text(data, &url).await.map_err(|e| {
        anyhow_error_and_log(format!(
            "Could not store data with ID {} and type {}: {}",
            request_id, data_type, e
        ))
    })
}

/// Delete ALL data under a given `request_id`.
/// Observe that this method does not produce any error regardless of any whether data is deleted or not.
pub async fn delete_all_at_request_id<S: Storage>(storage: &mut S, request_id: &RequestId) {
    for cur_type in PrivDataType::iter() {
        // Ignore an error as it is likely because the data does not exist
        let _ = delete_at_request_id(storage, request_id, &cur_type.to_string()).await;
    }
    for cur_type in PubDataType::iter() {
        // Ignore an error as it is likely because the data does not exist
        let _ = delete_at_request_id(storage, request_id, &cur_type.to_string()).await;
    }
}

// Helper method to remove data based on a data type and request ID.
pub async fn delete_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<()> {
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.delete_data(&url).await.map_err(|e| {
        anyhow::anyhow!(format!(
            "Could not delete data with ID {} and type {}: {}",
            request_id, data_type, e
        ))
    })
}

// Helper method to remove data based on a data type and request ID.
pub async fn delete_pk_at_request_id<S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
) -> anyhow::Result<()> {
    let _ = delete_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string()).await;
    let _ = delete_at_request_id(
        storage,
        request_id,
        &PubDataType::PublicKeyMetadata.to_string(),
    )
    .await;
    // Don't report errors
    Ok(())
}

/// Read some data stored in a location defined by `request_id` and `data_type`.
/// The returned result is automatically unversioned.
pub async fn read_versioned_at_request_id<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    request_id: &RequestId,
    data_type: &str,
) -> anyhow::Result<T>
where
    <T as tfhe_versionable::VersionizeOwned>::VersionedOwned: Send,
{
    let url = storage.compute_url(&request_id.to_string(), data_type)?;
    storage.read_data(&url).await
}

/// This function will perform verionize on the type.
pub async fn store_pk_at_request_id<'a, S: Storage>(
    storage: &mut S,
    request_id: &RequestId,
    pk: WrappedPublicKey<'a>,
) -> anyhow::Result<()> {
    match pk {
        WrappedPublicKey::Compact(inner_pk) => {
            store_versioned_at_request_id(
                storage,
                request_id,
                inner_pk,
                &PubDataType::PublicKey.to_string(),
            )
            .await?;
            store_versioned_at_request_id(
                storage,
                request_id,
                &PublicKeyType::Compact,
                &PubDataType::PublicKeyMetadata.to_string(),
            )
            .await?;
        }
    }
    Ok(())
}

pub async fn read_pk_at_request_id<S: Storage>(
    storage: &S,
    request_id: &RequestId,
) -> anyhow::Result<WrappedPublicKeyOwned> {
    let pk_type: PublicKeyType = read_versioned_at_request_id(
        storage,
        request_id,
        &PubDataType::PublicKeyMetadata.to_string(),
    )
    .await?;

    let out = match pk_type {
        PublicKeyType::Compact => WrappedPublicKeyOwned::Compact(
            read_versioned_at_request_id(storage, request_id, &PubDataType::PublicKey.to_string())
                .await?,
        ),
    };

    Ok(out)
}

/// Helper method for reading all data of a specific type.
pub async fn read_all_data_versioned<
    S: StorageReader,
    T: DeserializeOwned + Unversionize + Named + Send,
>(
    storage: &S,
    data_type: &str,
) -> anyhow::Result<HashMap<RequestId, T>> {
    let url_map = storage.all_urls(data_type).await?;
    let mut res = HashMap::with_capacity(url_map.len());
    for (data_ptr, url) in url_map.iter() {
        let data: T = storage
            .read_data(url)
            .await
            .map_err(|e| anyhow!("reading failed on url {url}: {e}"))?;
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

#[derive(Default, Clone, Debug)]
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
        Ok(path)
    }

    fn centralized_path(
        optional_path: Option<&Path>,
        storage_type: StorageType,
    ) -> anyhow::Result<PathBuf> {
        Ok(match optional_path {
            Some(path) => {
                let path = path.join(storage_type.to_string());
                fs::create_dir_all(&path)?;
                path.canonicalize()?
            }
            None => Self::default_path_with_prefix(&storage_type.to_string())?,
        })
    }

    fn threshold_path(
        optional_path: Option<&Path>,
        storage_type: StorageType,
        party_id: usize,
    ) -> anyhow::Result<PathBuf> {
        Ok(match optional_path {
            Some(path) => {
                let path = path.join(format!("{storage_type}-p{party_id}"));
                fs::create_dir_all(&path)?;
                path.canonicalize()?
            }
            None => Self::default_path_with_prefix(&format!("{storage_type}-p{party_id}"))?,
        })
    }

    fn new(path: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&path)?;
        Ok(Self { path })
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
        FileStorage::new(FileStorage::centralized_path(optional_path, storage_type)?)
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
        FileStorage::new(FileStorage::threshold_path(
            optional_path,
            storage_type,
            party_id,
        )?)
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
                .ok_or(anyhow!("Could not convert path to string"))?,
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

impl FileStorage {
    // Check if a path already exists and create it if not.
    async fn setup_dirs(&self, url_path: &Path) -> anyhow::Result<()> {
        if url_path.try_exists().is_ok_and(|res| res) {
            // If the path exists, then trace a warning
            tracing::warn!(
                "The path {} already exists. Keeping the data without overwriting",
                url_path
                    .to_str()
                    .ok_or(anyhow!("Could not convert path to string"))?
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
impl StorageForText for FileStorage {
    /// Store text with a specific [url], giving a warning if the data already exists and exits _without_ writing
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        let url_path = url_to_pathbuf(url);

        self.setup_dirs(&url_path).await?;

        write_text(
            url_path
                .to_str()
                .ok_or(anyhow!("Could not convert path to string"))?,
            text,
        )
        .await
        .map_err(|e| {
            tracing::warn!("Could not write to URL {}: {}", url, e);
            e
        })?;
        Ok(())
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
                .ok_or(anyhow!("Could not convert path to string"))?,
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
                .ok_or(anyhow!("Could not convert path to string"))?,
        )
        .await?)
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

    // Construct a storage for private keys
    pub async fn from_existing_keys(keys: &SoftwareKmsKeys) -> anyhow::Result<Self> {
        let mut ram_storage = Self::new(StorageType::PRIV);
        for (cur_req_id, cur_keys) in &keys.key_info {
            store_versioned_at_request_id(
                &mut ram_storage,
                cur_req_id,
                cur_keys,
                &PrivDataType::FheKeyInfo.to_string(),
            )
            .await?;
        }
        let sk_handle = compute_handle(&keys.sig_pk)?;
        ram_storage
            .store_data(
                &keys.sig_sk,
                &ram_storage.compute_url(&sk_handle, &PrivDataType::SigningKey.to_string())?,
            )
            .await?;
        Ok(ram_storage)
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

/// Converts a file:// URL into a PathBuf. Doesn't check the URL scheme though,
/// if it's not file://, it won't make a lot of sense to use this
/// function. Unlike Url::to_file_path, it accepts relative paths.
pub fn url_to_pathbuf(url: &Url) -> PathBuf {
    PathBuf::from(format!("{}{}", url.host_str().map_or("", |x| { x }), url.path()).as_str())
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

#[allow(dead_code)]
pub enum StorageVersion {
    Dev,
    Ram,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::rpc::rpc_types::PubDataType;
    use serde::{Deserialize, Serialize};
    use strum::IntoEnumIterator;
    use tfhe_versionable::VersionsDispatch;

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, VersionsDispatch)]
    enum TestTypeVersioned {
        V0(TestType),
    }

    impl Named for TestType {
        const NAME: &'static str = "TestType";
    }

    #[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Versionize)]
    #[versionize(TestTypeVersioned)]
    struct TestType {
        i: u32,
    }

    #[ignore]
    #[tokio::test]
    async fn threshold_dev_storage() {
        let path1 = tempfile::tempdir().unwrap();
        let path2 = tempfile::tempdir().unwrap();
        let path1_str = path1.path().to_str().unwrap().to_string();
        let mut storage1 = FileStorage {
            path: path1.into_path(),
        };
        assert_eq!(
            Url::parse(&format!("file://{}/type/id", path1_str)).unwrap(),
            storage1.compute_url("id", "type").unwrap()
        );
        let storage2 = FileStorage {
            path: path2.into_path(),
        };

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

    async fn file_storage_with_path(threshold: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut storage = if threshold {
            FileStorage::new_threshold(Some(path), StorageType::PUB, 1).unwrap()
        } else {
            FileStorage::new_centralized(Some(path), StorageType::PUB).unwrap()
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

    #[tokio::test]
    async fn storage_helper_methods_ramstorage() {
        let mut storage = RamStorage::new(StorageType::PUB);
        test_storage_read_store_methods(&mut storage).await;
        test_batch_helper_methods(&mut storage).await;
    }

    #[rstest::rstest]
    #[tokio::test]
    async fn storage_helper_methods_filestorage(#[values(true, false)] threshold: bool) {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path();
        let mut pub_storage = if threshold {
            FileStorage::new_threshold(Some(path), StorageType::PUB, 1).unwrap()
        } else {
            FileStorage::new_centralized(Some(path), StorageType::PUB).unwrap()
        };
        let mut priv_storage = if threshold {
            FileStorage::new_threshold(Some(path), StorageType::PRIV, 1).unwrap()
        } else {
            FileStorage::new_centralized(Some(path), StorageType::PRIV).unwrap()
        };
        test_storage_read_store_methods(&mut pub_storage).await;
        test_storage_read_store_methods(&mut priv_storage).await;
        test_batch_helper_methods(&mut pub_storage).await;
        test_batch_helper_methods(&mut priv_storage).await;
    }

    pub async fn test_storage_read_store_methods<S: Storage>(storage: &mut S) {
        let data = TestType { i: 42 };
        let data_type = "TestType";
        let req_id = RequestId::derive("123").unwrap();

        // Ensure no old data is present
        let _ = delete_at_request_id(storage, &req_id, data_type).await;
        assert!(
            store_versioned_at_request_id(storage, &req_id, &data, data_type)
                .await
                .is_ok()
        );
        let retrieved_store: TestType = read_versioned_at_request_id(storage, &req_id, data_type)
            .await
            .unwrap();
        assert_eq!(data, retrieved_store);
        assert!(delete_at_request_id(storage, &req_id, data_type)
            .await
            .is_ok());
        let reretrieved_store: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id, data_type).await;
        assert!(reretrieved_store.is_err());
    }

    pub async fn test_batch_helper_methods<S: Storage>(storage: &mut S) {
        // Setup data
        let req_id_1 = RequestId::derive("1").unwrap();
        let data_1_pk = TestType { i: 1 };
        let data_1_vk = TestType { i: 2 };
        let req_id_2 = RequestId::derive("2").unwrap();
        let data_2_pk = TestType { i: 3 };
        let url_1_pk = storage
            .compute_url(&req_id_1.to_string(), &PubDataType::PublicKey.to_string())
            .unwrap();
        let url_1_vk = storage
            .compute_url(&req_id_1.to_string(), &PubDataType::VerfKey.to_string())
            .unwrap();
        let url_2_pk = storage
            .compute_url(&req_id_2.to_string(), &PubDataType::PublicKey.to_string())
            .unwrap();

        // Ensure no old test data is present
        println!("deleting..");
        delete_all_at_request_id(storage, &req_id_1).await;
        delete_all_at_request_id(storage, &req_id_2).await;

        // Store data
        println!("storing..");
        storage.store_data(&data_1_pk, &url_1_pk).await.unwrap();
        storage.store_data(&data_1_vk, &url_1_vk).await.unwrap();
        storage.store_data(&data_2_pk, &url_2_pk).await.unwrap();

        // Check data retrieval
        println!("retrieving.. {}", storage.info());
        let req_id_1_pk: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id_1, &PubDataType::PublicKey.to_string())
                .await;
        assert_eq!(&req_id_1_pk.unwrap(), &data_1_pk);
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert_eq!(pks.len(), 2);
        assert_eq!(pks.get(&req_id_1).unwrap(), &data_1_pk);
        assert_eq!(pks.get(&req_id_2).unwrap(), &data_2_pk);
        let verfs: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::VerfKey.to_string())
                .await
                .unwrap();
        assert_eq!(verfs.len(), 1);
        assert_eq!(verfs.get(&req_id_1).unwrap(), &data_1_vk);

        // Delete data
        delete_all_at_request_id(storage, &req_id_1).await;

        // Check data retrieval again
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert_eq!(pks.len(), 1);
        assert_eq!(pks.get(&req_id_2).unwrap(), &data_2_pk);
        let req_id_1_pk: anyhow::Result<TestType> =
            read_versioned_at_request_id(storage, &req_id_1, &PubDataType::PublicKey.to_string())
                .await;
        // Check there is no longer a pk for req_id_1
        assert!(req_id_1_pk.is_err());

        let verfs: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::VerfKey.to_string())
                .await
                .unwrap();
        assert!(verfs.is_empty());

        // Delete last data
        delete_all_at_request_id(storage, &req_id_2).await;

        // Check data retrieval again
        let pks: HashMap<RequestId, TestType> =
            read_all_data_versioned(storage, &PubDataType::PublicKey.to_string())
                .await
                .unwrap();
        assert!(pks.is_empty());
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
