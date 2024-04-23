use crate::{
    anyhow_error_and_log,
    consts::KEY_PATH_PREFIX,
    kms::{FhePubKeyInfo, RequestId},
    rpc::{central_rpc::tonic_some_or_err, rpc_types::PubDataType},
    util::file_handling::{read_element, write_element},
};
use distributed_decryption::execution::{
    endpoints::keygen::FhePubKeySet, zk::ceremony::PublicParameter,
};
use serde::de::DeserializeOwned;
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
};
use url::Url;

/// Trait for public KMS storage reading
pub trait PublicStorageReader {
    fn data_exists(&self, request_id: &RequestId, key_type: PubDataType) -> anyhow::Result<bool>;
    fn read_data<T: DeserializeOwned + serde::Serialize>(&self, url: Url) -> anyhow::Result<T>;
    fn compute_url(
        &self,
        request: &RequestId,
        info: &FhePubKeyInfo,
        key_type: PubDataType,
    ) -> anyhow::Result<Url>;
}

// Trait for KMS public storage reading and writing
pub trait PublicStorage: PublicStorageReader {
    fn store_data<T: serde::Serialize>(&self, data: T, url: Url) -> bool;
}

pub fn compute_all_urls<S: PublicStorageReader>(
    storage: &S,
    request_id: &RequestId,
    public_info: &HashMap<PubDataType, FhePubKeyInfo>,
) -> anyhow::Result<HashMap<PubDataType, Url>> {
    let mut urls = HashMap::new();
    for (key_type, info) in public_info {
        let url = storage.compute_url(request_id, info, key_type.to_owned())?;
        urls.insert(key_type.to_owned(), url);
    }
    Ok(urls)
}

pub fn store_public_keys<S: PublicStorage>(
    storage: &S,
    request_id: &RequestId,
    public_key_info: &HashMap<PubDataType, FhePubKeyInfo>,
    pub_keys: &FhePubKeySet,
) -> anyhow::Result<()> {
    let urls = compute_all_urls(storage, request_id, public_key_info)?;
    let pk_url = match urls.get(&PubDataType::PublicKey) {
        Some(pk_url) => pk_url.to_owned(),
        None => return Err(anyhow_error_and_log("Public key is not produced")),
    };
    let sk_url = match urls.get(&PubDataType::ServerKey) {
        Some(sk_url) => sk_url.to_owned(),
        None => return Err(anyhow_error_and_log("Server key is not produced")),
    };
    if !storage.store_data(&pub_keys.public_key, pk_url) {
        return Err(anyhow_error_and_log("Could not store public key!"));
    }
    if !storage.store_data(&pub_keys.server_key, sk_url) {
        return Err(anyhow_error_and_log("Could not store server key!"));
    }
    Ok(())
}

pub fn store_crs<S: PublicStorage>(
    storage: &S,
    request_id: &RequestId,
    crs_info: &FhePubKeyInfo, // TODO: rename this type to PublicInfo or PubDataSigHandle, but do it later to not conflict with other PRs now
    crs: &PublicParameter,
) -> anyhow::Result<()> {
    let crs_url = storage.compute_url(request_id, crs_info, PubDataType::CRS)?;
    if !storage.store_data(crs, crs_url) {
        return Err(anyhow_error_and_log("Could not store CRS!"));
    }
    Ok(())
}

#[derive(Default)]
pub struct DevStorage {
    extra_prefix: String,
}

impl DevStorage {
    pub fn root_dir(&self) -> PathBuf {
        PathBuf::from(format!("{}/{}/dev", KEY_PATH_PREFIX, self.extra_prefix))
    }

    pub fn new(extra_prefix: &str) -> Self {
        Self {
            extra_prefix: extra_prefix.to_owned(),
        }
    }
}

impl PublicStorageReader for DevStorage {
    fn compute_url(
        &self,
        request_id: &RequestId,
        _info: &FhePubKeyInfo,
        key_type: PubDataType,
    ) -> anyhow::Result<Url> {
        let raw_dir = env::current_dir()?;
        let cur_dir = tonic_some_or_err(
            raw_dir.to_str(),
            "Could not get current directory".to_string(),
        )?;
        let public_key_path = format!(
            "{}/{}/{}/dev/{}-{}.key",
            cur_dir, KEY_PATH_PREFIX, self.extra_prefix, request_id, key_type
        );
        let url = Url::from_file_path(public_key_path)
            .map_err(|_e| anyhow_error_and_log("Could not turn path into URL"))?;
        Ok(url)
    }

    fn data_exists(&self, request_id: &RequestId, key_type: PubDataType) -> anyhow::Result<bool> {
        let raw_dir = env::current_dir()?;
        let cur_dir = tonic_some_or_err(
            raw_dir.to_str(),
            "Could not get current directory".to_string(),
        )?;
        let path = format!(
            "{}/{}/{}/dev/{}-{}.key",
            cur_dir, KEY_PATH_PREFIX, self.extra_prefix, request_id, key_type
        );
        Path::new(&path)
            .try_exists()
            .map_err(|_| anyhow_error_and_log(format!("The path {} does not exist", path)))
    }

    fn read_data<T: DeserializeOwned + serde::Serialize>(&self, url: Url) -> anyhow::Result<T> {
        let res: T = read_element(url.path())?;
        Ok(res)
    }
}

impl PublicStorage for DevStorage {
    fn store_data<T: serde::Serialize>(&self, data: T, url: Url) -> bool {
        match fs::create_dir_all(format!("{}/{}/dev", KEY_PATH_PREFIX, self.extra_prefix)) {
            Ok(_) => match write_element(url.path().to_string(), &data) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!("Could not write to URL {}, error {}", url, e);
                    false
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Could not create directory {}, error {}",
                    KEY_PATH_PREFIX,
                    e
                );
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_dev_storage() {
        let prefix1 = "p1";
        let prefix2 = "p2";
        let storage1 = DevStorage::new(prefix1);
        let storage2 = DevStorage::new(prefix2);

        // clear out storage
        let _ = fs::remove_dir_all(storage1.root_dir());
        let _ = fs::remove_dir_all(storage2.root_dir());

        let reqid = RequestId {
            request_id: "hello".to_string(),
        };
        let data = "data".to_string();
        // NOTE: info is not used for dev storage
        let info = FhePubKeyInfo {
            key_handle: "".to_string(),
            signature: vec![],
        };
        let url = storage1
            .compute_url(&reqid, &info, PubDataType::CRS)
            .unwrap();

        // make sure we can put it in storage1
        assert!(storage1.store_data(data, url));
        assert!(storage1.data_exists(&reqid, PubDataType::CRS).unwrap());
        assert!(!storage1
            .data_exists(&reqid, PubDataType::PublicKey)
            .unwrap());

        // check that we're not storing to storage2
        assert!(!storage2.data_exists(&reqid, PubDataType::CRS).unwrap());
    }
}
