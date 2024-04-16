use crate::{
    anyhow_error_and_log,
    consts::KEY_PATH_PREFIX,
    kms::{FhePubKeyInfo, RequestId},
    rpc::{central_rpc::tonic_some_or_err, rpc_types::PubDataType},
    util::file_handling::{read_element, write_element},
};
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
use serde::de::DeserializeOwned;
use std::{collections::HashMap, env, fs, path::Path};
use url::Url;

/// Trait for public KMS storage reading
pub trait PublicStorageReader {
    fn data_exits(&self, request_id: &RequestId, key_type: PubDataType) -> anyhow::Result<bool>;
    fn read_data<T: DeserializeOwned + serde::Serialize>(&self, url: Url) -> anyhow::Result<T>;
    fn compute_url(
        &self,
        request: RequestId,
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
    request_id: RequestId,
    public_info: &HashMap<PubDataType, FhePubKeyInfo>,
) -> anyhow::Result<HashMap<PubDataType, Url>> {
    let mut urls = HashMap::new();
    for (key_type, info) in public_info {
        let url = storage.compute_url(request_id.clone(), info, key_type.to_owned())?;
        urls.insert(key_type.to_owned(), url);
    }
    Ok(urls)
}

pub fn store_public_keys<S: PublicStorage>(
    storage: &S,
    request_id: RequestId,
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
        return Err(anyhow::anyhow!("Could not store public key!"));
    }
    if !storage.store_data(&pub_keys.server_key, sk_url) {
        return Err(anyhow::anyhow!("Could not store server key!"));
    }
    Ok(())
}

#[derive(Default)]
pub struct DevStorage {}

impl DevStorage {
    pub fn root_dir() -> String {
        format!("{}/dev", KEY_PATH_PREFIX)
    }
}

impl PublicStorageReader for DevStorage {
    fn compute_url(
        &self,
        request_id: RequestId,
        _info: &FhePubKeyInfo,
        key_type: PubDataType,
    ) -> anyhow::Result<Url> {
        let raw_dir = env::current_dir()?;
        let cur_dir = tonic_some_or_err(
            raw_dir.to_str(),
            "Could not get current directory".to_string(),
        )?;
        let public_key_path = format!(
            "{}/{}/dev/{}-{}.key",
            cur_dir, KEY_PATH_PREFIX, request_id, key_type
        );
        let url = Url::from_file_path(public_key_path)
            .map_err(|_e| anyhow::anyhow!("Could not turn path into URL"))?;
        Ok(url)
    }

    fn data_exits(&self, request_id: &RequestId, key_type: PubDataType) -> anyhow::Result<bool> {
        let raw_dir = env::current_dir()?;
        let cur_dir = tonic_some_or_err(
            raw_dir.to_str(),
            "Could not get current directory".to_string(),
        )?;
        let path = format!(
            "{}/{}/dev/{}-{}.key",
            cur_dir, KEY_PATH_PREFIX, request_id, key_type
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
        match fs::create_dir_all(format!("{}/dev", KEY_PATH_PREFIX)) {
            Ok(_) => match write_element(url.path().to_string(), &data) {
                Ok(_) => true,
                Err(_) => {
                    tracing::warn!("Could not write to URL {}", url.to_string());
                    false
                }
            },
            Err(_) => {
                tracing::warn!("Could not create directory {}", KEY_PATH_PREFIX);
                false
            }
        }
    }
}
