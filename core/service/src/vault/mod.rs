use serde::{de::DeserializeOwned, Serialize};
use std::collections::HashMap;
use tfhe::{named::Named, Unversionize, Versionize};
use url::Url;

use keychain::{Keychain, KeychainProxy};
use storage::{Storage, StorageForText, StorageProxy, StorageReader};

pub mod aws;
pub mod keychain;
pub mod storage;

pub struct Vault {
    pub storage: StorageProxy,
    pub keychain: Option<KeychainProxy>,
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl StorageReader for Vault {
    async fn read_data<T: DeserializeOwned + Unversionize + Named + Send>(
        &self,
        url: &Url,
    ) -> anyhow::Result<T> {
        match self.keychain.as_ref() {
            Some(k) => {
                let mut encrypted_data = self.storage.read_data(url).await?;
                k.decrypt(&mut encrypted_data).await
            }
            None => self.storage.read_data(url).await,
        }
    }

    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        self.storage.data_exists(url).await
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        self.storage.compute_url(data_id, data_type)
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        self.storage.all_urls(data_type).await
    }

    fn info(&self) -> String {
        self.storage.info()
    }
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl Storage for Vault {
    async fn store_data<T: Serialize + Versionize + Named + Send + Sync>(
        &mut self,
        data: &T,
        url: &Url,
    ) -> anyhow::Result<()> {
        match self.keychain.as_ref() {
            Some(k) => {
                let encrypted_data = k.encrypt(data).await?;
                self.storage.store_data(&encrypted_data, url).await
            }
            None => self.storage.store_data(data, url).await,
        }
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        self.storage.delete_data(url).await
    }
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl StorageForText for Vault {
    async fn store_text(&mut self, text: &str, url: &Url) -> anyhow::Result<()> {
        self.storage.store_text(text, url).await
    }
    async fn read_text(&mut self, url: &Url) -> anyhow::Result<String> {
        self.storage.read_text(url).await
    }
}
