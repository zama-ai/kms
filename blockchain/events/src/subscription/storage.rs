use std::path::Path;

use super::handler::SubscriptionError;
use async_trait::async_trait;
use koit_toml::format::Toml;
use koit_toml::FileDatabase;
#[cfg(test)]
use mockall::automock;
use serde::{Deserialize, Serialize};

#[cfg_attr(test, automock)]
#[async_trait]
pub trait StorageService {
    async fn get_last_height(&self) -> Result<u64, SubscriptionError>;
    async fn save_last_height(&self, height: u64) -> Result<(), SubscriptionError>;
}

#[derive(Default, Deserialize, Serialize)]
pub(crate) struct SyncPointer {
    height: Option<u64>,
}

pub struct TomlStorageServiceImpl {
    db: FileDatabase<SyncPointer, Toml>,
    outside_height: Option<u64>,
}

impl TomlStorageServiceImpl {
    pub(crate) async fn new(
        storage_path: &Path,
        outside_height: Option<u64>,
    ) -> Result<Self, SubscriptionError> {
        let path = storage_path.to_path_buf();
        let dir = path.parent().unwrap_or_else(|| {
            panic!(
                "Wrong path for storage {:?}. Expected path and file. Example './temp/events.toml'",
                path
            )
        });
        if !dir.exists() {
            let _ = tokio::fs::create_dir_all(dir).await;
        }
        tracing::debug!("Loading storage from path {:?}", path);
        let db = FileDatabase::load_from_path_or_default(path.clone()).await?;
        tracing::debug!("Loaded storage from path {:?}", path.clone());

        Ok(TomlStorageServiceImpl { db, outside_height })
    }
}

#[async_trait]
impl StorageService for TomlStorageServiceImpl {
    async fn save_last_height(&self, height: u64) -> Result<(), SubscriptionError> {
        self.db
            .write(|pointer| {
                pointer.height = Some(height);
            })
            .await;
        self.db.save().await?;
        Ok(())
    }

    async fn get_last_height(&self) -> Result<u64, SubscriptionError> {
        self.db
            .read(|pointer| Ok(pointer.height.unwrap_or(self.outside_height.unwrap_or(0))))
            .await
    }
}
