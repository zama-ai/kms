use anyhow::anyhow;
use std::fmt;
use std::panic::Location;

// copied from tonic since we're cannot pull in tonic for wasm
macro_rules! my_include_proto {
    ($package: tt) => {
        include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
    };
}
pub mod kms {
    my_include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod client;
pub mod consts;
#[cfg(feature = "non-wasm")]
pub mod util {
    pub mod aws;
    pub mod file_handling;
    pub mod key_setup;
    pub mod meta_store;
}
pub mod cryptography {
    #[cfg(feature = "non-wasm")]
    pub mod central_kms;
    pub mod der_types;
    pub mod nitro_enclave;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod threshold {
    pub mod generic;
    #[cfg(any(test, feature = "testing"))]
    pub mod mock_threshold_kms;
    pub mod threshold_kms;
}
#[cfg(feature = "non-wasm")]
pub mod storage;
pub mod rpc {
    #[cfg(feature = "non-wasm")]
    pub mod central_rpc;
    #[cfg(feature = "non-wasm")]
    pub mod central_rpc_proxy;
    pub mod rpc_types;
}
#[cfg(feature = "non-wasm")]
pub mod conf;

/// Truncate s to a maximum of 128 chars.
pub(crate) fn top_n_chars(mut s: String) -> String {
    s.truncate(128);
    s
}

/// Helper method for returning the optional value of `input` if it exists, otherwise
/// returning a custom anyhow error.
pub fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> anyhow::Result<T> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        anyhow!("Missing value: {}", top_n_chars(error.to_string()))
    })
}

// NOTE: the below is copied from core/threshold
// since the calling tracing from another crate
// does not generate correct logs in tracing_test::traced_test
#[track_caller]
pub(crate) fn anyhow_error_and_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow!("Error in {}: {}", Location::caller(), msg)
}

#[track_caller]
pub(crate) fn anyhow_error_and_warn_log<S: AsRef<str> + fmt::Display>(msg: S) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}

#[cfg(feature = "non-wasm")]
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "non-wasm")]
use std::collections::HashMap;
#[cfg(feature = "non-wasm")]
use storage::{FileStorage, RamStorage, Storage, StorageReader};
#[cfg(feature = "non-wasm")]
use url::Url;
#[cfg(feature = "non-wasm")]
use util::aws::{EnclaveS3Storage, S3Storage};

/// Represents all storage types as variants of one concrete type. This
/// monstrosity is required to work around the Rust's inability to create trait
/// objects if the trait has methods with generic parameters. Without it, the
/// code in `main()` that creates storage objects and passes them to the server
/// startup functions will blow up quadratically in the number of available
/// storage backends, as one would have to create both public and private
/// storage object at the same time as passing them to the server startup
/// function.
#[cfg(feature = "non-wasm")]
pub enum StorageProxy {
    File(FileStorage),
    #[allow(dead_code)]
    Ram(RamStorage),
    S3(S3Storage),
    EnclaveS3(EnclaveS3Storage),
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl StorageReader for StorageProxy {
    async fn data_exists(&self, url: &Url) -> anyhow::Result<bool> {
        match &self {
            StorageProxy::File(s) => s.data_exists(url).await,
            StorageProxy::Ram(s) => s.data_exists(url).await,
            StorageProxy::S3(s) => s.data_exists(url).await,
            StorageProxy::EnclaveS3(s) => s.data_exists(url).await,
        }
    }

    async fn read_data<Ser: DeserializeOwned + Send>(&self, url: &Url) -> anyhow::Result<Ser> {
        match &self {
            StorageProxy::File(s) => s.read_data(url).await,
            StorageProxy::Ram(s) => s.read_data(url).await,
            StorageProxy::S3(s) => s.read_data(url).await,
            StorageProxy::EnclaveS3(s) => s.read_data(url).await,
        }
    }

    fn compute_url(&self, data_id: &str, data_type: &str) -> anyhow::Result<Url> {
        match &self {
            StorageProxy::File(s) => s.compute_url(data_id, data_type),
            StorageProxy::Ram(s) => s.compute_url(data_id, data_type),
            StorageProxy::S3(s) => s.compute_url(data_id, data_type),
            StorageProxy::EnclaveS3(s) => s.compute_url(data_id, data_type),
        }
    }

    async fn all_urls(&self, data_type: &str) -> anyhow::Result<HashMap<String, Url>> {
        match &self {
            StorageProxy::File(s) => s.all_urls(data_type).await,
            StorageProxy::Ram(s) => s.all_urls(data_type).await,
            StorageProxy::S3(s) => s.all_urls(data_type).await,
            StorageProxy::EnclaveS3(s) => s.all_urls(data_type).await,
        }
    }

    fn info(&self) -> String {
        match &self {
            StorageProxy::File(s) => s.info(),
            StorageProxy::Ram(s) => s.info(),
            StorageProxy::S3(s) => s.info(),
            StorageProxy::EnclaveS3(s) => s.info(),
        }
    }
}

#[cfg(feature = "non-wasm")]
#[tonic::async_trait]
impl Storage for StorageProxy {
    async fn store_data<Ser: Serialize + Send + Sync + ?Sized>(
        &mut self,
        data: &Ser,
        url: &Url,
    ) -> anyhow::Result<()> {
        match &mut self {
            StorageProxy::File(s) => s.store_data(data, url).await,
            StorageProxy::Ram(s) => s.store_data(data, url).await,
            StorageProxy::S3(s) => s.store_data(data, url).await,
            StorageProxy::EnclaveS3(s) => s.store_data(data, url).await,
        }
    }

    async fn delete_data(&mut self, url: &Url) -> anyhow::Result<()> {
        match &mut self {
            StorageProxy::File(s) => s.delete_data(url).await,
            StorageProxy::Ram(s) => s.delete_data(url).await,
            StorageProxy::S3(s) => s.delete_data(url).await,
            StorageProxy::EnclaveS3(s) => s.delete_data(url).await,
        }
    }
}
