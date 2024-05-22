use anyhow::anyhow;
#[cfg(feature = "non-wasm")]
use consts::DEFAULT_PARAM_PATH;
use std::fmt;
use std::panic::Location;
#[cfg(feature = "non-wasm")]
use util::file_handling::write_element;

// copied from tonic since we're cannot pull in tonic for wasm
macro_rules! my_include_proto {
    ($package: tt) => {
        include!(concat!(env!("OUT_DIR"), concat!("/", $package, ".rs")));
    };
}
pub mod kms {
    my_include_proto!("kms"); // The string specified here must match the proto package name
}
#[cfg(feature = "non-wasm")]
pub mod connector {
    my_include_proto!("connector");
}
#[cfg(feature = "non-wasm")]
pub mod ddec_core {
    my_include_proto!("ddec_core");
}
pub mod client;
pub mod consts;
#[cfg(feature = "non-wasm")]
pub mod util {
    pub mod aws;
    pub mod file_handling;
    pub mod key_setup;
}
pub mod cryptography {
    #[cfg(feature = "non-wasm")]
    pub mod central_kms;
    pub mod der_types;
    pub mod nitro_enclave;
    #[cfg(feature = "non-wasm")]
    pub mod request;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod threshold {
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

/// Take the max(20, s.len()) characters of s.
pub(crate) fn top_n_chars(mut s: String) -> String {
    let n = std::cmp::max(s.len(), 20);
    _ = s.split_off(n);
    s
}

/// Helper method for returning the optional value of `input` if it exists, otherwise
/// returning a custom anyhow error.
pub fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> anyhow::Result<T> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        anyhow!("Invalid request: {}", top_n_chars(error.to_string()))
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
pub async fn write_default_keys(path: &str) {
    use crate::consts::{DEFAULT_KEY_ID, OTHER_DEFAULT_ID, TMP_PATH_PREFIX};
    use crate::util::file_handling::read_element;
    use crate::util::key_setup::{ensure_central_keys_exist, CentralizedTestingKeys};
    use std::path::Path;

    // Check if all keys have already been written and return if so.
    if Path::new(&format!("{TMP_PATH_PREFIX}/pks.bin"))
        .try_exists()
        .unwrap()
        && Path::new(&format!("{TMP_PATH_PREFIX}/sks.bin"))
            .try_exists()
            .unwrap()
        && Path::new(&format!("{TMP_PATH_PREFIX}/cks.bin"))
            .try_exists()
            .unwrap()
    {
        println!("Keys already exist. Done executing write_default_keys without the need for writing anything.");
        return;
    }
    ensure_central_keys_exist(
        DEFAULT_PARAM_PATH,
        path,
        &DEFAULT_KEY_ID.clone(),
        &OTHER_DEFAULT_ID.clone(),
    )
    .await;
    let central_keys: CentralizedTestingKeys = read_element(path).unwrap();
    let pks = central_keys.pub_fhe_keys.get(&DEFAULT_KEY_ID).unwrap();
    // Write down the seperate keys needed to run the server
    if !Path::new(&format!("{TMP_PATH_PREFIX}/pks.bin"))
        .try_exists()
        .unwrap()
    {
        println!("Writing default pks");
        write_element(format!("{TMP_PATH_PREFIX}/pks.bin"), &pks.public_key).unwrap();
    }
    if !Path::new(&format!("{TMP_PATH_PREFIX}/sks.bin"))
        .try_exists()
        .unwrap()
    {
        println!("Writing default sks");
        write_element(format!("{TMP_PATH_PREFIX}/sks.bin"), &pks.server_key).unwrap();
    }
    if !Path::new(&format!("{TMP_PATH_PREFIX}/cks.bin"))
        .try_exists()
        .unwrap()
    {
        println!("Writing default cks");
        write_element(
            format!("{TMP_PATH_PREFIX}/cks.bin"),
            &central_keys
                .software_kms_keys
                .key_info
                .get(&DEFAULT_KEY_ID)
                .unwrap()
                .client_key,
        )
        .unwrap();
    }
    println!("Keys have been written. Done executing write_default_keys");
}

#[cfg(feature = "non-wasm")]
pub async fn write_default_crs_store() {
    use crate::consts::{DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CRS_ID};
    use util::key_setup::ensure_central_crs_store_exists;

    ensure_central_crs_store_exists(
        DEFAULT_PARAM_PATH,
        DEFAULT_CENTRAL_CRS_PATH,
        DEFAULT_CENTRAL_KEYS_PATH,
        &DEFAULT_CRS_ID,
    )
    .await;
}

#[cfg(feature = "slow_tests")]
#[cfg(test)]
mod tests {
    #[cfg(test)]
    #[tokio::test]
    #[ctor::ctor]
    async fn ensure_server_keys_crs_exist() {
        use crate::consts::DEFAULT_CENTRAL_KEYS_PATH;
        use crate::{write_default_crs_store, write_default_keys};

        println!("Write default keys started...");
        write_default_keys(DEFAULT_CENTRAL_KEYS_PATH).await;

        println!("Write default CRS store started...");
        write_default_crs_store().await;
    }
}
