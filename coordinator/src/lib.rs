use anyhow::anyhow;
#[cfg(feature = "non-wasm")]
use consts::{DEFAULT_PARAM_PATH, TEST_KEY_ID};
#[cfg(feature = "non-wasm")]
use cryptography::central_kms::{CrsHashMap, SoftwareKmsKeys};
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
    pub mod file_handling;
    pub mod key_setup;
}
pub mod cryptography {
    #[cfg(feature = "non-wasm")]
    pub mod central_kms;
    pub mod der_types;
    #[cfg(feature = "non-wasm")]
    pub mod request;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod threshold {
    pub mod threshold_kms;
}
#[cfg(feature = "non-wasm")]
pub mod storage;
pub mod rpc {
    #[cfg(feature = "non-wasm")]
    pub mod central_rpc;
    #[cfg(feature = "non-wasm")]
    pub mod kms_proxy_rpc;
    pub mod rpc_types;
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
pub fn write_default_keys(path: &str) -> SoftwareKmsKeys {
    use crate::{
        consts::TMP_PATH_PREFIX,
        util::file_handling::read_element,
        util::key_setup::{ensure_central_keys_exist, CentralizedTestingKeys},
    };
    use std::path::Path;

    ensure_central_keys_exist(DEFAULT_PARAM_PATH, path, Some(TEST_KEY_ID.to_string()));
    let central_keys: CentralizedTestingKeys = read_element(path).unwrap();
    let pks = central_keys.pub_fhe_keys.get(TEST_KEY_ID).unwrap();
    // Write down the seperate keys needed to run the server
    if !Path::new("{TMP_PATH_PREFIX}/pks.bin").try_exists().unwrap() {
        write_element(format!("{TMP_PATH_PREFIX}/pks.bin"), &pks.public_key).unwrap();
    }
    if !Path::new("{TMP_PATH_PREFIX}/sks.bin").try_exists().unwrap() {
        write_element(format!("{TMP_PATH_PREFIX}/sks.bin"), &pks.server_key).unwrap();
    }
    if !Path::new("{TMP_PATH_PREFIX}/cks.bin").try_exists().unwrap() {
        write_element(
            format!("{TMP_PATH_PREFIX}/cks.bin"),
            &central_keys
                .software_kms_keys
                .key_info
                .get(TEST_KEY_ID)
                .unwrap()
                .client_key,
        )
        .unwrap();
    }
    central_keys.software_kms_keys
}

#[cfg(feature = "non-wasm")]
pub fn write_default_crs_store() -> CrsHashMap {
    use crate::{
        consts::{DEFAULT_CENTRAL_CRS_PATH, TEST_CRS_ID},
        util::file_handling::read_element,
    };
    use util::key_setup::ensure_central_crs_store_exists;

    ensure_central_crs_store_exists(
        DEFAULT_PARAM_PATH,
        DEFAULT_CENTRAL_CRS_PATH,
        Some(TEST_CRS_ID.to_string()),
    );
    let crs_map: CrsHashMap = read_element(DEFAULT_CENTRAL_CRS_PATH).unwrap();
    crs_map
}

#[cfg(feature = "slow_tests")]
#[cfg(test)]
mod tests {

    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_server_keys_exist() {
        use crate::consts::DEFAULT_CENTRAL_KEYS_PATH;
        use crate::write_default_keys;

        let _ = write_default_keys(DEFAULT_CENTRAL_KEYS_PATH);
    }

    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_crs_exist() {
        use crate::write_default_crs_store;
        let _ = write_default_crs_store();
    }
}
