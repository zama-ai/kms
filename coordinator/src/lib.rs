use aes_prng::AesRng;
use anyhow::anyhow;
use consts::{DEFAULT_CRS_HANDLE, DEFAULT_PARAM_PATH, KEY_HANDLE};
#[cfg(feature = "non-wasm")]
use core::kms_core::{gen_sig_keys, CrsHashMap, SoftwareKmsKeys};
use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::tfhe_internals::test_feature::gen_key_set;
#[cfg(feature = "non-wasm")]
use file_handling::{read_as_json, write_element};
use rand::SeedableRng;
#[cfg(feature = "non-wasm")]
use std::collections::HashMap;
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
pub mod setup_rpc;
pub mod core {
    pub mod der_types;
    #[cfg(feature = "non-wasm")]
    pub mod kms_core;
    #[cfg(feature = "non-wasm")]
    pub mod request;
    pub mod signcryption;
}
#[cfg(feature = "non-wasm")]
pub mod threshold {
    pub mod threshold_kms;
}
#[cfg(feature = "non-wasm")]
pub mod file_handling;
pub mod rpc {
    #[cfg(feature = "non-wasm")]
    pub mod kms_proxy_rpc;
    #[cfg(feature = "non-wasm")]
    pub mod kms_rpc;
    pub mod rpc_types;
}

#[track_caller]
pub fn anyhow_error_and_log(msg: String) -> anyhow::Error {
    tracing::error!("Error in {}: {}", Location::caller(), msg);
    anyhow!("Error in {}: {}", Location::caller(), msg)
}

#[track_caller]
pub fn anyhow_error_and_warn_log(msg: String) -> anyhow::Error {
    tracing::warn!("Warning in {}: {}", Location::caller(), msg);
    anyhow!("Warning in {}: {}", Location::caller(), msg)
}

#[cfg(feature = "non-wasm")]
pub fn write_default_keys(path: &str) -> SoftwareKmsKeys {
    let mut rng = AesRng::from_entropy();
    let params: NoiseFloodParameters = read_as_json(DEFAULT_PARAM_PATH.to_owned()).unwrap();
    // Generate keys for SnS
    let key_set = gen_key_set(params, &mut rng);
    let (server_pk, server_sk) = gen_sig_keys(&mut rng);

    // ensure that path ends with a '/' to avoid problems with file handling in the rest of this fn
    let mut path_string = path.to_string();
    if !path_string.ends_with('/') {
        path_string.push('/');
    }

    write_element(
        format!("{path_string}pks.bin"),
        &key_set.public_keys.public_key,
    )
    .unwrap();
    write_element(format!("{path_string}sks.bin"), &key_set.client_key).unwrap();
    write_element(
        format!("{path_string}cks.bin"),
        &key_set.public_keys.server_key,
    )
    .unwrap();

    let software_kms_keys = SoftwareKmsKeys {
        client_keys: HashMap::from([(KEY_HANDLE.to_string(), key_set.client_key)]),
        sig_sk: server_sk,
        sig_pk: server_pk.clone(),
    };
    write_element(
        format!("{path_string}default-software-keys.bin"),
        &software_kms_keys,
    )
    .unwrap();

    software_kms_keys
}

#[cfg(feature = "non-wasm")]
pub fn write_default_crs_store(path: &str) -> CrsHashMap {
    let mut rng = AesRng::from_entropy();
    let params: NoiseFloodParameters = read_as_json(DEFAULT_PARAM_PATH.to_owned()).unwrap();

    // ensure that path ends with a '/' to avoid problems with file handling in the rest of this fn
    let mut path_string = path.to_string();
    if !path_string.ends_with('/') {
        path_string.push('/');
    }

    let crs = crate::core::kms_core::gen_centralized_crs(&params, &mut rng);
    let crs_store = CrsHashMap::from([(DEFAULT_CRS_HANDLE.to_string(), crs)]);

    write_element(format!("{path_string}default-crs-store.bin"), &crs_store).unwrap();

    crs_store
}

#[cfg(test)]
mod tests {
    use crate::consts::{
        CRS_PATH_PREFIX, DEFAULT_CENTRAL_CRS_PATH, DEFAULT_SOFTWARE_CENTRAL_KEY_PATH,
        TMP_PATH_PREFIX,
    };
    use crate::setup_rpc::ensure_dir_exist;
    use crate::write_default_crs_store;
    use std::path::Path;

    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_server_keys_exist() {
        use crate::write_default_keys;
        ensure_dir_exist();

        if !Path::new(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH).exists() {
            let _ = write_default_keys(TMP_PATH_PREFIX);
        }
    }
    #[cfg(test)]
    #[ctor::ctor]
    fn ensure_crs_store_exist() {
        ensure_dir_exist();
        if !Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
            let _ = write_default_crs_store(CRS_PATH_PREFIX);
        }
    }
}
