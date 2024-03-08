use aes_prng::AesRng;
use anyhow::anyhow;
use core::kms_core::{gen_sig_keys, SoftwareKmsKeys};
use distributed_decryption::lwe::{gen_key_set, ThresholdLWEParameters};
use file_handling::read_as_json;
use file_handling::write_element;
use rand::SeedableRng;
use setup_rpc::recover_bsk;
use setup_rpc::recover_pk;
use setup_rpc::recover_sk;
use std::panic::Location;

use self::setup_rpc::DEFAULT_PARAM_PATH;

pub mod kms {
    tonic::include_proto!("kms"); // The string specified here must match the proto package name
}
pub mod setup_rpc;
pub mod core {
    pub mod der_types;
    pub mod kms_core;
    pub mod request;
    pub mod signcryption;
}
pub mod threshold {
    pub mod threshold_kms;
}
pub mod file_handling;
pub mod rpc {
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

pub fn write_default_keys(path: &str) -> SoftwareKmsKeys {
    let mut rng = AesRng::from_entropy();
    let params: ThresholdLWEParameters = read_as_json(DEFAULT_PARAM_PATH.to_owned()).unwrap();
    let key_set = gen_key_set(params, &mut rng);
    let fhe_pk = recover_pk(key_set.sk.clone());
    let fhe_sk = recover_sk(key_set.sk);
    let fhe_bsk = recover_bsk(&fhe_sk);
    let (server_pk, server_sk) = gen_sig_keys(&mut rng);

    write_element(format!("{path}pks.bin"), &fhe_pk).unwrap();
    write_element(format!("{path}sks.bin"), &fhe_bsk).unwrap();
    write_element(format!("{path}cks.bin"), &fhe_sk).unwrap();

    let software_kms_keys = SoftwareKmsKeys {
        fhe_sk,
        sig_sk: server_sk,
        sig_pk: server_pk.clone(),
    };
    write_element(
        format!("{path}default-software-keys.bin"),
        &software_kms_keys,
    )
    .unwrap();

    software_kms_keys
}

#[cfg(test)]
mod tests {
    use crate::write_default_keys;
    use ctor::ctor;
    use std::path::Path;

    #[ctor]
    #[test]
    #[ignore]
    fn ensure_server_keys_exist() {
        let file = "temp/default_keys.bin";
        if !Path::new(file).exists() {
            let _ = write_default_keys(file);
        }
    }
}
