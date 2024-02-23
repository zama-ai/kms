use kms_lib::{
    core::kms_core::SoftwareKmsKeys, file_handling::read_element, rpc::kms_rpc::server_handle,
};
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

pub const DEFAULT_SOFTWARE_CENTRAL_KEY_PATH: &str = "temp/default-software-keys.bin";

// URL format is without protocol e.g.: 0.0.0.0:50051
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(
            "Server URL not provided. Please provide the server URL as the second argument.".into(),
        );
    }
    let url = &args[1];
    let keys: SoftwareKmsKeys = read_element(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH)?;
    server_handle(url, keys).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::DEFAULT_SOFTWARE_CENTRAL_KEY_PATH;
    use aes_prng::AesRng;
    use ctor::ctor;
    use distributed_decryption::lwe::{gen_key_set, ThresholdLWEParameters};
    use kms_lib::{
        core::kms_core::{gen_sig_keys, SoftwareKmsKeys},
        file_handling::{read_as_json, write_element},
        setup_rpc::{recover_sk, DEFAULT_PARAM_PATH},
    };
    use rand::SeedableRng;
    use std::path::Path;

    #[ctor]
    #[test]
    fn ensure_server_keys_exist() {
        if !Path::new(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH).exists() {
            let mut rng = AesRng::seed_from_u64(1);
            let params: ThresholdLWEParameters =
                read_as_json(DEFAULT_PARAM_PATH.to_owned()).unwrap();
            let key_set = gen_key_set(params, &mut rng);
            let fhe_sk = recover_sk(key_set.sk);
            let mut rng = AesRng::seed_from_u64(1);
            let (server_pk, server_sk) = gen_sig_keys(&mut rng);
            let software_kms_keys = SoftwareKmsKeys {
                fhe_sk,
                sig_sk: server_sk,
                sig_pk: server_pk.clone(),
            };
            assert!(write_element(
                DEFAULT_SOFTWARE_CENTRAL_KEY_PATH.to_string(),
                &software_kms_keys,
            )
            .is_ok());
        }
    }
}
