use aes_prng::AesRng;
use distributed_decryption::lwe::{gen_key_set, ThresholdLWEParameters};
use kms_lib::{
    core::kms_core::{gen_sig_keys, SoftwareKmsKeys},
    file_handling::{read_as_json, read_element, write_element},
    rpc::kms_rpc::server_handle,
    setup_rpc::{recover_sk, DEFAULT_PARAM_PATH},
};
use rand::SeedableRng;
use std::{env, path::Path};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

pub const DEFAULT_SOFTWARE_CENTRAL_KEY_PATH: &str = "temp/default-software-keys.bin";

// URL format is without protocol e.g.: 0.0.0.0:50051
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();

    let args: Vec<String> = env::args().collect();
    let url = if args.len() < 2 {
        tracing::info!("No URL supplied. Using localhost: \"http://0.0.0.0\"");
        "http://0.0.0.0".to_string()
    } else if !args[1].contains("://") {
        tracing::info!("No protocol specified in URL. Using http as default");
        format!("http://{}", args[1])
    } else {
        args[1].to_owned()
    };
    let keys: SoftwareKmsKeys = if Path::new(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH).exists() {
        read_element(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH)?
    } else {
        tracing::info!(
            "Could not find default keys. Generating new keys with default parameters..."
        );
        write_default_keys()
    };
    server_handle(&url, keys).await?;
    Ok(())
}

fn write_default_keys() -> SoftwareKmsKeys {
    let mut rng = AesRng::from_entropy();
    let params: ThresholdLWEParameters = read_as_json(DEFAULT_PARAM_PATH.to_owned()).unwrap();
    let key_set = gen_key_set(params, &mut rng);
    let fhe_sk = recover_sk(key_set.sk);
    let (server_pk, server_sk) = gen_sig_keys(&mut rng);
    let software_kms_keys = SoftwareKmsKeys {
        fhe_sk,
        sig_sk: server_sk,
        sig_pk: server_pk.clone(),
    };
    write_element(
        DEFAULT_SOFTWARE_CENTRAL_KEY_PATH.to_string(),
        &software_kms_keys,
    )
    .unwrap();
    software_kms_keys
}

#[cfg(test)]
mod tests {
    use crate::{write_default_keys, DEFAULT_SOFTWARE_CENTRAL_KEY_PATH};
    use ctor::ctor;
    use std::path::Path;

    #[ctor]
    #[test]
    #[ignore]
    fn ensure_server_keys_exist() {
        if !Path::new(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH).exists() {
            let _ = write_default_keys();
        }
    }
}
