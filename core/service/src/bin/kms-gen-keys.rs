use clap::{Parser, Subcommand};
use kms_lib::consts::AMOUNT_PARTIES;
use kms_lib::rpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::storage::StorageReader;
use kms_lib::util::key_setup::test_tools::ensure_threshold_keys_exist;
use kms_lib::{
    consts::{
        DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_THRESHOLD_KEY_ID, OTHER_CENTRAL_DEFAULT_ID,
    },
    storage::{FileStorage, StorageType},
    util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist,
        ensure_central_server_signing_keys_exist,
    },
};
use std::path::Path;
use strum::IntoEnumIterator;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, layer::SubscriberExt, Layer};

#[derive(Parser)]
#[clap(name = "Zama KMS Key Material Generator")]
#[clap(about = "A CLI tool for generating key materials. \
    In the centralized mode, it will generate FHE keys, signing keys and the CRS. \
    In the threshold mode, it will generate FHE key shares and the signing keys, \
    the FHE key shares should be used for testing only. \
    Use the threshold protocols to generate FHE key shares. \
    But observe that threshold mode should only be used for testing since keys will get generated centrally. \n
    For example, to generate centralized keys with the default parameters \
    (from parameters/default_params.json) run: \n
    ./kms-gen-keys centralized \n
    Multiple options are supported which can be explored with \
    kms-key-gen --help")]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Generate centralized FHE keys, signing keys and the CRS.
    Centralized {
        /// Path to the parameters file.
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// Optional parameter for the private storage path,
        /// only use this argument when using file-based storage.
        #[clap(long, default_value = None)]
        priv_path: Option<String>,
        /// Optional parameter for the public storage path,
        /// only use this argument when using file-based storage.
        #[clap(long, default_value = None)]
        pub_path: Option<String>,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
        /// Whether to overwrite ALL the existing keys,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
        /// Whether to output the private FHE key separately,
        #[clap(long, default_value_t = false)]
        write_privkey: bool,
        /// Only show existing keys, do not generate any
        #[clap(long, default_value_t = false)]
        show_existing: bool,
    },

    /// Generate shares of FHE key shares and signing keys.
    /// The FHE key shares should only be used for testing.
    /// At the moment it's only limited to 4 parties.
    Threshold {
        /// Path to the parameters file
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// Optional parameter for the private storage path,
        /// only use this argument when using file-based storage.
        #[clap(long, default_value = None)]
        priv_path: Option<String>,
        /// Optional parameter for the public storage path,
        /// only use this argument when using file-based storage.
        #[clap(long, default_value = None)]
        pub_path: Option<String>,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
        /// Whether to overwrite the existing keys,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
        /// Only show existing keys, do not generate any
        #[clap(long, default_value_t = false)]
        show_existing: bool,
    },
}

/// Execute the KMS key generation
/// Key generation is supported for 2 different modes; centralized and threshold.
/// However, the threshold mode should only be used for testing since keys will get generated centrally.
///
/// For example, to generate centralized keys with the default parameters
/// (from parameters/default_params.json) run:
/// ```
/// ./kms-gen-keys centralized
/// ```
/// Or from cargo:
/// ```
/// cargo run --bin kms-gen-keys centralized
/// ```
/// Multiple options are supported which can be explored with
/// ```
/// ./kms-key-gen --help
/// ```
#[tokio::main]
async fn main() {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();
    let args = Args::parse();
    match args.mode {
        Mode::Centralized {
            param_path,
            priv_path,
            pub_path,
            deterministic,
            overwrite,
            write_privkey,
            show_existing,
        } => {
            let pub_path = pub_path.as_ref().map(Path::new);
            let priv_path = priv_path.as_ref().map(Path::new);
            if show_existing {
                show_keys_centralized(pub_path, priv_path).await;
                return;
            }
            if overwrite {
                // Remove any existing keys
                let _ = FileStorage::purge_centralized(pub_path, StorageType::PUB);
                let _ = FileStorage::purge_centralized(priv_path, StorageType::PRIV);
            }
            if !ensure_central_server_signing_keys_exist(priv_path, pub_path, deterministic).await {
                tracing::warn!("Signing keys already exist, skipping generation");
            }
            if !ensure_central_keys_exist(
                priv_path,
                pub_path,
                &param_path,
                &DEFAULT_CENTRAL_KEY_ID,
                &OTHER_CENTRAL_DEFAULT_ID,
                deterministic,
                write_privkey,
            )
            .await
            {
                tracing::warn!(
                    "FHE keys with default ID {} already exist, skipping generation",
                    DEFAULT_CENTRAL_KEY_ID.to_string()
                );
            }
            if !ensure_central_crs_store_exists(
                priv_path,
                pub_path,
                &param_path,
                &DEFAULT_CRS_ID,
                deterministic,
            )
            .await
            {
                tracing::warn!(
                    "CRS with default ID {} already exist, skipping generation",
                    DEFAULT_CRS_ID.to_string()
                );
            }

            tracing::info!(
                "Default centralized keys written based on parameters stored in {}",
                param_path
            );
        }
        Mode::Threshold {
            param_path,
            priv_path,
            pub_path,
            deterministic,
            overwrite,
            show_existing,
        } => {
            let pub_path = pub_path.as_ref().map(Path::new);
            let priv_path = priv_path.as_ref().map(Path::new);
            if show_existing {
                unimplemented!();
            }
            if overwrite {
                // Remove any existing keys
                for i in 1..=AMOUNT_PARTIES {
                    let _ = FileStorage::purge_threshold(pub_path, StorageType::PUB, i);
                    let _ = FileStorage::purge_threshold(priv_path, StorageType::PRIV, i);
                }
            }
            ensure_threshold_keys_exist(
                priv_path,
                pub_path,
                &param_path,
                &DEFAULT_THRESHOLD_KEY_ID,
                deterministic,
            )
            .await;
            println!(
                "Default threshold keys written based on parameters stored in {}",
                param_path
            );
        }
    }
}

async fn show_keys_centralized(priv_path: Option<&Path>, pub_path: Option<&Path>) {
    let pub_storage = FileStorage::new_centralized(pub_path, StorageType::PUB).unwrap();
    for data_type in PubDataType::iter() {
        let data_type = data_type.to_string();
        let urlmap = pub_storage.all_urls(&data_type).await.unwrap();
        for (k, v) in urlmap {
            // TODO read the key material and print extra info
            let buf: Vec<u8> = pub_storage.read_data(&v).await.unwrap();
            println!("{data_type}, {k}, {v}, {}", buf.len());
        }
    }

    let priv_storage = FileStorage::new_centralized(priv_path, StorageType::PRIV).unwrap();
    for data_type in PrivDataType::iter() {
        let data_type = data_type.to_string();
        let urlmap = priv_storage.all_urls(&data_type).await.unwrap();
        for (k, v) in urlmap {
            // TODO read the key material and print extra info
            let buf: Vec<u8> = pub_storage.read_data(&v).await.unwrap();
            println!("{data_type}, {k}, {v}, {}", buf.len());
        }
    }
}
