use std::path::Path;

use clap::{Parser, Subcommand};
use kms_lib::{
    consts::{
        DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_THRESHOLD_KEY_ID, OTHER_CENTRAL_DEFAULT_ID,
    },
    storage::{FileStorage, StorageType},
    util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist,
        ensure_central_server_signing_keys_exist, ensure_threshold_keys_exist,
        ensure_threshold_server_signing_keys_exist,
    },
};
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
    For example, to generate centralized keys with the default paramters \
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
        /// Whether to overwrite the existing keys,
        #[clap(long, default_value_t = false)]
        overwrite: bool,
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
    },
}

/// Execute the KMS key generation
/// Key generation is supported for 2 different modes; centralized and threshold.
/// However, the threshold mode should only be used for testing since keys will get generated centrally.
///
/// For example, to generate centralized keys with the default paramters
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
        } => {
            let pub_path = pub_path.as_ref().map(Path::new);
            let priv_path = priv_path.as_ref().map(Path::new);
            if overwrite {
                // Remove any existing keys
                for storage in StorageType::iter() {
                    FileStorage::purge_centralized(pub_path, storage).unwrap();
                    FileStorage::purge_centralized(priv_path, storage).unwrap();
                }
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
            )
            .await
            {
                tracing::warn!("FHE keys already exist, skipping generation");
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
                tracing::warn!("CRS already exist, skipping generation");
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
        } => {
            let pub_path = pub_path.as_ref().map(Path::new);
            let priv_path = priv_path.as_ref().map(Path::new);
            ensure_threshold_server_signing_keys_exist(priv_path, pub_path, deterministic).await;
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
