use clap::{Parser, Subcommand};
use kms_lib::{
    consts::{
        DEFAULT_CENTRAL_KEY_ID, DEFAULT_CRS_ID, DEFAULT_THRESHOLD_KEY_ID, OTHER_CENTRAL_DEFAULT_ID,
    },
    util::key_setup::{
        ensure_central_crs_store_exists, ensure_central_keys_exist,
        ensure_central_server_signing_keys_exist, ensure_dir_exist, ensure_threshold_keys_exist,
        ensure_threshold_server_signing_keys_exist,
    },
};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, layer::SubscriberExt, Layer};

#[derive(Parser)]
#[clap(name = "Zama KMS Key Material Generator")]
#[clap(about = "A CLI tool for generating key materials. \
    In the centralized mode, it will generate FHE keys and signing keys. \
    In the threshold mode, it will only generate signing keys, \
    the threshold key shares must be generated using a distributed protocol.")]
struct Args {
    #[clap(subcommand)]
    mode: Mode,
}

#[derive(Clone, Subcommand)]
enum Mode {
    /// Generate centralized FHE keys, signing keys and the CRS.
    Centralized {
        /// Path to the parameters file
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
    },
    /// Generate shares of FHE keys, signing keys and the CRS.
    /// This option should only be used for testing.
    Threshold {
        /// Path to the parameters file
        #[clap(long, default_value = "parameters/default_params.json")]
        param_path: String,
        /// Whether to generate keys deterministically,
        /// only use this option for testing.
        /// The determinism is not guaranteed to be the same between releases.
        #[clap(long, default_value_t = false)]
        deterministic: bool,
    },
}

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
            deterministic,
        } => {
            ensure_dir_exist().await;
            ensure_central_server_signing_keys_exist(deterministic).await;
            ensure_central_keys_exist(
                &param_path,
                &DEFAULT_CENTRAL_KEY_ID,
                &OTHER_CENTRAL_DEFAULT_ID,
                deterministic,
            )
            .await;
            ensure_central_crs_store_exists(&param_path, &DEFAULT_CRS_ID, deterministic).await;

            println!(
                "Default centralized keys written based on parameters stored in {}",
                param_path
            );
        }
        Mode::Threshold {
            param_path,
            deterministic,
        } => {
            ensure_dir_exist().await;
            ensure_threshold_server_signing_keys_exist(deterministic).await;
            ensure_threshold_keys_exist(&param_path, &DEFAULT_THRESHOLD_KEY_ID, deterministic)
                .await;
            // The CRS store is the same in both cases.
            ensure_central_crs_store_exists(&param_path, &DEFAULT_CRS_ID, deterministic).await;

            println!(
                "Default threshold keys written based on parameters stored in {}",
                param_path
            );
        }
    }
}
