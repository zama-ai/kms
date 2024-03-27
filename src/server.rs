use kms_lib::consts::{
    CRS_PATH_PREFIX, DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CRS_HANDLE,
    DEFAULT_SOFTWARE_CENTRAL_KEY_PATH, KEY_HANDLE, TMP_PATH_PREFIX,
};
use kms_lib::core::kms_core::{CrsHashMap, SoftwareKmsKeys};
use kms_lib::file_handling::read_element;
use kms_lib::rpc::kms_rpc::server_handle;
use kms_lib::{write_default_crs_store, write_default_keys};
use std::env;
use std::path::Path;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

// Starts a server where the first argument is the URL and following arguments are key handles of
// existing keys.
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
            "Could not find default keys. Generating new keys with default parameters and handle \"{}\"...", KEY_HANDLE
        );
        write_default_keys(TMP_PATH_PREFIX)
    };

    let crs_store: CrsHashMap = if Path::new(DEFAULT_CENTRAL_CRS_PATH).exists() {
        read_element(DEFAULT_CENTRAL_CRS_PATH)?
    } else {
        tracing::info!(
            "Could not find default CRS store. Generating new CRS store with default parameters and handle \"{}\"...", DEFAULT_CRS_HANDLE
        );
        write_default_crs_store(CRS_PATH_PREFIX)
    };

    server_handle(&url, keys, Some(crs_store)).await?;
    Ok(())
}
