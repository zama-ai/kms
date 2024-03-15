use kms_lib::core::kms_core::SoftwareKmsKeys;
use kms_lib::file_handling::read_element;
use kms_lib::rpc::kms_rpc::server_handle;
use kms_lib::setup_rpc::KEY_HANDLE;
use kms_lib::write_default_keys;
use std::env;
use std::path::Path;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

pub const DEFAULT_SOFTWARE_CENTRAL_KEY_PATH: &str = "temp/";

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
        read_element(&format!(
            "{DEFAULT_SOFTWARE_CENTRAL_KEY_PATH}default-software-keys.bin"
        ))?
    } else {
        tracing::info!(
            "Could not find default keys. Generating new keys with default parameters and handle \"{}\"...", KEY_HANDLE
        );
        write_default_keys(DEFAULT_SOFTWARE_CENTRAL_KEY_PATH)
    };

    server_handle(&url, keys).await?;
    Ok(())
}
