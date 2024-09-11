use clap::Parser;
use simulator::*;
use std::path::Path;

// CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Logging configuration
    setup_logging();

    // Parse command line arguments and configuration file
    // TODO: handle different deployment modes in the configuration
    let config = Config::parse();

    let keys_folder: &Path = Path::new("keys");
    let res = main_from_config(
        &config
            .file_conf
            .unwrap_or_else(|| "config/local.toml".to_string()),
        &config.command,
        keys_folder,
    )
    .await;

    match res {
        Ok(_) => return Ok(()),
        Err(err) => return Err(err),
    }
}
