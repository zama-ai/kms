use clap::Parser;
use simulator::*;
use std::path::Path;

// CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    // Parse command line arguments and configuration file
    // TODO: handle different deployment modes in the configuration
    let config = Config::parse();
    if config.logs {
        // Logging configuration
        setup_logging();
    }

    let keys_folder: &Path = Path::new("keys");
    let res = main_from_config(
        &config
            .file_conf
            .unwrap_or_else(|| "config/local_centralized.toml".to_string()),
        &config.command,
        keys_folder,
        Some(config.max_iter),
    )
    .await;

    match res {
        Ok(success) => {
            if let Some(value) = success {
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    }
}
