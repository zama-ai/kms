use clap::Parser;
use kms_core_client::*;
use kms_lib::util::key_setup::ensure_client_keys_exist;
use std::path::Path;

// CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    println!("Starting Core Client");

    // Parse command line arguments and configuration file
    // TODO: handle different deployment modes in the configuration
    let config = CmdConfig::parse();
    if config.logs {
        // Logging configuration
        setup_logging();
    }

    let keys_folder: &Path = Path::new("keys");

    ensure_client_keys_exist(
        Some(keys_folder),
        &kms_grpc::rpc_types::SIGNING_KEY_ID,
        true,
    )
    .await;

    let res = execute_cmd(&config, keys_folder).await;

    match res {
        Ok((success, msg)) => {
            if let Some(value) = success {
                println!("{msg} - {}", serde_json::to_string_pretty(&value)?);
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    }
}
