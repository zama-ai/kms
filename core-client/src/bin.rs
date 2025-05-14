use clap::Parser;
use kms_core_client::*;
use kms_lib::util::key_setup::{ensure_client_keys_exist, test_tools::SIGNING_KEY_ID};
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

    ensure_client_keys_exist(Some(keys_folder), &SIGNING_KEY_ID, true).await;

    let res = execute_cmd(&config, keys_folder).await;

    match res {
        Ok(vec_res) => {
            for (success, msg) in vec_res.into_iter() {
                if let Some(value) = success {
                    // WARNING: This format MUST not be changed since the current deployment configuration runs a grep on "request_id"
                    println!("{msg} - \"request_id\": \"{}\"", value);
                }
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    }
}
