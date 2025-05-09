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

    // We need to make sure the request_id is
    // formatted using serde_json in the old way,
    // so we create a temporary struct to do this.
    #[derive(serde::Serialize)]
    struct FormattedRequestId {
        request_id: String,
    }

    match res {
        Ok(vec_res) => {
            for (success, msg) in vec_res.into_iter() {
                if let Some(value) = success {
                    let formatted_request_id = FormattedRequestId {
                        request_id: format!("{}", value),
                    };
                    println!(
                        "{msg} - {}",
                        serde_json::to_string_pretty(&formatted_request_id)?
                    );
                }
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    }
}
