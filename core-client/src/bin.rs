use clap::Parser;
use kms_core_client::{execute_cmd, setup_logging, CmdConfig};
use kms_lib::consts::SIGNING_KEY_ID;
use kms_lib::engine::context::SoftwareVersion;
use kms_lib::util::key_setup::ensure_client_keys_exist;
use std::path::Path;
use validator::Validate;

// CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    println!("Starting KMS Core Client v{}", SoftwareVersion::current()?);

    // Parse command line arguments and configuration file
    // TODO: handle different deployment modes in the configuration
    let config = CmdConfig::parse();
    config.validate()?;
    if config.logs {
        // Logging configuration
        setup_logging();
    }

    let keys_folder: &Path = Path::new("keys");

    ensure_client_keys_exist(Some(keys_folder), &SIGNING_KEY_ID, true).await;

    let res = execute_cmd(&config, keys_folder).await;

    match res {
        Ok(vec_res) => {
            for (opt_req_id, msg) in vec_res {
                match opt_req_id {
                    Some(req_id) => {
                        // WARNING: This format MUST not be changed since the current deployment configuration runs a grep on "request_id"
                        println!("{msg} - \"request_id\": \"{req_id}\"");
                    }
                    None => {
                        println!("{msg} - no request_id returned");
                    }
                }
            }
            return Ok(());
        }
        Err(err) => return Err(err),
    }
}
