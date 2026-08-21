use clap::Parser;
use kms_core_client::{CmdConfig, execute_cmd, setup_logging};
use kms_lib::engine::context::SoftwareVersion;
use std::path::Path;
use validator::Validate;

// CLI
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + 'static>> {
    println!("Starting KMS Core Client v{}", SoftwareVersion::current()?);
    println!(
        "CORE_CLIENT_THREADING phase=startup available_parallelism={} tokio_workers={} process_threads={}",
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        tokio::runtime::Handle::current().metrics().num_workers(),
        std::fs::read_dir("/proc/self/task").map_or(0, |tasks| tasks.count()),
    );

    // Parse command line arguments and configuration file
    // TODO: handle different deployment modes in the configuration
    let config = CmdConfig::parse();
    config.validate()?;
    if config.logs {
        // Logging configuration
        setup_logging();
    }

    let keys_folder: &Path = Path::new("keys");
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
