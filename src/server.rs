use kms::rpc::kms_rpc::server_handle;
use setup_rpc::DEFAULT_KMS_KEY_PATH;
use std::env;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

mod setup_rpc;

// URL format is without protocol e.g.: 0.0.0.0:50051
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        return Err(
            "Server URL not provided. Please provide the server URL as the second argument.".into(),
        );
    }
    let url = &args[1];
    server_handle(url, DEFAULT_KMS_KEY_PATH.to_string()).await?;
    Ok(())
}
