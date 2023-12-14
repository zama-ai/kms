use setup_rpc::{server_handle, DEFAULT_KMS_KEY_PATH};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, Layer};

mod setup_rpc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::WARN))
        .init();

    server_handle(
        "0.0.0.0:50051".to_string(),
        DEFAULT_KMS_KEY_PATH.to_string(),
    )
    .await;
    Ok(())
}
