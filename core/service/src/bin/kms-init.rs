use clap::Parser;
use kms_lib::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
use kms_lib::kms::{Config, InitRequest};
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{filter, layer::SubscriberExt, Layer};

/// This CLI initializes the threshold KMS core nodes.
/// After the KMS servers are up and running (using the kms-server)
/// command, a final step is needed to initialize the nodes.
/// In more details, this is to initialize the PRSS state.
/// The easiest way is to execute the command
/// `kms-init -a http://127.0.0.1:50100 http://127.0.0.1:50200 http://127.0.0.1:50300 http://127.0.0.1:50400`
/// if all the nodes are on the same network.
/// Alternatively, if the client-facing GRPC endpoint is not publicly reachable,
/// then `kms-init` must be executed against every KMS core node.
#[derive(Parser)]
#[clap(name = "KMS initialization CLI")]
struct Args {
    /// A list of addresses of uninitialized cores.
    #[clap(short, long, required = true)]
    #[arg(num_args(1..))]
    addresses: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();
    let args = Args::parse();

    let mut handles = Vec::new();
    for addr in args.addresses {
        handles.push(tokio::spawn(async {
            let mut kms_client = CoordinatorEndpointClient::connect(addr).await.unwrap();
            let request = InitRequest {
                config: Some(Config {}),
            };
            let _ = kms_client.init(request).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}
