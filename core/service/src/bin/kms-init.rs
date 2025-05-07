use clap::Parser;
use conf_trace::conf::TelemetryConfig;
use conf_trace::telemetry::init_tracing;
use kms_grpc::kms::v1::{InitRequest, RequestId};
use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
use kms_lib::consts::PRSS_INIT_REQ_ID;

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
    // Initialize telemetry with stdout tracing only and disabled metrics
    let telemetry = TelemetryConfig::builder()
        .tracing_service_name("kms_core".to_string())
        .build();
    init_tracing(&telemetry)?;

    let args = Args::parse();

    let mut handles = Vec::new();

    for addr in args.addresses {
        handles.push(tokio::spawn(async {
            let mut kms_client = CoreServiceEndpointClient::connect(addr).await.unwrap();

            // TODO: the init epoch ID is currently fixed to PRSS_INIT_REQ_ID
            // change this once we want to trigger another init for a different context/epoch
            let req_id = RequestId {
                request_id: PRSS_INIT_REQ_ID.to_string(),
            };

            let request = InitRequest {
                request_id: Some(req_id),
            };
            let _ = kms_client.init(request).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await?;
    }

    Ok(())
}
