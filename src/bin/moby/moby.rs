use distributed_decryption::conf::telemetry::init_tracing;
use distributed_decryption::conf::{party::PartyConf, Settings};
use distributed_decryption::grpc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings: PartyConf = Settings::builder().build().init_conf()?;
    init_tracing(settings.tracing.clone())?;
    grpc::server::run(&settings).await
}
