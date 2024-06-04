use clap::Parser;
use distributed_decryption::conf::telemetry::init_tracing;
use distributed_decryption::conf::{party::PartyConf, Settings};
use distributed_decryption::grpc;

#[derive(Parser, Debug)]
#[clap(name = "moby")]
#[clap(about = "MPC party in a FHE threshold network")]
pub struct Cli {
    /// Config file with the party's configuration.
    #[clap(short, long)]
    conf_file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    let settings_builder = Settings::builder();
    let settings: PartyConf = if let Some(path) = args.conf_file {
        settings_builder.path(&path).build().init_conf()?
    } else {
        settings_builder.build().init_conf()?
    };

    init_tracing(settings.tracing.clone())?;
    grpc::server::run(&settings).await
}
