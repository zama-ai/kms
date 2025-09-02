use anyhow::Result;
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use std::path::Path;
use std::path::PathBuf;

mod checks;
mod config;
mod grpc_client;
mod output;

#[derive(Parser)]
#[command(name = "kms-health-check")]
#[command(
    about = "Minimal KMS health check tool for configuration validation and live health monitoring"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output format
    #[arg(short, long, value_enum, default_value = "text")]
    format: OutputFormat,

    /// Verbosity level
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate KMS configuration file
    Config {
        /// Path to KMS config file (centralized or threshold)
        #[arg(short, long)]
        file: PathBuf,
    },
    /// Check live KMS instance health
    Live {
        /// KMS endpoint (e.g., http://localhost:9090)
        #[arg(short, long)]
        endpoint: String,

        /// Optional config file for peer checks (threshold only)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Run all checks (config + live)
    Full {
        /// KMS endpoint
        #[arg(short, long)]
        endpoint: String,

        /// Config file path
        #[arg(short, long)]
        config: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing based on verbosity
    let log_level = match cli.verbose {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let result = match cli.command {
        Commands::Config { file } => checks::run_config_validation(file.to_str().unwrap()).await?,
        Commands::Live { endpoint, config } => {
            checks::check_live(&endpoint, config.as_deref().map(Path::new)).await?
        }
        Commands::Full { endpoint, config } => {
            checks::run_full_check(Some(config.to_str().unwrap()), &endpoint).await?
        }
    };

    output::print_result(result, &cli.format)?;
    Ok(())
}
