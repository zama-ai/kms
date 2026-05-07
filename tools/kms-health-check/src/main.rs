use anyhow::Result;
use clap::ValueEnum;
use clap::{Parser, Subcommand};
use std::path::Path;
use std::path::PathBuf;

use crate::output::print_bandwidth_benchmark_text;

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
        /// KMS endpoint (e.g., http://localhost:50100)
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
    /// Runs a bandwidth benchmark against the KMS endpoint
    /// NOTE: It makes more sense to run it on all the parties at the same time to emulate real bandwidth usage, but it can be run on a single party as well.
    BandwidthBench {
        /// KMS endpoint
        #[arg(short, long)]
        endpoint: Vec<String>,

        /// Context id for the bandwidth benchmark
        #[arg(short, long)]
        context_id: String,

        /// Duration of the benchmark in seconds
        #[arg(short, long)]
        duration_seconds: u64,

        /// Number of sessions trying to send bytes in parallel
        #[arg(short, long)]
        num_sessions: u32,

        /// Payload size per session in bytes
        #[arg(short, long)]
        payload_size: u32,
    },
}

#[derive(Debug, Clone, ValueEnum)]
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

    // Display startup configuration info
    tracing::info!("KMS Health Check Tool starting...");
    tracing::info!("Log level: {}", log_level);
    tracing::info!("Output format: {:?}", cli.format);

    match cli.command {
        Commands::Config { file } => {
            output::print_result(
                checks::run_config_validation(file.to_str().unwrap()).await?,
                &cli.format,
            )?;
        }
        Commands::Live { endpoint, config } => {
            output::print_result(
                checks::check_live(&endpoint, config.as_deref().map(Path::new)).await?,
                &cli.format,
            )?;
        }
        Commands::Full { endpoint, config } => {
            output::print_result(
                checks::run_full_check(Some(config.to_str().unwrap()), &endpoint).await?,
                &cli.format,
            )?;
        }
        Commands::BandwidthBench {
            endpoint,
            context_id,
            duration_seconds,
            num_sessions,
            payload_size,
        } => {
            if let OutputFormat::Json = cli.format {
                println!(
                    "Json not suported for bandwidth benchmark results, defaulting to text output"
                );
            }
            let mut joinset = tokio::task::JoinSet::new();
            for ep in endpoint {
                let context_id = context_id.clone();
                joinset.spawn(async move {
                    let result = checks::run_bandwidth_benchmark(
                        &ep,
                        context_id,
                        duration_seconds,
                        num_sessions,
                        payload_size,
                    )
                    .await;
                    (ep, result)
                });
            }
            let mut results = Vec::new();
            while let Some(res) = joinset.join_next().await {
                let (endpoint, result) = res?;
                let result = result?;
                results.push((endpoint, result));
            }
            print_bandwidth_benchmark_text(duration_seconds, num_sessions, payload_size, results)?;
        }
    };

    Ok(())
}
