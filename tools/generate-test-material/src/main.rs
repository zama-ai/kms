//! Pre-generation tool for KMS test material
//!
//! This tool generates cryptographic material for KMS tests ahead of time so
//! test runs can copy read-only fixtures into isolated temporary directories.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use kms_lib::testing::material::{
    CENTRALIZED_MATERIAL_SUBDIR, MaterialType, material_subdir, threshold_material_subdir,
};
use kms_lib::testing::utils::setup::{
    generate_central_material_to_path, generate_threshold_material_to_path,
};
use path_absolutize::Absolutize;
use std::collections::BTreeSet;
use tracing::info;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum Profile {
    /// Testing parameters (fast, small keys)
    Insecure,
    /// Default parameters (production-like, slower)
    Secure,
}

impl From<Profile> for MaterialType {
    fn from(profile: Profile) -> Self {
        match profile {
            Profile::Insecure => MaterialType::Testing,
            Profile::Secure => MaterialType::Default,
        }
    }
}

#[derive(Parser)]
#[command(name = "generate-test-material")]
#[command(about = "Pre-generates test material for KMS tests")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Output directory for generated material
    #[arg(short, long, default_value = "./test-material")]
    output: PathBuf,

    /// Cryptographic profile(s) to generate.
    /// Use `insecure,secure` to generate all test material.
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [Profile::Insecure, Profile::Secure])]
    profile: Vec<Profile>,

    /// Threshold party counts to generate in addition to centralized material
    #[arg(long, value_delimiter = ',')]
    parties: Vec<usize>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Remove any existing profile directory before regenerating it
    #[arg(short, long)]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Clean existing test material
    Clean,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let default_level = if cli.verbose { "debug" } else { "info" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(format!(
            "generate_test_material={default_level},kms={default_level}"
        ))
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Ensure output directory is absolute
    let output_dir = cli
        .output
        .absolutize()
        .context("Failed to resolve absolute path for output directory")?
        .to_path_buf();

    info!("KMS Test Material Generator");
    info!("Output directory: {}", output_dir.display());

    // Create output directory if it doesn't exist
    tokio::fs::create_dir_all(&output_dir)
        .await
        .with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;

    match cli.command {
        Some(Commands::Clean) => {
            clean_material(&output_dir).await?;
        }
        None => {
            generate_requested_material(&output_dir, &cli.profile, &cli.parties, cli.force).await?;
        }
    }

    info!("Operation completed successfully");
    Ok(())
}

async fn generate_requested_material(
    output_dir: &Path,
    profiles: &[Profile],
    parties: &[usize],
    force: bool,
) -> Result<()> {
    if profiles.is_empty() {
        bail!("At least one --profile must be provided");
    }

    for profile in profiles {
        generate_profile_material(output_dir, *profile, parties, force).await?;
    }

    Ok(())
}

async fn generate_profile_material(
    output_dir: &Path,
    profile: Profile,
    parties: &[usize],
    force: bool,
) -> Result<()> {
    use tokio::fs;

    let material_type: MaterialType = profile.into();
    let profile_dir = output_dir.join(material_subdir(material_type));

    info!(
        "Generating {:?} material with centralized fixtures and threshold parties {:?}",
        profile, parties
    );

    if force && profile_dir.exists() {
        fs::remove_dir_all(&profile_dir).await.with_context(|| {
            format!(
                "Failed to remove existing material directory: {}",
                profile_dir.display()
            )
        })?;
    }

    fs::create_dir_all(&profile_dir).await?;
    let centralized_dir = profile_dir.join(CENTRALIZED_MATERIAL_SUBDIR);
    generate_central_material_to_path(material_type, Some(&centralized_dir)).await;

    for party_count in parties.iter().copied().collect::<BTreeSet<_>>() {
        let threshold_dir = profile_dir.join(threshold_material_subdir(party_count));
        generate_threshold_material_to_path(material_type, Some(&threshold_dir), party_count)
            .await?;
    }

    info!(
        "{:?} material generated successfully at: {}",
        profile,
        profile_dir.display()
    );
    Ok(())
}

async fn clean_material(output_dir: &Path) -> Result<()> {
    info!("Cleaning test material in: {}", output_dir.display());

    if !output_dir.exists() {
        info!("Output directory does not exist, nothing to clean");
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(output_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            tokio::fs::remove_dir_all(&path).await?;
        } else {
            tokio::fs::remove_file(&path).await?;
        }
        info!("Removed: {}", path.display());
    }

    info!("Test material cleaned successfully");
    Ok(())
}
