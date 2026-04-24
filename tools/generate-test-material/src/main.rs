//! Pre-generation tool for KMS test material
//!
//! This tool generates cryptographic material for KMS tests ahead of time so
//! test runs can copy read-only fixtures into isolated temporary directories.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use kms_lib::testing::material::{MaterialType, material_subdir};
use kms_lib::testing::utils::setup::generate_material_to_path;
use kms_lib::vault::storage::StorageType;
use path_absolutize::Absolutize;
use tracing::{info, warn};

/// Storage types that are required for test material.
/// Note: BACKUP is excluded as it's not used in test material generation.
const REQUIRED_STORAGE_TYPES: [StorageType; 3] =
    [StorageType::PUB, StorageType::PRIV, StorageType::CLIENT];

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
    /// Validate existing test material
    Validate,
    /// Clean existing test material
    Clean,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "generate_test_material={},kms={}",
            log_level, log_level
        ))
        .init();

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
        Some(Commands::Validate) => {
            validate_material(&output_dir).await?;
        }
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
    generate_material_to_path(material_type, Some(&profile_dir), parties).await?;

    info!(
        "{:?} material generated successfully at: {}",
        profile,
        profile_dir.display()
    );
    Ok(())
}

async fn validate_material(output_dir: &Path) -> Result<()> {
    info!("Validating test material in: {}", output_dir.display());

    if !output_dir.exists() {
        warn!("Output directory does not exist: {}", output_dir.display());
        return Ok(());
    }

    let mut validation_errors = Vec::new();

    if testing_material_exists(output_dir).await? {
        info!("✓ Insecure material found");
    } else {
        validation_errors.push("Insecure material missing");
    }

    if default_material_exists(output_dir).await? {
        info!("✓ Secure material found");
    } else {
        validation_errors.push("Secure material missing");
    }

    validate_directory_structure(output_dir, &mut validation_errors).await?;

    if validation_errors.is_empty() {
        info!("✓ All validation checks passed");
    } else {
        warn!("Validation errors found:");
        for error in validation_errors {
            warn!("  - {}", error);
        }
    }

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

async fn testing_material_exists(output_dir: &Path) -> Result<bool> {
    profile_material_exists(output_dir, MaterialType::Testing).await
}

async fn default_material_exists(output_dir: &Path) -> Result<bool> {
    profile_material_exists(output_dir, MaterialType::Default).await
}

async fn profile_material_exists(output_dir: &Path, material_type: MaterialType) -> Result<bool> {
    let profile_dir = output_dir.join(material_subdir(material_type));

    if !profile_dir.exists() {
        return Ok(false);
    }

    for storage_type in &REQUIRED_STORAGE_TYPES {
        let path = profile_dir.join(storage_type.to_string());
        if path.exists() {
            return Ok(true);
        }
    }

    Ok(false)
}

async fn validate_directory_structure(
    output_dir: &Path,
    errors: &mut Vec<&'static str>,
) -> Result<()> {
    let testing_dir = output_dir.join(material_subdir(MaterialType::Testing));
    let default_dir = output_dir.join(material_subdir(MaterialType::Default));

    if testing_dir.exists() {
        for storage_type in &REQUIRED_STORAGE_TYPES {
            let path = testing_dir.join(storage_type.to_string());
            if !path.exists() {
                errors.push("Insecure material missing required subdirectories");
                break;
            }
        }
    }

    if default_dir.exists() {
        for storage_type in &REQUIRED_STORAGE_TYPES {
            let path = default_dir.join(storage_type.to_string());
            if !path.exists() {
                errors.push("Secure material missing required subdirectories");
                break;
            }
        }
    }

    Ok(())
}
