//! Pre-generation tool for KMS test material
//!
//! This tool generates all necessary cryptographic material for KMS tests
//! in advance, eliminating the need for Docker and runtime key generation.
//!
//! The generated material serves as a read-only source that tests copy from
//! into isolated temporary directories, preventing tests from interfering
//! with each other.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use path_absolutize::Absolutize;
use tracing::{info, warn};

use kms_lib::testing::material::{MaterialType, TestMaterialSpec};
#[cfg(feature = "slow_tests")]
use kms_lib::testing::utils::setup::ensure_default_material_exists_to_path;
use kms_lib::testing::utils::setup::ensure_testing_material_exists;

#[derive(Parser)]
#[command(name = "generate-test-material")]
#[command(about = "Pre-generates test material for KMS tests")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Output directory for generated material
    #[arg(short, long, default_value = "./test-material")]
    output: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Force regeneration even if material exists, replacing any existing material
    #[arg(short, long)]
    force: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate all test material (testing + default parameters)
    All,
    /// Generate only testing material (fast, small keys)
    Testing,
    /// Generate only default material (production-like, slower)
    Default,
    /// Generate material for specific test specifications
    Custom {
        /// JSON file containing test material specifications
        #[arg(short, long)]
        spec_file: PathBuf,
    },
    /// Validate existing test material
    Validate,
    /// Clean existing test material
    Clean,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
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
        Commands::All => {
            generate_all_material(&output_dir, cli.force).await?;
        }
        Commands::Testing => {
            generate_testing_material(&output_dir, cli.force).await?;
        }
        Commands::Default => {
            generate_default_material(&output_dir, cli.force).await?;
        }
        Commands::Custom { spec_file } => {
            generate_custom_material(&output_dir, &spec_file, cli.force).await?;
        }
        Commands::Validate => {
            validate_material(&output_dir).await?;
        }
        Commands::Clean => {
            clean_material(&output_dir).await?;
        }
    }

    info!("Operation completed successfully");
    Ok(())
}

/// Generate all test material (testing + default)
async fn generate_all_material(output_dir: &Path, force: bool) -> Result<()> {
    info!("Generating all test material...");

    if !force && material_exists(output_dir).await? {
        warn!("Test material already exists. Use --force to regenerate.");
        return Ok(());
    }

    // Generate testing material first (faster)
    generate_testing_material(output_dir, force).await?;

    // Generate default material (slower)
    generate_default_material(output_dir, force).await?;

    info!("All test material generated successfully");
    Ok(())
}

/// Generate testing material (fast, small keys)
async fn generate_testing_material(output_dir: &Path, force: bool) -> Result<()> {
    use tokio::fs;

    info!("Generating testing material...");

    let testing_dir = output_dir.join("testing");

    if !force && testing_material_exists(output_dir).await? {
        info!("Testing material already exists, skipping generation");
        return Ok(());
    }

    // Create testing subdirectory
    fs::create_dir_all(&testing_dir).await?;

    // Generate testing material using existing KMS functions
    ensure_testing_material_exists(Some(&testing_dir)).await;

    info!(
        "Testing material generated successfully at: {}",
        testing_dir.display()
    );
    Ok(())
}

/// Generate default material (production-like, slower)
async fn generate_default_material(output_dir: &Path, force: bool) -> Result<()> {
    info!("Generating default material (this may take several minutes)...");

    if !force && default_material_exists(output_dir).await? {
        info!("Default material already exists, skipping generation");
        return Ok(());
    }

    // Generate default material using existing KMS functions
    #[cfg(feature = "slow_tests")]
    {
        use tokio::fs;

        let default_dir = output_dir.join("default");

        // Create default subdirectory
        fs::create_dir_all(&default_dir).await?;

        // Generate default material directly to the default subdirectory
        // This matches the pattern used for testing material
        ensure_default_material_exists_to_path(Some(&default_dir)).await;

        info!(
            "Default material generated successfully at: {}",
            default_dir.display()
        );
    }

    #[cfg(not(feature = "slow_tests"))]
    {
        warn!("Default material generation requires 'slow_tests' feature");
        warn!("Run with: cargo run --features slow_tests");
    }

    Ok(())
}

/// Generate material based on custom specifications
async fn generate_custom_material(output_dir: &Path, spec_file: &Path, _force: bool) -> Result<()> {
    info!("Generating custom material from: {}", spec_file.display());

    // Read specification file
    let spec_content = tokio::fs::read_to_string(spec_file)
        .await
        .with_context(|| format!("Failed to read spec file: {}", spec_file.display()))?;

    let specs: Vec<TestMaterialSpec> = serde_json::from_str(&spec_content)
        .with_context(|| format!("Failed to parse spec file: {}", spec_file.display()))?;

    info!("Found {} test material specifications", specs.len());

    for (i, spec) in specs.iter().enumerate() {
        info!(
            "Generating material for specification {} of {}",
            i + 1,
            specs.len()
        );
        generate_material_for_spec(output_dir, spec).await?;
    }

    info!("Custom material generated successfully");
    Ok(())
}

/// Generate material for a specific specification
async fn generate_material_for_spec(output_dir: &Path, spec: &TestMaterialSpec) -> Result<()> {
    info!("Generating material for spec: {:?}", spec);

    // Create subdirectory for this specification
    let spec_dir = output_dir.join(format!(
        "{:?}_{}_parties",
        spec.material_type,
        spec.party_count()
    ));
    tokio::fs::create_dir_all(&spec_dir).await?;

    // Generate based on material type
    match spec.material_type {
        MaterialType::Testing => {
            ensure_testing_material_exists(Some(&spec_dir)).await;
        }
        MaterialType::Default => {
            #[cfg(feature = "slow_tests")]
            {
                ensure_default_material_exists_to_path(Some(&spec_dir)).await;
            }
            #[cfg(not(feature = "slow_tests"))]
            {
                warn!("Default material requires 'slow_tests' feature");
            }
        }
    }

    // Note: We intentionally generate ALL material for the given material_type,
    // not just the keys specified in spec.required_keys. This is because:
    // 1. Generation is a one-time operation (pre-generation phase)
    // 2. TestMaterialManager::copy_material() handles selective copying based on
    //    spec.required_keys when setting up individual test environments
    // 3. Generating everything once is simpler and avoids partial state issues

    Ok(())
}

/// Validate existing test material
async fn validate_material(output_dir: &Path) -> Result<()> {
    info!("Validating test material in: {}", output_dir.display());

    if !output_dir.exists() {
        warn!("Output directory does not exist: {}", output_dir.display());
        return Ok(());
    }

    let mut validation_errors = Vec::new();

    // Check for testing material
    if testing_material_exists(output_dir).await? {
        info!("✓ Testing material found");
    } else {
        validation_errors.push("Testing material missing");
    }

    // Check for default material
    if default_material_exists(output_dir).await? {
        info!("✓ Default material found");
    } else {
        validation_errors.push("Default material missing");
    }

    // Check directory structure
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

/// Clean existing test material
async fn clean_material(output_dir: &Path) -> Result<()> {
    info!("Cleaning test material in: {}", output_dir.display());

    if !output_dir.exists() {
        info!("Output directory does not exist, nothing to clean");
        return Ok(());
    }

    // Remove all contents of the output directory
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

/// Check if any test material exists
async fn material_exists(output_dir: &Path) -> Result<bool> {
    Ok(testing_material_exists(output_dir).await? || default_material_exists(output_dir).await?)
}

/// Check if testing material exists
async fn testing_material_exists(output_dir: &Path) -> Result<bool> {
    // Check for testing subdirectory with key indicators
    let testing_dir = output_dir.join("testing");

    if !testing_dir.exists() {
        return Ok(false);
    }

    // Check for key indicators of testing material in subdirectory
    let indicators = ["PUB", "PRIV", "CLIENT"];

    for indicator in &indicators {
        let path = testing_dir.join(indicator);
        if path.exists() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Check if default material exists
async fn default_material_exists(output_dir: &Path) -> Result<bool> {
    // Check for default subdirectory with key indicators
    let default_dir = output_dir.join("default");

    if !default_dir.exists() {
        return Ok(false);
    }

    // Check for key indicators of default material in subdirectory
    let indicators = ["PUB", "PRIV", "CLIENT"];

    for indicator in &indicators {
        let path = default_dir.join(indicator);
        if path.exists() {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Validate directory structure
async fn validate_directory_structure(
    output_dir: &Path,
    errors: &mut Vec<&'static str>,
) -> Result<()> {
    // Check that testing and/or default directories have proper subdirectories
    let testing_dir = output_dir.join("testing");
    let default_dir = output_dir.join("default");

    let required_subdirs = ["PUB", "PRIV", "CLIENT"];

    // Validate testing directory if it exists
    if testing_dir.exists() {
        for subdir in &required_subdirs {
            let path = testing_dir.join(subdir);
            if !path.exists() {
                errors.push("Testing material missing required subdirectories");
                break;
            }
        }
    }

    // Validate default directory if it exists
    if default_dir.exists() {
        for subdir in &required_subdirs {
            let path = default_dir.join(subdir);
            if !path.exists() {
                errors.push("Default material missing required subdirectories");
                break;
            }
        }
    }

    Ok(())
}
