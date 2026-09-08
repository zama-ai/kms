//! Pre-generation tool for KMS test material
//!
//! This tool generates cryptographic material for KMS tests ahead of time so
//! test runs can copy read-only fixtures into isolated temporary directories.
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use kms_lib::consts::{KEY_PATH_PREFIX, TMP_PATH_PREFIX};
use kms_lib::testing::material::{MaterialType, material_subdir};
use kms_lib::testing::utils::setup::generate_material_to_path;
use kms_lib::vault::storage::StorageType;
use path_absolutize::Absolutize;
use std::collections::BTreeSet;
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
        bail!("Output directory does not exist: {}", output_dir.display());
    }

    let mut validation_errors = Vec::new();

    if testing_material_exists(output_dir).await? {
        info!("✓ Insecure material found");
    } else {
        validation_errors.push("Insecure material missing".to_string());
    }

    if default_material_exists(output_dir).await? {
        info!("✓ Secure material found");
    } else {
        validation_errors.push("Secure material missing".to_string());
    }

    validate_directory_structure(output_dir, &mut validation_errors).await?;

    if validation_errors.is_empty() {
        info!("✓ All validation checks passed");
    } else {
        warn!("Validation errors found:");
        for error in &validation_errors {
            warn!("  - {}", error);
        }
        bail!(
            "test material validation failed with {} error(s)",
            validation_errors.len()
        );
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

    if !profile_dir.is_dir() {
        return Ok(false);
    }

    for storage_type in REQUIRED_STORAGE_TYPES {
        let path = profile_dir.join(storage_type.to_string());
        if !path.is_dir() {
            return Ok(false);
        }
    }

    Ok(true)
}

async fn validate_directory_structure(output_dir: &Path, errors: &mut Vec<String>) -> Result<()> {
    let expected_profiles = [
        material_subdir(MaterialType::Testing),
        material_subdir(MaterialType::Default),
    ];
    let mut entries = tokio::fs::read_dir(output_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !expected_profiles.contains(&name.as_str()) {
            errors.push(format!("Unexpected entry in material root: {name}"));
        }
    }

    for (material_type, label) in [
        (MaterialType::Testing, "Insecure"),
        (MaterialType::Default, "Secure"),
    ] {
        let profile_dir = output_dir.join(material_subdir(material_type));
        if !profile_dir.exists() {
            continue;
        }
        if !profile_dir.is_dir() {
            errors.push(format!("{label} material is not a directory"));
            continue;
        }

        let mut profile_entries = tokio::fs::read_dir(&profile_dir).await?;
        let mut threshold_parties = BTreeSet::new();
        let mut threshold_private_parties = BTreeSet::new();
        while let Some(entry) = profile_entries.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            if [KEY_PATH_PREFIX, TMP_PATH_PREFIX].contains(&name.as_str()) {
                if !path.is_dir() {
                    errors.push(format!("{label} material entry is not a directory: {name}"));
                }
                continue;
            }

            let Some((storage_type, party)) = storage_directory_name(&name) else {
                errors.push(format!("Unexpected entry in {label} material: {name}"));
                continue;
            };
            if let Some(party) = party {
                if party == 0 {
                    errors.push(format!(
                        "{label} material has an invalid party directory: {name}"
                    ));
                } else if storage_type == StorageType::PUB {
                    threshold_parties.insert(party);
                } else {
                    threshold_private_parties.insert(party);
                }
            }
            validate_storage_directory(&path, label, storage_type, errors).await?;
        }

        for party in threshold_parties.symmetric_difference(&threshold_private_parties) {
            errors.push(format!(
                "{label} material is missing a matching PUB/PRIV directory for party {party}"
            ));
        }
        if let Some(max_party) = threshold_parties
            .iter()
            .chain(threshold_private_parties.iter())
            .copied()
            .max()
        {
            for party in 1..=max_party {
                if !threshold_parties.contains(&party)
                    || !threshold_private_parties.contains(&party)
                {
                    errors.push(format!(
                        "{label} material has a gap in threshold party directories at party {party}"
                    ));
                }
            }
        }

        for storage_type in REQUIRED_STORAGE_TYPES {
            let path = profile_dir.join(storage_type.to_string());
            if !path.is_dir() {
                errors.push(format!(
                    "{label} material missing required directory: {}",
                    storage_type
                ));
            }
        }
    }

    Ok(())
}

fn storage_directory_name(name: &str) -> Option<(StorageType, Option<usize>)> {
    for storage_type in [StorageType::PUB, StorageType::PRIV, StorageType::CLIENT] {
        let prefix = storage_type.to_string();
        if name == prefix {
            return Some((storage_type, None));
        }
        if matches!(storage_type, StorageType::PUB | StorageType::PRIV)
            && let Some(party) = name.strip_prefix(&format!("{prefix}-p"))
        {
            return Some((storage_type, Some(party.parse().unwrap_or(0))));
        }
    }
    None
}

fn is_known_data_type(storage_type: StorageType, name: &str) -> bool {
    match storage_type {
        StorageType::PUB => name.parse::<PubDataType>().is_ok(),
        StorageType::PRIV => PrivDataType::try_from(name).is_ok(),
        StorageType::CLIENT => {
            name.parse::<PubDataType>().is_ok() || PrivDataType::try_from(name).is_ok()
        }
        StorageType::BACKUP => false,
    }
}

async fn validate_storage_directory(
    storage_dir: &Path,
    label: &str,
    storage_type: StorageType,
    errors: &mut Vec<String>,
) -> Result<()> {
    if !storage_dir.is_dir() {
        errors.push(format!(
            "{label} material storage is not a directory: {}",
            storage_dir.display()
        ));
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(storage_dir).await?;
    let mut data_type_count = 0;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name().to_string_lossy().into_owned();
        let known_data_type = is_known_data_type(storage_type, &name);
        if !known_data_type {
            errors.push(format!(
                "Unexpected data type in {} material storage: {name}",
                storage_dir.display()
            ));
        } else if !entry.path().is_dir() {
            errors.push(format!(
                "Material data type is not a directory: {}",
                entry.path().display()
            ));
        } else {
            data_type_count += 1;
        }
    }

    if data_type_count == 0 {
        errors.push(format!(
            "{} material storage has no data type directories",
            storage_dir.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_directory() -> PathBuf {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "generate-test-material-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn validator_rejects_stale_entries() {
        let root = test_directory();
        tokio::fs::create_dir(root.join("stale")).await.unwrap();
        let private_dir = root
            .join(material_subdir(MaterialType::Testing))
            .join(StorageType::PRIV.to_string());
        tokio::fs::create_dir_all(private_dir.join("stale"))
            .await
            .unwrap();
        let mut errors = Vec::new();

        validate_directory_structure(&root, &mut errors)
            .await
            .unwrap();

        assert!(
            errors
                .iter()
                .any(|error| error.contains("Unexpected entry in material root: stale")),
            "got {errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|error| error.contains("Unexpected data type") && error.contains("stale")),
            "got {errors:?}"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn validate_material_returns_an_error_for_invalid_material() {
        let root = test_directory();
        let error = validate_material(&root)
            .await
            .expect_err("invalid material must fail");
        assert!(error.to_string().contains("validation failed"));
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
