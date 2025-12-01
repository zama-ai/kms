//! Test material management for isolated test execution
//!
//! This module provides utilities for copying pre-generated test material
//! into isolated temporary directories for each test.

use super::test_material_spec::{KeyType, MaterialType, TestMaterialSpec};
use crate::consts::{
    DEFAULT_CENTRAL_CRS_ID, DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_CRS_ID_10P,
    DEFAULT_THRESHOLD_CRS_ID_13P, DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_KEY_ID_10P,
    DEFAULT_THRESHOLD_KEY_ID_13P, DEFAULT_THRESHOLD_KEY_ID_4P, KEY_PATH_PREFIX,
    OTHER_CENTRAL_DEFAULT_ID, OTHER_CENTRAL_TEST_ID, SIGNING_KEY_ID, TEST_CENTRAL_CRS_ID,
    TEST_CENTRAL_KEY_ID, TEST_THRESHOLD_CRS_ID_10P, TEST_THRESHOLD_CRS_ID_4P,
    TEST_THRESHOLD_KEY_ID_10P, TEST_THRESHOLD_KEY_ID_4P, TMP_PATH_PREFIX,
};
use crate::vault::storage::StorageType;
use anyhow::{anyhow, Context, Result};
use kms_grpc::rpc_types::{PrivDataType, PubDataType};
use std::path::{Path, PathBuf};
#[cfg(any(test, feature = "testing"))]
use tempfile::TempDir;
use threshold_fhe::execution::runtime::party::Role;
use tokio::fs;

/// Helper function to compute storage path like FileStorage does
fn compute_storage_path(
    base_path: Option<&Path>,
    storage_type: StorageType,
    party_role: Option<Role>,
) -> PathBuf {
    let extra_prefix = match party_role {
        Some(party_role) => format!("{storage_type}-p{party_role}"),
        None => storage_type.to_string(),
    };
    match base_path {
        Some(path) => path.join(extra_prefix),
        None => std::env::current_dir()
            .unwrap_or_default()
            .join(KEY_PATH_PREFIX)
            .join(extra_prefix),
    }
}

/// Handle to test material that can be either isolated (copied) or shared (in-place)
#[cfg(any(test, feature = "testing"))]
pub enum TestMaterialHandle {
    /// Isolated material in a temporary directory (auto-deleted on drop)
    Isolated(TempDir),
    /// Shared material in the source directory (not deleted)
    Shared(PathBuf),
}

#[cfg(any(test, feature = "testing"))]
impl TestMaterialHandle {
    /// Get the path to the test material
    pub fn path(&self) -> &Path {
        match self {
            TestMaterialHandle::Isolated(temp_dir) => temp_dir.path(),
            TestMaterialHandle::Shared(path) => path.as_path(),
        }
    }
}

/// Manager for test material operations
pub struct TestMaterialManager {
    /// Path to the pre-generated test material
    source_path: Option<PathBuf>,
}

impl Default for TestMaterialManager {
    fn default() -> Self {
        Self::new(None)
    }
}

impl TestMaterialManager {
    /// Create a new test material manager
    pub fn new(source_path: Option<PathBuf>) -> Self {
        Self { source_path }
    }

    /// Setup test material in a temporary directory
    #[cfg(any(test, feature = "testing"))]
    pub async fn setup_test_material(
        &self,
        spec: &TestMaterialSpec,
        test_name: &str,
    ) -> Result<TempDir> {
        // Verify source material exists for the requested material type
        self.verify_material_exists(spec)?;

        let temp_dir = tempfile::tempdir().with_context(|| {
            format!(
                "Failed to create temporary directory for test: {}",
                test_name
            )
        })?;

        // Create required directory structure
        self.create_directory_structure(&temp_dir, spec).await?;

        // Copy required material based on specification
        self.copy_material(&temp_dir, spec).await?;

        tracing::debug!(
            "Setup test material for '{}' (type: {:?}) in: {}",
            test_name,
            spec.material_type,
            temp_dir.path().display()
        );

        Ok(temp_dir)
    }

    /// Setup test material using shared source directory (no copying)
    ///
    /// This is useful in CI environments where:
    /// - Tests run sequentially (no parallel conflicts)
    /// - Disk space is limited
    /// - Material is read-only
    ///
    /// Returns the path to the shared material directory.
    /// The directory is NOT deleted (it's the source material).
    #[cfg(any(test, feature = "testing"))]
    pub fn setup_test_material_shared(
        &self,
        spec: &TestMaterialSpec,
        test_name: &str,
    ) -> Result<PathBuf> {
        // Verify source material exists
        self.verify_material_exists(spec)?;

        let source_path = self
            .source_path
            .as_ref()
            .ok_or_else(|| anyhow!("Source path must be configured for shared material mode"))?;

        // Determine subdirectory based on material type
        let material_subdir = match spec.material_type {
            super::test_material_spec::MaterialType::Testing => "testing",
            super::test_material_spec::MaterialType::Default => "default",
        };

        let material_path = source_path.join(material_subdir);

        tracing::debug!(
            "Using shared test material for '{}' (type: {:?}) from: {}",
            test_name,
            spec.material_type,
            material_path.display()
        );

        Ok(material_path)
    }

    /// Automatically choose between shared and isolated material based on environment
    ///
    /// Uses shared material (no copying) if:
    /// - KMS_TEST_SHARED_MATERIAL=1 environment variable is set (CI mode)
    /// - Saves disk space by not copying material
    /// - Requires sequential test execution
    ///
    /// Uses isolated material (with copying) otherwise:
    /// - Each test gets its own temporary directory
    /// - Safe for parallel test execution
    /// - Uses more disk space
    #[cfg(any(test, feature = "testing"))]
    pub async fn setup_test_material_auto(
        &self,
        spec: &TestMaterialSpec,
        test_name: &str,
    ) -> Result<TestMaterialHandle> {
        let use_shared = std::env::var("KMS_TEST_SHARED_MATERIAL")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        tracing::info!(
            "setup_test_material_auto for '{}': KMS_TEST_SHARED_MATERIAL={}, mode={}",
            test_name,
            std::env::var("KMS_TEST_SHARED_MATERIAL").unwrap_or_else(|_| "not set".to_string()),
            if use_shared {
                "SHARED (no copying)"
            } else {
                "ISOLATED (copying)"
            }
        );

        if use_shared {
            let path = self.setup_test_material_shared(spec, test_name)?;
            Ok(TestMaterialHandle::Shared(path))
        } else {
            let temp_dir = self.setup_test_material(spec, test_name).await?;
            Ok(TestMaterialHandle::Isolated(temp_dir))
        }
    }

    /// Verify that source material exists for the requested material type
    #[cfg(any(test, feature = "testing"))]
    fn verify_material_exists(&self, spec: &TestMaterialSpec) -> Result<()> {
        use crate::util::key_setup::test_material_spec::MaterialType;

        // If no source path is configured, skip verification
        // This allows tests to work without pre-generated material
        let source_path = match &self.source_path {
            Some(path) => path,
            None => {
                tracing::debug!("No source path configured, skipping material verification");
                return Ok(());
            }
        };

        // Determine subdirectory based on material type
        let material_subdir = match spec.material_type {
            MaterialType::Testing => "testing",
            MaterialType::Default => "default",
        };

        let material_path = source_path.join(material_subdir);

        if !material_path.exists() {
            return Err(anyhow!(
                "Material not found for {:?} at: {}\n\
                 Run: make generate-test-material-{}",
                spec.material_type,
                material_path.display(),
                match spec.material_type {
                    MaterialType::Testing => "testing",
                    MaterialType::Default => "all",
                }
            ));
        }

        tracing::debug!(
            "Verified material exists for {:?} at: {}",
            spec.material_type,
            material_path.display()
        );

        Ok(())
    }

    /// Create the required directory structure
    #[cfg(any(test, feature = "testing"))]
    async fn create_directory_structure(
        &self,
        temp_dir: &TempDir,
        spec: &TestMaterialSpec,
    ) -> Result<()> {
        let base_path = temp_dir.path();

        // Create basic directories
        fs::create_dir_all(base_path.join(TMP_PATH_PREFIX)).await?;
        fs::create_dir_all(base_path.join(KEY_PATH_PREFIX)).await?;

        // Create storage directories based on test type
        if spec.is_threshold() {
            // Create directories for each party
            for i in 1..=spec.party_count() {
                let role = Role::indexed_from_one(i);
                let pub_path = compute_storage_path(Some(base_path), StorageType::PUB, Some(role));
                let priv_path =
                    compute_storage_path(Some(base_path), StorageType::PRIV, Some(role));

                fs::create_dir_all(&pub_path).await?;
                fs::create_dir_all(&priv_path).await?;
            }
        } else {
            // Create centralized directories
            let pub_path = compute_storage_path(Some(base_path), StorageType::PUB, None);
            let priv_path = compute_storage_path(Some(base_path), StorageType::PRIV, None);

            fs::create_dir_all(&pub_path).await?;
            fs::create_dir_all(&priv_path).await?;
        }

        // Create client directory if needed
        if spec.requires_key_type(KeyType::ClientKeys) {
            let client_path = compute_storage_path(Some(base_path), StorageType::CLIENT, None);
            fs::create_dir_all(&client_path).await?;
        }

        Ok(())
    }

    /// Copy required material to the temporary directory
    #[cfg(any(test, feature = "testing"))]
    async fn copy_material(&self, temp_dir: &TempDir, spec: &TestMaterialSpec) -> Result<()> {
        // Determine source subdirectory based on material type
        let material_subdir = match spec.material_type {
            MaterialType::Testing => "testing",
            MaterialType::Default => "default",
        };

        let source_base = self.source_path.as_ref().map(|p| p.join(material_subdir));
        let source_base_ref = source_base.as_deref();
        let dest_base = temp_dir.path();

        // Copy client keys if required
        if spec.requires_key_type(KeyType::ClientKeys) {
            self.copy_client_keys(source_base_ref, dest_base).await?;
        }

        // Copy signing keys if required (client or server signing keys)
        if spec.requires_key_type(KeyType::SigningKeys)
            || spec.requires_key_type(KeyType::ServerSigningKeys)
        {
            self.copy_signing_keys(source_base_ref, dest_base, spec)
                .await?;
        }

        // Copy FHE keys if required
        if spec.requires_key_type(KeyType::FheKeys) {
            self.copy_fhe_keys(source_base_ref, dest_base, spec).await?;
        }

        // Copy CRS keys if required
        if spec.requires_key_type(KeyType::CrsKeys) && spec.include_slow_material {
            self.copy_crs_keys(source_base_ref, dest_base, spec).await?;
        }

        // Copy PRSS setup for threshold tests
        if spec.requires_key_type(KeyType::PrssSetup) && spec.is_threshold() {
            self.copy_prss_setup(source_base_ref, dest_base, spec)
                .await?;
        }

        Ok(())
    }

    /// Copy client keys
    async fn copy_client_keys(&self, source_base: Option<&Path>, dest_base: &Path) -> Result<()> {
        let source_client_path = compute_storage_path(source_base, StorageType::CLIENT, None);
        let dest_client_path = compute_storage_path(Some(dest_base), StorageType::CLIENT, None);

        if source_client_path.exists() {
            self.copy_directory_contents(&source_client_path, &dest_client_path)
                .await?;
        }

        Ok(())
    }

    /// Copy signing keys
    async fn copy_signing_keys(
        &self,
        source_base: Option<&Path>,
        dest_base: &Path,
        spec: &TestMaterialSpec,
    ) -> Result<()> {
        if spec.is_threshold() {
            // Copy signing keys for each party
            for i in 1..=spec.party_count() {
                let role = Role::indexed_from_one(i);

                let source_pub = compute_storage_path(source_base, StorageType::PUB, Some(role));
                let source_priv = compute_storage_path(source_base, StorageType::PRIV, Some(role));
                let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, Some(role));
                let dest_priv =
                    compute_storage_path(Some(dest_base), StorageType::PRIV, Some(role));

                // Create destination directories once
                fs::create_dir_all(&dest_pub).await?;
                fs::create_dir_all(&dest_priv).await?;

                // Copy verification keys
                self.copy_key_files_no_mkdir(
                    &source_pub,
                    &dest_pub,
                    &PubDataType::VerfKey.to_string(),
                    &SIGNING_KEY_ID.to_string(),
                )
                .await?;

                // Copy verification addresses
                self.copy_key_files_no_mkdir(
                    &source_pub,
                    &dest_pub,
                    &PubDataType::VerfAddress.to_string(),
                    &SIGNING_KEY_ID.to_string(),
                )
                .await?;

                // Copy signing keys
                self.copy_key_files_no_mkdir(
                    &source_priv,
                    &dest_priv,
                    &PrivDataType::SigningKey.to_string(),
                    &SIGNING_KEY_ID.to_string(),
                )
                .await?;
            }
        } else {
            // Copy centralized signing keys
            let source_pub = compute_storage_path(source_base, StorageType::PUB, None);
            let source_priv = compute_storage_path(source_base, StorageType::PRIV, None);
            let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, None);
            let dest_priv = compute_storage_path(Some(dest_base), StorageType::PRIV, None);

            // Create destination directories once
            fs::create_dir_all(&dest_pub).await?;
            fs::create_dir_all(&dest_priv).await?;

            self.copy_key_files_no_mkdir(
                &source_pub,
                &dest_pub,
                &PubDataType::VerfKey.to_string(),
                &SIGNING_KEY_ID.to_string(),
            )
            .await?;

            self.copy_key_files_no_mkdir(
                &source_pub,
                &dest_pub,
                &PubDataType::VerfAddress.to_string(),
                &SIGNING_KEY_ID.to_string(),
            )
            .await?;

            self.copy_key_files_no_mkdir(
                &source_priv,
                &dest_priv,
                &PrivDataType::SigningKey.to_string(),
                &SIGNING_KEY_ID.to_string(),
            )
            .await?;
        }

        Ok(())
    }

    /// Copy FHE keys
    async fn copy_fhe_keys(
        &self,
        source_base: Option<&Path>,
        dest_base: &Path,
        spec: &TestMaterialSpec,
    ) -> Result<()> {
        let key_ids = self.get_key_ids_for_spec(spec);

        if spec.is_threshold() {
            // Copy threshold FHE keys
            for i in 1..=spec.party_count() {
                let role = Role::indexed_from_one(i);
                let source_pub = compute_storage_path(source_base, StorageType::PUB, Some(role));
                let source_priv = compute_storage_path(source_base, StorageType::PRIV, Some(role));
                let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, Some(role));
                let dest_priv =
                    compute_storage_path(Some(dest_base), StorageType::PRIV, Some(role));

                for key_id in &key_ids.fhe_keys {
                    // Copy various FHE key types
                    self.copy_key_files(
                        &source_pub,
                        &dest_pub,
                        &PubDataType::PublicKey.to_string(),
                        key_id,
                    )
                    .await?;
                    self.copy_key_files(
                        &source_pub,
                        &dest_pub,
                        &PubDataType::ServerKey.to_string(),
                        key_id,
                    )
                    .await?;
                    self.copy_key_files(
                        &source_priv,
                        &dest_priv,
                        &PrivDataType::FhePrivateKey.to_string(),
                        key_id,
                    )
                    .await?;

                    if spec.requires_key_type(KeyType::DecompressionKeys) {
                        self.copy_key_files(
                            &source_pub,
                            &dest_pub,
                            &PubDataType::DecompressionKey.to_string(),
                            key_id,
                        )
                        .await?;
                    }
                }
            }
        } else {
            // Copy centralized FHE keys
            let source_pub = compute_storage_path(source_base, StorageType::PUB, None);
            let source_priv = compute_storage_path(source_base, StorageType::PRIV, None);
            let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, None);
            let dest_priv = compute_storage_path(Some(dest_base), StorageType::PRIV, None);

            for key_id in &key_ids.fhe_keys {
                self.copy_key_files(
                    &source_pub,
                    &dest_pub,
                    &PubDataType::PublicKey.to_string(),
                    key_id,
                )
                .await?;
                self.copy_key_files(
                    &source_pub,
                    &dest_pub,
                    &PubDataType::ServerKey.to_string(),
                    key_id,
                )
                .await?;
                self.copy_key_files(
                    &source_priv,
                    &dest_priv,
                    &PrivDataType::FhePrivateKey.to_string(),
                    key_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Copy CRS keys
    async fn copy_crs_keys(
        &self,
        source_base: Option<&Path>,
        dest_base: &Path,
        spec: &TestMaterialSpec,
    ) -> Result<()> {
        let key_ids = self.get_key_ids_for_spec(spec);

        if spec.is_threshold() {
            for i in 1..=spec.party_count() {
                let role = Role::indexed_from_one(i);
                let source_pub = compute_storage_path(source_base, StorageType::PUB, Some(role));
                let source_priv = compute_storage_path(source_base, StorageType::PRIV, Some(role));
                let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, Some(role));
                let dest_priv =
                    compute_storage_path(Some(dest_base), StorageType::PRIV, Some(role));

                for crs_id in &key_ids.crs_keys {
                    self.copy_key_files(
                        &source_pub,
                        &dest_pub,
                        &PubDataType::CRS.to_string(),
                        crs_id,
                    )
                    .await?;
                    self.copy_key_files(
                        &source_priv,
                        &dest_priv,
                        &PrivDataType::CrsInfo.to_string(),
                        crs_id,
                    )
                    .await?;
                }
            }
        } else {
            let source_pub = compute_storage_path(source_base, StorageType::PUB, None);
            let source_priv = compute_storage_path(source_base, StorageType::PRIV, None);
            let dest_pub = compute_storage_path(Some(dest_base), StorageType::PUB, None);
            let dest_priv = compute_storage_path(Some(dest_base), StorageType::PRIV, None);

            for crs_id in &key_ids.crs_keys {
                self.copy_key_files(
                    &source_pub,
                    &dest_pub,
                    &PubDataType::CRS.to_string(),
                    crs_id,
                )
                .await?;
                self.copy_key_files(
                    &source_priv,
                    &dest_priv,
                    &PrivDataType::CrsInfo.to_string(),
                    crs_id,
                )
                .await?;
            }
        }

        Ok(())
    }

    /// Copy PRSS setup for threshold tests
    async fn copy_prss_setup(
        &self,
        source_base: Option<&Path>,
        dest_base: &Path,
        spec: &TestMaterialSpec,
    ) -> Result<()> {
        for i in 1..=spec.party_count() {
            let role = Role::indexed_from_one(i);
            let source_priv = compute_storage_path(source_base, StorageType::PRIV, Some(role));
            let dest_priv = compute_storage_path(Some(dest_base), StorageType::PRIV, Some(role));

            // Copy PRSS setup files
            self.copy_key_files(
                &source_priv,
                &dest_priv,
                "PrssSetup",
                "000000000000000000000000000000000000000000000000000000000000000000000001",
            )
            .await?;
        }

        Ok(())
    }

    /// Copy specific key files (creates directories if needed)
    async fn copy_key_files(
        &self,
        source_dir: &Path,
        dest_dir: &Path,
        key_type: &str,
        key_id: &str,
    ) -> Result<()> {
        let source_type_dir = source_dir.join(key_type);
        let dest_type_dir = dest_dir.join(key_type);

        if !source_type_dir.exists() {
            return Ok(()); // Skip if source doesn't exist
        }

        fs::create_dir_all(&dest_type_dir).await?;

        let source_file = source_type_dir.join(key_id);
        let dest_file = dest_type_dir.join(key_id);

        if source_file.exists() {
            fs::copy(&source_file, &dest_file).await.with_context(|| {
                format!(
                    "Failed to copy {} from {} to {}",
                    key_type,
                    source_file.display(),
                    dest_file.display()
                )
            })?;
        }

        Ok(())
    }

    /// Copy specific key files (assumes directories already exist)
    async fn copy_key_files_no_mkdir(
        &self,
        source_dir: &Path,
        dest_dir: &Path,
        key_type: &str,
        key_id: &str,
    ) -> Result<()> {
        let source_type_dir = source_dir.join(key_type);
        let dest_type_dir = dest_dir.join(key_type);

        if !source_type_dir.exists() {
            return Ok(()); // Skip if source doesn't exist
        }

        // Create only the key_type subdirectory
        fs::create_dir_all(&dest_type_dir).await?;

        let source_file = source_type_dir.join(key_id);
        let dest_file = dest_type_dir.join(key_id);

        if source_file.exists() {
            fs::copy(&source_file, &dest_file).await.with_context(|| {
                format!(
                    "Failed to copy {} from {} to {}",
                    key_type,
                    source_file.display(),
                    dest_file.display()
                )
            })?;
        }

        Ok(())
    }

    /// Copy entire directory contents
    #[allow(clippy::only_used_in_recursion)]
    fn copy_directory_contents<'a>(
        &'a self,
        source: &'a Path,
        dest: &'a Path,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + 'a>> {
        Box::pin(async move {
            if !source.exists() {
                return Ok(());
            }

            fs::create_dir_all(dest).await?;

            let mut entries = fs::read_dir(source).await?;
            while let Some(entry) = entries.next_entry().await? {
                let source_path = entry.path();
                let dest_path = dest.join(entry.file_name());

                if source_path.is_dir() {
                    self.copy_directory_contents(&source_path, &dest_path)
                        .await?;
                } else {
                    fs::copy(&source_path, &dest_path).await?;
                }
            }

            Ok(())
        })
    }

    /// Get key IDs based on specification
    fn get_key_ids_for_spec(&self, spec: &TestMaterialSpec) -> KeyIds {
        match spec.material_type {
            MaterialType::Testing => KeyIds {
                fhe_keys: match spec.party_count() {
                    4 => vec![TEST_THRESHOLD_KEY_ID_4P.to_string()],
                    10 => vec![TEST_THRESHOLD_KEY_ID_10P.to_string()],
                    _ => vec![
                        TEST_CENTRAL_KEY_ID.to_string(),
                        OTHER_CENTRAL_TEST_ID.to_string(),
                    ],
                },
                crs_keys: match spec.party_count() {
                    4 => vec![TEST_THRESHOLD_CRS_ID_4P.to_string()],
                    10 => vec![TEST_THRESHOLD_CRS_ID_10P.to_string()],
                    _ => vec![TEST_CENTRAL_CRS_ID.to_string()],
                },
            },
            MaterialType::Default => KeyIds {
                fhe_keys: match spec.party_count() {
                    4 => vec![DEFAULT_THRESHOLD_KEY_ID_4P.to_string()],
                    10 => vec![DEFAULT_THRESHOLD_KEY_ID_10P.to_string()],
                    13 => vec![DEFAULT_THRESHOLD_KEY_ID_13P.to_string()],
                    _ => vec![
                        DEFAULT_CENTRAL_KEY_ID.to_string(),
                        OTHER_CENTRAL_DEFAULT_ID.to_string(),
                    ],
                },
                crs_keys: match spec.party_count() {
                    4 => vec![DEFAULT_THRESHOLD_CRS_ID_4P.to_string()],
                    10 => vec![DEFAULT_THRESHOLD_CRS_ID_10P.to_string()],
                    13 => vec![DEFAULT_THRESHOLD_CRS_ID_13P.to_string()],
                    _ => vec![DEFAULT_CENTRAL_CRS_ID.to_string()],
                },
            },
        }
    }
}

/// Key IDs for different types of keys
struct KeyIds {
    fhe_keys: Vec<String>,
    crs_keys: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_setup_centralized_material() {
        let manager = TestMaterialManager::default();
        let spec = TestMaterialSpec::centralized_basic();

        let temp_dir = manager
            .setup_test_material(&spec, "test_centralized")
            .await
            .unwrap();

        // Verify directory structure was created
        let base_path = temp_dir.path();
        assert!(base_path.join(TMP_PATH_PREFIX).exists());
        assert!(base_path.join(KEY_PATH_PREFIX).exists());

        let pub_path = compute_storage_path(Some(base_path), StorageType::PUB, None);
        let priv_path = compute_storage_path(Some(base_path), StorageType::PRIV, None);
        assert!(pub_path.exists());
        assert!(priv_path.exists());
    }

    #[tokio::test]
    async fn test_setup_threshold_material() {
        let manager = TestMaterialManager::default();
        let spec = TestMaterialSpec::threshold_basic(4);

        let temp_dir = manager
            .setup_test_material(&spec, "test_threshold")
            .await
            .unwrap();

        // Verify directory structure for all parties
        let base_path = temp_dir.path();
        for i in 1..=4 {
            let role = Role::indexed_from_one(i);
            let pub_path = compute_storage_path(Some(base_path), StorageType::PUB, Some(role));
            let priv_path = compute_storage_path(Some(base_path), StorageType::PRIV, Some(role));
            assert!(pub_path.exists());
            assert!(priv_path.exists());
        }
    }
}
