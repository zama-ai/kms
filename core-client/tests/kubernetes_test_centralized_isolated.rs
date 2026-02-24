//! Kubernetes Cluster Integration Tests - Centralized Mode
//!
//! Tests CLI functionality against a real centralized KMS cluster running in Kubernetes (kind).
//! These tests verify end-to-end functionality in a production-like environment.
//!
//! ## Purpose
//!
//! These tests:
//! - Connect to actual KMS pods running in Kubernetes cluster
//! - Test real network communication and service discovery
//! - Verify CLI works with production-like deployment
//! - Validate Kubernetes-specific configurations
//!
//! ## Test Coverage
//!
//! **Centralized Mode Tests:**
//! - `k8s_test_centralized_insecure` - Keygen + CRS generation
//! - `full_gen_tests_default_k8s_centralized_sequential_crs` - Sequential CRS generation
//!
//! ## Architecture
//!
//! **Cluster Setup:**
//! - Uses kind (Kubernetes in Docker) cluster
//! - KMS pods deployed via Helm charts
//! - CLI connects via service endpoints
//!
//! ## Configuration
//!
//! Tests use: `core-client/config/client_local_kind_centralized.toml`
//! - Points to KMS service endpoints in kind cluster
//! - Configured for local kind cluster access
//! - Must match actual cluster deployment
//!
//! **Test Flow:**
//! 1. Assumes KMS cluster is already running (deployed separately)
//! 2. CLI connects to cluster via config file
//! 3. Executes commands against real KMS services
//! 4. Validates responses and behavior
//!
//! This file will eventually replace `kubernetes_test_centralized.rs`.

#![cfg(feature = "k8s_tests")]

use kms_core_client::*;
use std::path::Path;
use std::path::PathBuf;
use std::string::String;

// ============================================================================
// TEST INFRASTRUCTURE
// ============================================================================

/// Test context for K8s centralized tests.
/// Provides consistent setup, logging, and helper methods.
struct K8sTestContext {
    name: &'static str,
    temp_dir: tempfile::TempDir,
    start_time: std::time::Instant,
}

impl K8sTestContext {
    /// Create a new test context with the given test name.
    fn new(name: &'static str) -> Self {
        init_testing();
        let temp_dir = tempfile::tempdir().unwrap();

        println!("\n========================================");
        println!("[K8S-CENTRALIZED] TEST: {}", name);
        println!("[K8S-CENTRALIZED] Workspace: {}", temp_dir.path().display());
        println!("========================================\n");

        Self {
            name,
            temp_dir,
            start_time: std::time::Instant::now(),
        }
    }

    /// Get the test workspace path.
    fn workspace(&self) -> &Path {
        self.temp_dir.path()
    }

    /// Get the config file path.
    fn config_path(&self) -> PathBuf {
        Self::root_path().join("core-client/config/client_local_kind_centralized.toml")
    }

    fn root_path() -> PathBuf {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
        PathBuf::from(manifest_dir)
            .parent()
            .expect("Failed to get parent directory")
            .to_path_buf()
    }

    /// Execute a CLI command and return results.
    async fn execute(&self, command: CCCommand) -> Vec<(Option<kms_grpc::RequestId>, String)> {
        let config = CmdConfig {
            file_conf: Some(vec![self.config_path().to_string_lossy().to_string()]),
            command,
            logs: true,
            max_iter: 200,
            expect_all_responses: true,
            download_all: false,
        };

        execute_cmd(&config, self.workspace()).await.unwrap()
    }

    /// Generate a key using InsecureKeyGen.
    async fn insecure_keygen(&self) -> String {
        println!("[K8S-CENTRALIZED] Executing InsecureKeyGen...");
        let start = std::time::Instant::now();

        let results = self
            .execute(CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
                shared_args: SharedKeyGenParameters::default(),
            }))
            .await;

        let key_id = results
            .first()
            .and_then(|(id, _)| id.as_ref())
            .expect("InsecureKeyGen must return a key ID")
            .to_string();

        println!(
            "[K8S-CENTRALIZED] ✅ KeyGen completed in {:.2}s: {}",
            start.elapsed().as_secs_f64(),
            key_id
        );
        key_id
    }

    /// Generate a CRS.
    async fn crs_gen(&self) -> String {
        println!("[K8S-CENTRALIZED] Executing CrsGen (max_num_bits=2048)...");
        let start = std::time::Instant::now();

        let results = self
            .execute(CCCommand::CrsGen(CrsParameters { max_num_bits: 2048 }))
            .await;

        let crs_id = results
            .first()
            .and_then(|(id, _)| id.as_ref())
            .expect("CrsGen must return a CRS ID")
            .to_string();

        println!(
            "[K8S-CENTRALIZED] ✅ CrsGen completed in {:.2}s: {}",
            start.elapsed().as_secs_f64(),
            crs_id
        );
        crs_id
    }

    /// Mark test as passed and print summary.
    fn pass(self) {
        let duration = self.start_time.elapsed();
        println!("\n========================================");
        println!(
            "[K8S-CENTRALIZED] ✅ PASSED: {} ({:.2}s)",
            self.name,
            duration.as_secs_f64()
        );
        println!("========================================\n");
    }
}

// ============================================================================
// TESTS
// ============================================================================

/// Basic test: Generate a key and CRS.
/// Validates that the fundamental operations work in K8s.
#[tokio::test]
async fn k8s_test_centralized_insecure() {
    let ctx = K8sTestContext::new("k8s_test_centralized_insecure");

    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    let crs_id = ctx.crs_gen().await;
    assert!(!crs_id.is_empty(), "CRS ID must not be empty");

    ctx.pass();
}

/// Test that multiple CRS generations produce unique IDs.
/// Validates CRS generation is independent across calls.
#[tokio::test]
async fn full_gen_tests_default_k8s_centralized_sequential_crs() {
    let ctx = K8sTestContext::new("full_gen_tests_default_k8s_centralized_sequential_crs");

    let crs1 = ctx.crs_gen().await;
    let crs2 = ctx.crs_gen().await;

    assert_ne!(crs1, crs2, "CRS IDs must be unique");

    println!("[K8S-CENTRALIZED] ✅ Both CRS IDs are unique");
    ctx.pass();
}
