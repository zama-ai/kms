//! Kubernetes Cluster Integration Tests - Threshold Mode
//!
//! Tests CLI functionality against a real threshold KMS cluster running in Kubernetes (kind).
//!
//! ## Purpose
//!
//! Unlike isolated tests (which use in-process native servers), these tests:
//! - Connect to actual threshold KMS pods (4 parties) in Kubernetes
//! - Test real distributed MPC operations across network
//! - Verify CLI works with production-like threshold deployment
//! - Use Default FHE parameters (production-like)
//! - **Use TLS for MPC (party-to-party) communication** (production-like)
//!
//! ## Test Coverage
//!
//! | Test | Description |
//! |------|-------------|
//! | `k8s_test_keygen_and_crs` | Basic keygen + CRS generation |
//! | `k8s_test_keygen_uniqueness` | Multiple keygens produce unique keys |
//! | `k8s_test_crs_uniqueness` | Multiple CRS generations produce unique IDs |
//!
//! ## Architecture
//!
//! - Uses kind (Kubernetes in Docker) cluster
//! - 4 KMS pods deployed via Helm charts with TLS enabled
//! - MPC connections between parties use TLS (mutual TLS)
//! - CLI connects via port-forwarded service endpoints (plain gRPC)
//! - Config: `client_local_kind_threshold.toml`
//!
//! ## Running These Tests
//!
//! ```bash
//! # 1. Start kind cluster with threshold KMS deployed (TLS enabled)
//! ENABLE_TLS=true ./ci/kube-testing/scripts/manage_kind_setup.sh start
//!
//! # 2. Run tests
//! cargo test --test kubernetes_test_threshold --features k8s_tests,testing
//! ```
//!
//! ## Adding New Tests
//!
//! Use the `K8sTestContext` helper for consistent setup:
//!
//! ```ignore
//! #[tokio::test]
//! async fn test_my_feature() {
//!     let ctx = K8sTestContext::new("my_feature");
//!     
//!     // Use helper methods
//!     let key_id = ctx.insecure_keygen().await;
//!     let crs_id = ctx.crs_gen().await;
//!     
//!     ctx.pass();
//! }
//! ```

#![cfg(feature = "k8s_tests")]

use kms_core_client::*;
use std::path::{Path, PathBuf};

// ============================================================================
// TEST INFRASTRUCTURE
// ============================================================================

/// Test context for K8s threshold tests.
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
        println!("[K8S-THRESHOLD] TEST: {}", name);
        println!("[K8S-THRESHOLD] Workspace: {}", temp_dir.path().display());
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
        Self::root_path().join("core-client/config/client_local_kind_threshold.toml")
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
            file_conf: Some(self.config_path().to_string_lossy().to_string()),
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
        println!("[K8S-THRESHOLD] Executing InsecureKeyGen...");
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
            "[K8S-THRESHOLD] ✅ KeyGen completed in {:.2}s: {}",
            start.elapsed().as_secs_f64(),
            key_id
        );
        key_id
    }

    /// Generate a CRS.
    async fn crs_gen(&self) -> String {
        println!("[K8S-THRESHOLD] Executing CrsGen (max_num_bits=2048)...");
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
            "[K8S-THRESHOLD] ✅ CrsGen completed in {:.2}s: {}",
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
            "[K8S-THRESHOLD] ✅ PASSED: {} ({:.2}s)",
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
/// Validates that the fundamental MPC operations work in K8s.
#[tokio::test]
async fn k8s_test_keygen_and_crs() {
    let ctx = K8sTestContext::new("k8s_test_keygen_and_crs");

    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    let crs_id = ctx.crs_gen().await;
    assert!(!crs_id.is_empty(), "CRS ID must not be empty");

    ctx.pass();
}

/// Test that multiple key generations produce unique keys.
/// Validates MPC protocol handles sequential operations correctly.
#[tokio::test]
async fn k8s_test_keygen_uniqueness() {
    let ctx = K8sTestContext::new("k8s_test_keygen_uniqueness");

    let key1 = ctx.insecure_keygen().await;
    let key2 = ctx.insecure_keygen().await;
    let key3 = ctx.insecure_keygen().await;

    assert_ne!(key1, key2, "Keys must be unique");
    assert_ne!(key1, key3, "Keys must be unique");
    assert_ne!(key2, key3, "Keys must be unique");

    println!("[K8S-THRESHOLD] ✅ All 3 keys are unique");
    ctx.pass();
}

/// Test that multiple CRS generations produce unique IDs.
/// Validates CRS generation is independent across calls.
#[tokio::test]
async fn k8s_test_crs_uniqueness() {
    let ctx = K8sTestContext::new("k8s_test_crs_uniqueness");

    let crs1 = ctx.crs_gen().await;
    let crs2 = ctx.crs_gen().await;

    assert_ne!(crs1, crs2, "CRS IDs must be unique");

    println!("[K8S-THRESHOLD] ✅ Both CRS IDs are unique");
    ctx.pass();
}
