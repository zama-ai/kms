//! Kubernetes Cluster Integration Tests - Centralized Mode
//!
//! Tests CLI functionality against a real KMS cluster running in Kubernetes (kind).
//! These tests verify end-to-end functionality in a production-like environment.
//!
//! ## Purpose
//!
//! Unlike isolated tests (which use in-process native servers), these tests:
//! - Connect to actual KMS pods running in Kubernetes cluster
//! - Test real network communication and service discovery
//! - Verify CLI works with production-like deployment
//! - Validate Kubernetes-specific configurations
//!
//! ## Test Coverage
//!
//! **Centralized Mode Tests:**
//! - `k8s_test_centralized_insecure` - Keygen + decryption workflow
//!
//! ## Architecture
//!
//! **Cluster Setup:**
//! - Uses kind (Kubernetes in Docker) cluster
//! - KMS pods deployed via Helm charts
//! - CLI connects via service endpoints
//! - Config: `client_local_kind_centralized.toml`
//!
//! **Test Flow:**
//! 1. Assumes KMS cluster is already running (deployed separately)
//! 2. CLI connects to cluster via config file
//! 3. Executes commands against real KMS services
//! 4. Validates responses and behavior
//!
//! ## Running These Tests
//!
//! **Prerequisites:**
//! ```bash
//! # 1. Start kind cluster with KMS deployed
//! make kind-start-centralized  # or equivalent deployment
//!
//! # 2. Verify cluster is ready
//! kubectl get pods -n kms
//! ```
//!
//! **Run tests:**
//! ```bash
//! # Run all k8s tests
//! cargo test --test kubernetes_test_centralized --features k8s_tests
//!
//! # Via Makefile (if available)
//! make test-k8s-centralized
//! ```
//!
//! ## Configuration
//!
//! Tests use: `core-client/config/client_local_kind_centralized.toml`
//! - Points to KMS service endpoints in kind cluster
//! - Configured for local kind cluster access
//! - Must match actual cluster deployment

use kms_core_client::*;
use std::path::Path;
use std::path::PathBuf;
use std::string::String;

fn root_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf()
}

fn config_path() -> String {
    "core-client/config/client_local_kind_centralized.toml".to_string()
}

async fn insecure_key_gen(test_path: &Path) -> String {
    let path_to_config = root_path().join(config_path());
    println!("[K8S-CENTRALIZED] Starting insecure key generation");
    println!("[K8S-CENTRALIZED]   Config: {}", path_to_config.display());
    println!("[K8S-CENTRALIZED]   Keys folder: {}", test_path.display());

    let config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    let start = std::time::Instant::now();
    println!("[K8S-CENTRALIZED] Executing insecure key-gen command (max_iter=200)...");
    let key_gen_results = execute_cmd(&config, test_path).await.unwrap();
    let duration = start.elapsed();
    println!(
        "[K8S-CENTRALIZED] ✅ Insecure key-gen completed in {:.2}s",
        duration.as_secs_f64()
    );

    assert_eq!(
        key_gen_results.len(),
        1,
        "Expected exactly 1 key generation result"
    );
    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => {
            println!("[K8S-CENTRALIZED]   Generated key ID: {}", value);
            value
        }
        _ => panic!("Error doing insecure keygen: no key ID returned"),
    };

    key_id.to_string()
}

async fn crs_gen(test_path: &Path) -> String {
    let path_to_config = root_path().join(config_path());
    println!("[K8S-CENTRALIZED] Starting CRS generation");
    println!("[K8S-CENTRALIZED]   Config: {}", path_to_config.display());
    println!("[K8S-CENTRALIZED]   Keys folder: {}", test_path.display());
    println!("[K8S-CENTRALIZED]   Parameters: max_num_bits=2048");

    let command = CCCommand::CrsGen(CrsParameters { max_num_bits: 2048 });
    let config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    let start = std::time::Instant::now();
    println!("[K8S-CENTRALIZED] Executing CRS-gen command (max_iter=200)...");
    let crs_gen_results = execute_cmd(&config, test_path).await.unwrap();
    let duration = start.elapsed();
    println!(
        "[K8S-CENTRALIZED] ✅ CRS generation completed in {:.2}s",
        duration.as_secs_f64()
    );

    assert_eq!(
        crs_gen_results.len(),
        1,
        "Expected exactly 1 CRS generation result"
    );
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => {
            println!("[K8S-CENTRALIZED]   Generated CRS ID: {}", value);
            value
        }
        _ => panic!("Error doing CRS generation: no CRS ID returned"),
    };

    crs_id.to_string()
}

#[tokio::test]
async fn test_k8s_centralized_insecure() {
    println!("\n========================================");
    println!("[K8S-CENTRALIZED] TEST: test_k8s_centralized_insecure");
    println!("[K8S-CENTRALIZED] Testing basic centralized KMS operations in K8s");
    println!("========================================\n");

    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    println!(
        "[K8S-CENTRALIZED] Test workspace: {}",
        keys_folder.display()
    );

    let test_start = std::time::Instant::now();

    println!("\n[K8S-CENTRALIZED] Step 1/2: Insecure Key Generation");
    let key_id = insecure_key_gen(keys_folder).await;
    println!("[K8S-CENTRALIZED] Key ID: {}", key_id);

    println!("\n[K8S-CENTRALIZED] Step 2/2: CRS Generation");
    let crs_id = crs_gen(keys_folder).await;
    println!("[K8S-CENTRALIZED] CRS ID: {}", crs_id);

    let total_duration = test_start.elapsed();
    println!("\n========================================");
    println!("[K8S-CENTRALIZED] ✅ TEST PASSED: test_k8s_centralized_insecure");
    println!(
        "[K8S-CENTRALIZED] Total test duration: {:.2}s",
        total_duration.as_secs_f64()
    );
    println!("========================================\n");
}

#[tokio::test]
async fn full_gen_tests_default_k8s_centralized_sequential_crs() {
    println!("\n========================================");
    println!("[K8S-CENTRALIZED] TEST: full_gen_tests_default_k8s_centralized_sequential_crs");
    println!("[K8S-CENTRALIZED] Testing sequential CRS generation with Default FHE params");
    println!("[K8S-CENTRALIZED] This validates that multiple CRS generations produce unique IDs");
    println!("========================================\n");

    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    println!(
        "[K8S-CENTRALIZED] Test workspace: {}",
        keys_folder.display()
    );

    let test_start = std::time::Instant::now();

    println!("\n[K8S-CENTRALIZED] Step 1/2: First CRS Generation");
    let crs_id_1 = crs_gen(keys_folder).await;
    println!("[K8S-CENTRALIZED] First CRS ID: {}", crs_id_1);

    println!("\n[K8S-CENTRALIZED] Step 2/2: Second CRS Generation");
    let crs_id_2 = crs_gen(keys_folder).await;
    println!("[K8S-CENTRALIZED] Second CRS ID: {}", crs_id_2);

    println!("\n[K8S-CENTRALIZED] Validating uniqueness...");
    assert_ne!(
        crs_id_1, crs_id_2,
        "CRS IDs must be unique: {} vs {}",
        crs_id_1, crs_id_2
    );
    println!("[K8S-CENTRALIZED] ✅ CRS IDs are unique");

    let total_duration = test_start.elapsed();
    println!("\n========================================");
    println!(
        "[K8S-CENTRALIZED] ✅ TEST PASSED: full_gen_tests_default_k8s_centralized_sequential_crs"
    );
    println!(
        "[K8S-CENTRALIZED] Total test duration: {:.2}s",
        total_duration.as_secs_f64()
    );
    println!("========================================\n");
}
