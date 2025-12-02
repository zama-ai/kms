//! Kubernetes Cluster Integration Tests - Threshold Mode
//!
//! Tests CLI functionality against a real threshold KMS cluster running in Kubernetes (kind).
//! These tests verify end-to-end threshold cryptography in a production-like environment.
//!
//! ## Purpose
//!
//! Unlike isolated tests (which use in-process native servers), these tests:
//! - Connect to actual threshold KMS pods (multiple parties) in Kubernetes
//! - Test real distributed MPC operations across network
//! - Verify CLI works with production-like threshold deployment
//! - Validate Kubernetes-specific threshold configurations
//! - Test actual party-to-party communication
//!
//! ## Test Coverage
//!
//! **Threshold Mode Tests:**
//! - `k8s_test_threshold_insecure` - Distributed keygen + decryption workflow
//!
//! ## Architecture
//!
//! **Cluster Setup:**
//! - Uses kind (Kubernetes in Docker) cluster
//! - Multiple KMS pods (typically 4 parties) deployed via Helm charts
//! - Each party runs as separate pod with own storage
//! - CLI connects to all parties via service endpoints
//! - Config: `client_local_kind_threshold.toml`
//!
//! **Threshold Flow:**
//! 1. Assumes threshold KMS cluster is already running (all parties deployed)
//! 2. CLI connects to all parties via config file
//! 3. Executes distributed operations (keygen, decryption) across parties
//! 4. Validates MPC protocol execution and results
//!
//! ## Running These Tests
//!
//! **Prerequisites:**
//! ```bash
//! # 1. Start kind cluster with threshold KMS deployed (all parties)
//! make kind-start-threshold  # or equivalent deployment
//!
//! # 2. Verify all parties are ready
//! kubectl get pods -n kms
//! # Should show multiple kms-core pods (e.g., kms-core-0, kms-core-1, kms-core-2, kms-core-3)
//!
//! # 3. Verify party communication
//! kubectl logs -n kms kms-core-0 | grep "Connected to peer"
//! ```
//!
//! **Run tests:**
//! ```bash
//! # Run all k8s threshold tests
//! cargo test --test kubernetes_test_threshold --features k8s_tests
//!
//! # Via Makefile (if available)
//! make test-k8s-threshold
//! ```
//!
//! ## Configuration
//!
//! Tests use: `core-client/config/client_local_kind_threshold.toml`
//! - Points to all party endpoints in kind cluster
//! - Configured for local kind cluster access
//! - Must list all parties (typically 4)
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
    "core-client/config/client_local_kind_threshold.toml".to_string()
}

async fn insecure_key_gen(test_path: &Path) -> String {
    let path_to_config = root_path().join(config_path());
    println!("[K8S-THRESHOLD] Starting insecure key generation");
    println!("[K8S-THRESHOLD]   Config: {}", path_to_config.display());
    println!("[K8S-THRESHOLD]   Keys folder: {}", test_path.display());

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
    println!("[K8S-THRESHOLD] Executing insecure key-gen command (max_iter=200)...");
    let key_gen_results = execute_cmd(&config, test_path).await.unwrap();
    let duration = start.elapsed();
    println!(
        "[K8S-THRESHOLD] ✅ Insecure key-gen completed in {:.2}s",
        duration.as_secs_f64()
    );

    assert_eq!(
        key_gen_results.len(),
        1,
        "Expected exactly 1 key generation result"
    );
    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => {
            println!("[K8S-THRESHOLD]   Generated key ID: {}", value);
            value
        }
        _ => panic!("Error doing insecure keygen: no key ID returned"),
    };

    key_id.to_string()
}

async fn crs_gen(test_path: &Path) -> String {
    let path_to_config = root_path().join(config_path());
    println!("[K8S-THRESHOLD] Starting CRS generation");
    println!("[K8S-THRESHOLD]   Config: {}", path_to_config.display());
    println!("[K8S-THRESHOLD]   Keys folder: {}", test_path.display());
    println!("[K8S-THRESHOLD]   Parameters: max_num_bits=2048");

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
    println!("[K8S-THRESHOLD] Executing CRS-gen command (max_iter=200)...");
    let crs_gen_results = execute_cmd(&config, test_path).await.unwrap();
    let duration = start.elapsed();
    println!(
        "[K8S-THRESHOLD] ✅ CRS generation completed in {:.2}s",
        duration.as_secs_f64()
    );

    assert_eq!(
        crs_gen_results.len(),
        1,
        "Expected exactly 1 CRS generation result"
    );
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => {
            println!("[K8S-THRESHOLD]   Generated CRS ID: {}", value);
            value
        }
        _ => panic!("Error doing CRS generation: no CRS ID returned"),
    };

    crs_id.to_string()
}

#[tokio::test]
async fn test_k8s_threshold_insecure() {
    println!("\n========================================");
    println!("[K8S-THRESHOLD] TEST: test_k8s_threshold_insecure");
    println!("[K8S-THRESHOLD] Testing basic threshold KMS operations in K8s");
    println!("========================================\n");

    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    println!("[K8S-THRESHOLD] Test workspace: {}", keys_folder.display());

    let test_start = std::time::Instant::now();

    println!("\n[K8S-THRESHOLD] Step 1/2: Insecure Key Generation");
    let key_id = insecure_key_gen(keys_folder).await;
    println!("[K8S-THRESHOLD] Key ID: {}", key_id);

    println!("\n[K8S-THRESHOLD] Step 2/2: CRS Generation");
    let crs_id = crs_gen(keys_folder).await;
    println!("[K8S-THRESHOLD] CRS ID: {}", crs_id);

    let total_duration = test_start.elapsed();
    println!("\n========================================");
    println!("[K8S-THRESHOLD] ✅ TEST PASSED: test_k8s_threshold_insecure");
    println!(
        "[K8S-THRESHOLD] Total test duration: {:.2}s",
        total_duration.as_secs_f64()
    );
    println!("========================================\n");
}

#[tokio::test]
async fn full_gen_tests_default_k8s_threshold_sequential_crs() {
    println!("\n========================================");
    println!("[K8S-THRESHOLD] TEST: full_gen_tests_default_k8s_threshold_sequential_crs");
    println!("[K8S-THRESHOLD] Testing sequential CRS generation with Default FHE params");
    println!("[K8S-THRESHOLD] This validates that multiple CRS generations produce unique IDs");
    println!("========================================\n");

    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    println!("[K8S-THRESHOLD] Test workspace: {}", keys_folder.display());

    let test_start = std::time::Instant::now();

    println!("\n[K8S-THRESHOLD] Step 1/2: First CRS Generation");
    let crs_id_1 = crs_gen(keys_folder).await;
    println!("[K8S-THRESHOLD] First CRS ID: {}", crs_id_1);

    println!("\n[K8S-THRESHOLD] Step 2/2: Second CRS Generation");
    let crs_id_2 = crs_gen(keys_folder).await;
    println!("[K8S-THRESHOLD] Second CRS ID: {}", crs_id_2);

    println!("\n[K8S-THRESHOLD] Validating uniqueness...");
    assert_ne!(
        crs_id_1, crs_id_2,
        "CRS IDs must be unique: {} vs {}",
        crs_id_1, crs_id_2
    );
    println!("[K8S-THRESHOLD] ✅ CRS IDs are unique");

    let total_duration = test_start.elapsed();
    println!("\n========================================");
    println!("[K8S-THRESHOLD] ✅ TEST PASSED: full_gen_tests_default_k8s_threshold_sequential_crs");
    println!(
        "[K8S-THRESHOLD] Total test duration: {:.2}s",
        total_duration.as_secs_f64()
    );
    println!("========================================\n");
}
