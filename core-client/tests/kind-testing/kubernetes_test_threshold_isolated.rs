//! Kubernetes Cluster Integration Tests - Threshold Mode
//!
//! Tests CLI functionality against a real threshold KMS cluster running in Kubernetes (kind).
//!
//! ## Purpose
//!
//! These tests:
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
//! | `k8s_test_keygen_and_public_decrypt` | End-to-end: keygen → encrypt → public decrypt |
//!
//! ## Architecture
//!
//! - Uses kind (Kubernetes in Docker) cluster
//! - 4 KMS pods deployed via Helm charts with TLS enabled
//! - MPC connections between parties use TLS (mutual TLS)
//! - CLI connects via port-forwarded service endpoints (plain gRPC)
//! - Config: `core-client/config/client_local_kind_threshold.toml`
//!
//! ## TLS Configuration
//!
//! TLS is **enabled by default** for threshold mode deployments:
//!
//! 1. **Deployment**: `ci/scripts/lib/kms_deployment.sh` enables TLS automatically
//!    for threshold mode (`ENABLE_TLS=true` by default)
//! 2. **Certificates**: Generated and uploaded to K8s secrets during cluster setup
//! 3. **Pod-to-Pod**: All MPC communication uses mutual TLS (mTLS)
//! 4. **CLI-to-Pod**: Plain gRPC via kubectl port-forward (secure tunnel)
//!
//! The test validates MPC operations work correctly over TLS-secured channels.
//!
//! This file will eventually replace `kubernetes_test_threshold.rs`

#![cfg(feature = "kind_tests")]

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

    /// Step 1 of the encrypt→decrypt round-trip: encrypt a plaintext and write the
    /// ciphertext (plus original plaintext params) to a file in the workspace.
    ///
    /// Fetches the public FHE key for `key_id` from the cluster, encrypts `plaintext`
    /// locally, and serialises the result to `<workspace>/ciphertext.bin`.
    /// Returns the path to the ciphertext file.
    async fn encrypt(&self, key_id: &str, plaintext: &str, data_type: FheType) -> PathBuf {
        let cipher_path = self.workspace().join("ciphertext.bin");
        println!(
            "[K8S-THRESHOLD] Encrypting (key={}, plaintext={}, type={:?}) → {:?}",
            key_id, plaintext, data_type, cipher_path
        );

        let key_id_parsed = key_id.parse().expect("invalid key ID");
        self.execute(CCCommand::Encrypt(CipherParameters {
            to_encrypt: plaintext.to_string(),
            data_type,
            no_compression: false,
            no_precompute_sns: true,
            key_id: key_id_parsed,
            context_id: None,
            epoch_id: None,
            batch_size: 1,
            num_requests: 1,
            parallel_requests: 1,
            ciphertext_output_path: Some(cipher_path.clone()),
            inter_request_delay_ms: 0,
            compressed_keys: false,
        }))
        .await;

        assert!(
            cipher_path.exists(),
            "Ciphertext file must have been written"
        );
        println!("[K8S-THRESHOLD] ✅ Ciphertext written to {:?}", cipher_path);
        cipher_path
    }

    /// Step 2 of the encrypt→decrypt round-trip: decrypt a ciphertext file via
    /// threshold MPC and verify the result matches the original plaintext.
    ///
    /// Reads the ciphertext file produced by `encrypt()`, sends it to all threshold
    /// parties, and internally calls `check_external_decryption_signature` which
    /// compares every party's decrypted bytes against the original plaintext stored
    /// in the file — returns `Err` (panics via `.unwrap()`) on any mismatch.
    async fn public_decrypt_from_file(&self, cipher_path: PathBuf) {
        println!(
            "[K8S-THRESHOLD] Decrypting from file {:?} via threshold MPC",
            cipher_path
        );
        let start = std::time::Instant::now();

        let results = self
            .execute(CCCommand::PublicDecrypt(CipherArguments::FromFile(
                CipherFile {
                    input_path: cipher_path,
                    batch_size: 1,
                    num_requests: 1,
                    inter_request_delay_ms: 0,
                    parallel_requests: 1,
                },
            )))
            .await;

        assert!(
            !results.is_empty(),
            "PublicDecrypt must return at least one response"
        );
        println!(
            "[K8S-THRESHOLD] ✅ Decryption verified in {:.2}s",
            start.elapsed().as_secs_f64()
        );
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

/// End-to-end test: keygen → encrypt → threshold public decrypt → verify correctness.
///
/// Validates the full threshold use case across 4 MPC parties over mTLS:
/// 1. Generate a threshold FHE key
/// 2. Encrypt a known plaintext locally → ciphertext file
/// 3. Send ciphertext to threshold parties for decryption → verify result matches original
#[tokio::test]
async fn k8s_test_keygen_and_public_decrypt() {
    let ctx = K8sTestContext::new("k8s_test_keygen_and_public_decrypt");

    // Step 1: define the plaintext value that will be encrypted and later verified
    let plaintext = "0x1"; // true, encoded as Ebool
    let data_type = FheType::Ebool;

    // Step 2: generate a threshold FHE key via MPC (insecure DKG, 4 parties, mTLS)
    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    // Step 3: encrypt `plaintext` with the generated key — fetches public FHE key from
    // the cluster, encrypts locally, writes ciphertext to workspace/ciphertext.bin
    let cipher_path = ctx.encrypt(&key_id, plaintext, data_type).await;

    // Step 4: send ciphertext to all 4 threshold parties for decryption.
    // Internally verifies decrypted result == original `plaintext` bytes;
    // panics on any mismatch → test fails.
    ctx.public_decrypt_from_file(cipher_path).await;

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
