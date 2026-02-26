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
//! | `k8s_test_insecure_keygen_encrypt_and_public_decrypt` | End-to-end: insecure keygen → encrypt → public decrypt |
//! | `k8s_test_insecure_keygen_encrypt_multiple_types` | One key, multiple FHE types: encrypt + decrypt `Ebool` and `Euint8` |
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

/// Result of an encryption operation, carrying the ciphertext file path and
/// the original plaintext so tests can compose encrypt→decrypt→compare scenarios.
struct EncryptionResult {
    /// Path to the serialised `CipherWithParams` file (ciphertext + plaintext metadata).
    pub cipher_path: PathBuf,
    /// The original plaintext hex string that was encrypted.
    pub plaintext: String,
    /// The FHE data type that was encrypted.
    pub data_type: FheType,
}

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

    /// Returns the path to the temporary workspace directory for this test.
    ///
    /// The workspace is a per-test `tempdir` that is automatically cleaned up after
    /// the test completes. All output files (ciphertext, keys, etc.) are written here.
    ///
    /// Used internally by [`Self::execute`] and [`Self::encrypt`]. Call it directly in
    /// tests that need to inspect or reference output files — for example, to check that
    /// a file was written, read its contents, or pass its path to another operation.
    ///
    /// # Example
    /// ```ignore
    /// let enc = ctx.encrypt(&key_id, "0x1", FheType::Ebool).await;
    /// assert!(ctx.workspace().join("ciphertext_ebool.bin").exists());
    /// ```
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

        execute_cmd(&config, self.workspace()).await.expect("The async runtime works.")
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

    /// Encrypt a plaintext and write the ciphertext (plus original plaintext params) to a
    /// file in the workspace.
    ///
    /// Fetches the public FHE key for `key_id` from the cluster, encrypts `plaintext`
    /// locally, and serialises the result to `<workspace>/ciphertext_<type>.bin`.
    /// Returns an [`EncryptionResult`] carrying the ciphertext path and original plaintext
    /// for use in subsequent decrypt or comparison steps.
    async fn encrypt(&self, key_id: &str, plaintext: &str, data_type: FheType) -> EncryptionResult {
        let cipher_path = self.workspace().join(format!("ciphertext_{data_type}.bin"));
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
        EncryptionResult {
            cipher_path,
            plaintext: plaintext.to_string(),
            data_type,
        }
    }

    /// Decrypt a ciphertext file via threshold MPC, verifying the result matches the
    /// original plaintext.
    ///
    /// Reads the ciphertext file produced by [`Self::encrypt`], sends it to all threshold
    /// parties, and internally calls `check_external_decryption_signature` which compares
    /// every party's decrypted bytes against the original plaintext stored in the file —
    /// panics on any mismatch. A successful return means decryption is correct.
    async fn public_decrypt_from_file(&self, enc: &EncryptionResult) {
        println!(
            "[K8S-THRESHOLD] Decrypting {:?} via threshold MPC",
            enc.cipher_path
        );
        let start = std::time::Instant::now();

        let results = self
            .execute(CCCommand::PublicDecrypt(CipherArguments::FromFile(
                CipherFile {
                    input_path: enc.cipher_path.clone(),
                    batch_size: 1,
                    num_requests: 1,
                    inter_request_delay_ms: 0,
                    parallel_requests: 1,
                },
            )))
            .await;

        assert!(
            !results.is_empty(),
            "PublicDecrypt must return at least one result"
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

/// Smoke test: Generate a key (insecure DKG, no PRSS) and a CRS.
///
/// Uses `InsecureKeyGen` — a testing shortcut that skips PRSS preprocessing.
/// Production keygen uses `PreprocKeyGen` + `KeyGen`. This test validates that
/// the fundamental MPC cluster wiring (gRPC, mTLS, party coordination) works.
#[tokio::test]
async fn k8s_test_keygen_and_crs() {
    let ctx = K8sTestContext::new("k8s_test_keygen_and_crs");

    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    let crs_id = ctx.crs_gen().await;
    assert!(!crs_id.is_empty(), "CRS ID must not be empty");

    ctx.pass();
}

/// Test that sequential insecure key generations produce unique keys.
///
/// Uses `InsecureKeyGen` (no PRSS) to verify that the MPC protocol assigns
/// a fresh, unique key ID on each call. Not representative of production keygen.
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

/// Cluster smoke test: insecure keygen → encrypt → threshold public decrypt → verify.
///
/// Uses `InsecureKeyGen` (no PRSS preprocessing) — a testing shortcut not used in
/// production, where `PreprocKeyGen` + `KeyGen` is required. The `Encrypt` step
/// fetches both the `PublicKey` and `ServerKey` from the cluster; in real client
/// operation only the `PublicKey` is needed for encryption.
///
/// What this test validates:
/// 1. Cluster wiring: all 4 parties reachable, gRPC + mTLS functional
/// 2. Key material round-trip: keygen → S3 → encrypt → decrypt
/// 3. MPC decryption correctness: `check_external_decryption_signature` passes
#[tokio::test]
async fn k8s_test_insecure_keygen_encrypt_and_public_decrypt() {
    let ctx = K8sTestContext::new("k8s_test_insecure_keygen_encrypt_and_public_decrypt");

    // Step 1: define the plaintext value that will be encrypted and later verified
    let plaintext = "0x1"; // true, encoded as Ebool
    let data_type = FheType::Ebool;

    // Step 2: generate a threshold FHE key via MPC (insecure DKG, 4 parties, mTLS)
    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    // Step 3: encrypt `plaintext` with the generated key — fetches public FHE key from
    // the cluster, encrypts locally, writes ciphertext to workspace/ciphertext_ebool.bin
    let enc = ctx.encrypt(&key_id, plaintext, data_type).await;
    assert_eq!(
        enc.plaintext, plaintext,
        "EncryptionResult must carry original plaintext"
    );

    // Step 4: send ciphertext to all 4 threshold parties for decryption.
    // Internally verifies decrypted result == original `plaintext` bytes;
    // panics on any mismatch → test fails.
    ctx.public_decrypt_from_file(&enc).await;

    ctx.pass();
}

/// Cluster smoke test: one insecure key handles multiple FHE types correctly.
///
/// Uses `InsecureKeyGen` (no PRSS) — see `k8s_test_insecure_keygen_encrypt_and_public_decrypt`
/// for caveats. Validates that a single threshold key correctly serves ciphertexts
/// of different FHE types in sequence:
/// 1. Generate one threshold FHE key
/// 2. Encrypt `true` as `Ebool` → decrypt → verify (`enc.data_type == Ebool`)
/// 3. Encrypt `0x2a` as `Euint8` → decrypt → verify (`enc.data_type == Euint8`)
#[tokio::test]
async fn k8s_test_insecure_keygen_encrypt_multiple_types() {
    let ctx = K8sTestContext::new("k8s_test_insecure_keygen_encrypt_multiple_types");

    // Step 1: generate one threshold FHE key used for all encryptions below
    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    // Step 2: encrypt a boolean value and decrypt it
    let enc_bool = ctx.encrypt(&key_id, "0x1", FheType::Ebool).await;
    assert_eq!(
        enc_bool.data_type,
        FheType::Ebool,
        "EncryptionResult must carry the correct FHE type"
    );
    ctx.public_decrypt_from_file(&enc_bool).await;

    // Step 3: encrypt an 8-bit unsigned integer and decrypt it with the same key
    let enc_uint = ctx.encrypt(&key_id, "0x2a", FheType::Euint8).await;
    assert_eq!(
        enc_uint.data_type,
        FheType::Euint8,
        "EncryptionResult must carry the correct FHE type"
    );
    ctx.public_decrypt_from_file(&enc_uint).await;

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
