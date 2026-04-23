//! CLI Integration Tests - Native Execution (Docker-free)
//!
//! Verifies kms-core-client CLI tool functionality using isolated native KMS servers.
//! Replaces Docker Compose-based tests with faster, more reliable native execution.
//!
//! TODO: Currently this module resembles integration_test.rs which is big and monolithic.
//! TODO: It should be split into smaller modules for better organization after the migration.
//!
//! ## Test Coverage
//!
//! **Default Tests (9 tests, parallel execution)**:
//! - Centralized (4): keygen, CRS, backup/restore, custodian backup
//! - Threshold (5): sequential CRS, concurrent CRS, Default CRS, backup/restore, custodian backup
//!
//! **Threshold Tests (8 tests, enabled via `threshold_tests`, sequential execution)**:
//! - keygen (with PRSS), sequential preproc+keygen, concurrent preproc+keygen,
//!   Default preproc+keygen, MPC context init, MPC context switch (6-party), reshare
//! - Enable: `cargo nextest run --features threshold_tests`
//! - This flag only gates code/tests; it does NOT generate key material.
//! - For Default-param tests: pre-generated PRSS required in `test-material/default`
//!   (run `make generate-test-material-default`); missing PRSS is a hard error.
//! - Context init/switch/reshare tests generate PRSS live via `new_prss`
//!   and do NOT require pre-generated startup PRSS.
//!
//! ## Architecture
//!
//! **Test Isolation:**
//! - Each test gets isolated temporary directory with pre-generated cryptographic material
//! - Native KMS servers spawned in-process (no Docker Compose)
//! - Automatic cleanup on test completion (RAII pattern via TempDir)
//! - No shared state between tests (full isolation)
//!
//! **Execution:**
//! - Default tests run in parallel for speed
//! - PRSS tests run sequentially (marked with `#[serial]`) due to network coordination
//! - CLI commands unchanged (testing actual CLI functionality)
//!
//! **Feature Flags:**
//! - `threshold_tests`: Enables threshold PRSS tests and their setup helpers (`ensure_default_prss=true`).
//!   Implies `testing`. Does NOT enable Kind/Kubernetes tests.
//! - `kind_tests`: Enables Kind/Kubernetes cluster tests under `tests/kind-testing/`.
//! - `testing`: Base test helpers (required for compilation of all test targets).
//!
//! **Gating patterns:**
//! - `#[cfg(feature = "threshold_tests")]` on the fn — used when the test body calls
//!   feature-gated helpers (e.g. `setup_*_with_prss`, `real_preproc_and_keygen`).
//!   The test is invisible to `cargo test` without the feature.
//! - `#[cfg_attr(not(feature = "threshold_tests"), ignore)]` on the fn — used when the
//!   test body compiles without the feature (e.g. `test_threshold_mpc_context_init`,
//!   `test_threshold_mpc_context_switch_6`). The test is visible but skipped without the feature.
//!
//! ## How Tests Execute
//!
//! Native isolated tests run KMS servers as in-process Rust processes (no Docker):
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ Test Function Execution                                      │
//! ├─────────────────────────────────────────────────────────────┤
//! │                                                              │
//! │  1. Setup Phase                                              │
//! │     setup_isolated_centralized_cli_test("my_test")          │
//! │     ├─ Creates TempDir with isolated material               │
//! │     ├─ Spawns KMS server (native Rust process)              │
//! │     │  └─ Server listens on 127.0.0.1:54321 (dynamic port)  │
//! │     └─ Generates config file pointing to server             │
//! │                                                              │
//! │  2. CLI Command Execution                                    │
//! │     ├─ kms-core-client --config client_config.toml          │
//! │     ├─ Reads config → connects to 127.0.0.1:54321           │
//! │     └─ Sends gRPC request to running server                 │
//! │                                                              │
//! │  3. Server Processing                                        │
//! │     ├─ Receives gRPC request                                │
//! │     ├─ Performs operation (keygen, decrypt, etc.)           │
//! │     └─ Returns gRPC response                                │
//! │                                                              │
//! │  4. Test Validation                                          │
//! │     └─ assert!(output.status.success())                     │
//! │                                                              │
//! │  5. Automatic Cleanup (RAII)                                │
//! │     ├─ _server dropped → server.assert_shutdown()           │
//! │     ├─ Sends shutdown signal → server stops                 │
//! │     ├─ Verifies ports closed                                │
//! │     └─ material_dir dropped → temp directory deleted        │
//! │                                                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Key Points:**
//! - **Native Process:** Server runs as Rust process
//! - **Dynamic Ports:** Each test gets unique port (no conflicts)
//! - **RAII Cleanup:** Server and temp dir auto-cleanup via Drop trait
//! - **Real gRPC:** CLI sends actual gRPC requests to running server
//! - **Full Isolation:** Each test completely isolated (own server, material, temp dir)
//!
//! ## Writing New Tests
//!
//! ### Centralized Test Example
//!
//! ```no_run
//! #[tokio::test]
//! async fn test_my_centralized_feature() -> Result<()> {
//!     // Setup: Returns (TempDir, ServerHandle, PathBuf)
//!     let (material_dir, _server, config_path) =
//!         setup_isolated_centralized_cli_test("my_test").await?;
//!
//!     // Run CLI commands using config_path
//!     let output = Command::new(env!("CARGO_BIN_EXE_kms-core-client"))
//!         .args(["--config", config_path.to_str().unwrap()])
//!         .args(["your-command"])
//!         .output()?;
//!
//!     assert!(output.status.success());
//!     Ok(())
//! }
//! ```
//!
//! ### Threshold Test Example
//!
//! ```no_run
//! #[tokio::test]
//! async fn test_my_threshold_feature() -> Result<()> {
//!     // Setup: Returns (TempDir, HashMap<u32, ServerHandle>, PathBuf)
//!     let (material_dir, _servers, config_path) =
//!         setup_isolated_threshold_cli_test_default("my_test", 4).await?;
//!
//!     // CLI automatically communicates with all 4 parties via config
//!     // Run your test commands here
//!     Ok(())
//! }
//! ```
//!
//! **Threshold Test Execution Model:**
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │ Single Test Thread (tokio runtime)                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  Main Test Task                                                  │
//! │  ├─ setup_threshold_isolated(4 parties)                         │
//! │  │                                                               │
//! │  └─ Spawns 4 async tasks (tokio::spawn):                        │
//! │      ├─ Task 1: Party 1 Server (service port + MPC port)        │
//! │      ├─ Task 2: Party 2 Server (service port + MPC port)        │
//! │      ├─ Task 3: Party 3 Server (service port + MPC port)        │
//! │      └─ Task 4: Party 4 Server (service port + MPC port)        │
//! │                                                                  │
//! │  All tasks run concurrently on tokio thread pool                │
//! │  (NOT separate OS threads - async tasks!)                       │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! **Key Points:**
//! - Each party runs as a lightweight async task (via `tokio::spawn`)
//! - All tasks share the same tokio runtime (thread pool)
//! - Each party has unique ports: service port (gRPC) + MPC port (party communication)
//! - Real TCP communication between parties over localhost
//! - Efficient: Can run many parties without OS thread overhead
//!
//! ### Threshold Test Example (calls feature-gated helper → use `#[cfg(feature)]`)
//!
//! ```no_run
//! #[cfg(feature = "threshold_tests")]
//! #[tokio::test]
//! #[serial]
//! async fn test_my_threshold_feature() -> Result<()> {
//!     let (material_dir, _servers, config_path) =
//!         setup_isolated_threshold_cli_test_with_prss("my_test", 4).await?;
//!     // Run PRSS operations (keygen, preprocessing, etc.)
//!     Ok(())
//! }
//! ```
//!
//! ### Threshold Test Example (body compiles without feature → use `#[cfg_attr]`)
//!
//! ```no_run
//! #[tokio::test]
//! #[serial]
//! #[cfg_attr(not(feature = "threshold_tests"), ignore)]
//! async fn test_my_context_feature() -> Result<()> {
//!     let (material_dir, _servers, config_path) =
//!         setup_isolated_threshold_cli_test_signing_only("my_test", 4).await?;
//!     new_prss(&config_path, context_id, epoch_id, test_path).await?;
//!     Ok(())
//! }
//! ```
//!
//! ## Setup Function Variants
//!
//! **Centralized:**
//! - `setup_isolated_centralized_cli_test()` - Basic setup
//! - `setup_isolated_centralized_cli_test_with_backup()` - With backup vault
//! - `setup_isolated_centralized_cli_test_with_custodian_backup()` - With custodian keychain
//!
//! **Threshold:**
//! - `setup_isolated_threshold_cli_test()` - Test FHE params (fast)
//! - `setup_isolated_threshold_cli_test_default()` - Default FHE params (production-like)
//! - `setup_isolated_threshold_cli_test_with_prss()` - With PRSS (Test params)
//! - `setup_isolated_threshold_cli_test_with_prss_default()` - With PRSS (Default production-like params)
//! - `setup_isolated_threshold_cli_test_with_backup()` - With backup vault
//! - `setup_isolated_threshold_cli_test_with_custodian_backup()` - With custodian keychain
//!
//! ## Return Values Explained
//!
//! All setup functions return a tuple with:
//! 1. `TempDir` - Isolated temporary directory (auto-cleanup on drop)
//! 2. `ServerHandle` or `HashMap<u32, ServerHandle>` - Running KMS server(s) (auto-shutdown on drop)
//! 3. `PathBuf` - Path to generated CLI config file (use with `--config` flag)
//!
//! ## Running Tests
//!
//! ```bash
//! # Fast tests only (no PRSS)
//! cargo nextest run --test integration_test --features testing
//!
//! # All threshold tests (requires pre-generated Default PRSS for nightly_full_gen_tests_*)
//! cargo nextest run --test integration_test --features threshold_tests
//!
//! # Specific test
//! cargo nextest run --test integration_test --features testing -E 'test(test_centralized_insecure)'
//! ```

use anyhow::Result;
use futures::future::join_all;
use kms_core_client::*;
use kms_grpc::KeyId;
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::rpc_types::PubDataType;
use kms_lib::DecryptionMode;
use kms_lib::client::test_tools::ServerHandle;
use kms_lib::consts::{
    DEFAULT_EPOCH_ID, DEFAULT_MPC_CONTEXT, ID_LENGTH, SAFE_SER_SIZE_LIMIT, SIGNING_KEY_ID,
};
use kms_lib::testing::prelude::*;
use observability::conf::Settings;
use serde::Deserialize;
use serial_test::serial;
use std::collections::HashMap;
use std::fs::write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::string::String;
use tempfile::TempDir;
use test_utils::test_logging::init_test_logging as init_logging;
#[cfg(feature = "threshold_tests")]
use tfhe::zk::CompactPkeCrs;
use tracing::info;
use validator::Validate;

// Additional imports for custodian and threshold tests
use kms_core_client::mpc_context::create_test_context_info_from_core_config;
use kms_grpc::identifiers::EpochId;
use kms_grpc::{ContextId, RequestId};
use kms_lib::backup::SEED_PHRASE_DESC;
use kms_lib::engine::base::derive_request_id;
use std::fs::create_dir_all;
use std::process::{Command, Output};
use tfhe::safe_serialization::safe_serialize;

// Additional imports for reshare test (only needed with threshold_tests feature)
#[cfg(feature = "threshold_tests")]
use kms_lib::engine::base::{
    DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY, safe_serialize_hash_element_versioned,
};
#[cfg(feature = "threshold_tests")]
use kms_lib::util::key_setup::test_tools::{
    load_material_from_pub_storage, load_pk_from_pub_storage,
};

// ============================================================================
// UTILITY HELPERS
// ============================================================================

/// Serialize a validated `CoreClientConfig` to TOML for isolated test fixtures.
fn write_core_client_toml(path: &Path, cfg: &CoreClientConfig) -> Result<()> {
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("CoreClientConfig validation failed: {e}"))?;
    let toml_str = toml::to_string_pretty(cfg)
        .map_err(|e| anyhow::anyhow!("TOML serialization failed: {e}"))?;
    write(path, toml_str)?;
    Ok(())
}

/// Mock PCR value used for TLS auto mode in test configs.
/// This must match the value the test enclave mock expects.
const MOCK_PCR: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f";

/// Build a minimal `CoreConfig` for a threshold test party.
///
/// Constructing the config programmatically provides compile-time guarantees
/// that the generated TOML matches the `CoreConfig` schema (which uses
/// `#[serde(deny_unknown_fields)]`).
fn build_test_core_config(
    service_port: u16,
    mpc_port: u16,
    my_id: usize,
    threshold_value: u8,
    server_id: usize,
    material_path: &Path,
    peers: Vec<kms_lib::conf::threshold::PeerConf>,
) -> kms_lib::conf::CoreConfig {
    use kms_lib::conf::threshold::{ThresholdPartyConf, TlsConf};
    use kms_lib::conf::{
        AWSConfig, CoreConfig, FileStorage, S3Storage, ServiceEndpoint, Storage, VaultConfig,
    };
    use threshold_networking::tls::ReleasePCRValues;

    let mock_pcr_bytes = hex::decode(MOCK_PCR).expect("MOCK_PCR must be valid hex");

    CoreConfig {
        service: ServiceEndpoint {
            listen_address: "127.0.0.1".to_string(),
            listen_port: service_port,
            timeout_secs: 30,
            grpc_max_message_size: 104_857_600,
        },
        telemetry: None,
        aws: Some(AWSConfig {
            region: "us-east-1".to_string(),
            role_arn: None,
            imds_endpoint: None,
            sts_endpoint: None,
            s3_endpoint: Some("http://dev-s3-mock:9000".parse().expect("valid URL")),
            awskms_endpoint: None,
        }),
        public_vault: Some(VaultConfig {
            storage: Storage::S3(S3Storage {
                bucket: "kms-public".to_string(),
                prefix: Some(format!("PUB-p{server_id}")),
            }),
            keychain: None,
        }),
        private_vault: Some(VaultConfig {
            storage: Storage::File(FileStorage {
                path: material_path.join(format!("PRIV-p{server_id}")),
                prefix: None,
            }),
            keychain: None,
        }),
        backup_vault: None,
        rate_limiter_conf: None,
        threshold: Some(ThresholdPartyConf {
            listen_address: "127.0.0.1".to_string(),
            listen_port: mpc_port,
            tls: Some(TlsConf::Auto {
                eif_signing_cert: None,
                trusted_releases: vec![ReleasePCRValues {
                    pcr0: mock_pcr_bytes.clone(),
                    pcr1: mock_pcr_bytes.clone(),
                    pcr2: mock_pcr_bytes,
                }],
                ignore_aws_ca_chain: None,
                attest_private_vault_root_key: None,
                renew_slack_after_expiration: None,
                renew_fail_retry_timeout: None,
            }),
            threshold: threshold_value,
            my_id: Some(my_id),
            dec_capacity: 100,
            min_dec_cache: 10,
            preproc_redis: None,
            num_sessions_preproc: Some(2),
            peers: Some(peers),
            core_to_core_net: None,
            decryption_mode: DecryptionMode::NoiseFloodSmall,
        }),
        internal_config: None,
        mock_enclave: Some(true),
    }
}

/// Validate and serialize a `CoreConfig` to TOML, writing it to the given path.
fn write_core_config_toml(path: &Path, cfg: &kms_lib::conf::CoreConfig) -> Result<()> {
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("CoreConfig validation failed: {e}"))?;
    let toml_str = toml::to_string_pretty(cfg)
        .map_err(|e| anyhow::anyhow!("CoreConfig TOML serialization failed: {e}"))?;
    write(path, toml_str)?;
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_path = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else {
            std::fs::copy(entry.path(), dest_path)?;
        }
    }
    Ok(())
}

// ============================================================================
// CLI TEST SETUP FUNCTIONS
// ============================================================================

/// Helper to setup isolated centralized KMS for CLI testing (without backup vault)
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "centralized_insecure")
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `ServerHandle` - Running KMS server (auto-shutdown on drop)
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Example
/// ```no_run
/// let (material_dir, _server, config_path) =
///     setup_isolated_centralized_cli_test("my_test").await?;
/// ```
async fn setup_isolated_centralized_cli_test(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, false, false, FheParameter::Test).await
}

/// Helper to setup isolated centralized KMS for CLI testing with backup vault
async fn setup_isolated_centralized_cli_test_with_backup(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, false, FheParameter::Test).await
}

/// Helper to setup isolated centralized KMS for CLI testing with custodian backup vault
async fn setup_isolated_centralized_cli_test_with_custodian_backup(
    test_name: &str,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    setup_isolated_centralized_cli_test_impl(test_name, true, true, FheParameter::Test).await
}

/// Generate CLI config file for centralized KMS
///
/// Note: We generate configs dynamically (not from template files) because:
/// - Ports are dynamically allocated (random free ports per test)
/// - Paths are dynamic (unique TempDir per test)
/// - This ensures complete test isolation
///
/// Output matches the production client schema (`CoreClientConfig`); see
/// `core-client/config/client_local_centralized.toml` for the reference shape.
fn generate_centralized_cli_config(
    material_dir: &TempDir,
    server: &ServerHandle,
    fhe_params: FheParameter,
) -> Result<PathBuf> {
    let config_path = material_dir.path().join("client_config.toml");
    // Canonicalize the path to resolve symlinks (e.g., /var -> /private/var on macOS)
    // This ensures the CLI client uses the same path as the FileStorage
    let canonical_path = material_dir.path().canonicalize()?;
    let cfg = CoreClientConfig {
        kms_type: KmsType::Centralized,
        cores: vec![CoreConf {
            party_id: 1,
            address: format!("localhost:{}", server.service_port),
            s3_endpoint: format!("file://{}", canonical_path.display()),
            object_folder: "PUB".to_string(),
            private_object_folder: None,
            config_path: None,
        }],
        decryption_mode: None,
        num_majority: 1,
        num_reconstruct: 1,
        fhe_params: Some(fhe_params),
    };
    write_core_client_toml(&config_path, &cfg)?;
    Ok(config_path)
}

/// Internal implementation for centralized CLI test setup
async fn setup_isolated_centralized_cli_test_impl(
    test_name: &str,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
) -> Result<(TempDir, ServerHandle, PathBuf)> {
    // Use builder pattern with full feature support
    let mut builder = CentralizedTestEnv::builder().with_test_name(test_name);

    if with_backup_vault {
        builder = builder.with_backup_vault();
    }

    if with_custodian_keychain {
        builder = builder.with_custodian_keychain();
    }

    let env = builder.build().await?;

    // Extract components for CLI usage
    let material_dir = env.material_dir;
    let server = env.server;

    // Generate CLI config file pointing to local test material
    let config_path = generate_centralized_cli_config(&material_dir, &server, fhe_params)?;

    Ok((material_dir, server, config_path))
}

/// Helper to setup isolated threshold KMS for CLI testing (without PRSS / backup vault)
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_crs")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of running KMS servers (party_id -> ServerHandle)
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Example
/// ```no_run
/// let (material_dir, _servers, config_path) =
///     setup_isolated_threshold_cli_test("my_test", 4).await?;
/// ```
#[allow(dead_code)] // Part of test infrastructure API, kept for future use
async fn setup_isolated_threshold_cli_test(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing WITHOUT pre-loaded PRSS material.
///
/// These tests create their own MPC context and epoch from scratch.
/// The server will start with an empty epoch map, so `NewEpoch` calls won't conflict
/// with pre-loaded PRSS data.
async fn setup_isolated_threshold_cli_test_signing_only(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl_with_spec(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Test,
        Some(kms_lib::testing::material::TestMaterialSpec::threshold_signing_only(party_count)),
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with PRSS enabled
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_prss_keygen")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with PRSS material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of KMS servers with PRSS initialized
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Note
/// Requires `threshold_tests` feature. Tests using this must be marked with:
/// - `#[serial]` - Sequential execution required (PRSS network coordination)
/// - `#[cfg_attr(not(feature = "threshold_tests"), ignore)]`
///
/// This helper enables `ensure_default_prss=true` during server startup. The test material copy
/// includes pre-generated PRSS (from `test-material`). At startup, the server checks
/// whether the loaded PRSS profile matches the context shape; if it does, live MPC
/// PRSS init is skipped entirely.
///
/// With **Test params** (`FheParameter::Test`), missing PRSS can be initialized live.
/// For **Default params**, use `setup_isolated_threshold_cli_test_with_prss_default`,
/// which requires pre-generated PRSS material under `test-material/default`.
///
/// # Example
/// ```no_run
/// #[tokio::test]
/// #[serial]
/// #[cfg_attr(not(feature = "threshold_tests"), ignore)]
/// async fn test_prss_feature() -> Result<()> {
///     let (material_dir, _servers, config_path) =
///         setup_isolated_threshold_cli_test_with_prss("my_prss_test", 4).await?;
///     // Run PRSS operations
///     Ok(())
/// }
/// ```
#[cfg(feature = "threshold_tests")]
async fn setup_isolated_threshold_cli_test_with_prss(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        true,
        false,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with backup vault
async fn setup_isolated_threshold_cli_test_with_backup(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        true,
        false,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with custodian backup vault
async fn setup_isolated_threshold_cli_test_with_custodian_backup(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        true,
        true,
        FheParameter::Test,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with Default FHE parameters
///
/// # Arguments
/// * `test_name` - Test identifier for logging/debugging (e.g., "threshold_default")
/// * `party_count` - Number of parties in threshold cluster (typically 4)
///
/// # Returns
/// * `TempDir` - Isolated temporary directory with test material (auto-cleanup on drop)
/// * `HashMap<u32, ServerHandle>` - Map of running KMS servers with Default FHE params
/// * `PathBuf` - Path to generated CLI config file (for --config flag)
///
/// # Note
/// Uses Default FHE parameters (production-like, slower than Test params) with `ensure_default_prss=false`.
/// Internally uses `TestMaterialSpec::threshold_default_no_prss` — PRSS is excluded from
/// required material and is not used at all (no pre-generated PRSS needed).
///
/// # Example
/// ```no_run
/// let (material_dir, _servers, config_path) =
///     setup_isolated_threshold_cli_test_default("my_test", 4).await?;
/// ```
async fn setup_isolated_threshold_cli_test_default(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        false,
        false,
        false,
        FheParameter::Default,
    )
    .await
}

/// Helper to setup isolated threshold KMS for CLI testing with Default FHE parameters and PRSS enabled
///
/// Uses `ensure_default_prss=true` with `FheParameter::Default`.
///
/// Requires pre-generated Default PRSS material in `test-material/default`
/// (for example via `make generate-test-material-default`), otherwise setup fails fast.
#[cfg(feature = "threshold_tests")]
async fn setup_isolated_threshold_cli_test_with_prss_default(
    test_name: &str,
    party_count: usize,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl(
        test_name,
        party_count,
        true,
        false,
        false,
        FheParameter::Default,
    )
    .await
}

/// Generate CLI config files for threshold KMS
///
/// Note: We generate configs dynamically (not from template files) because:
/// - Ports are dynamically allocated (random free ports per test)
/// - Paths are dynamic (unique TempDir per test)
/// - Party count varies between tests (4, 6, etc.)
/// - This ensures complete test isolation
///
/// Client output matches `CoreClientConfig`; see `core-client/config/client_local_threshold.toml`.
/// Per-party `compose_*.toml` server configs are built from typed `CoreConfig` structs
/// to ensure compile-time schema compatibility.
fn generate_threshold_cli_config(
    material_dir: &kms_lib::testing::material::TestMaterialHandle,
    servers: &HashMap<u32, ServerHandle>,
    party_count: usize,
    fhe_params: FheParameter,
) -> Result<PathBuf> {
    use kms_lib::conf::threshold::PeerConf;

    let config_path = material_dir.path().join("client_config.toml");
    let majority = party_count / 2 + 1;

    // Create server config files for each party (needed for MPC context creation)
    let threshold_value = (party_count.div_ceil(3) - 1) as u8;
    let mut cores = Vec::with_capacity(party_count);

    for i in 1..=party_count {
        let server = servers
            .get(&(i as u32))
            .unwrap_or_else(|| panic!("Server {} should exist", i));

        let server_config_path = material_dir.path().join(format!("compose_{}.toml", i));

        // Build typed peer list for this party
        let peers: Vec<PeerConf> = (1..=party_count)
            .map(|j| {
                let peer_server = servers.get(&(j as u32)).unwrap();
                PeerConf {
                    party_id: j,
                    address: "127.0.0.1".to_string(),
                    mpc_identity: Some(format!("kms-core-{j}.local")),
                    port: peer_server
                        .mpc_port
                        .expect("MPC port should be set for threshold server"),
                    tls_cert: None,
                    verification_address: None,
                }
            })
            .collect();

        let core_config = build_test_core_config(
            server.service_port,
            server.mpc_port.expect("MPC port should be set"),
            i,
            threshold_value,
            i,
            material_dir.path(),
            peers,
        );
        write_core_config_toml(&server_config_path, &core_config)?;

        cores.push(CoreConf {
            party_id: i,
            address: format!("localhost:{}", server.service_port),
            s3_endpoint: format!("file://{}", material_dir.path().display()),
            object_folder: format!("PUB-p{i}"),
            private_object_folder: Some(format!("PRIV-p{i}")),
            config_path: Some(server_config_path),
        });
    }

    let cfg = CoreClientConfig {
        kms_type: KmsType::Threshold,
        cores,
        decryption_mode: None,
        num_majority: majority,
        num_reconstruct: majority,
        fhe_params: Some(fhe_params),
    };
    write_core_client_toml(&config_path, &cfg)?;
    Ok(config_path)
}

/// Internal implementation for threshold CLI test setup
async fn setup_isolated_threshold_cli_test_impl(
    test_name: &str,
    party_count: usize,
    ensure_default_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    setup_isolated_threshold_cli_test_impl_with_spec(
        test_name,
        party_count,
        ensure_default_prss,
        with_backup_vault,
        with_custodian_keychain,
        fhe_params,
        None,
    )
    .await
}

/// Internal implementation for threshold CLI test setup with optional material spec
async fn setup_isolated_threshold_cli_test_impl_with_spec(
    test_name: &str,
    party_count: usize,
    ensure_default_prss: bool,
    with_backup_vault: bool,
    with_custodian_keychain: bool,
    fhe_params: FheParameter,
    material_spec: Option<kms_lib::testing::material::TestMaterialSpec>,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
)> {
    // Use builder pattern with full feature support
    let mut builder = ThresholdTestEnv::builder()
        .with_test_name(test_name)
        .with_party_count(party_count);

    let default_material_spec = match (fhe_params, ensure_default_prss) {
        (FheParameter::Default, true) => {
            kms_lib::testing::material::TestMaterialSpec::threshold_default(party_count)
        }
        (FheParameter::Default, false) => {
            kms_lib::testing::material::TestMaterialSpec::threshold_default_no_prss(party_count)
        }
        _ => kms_lib::testing::material::TestMaterialSpec::threshold_basic(party_count),
    };
    builder = builder.with_material_spec(material_spec.unwrap_or(default_material_spec));

    if ensure_default_prss {
        builder = builder.with_prss();
    }

    if with_backup_vault {
        builder = builder.with_backup_vault();
    }

    if with_custodian_keychain {
        builder = builder.with_custodian_keychain();
    }

    let env = builder.build().await?;

    // Extract components for CLI usage
    let material_dir = env.material_dir;
    let servers = env.servers;

    // Generate CLI config files
    let config_path =
        generate_threshold_cli_config(&material_dir, &servers, party_count, fhe_params)?;

    Ok((material_dir, servers, config_path))
}

// ============================================================================
// PARTY RESHARING SETUP
// ============================================================================

/// Setup 6 servers with per-server peer configuration for party resharing tests.
///
/// This creates:
/// - Servers 1-4 with peers [1,2,3,4] (for context 1)
/// - Servers 5,6,4,3 with peers [5,6,4,3] as MPC parties [1,2,3,4] (for context 2)
///   - Server 5 → party 1 (replacing server 1)
///   - Server 6 → party 2 (replacing server 2)
///   - Server 4 → party 3 (was party 4 in context 1 — role swap)
///   - Server 3 → party 4 (was party 3 in context 1 — role swap)
///
/// The role swap for servers 3 and 4 makes the test more challenging by ensuring
/// that surviving servers change their MPC party roles between contexts.
///
/// Returns:
/// - TestMaterialHandle with test material
/// - HashMap of server handles
/// - Config path for context 1 (servers 1,2,3,4)
/// - Config path for context 2 (servers 5,6,4,3)
///
/// TODO: add possibility for dynamic party number setup
async fn setup_party_resharing_servers(
    test_name: &str,
) -> Result<(
    kms_lib::testing::material::TestMaterialHandle,
    HashMap<u32, ServerHandle>,
    PathBuf,
    PathBuf,
)> {
    use kms_lib::conf::threshold::PeerConf;
    use kms_lib::testing::helpers::create_test_material_manager;
    use kms_lib::testing::material::TestMaterialSpec;
    use kms_lib::vault::storage::StorageType;
    use kms_lib::vault::storage::file::FileStorage;

    let manager = create_test_material_manager();

    // Setup material for 4 parties (the test uses 6 servers but operates in 4-party contexts)
    // Servers 1-4 form context 1, servers 5,6,3,4 form context 2 (party resharing)
    // Use threshold_signing_only since this test generates FHE keys dynamically
    let spec = TestMaterialSpec::threshold_signing_only(4);
    let material_dir = manager.setup_test_material_auto(&spec, test_name).await?;

    // Create storage for each of the 6 servers
    let pub_prefixes = [
        Some("PUB-p1".to_string()),
        Some("PUB-p2".to_string()),
        Some("PUB-p3".to_string()),
        Some("PUB-p4".to_string()),
        Some("PUB-p5".to_string()),
        Some("PUB-p6".to_string()),
    ];
    let priv_prefixes = [
        Some("PRIV-p1".to_string()),
        Some("PRIV-p2".to_string()),
        Some("PRIV-p3".to_string()),
        Some("PRIV-p4".to_string()),
        Some("PRIV-p5".to_string()),
        Some("PRIV-p6".to_string()),
    ];

    let mut pub_storages = Vec::new();
    let mut priv_storages = Vec::new();
    for (pub_prefix, priv_prefix) in pub_prefixes.iter().zip(&priv_prefixes) {
        pub_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PUB,
            pub_prefix.as_deref(),
        )?);
        priv_storages.push(FileStorage::new(
            Some(material_dir.path()),
            StorageType::PRIV,
            priv_prefix.as_deref(),
        )?);
    }

    // Ensure signing keys exist for all 6 servers
    // The test material only has keys for 4 parties, so we need to generate for servers 5-6
    use kms_lib::consts::SIGNING_KEY_ID;
    use kms_lib::util::key_setup::{
        ThresholdSigningKeyConfig, ensure_threshold_server_signing_keys_exist,
    };
    let _ = ensure_threshold_server_signing_keys_exist(
        &mut pub_storages,
        &mut priv_storages,
        &SIGNING_KEY_ID,
        true, // deterministic
        ThresholdSigningKeyConfig::AllParties((1..=6).map(|i| format!("party-{i}")).collect()),
        false, // don't skip if exists
    )
    .await;

    // Create peer configurations for party resharing:
    // - Servers 1-4: peers [1,2,3,4] (standard 4-party setup)
    // - Servers 5-6: peers [5,6,3,4] where server 5 acts as party 1, server 6 as party 2
    //   (This allows servers 5,6 to replace servers 1,2 in context 2)

    // Peers for servers 1-4 (context 1)
    let peers_1234: Vec<PeerConf> = (1..=4)
        .map(|i| PeerConf {
            party_id: i,
            address: "127.0.0.1".to_string(),
            mpc_identity: Some(format!("kms-core-{}.local", i)),
            port: 0, // Will be updated by setup_threshold_with_custom_peers
            tls_cert: None,
            verification_address: None,
        })
        .collect();

    // Peers for context 2: servers [5,6,4,3] acting as MPC parties [1,2,3,4]
    // - Server 5 (index 4) acts as MPC party 1 (replacing server 1)
    // - Server 6 (index 5) acts as MPC party 2 (replacing server 2)
    // - Server 4 (index 3) acts as MPC party 3 (was party 4 in ctx1 — role swap)
    // - Server 3 (index 2) acts as MPC party 4 (was party 3 in ctx1 — role swap)
    let peers_ctx2: Vec<PeerConf> = vec![
        PeerConf {
            party_id: 1, // MPC party 1
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-5.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 2, // MPC party 2
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-6.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 3, // MPC party 3 — server 4 (swapped from party 4 in ctx1)
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-4.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
        PeerConf {
            party_id: 4, // MPC party 4 — server 3 (swapped from party 3 in ctx1)
            address: "127.0.0.1".to_string(),
            mpc_identity: Some("kms-core-3.local".to_string()),
            port: 0,
            tls_cert: None,
            verification_address: None,
        },
    ];

    // Server configs: (my_id, threshold, peers, peer_server_indices)
    // - my_id: The MPC party ID this server will act as
    // - peer_server_indices: Maps each peer (by index in peers vec) to physical server index (0-based)
    //
    // Context 1 servers (indices 0-3): peers map to servers 0,1,2,3
    // Context 2 servers (indices 4-5): peers map to servers 4,5,3,2 (with role swap for 3↔4)
    let peer_indices_ctx1 = vec![0, 1, 2, 3]; // Peers 1,2,3,4 → servers 0,1,2,3
    let peer_indices_ctx2 = vec![4, 5, 3, 2]; // Peers 1,2,3,4 → servers 4,5,3(=party4→party3),2(=party3→party4)

    let server_configs: Vec<(usize, u8, Vec<PeerConf>, Vec<usize>)> = vec![
        (1, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 1 (idx 0): party 1
        (2, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 2 (idx 1): party 2
        (3, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 3 (idx 2): party 3
        (4, 1, peers_1234.clone(), peer_indices_ctx1.clone()), // Server 4 (idx 3): party 4
        (1, 1, peers_ctx2.clone(), peer_indices_ctx2.clone()), // Server 5 (idx 4): party 1 in ctx2
        (2, 1, peers_ctx2.clone(), peer_indices_ctx2.clone()), // Server 6 (idx 5): party 2 in ctx2
    ];

    let vaults: Vec<Option<kms_lib::vault::Vault>> = (0..6).map(|_| None).collect();

    // Start servers with custom peer configurations
    let servers = kms_lib::client::test_tools::setup_threshold_with_custom_peers(
        server_configs,
        pub_storages,
        priv_storages,
        vaults,
        false, // ensure_default_prss - we'll do this per-context
        None,  // rate_limiter_conf
        None,  // decryption_mode
    )
    .await;

    // Generate server config files for MPC context creation (needed for PCR values)
    // These are minimal configs with mock_enclave = true and TLS auto mode
    let threshold_value = 1; // For 4 parties: threshold = 1

    // Helper: map party_id to physical server_id for a given context
    let party_to_server_ctx1 = |party_id: usize| -> u32 { party_id as u32 };
    let party_to_server_ctx2 = |party_id: usize| -> u32 {
        match party_id {
            1 => 5,
            2 => 6,
            3 => 4, // server 4 acts as party 3 in ctx2 (swapped)
            4 => 3, // server 3 acts as party 4 in ctx2 (swapped)
            _ => party_id as u32,
        }
    };

    // Generate a typed compose config file for a given server in a given context.
    let write_compose_config = |config_path: &Path,
                                server_id: usize,
                                my_party_id: usize,
                                peers: &[PeerConf],
                                party_to_server: &dyn Fn(usize) -> u32|
     -> Result<()> {
        let server = servers.get(&(server_id as u32)).unwrap();

        // Build typed peer list, resolving each peer's MPC port from the physical server
        let typed_peers: Vec<PeerConf> = peers
            .iter()
            .map(|peer| {
                let peer_server_id = party_to_server(peer.party_id);
                let peer_server = servers.get(&peer_server_id).unwrap();
                PeerConf {
                    party_id: peer.party_id,
                    address: "127.0.0.1".to_string(),
                    mpc_identity: Some(format!("kms-core-{peer_server_id}.local")),
                    port: peer_server.mpc_port.expect("MPC port should be set"),
                    tls_cert: None,
                    verification_address: None,
                }
            })
            .collect();

        let core_config = build_test_core_config(
            server.service_port,
            server.mpc_port.expect("MPC port should be set"),
            my_party_id,
            threshold_value as u8,
            server_id,
            material_dir.path(),
            typed_peers,
        );
        write_core_config_toml(config_path, &core_config)?;
        Ok(())
    };

    // Context 1 configs: servers 1-4 with peers_1234
    for server_id in 1..=4 {
        let path = material_dir
            .path()
            .join(format!("compose_{}.toml", server_id));
        write_compose_config(
            &path,
            server_id,
            server_id,
            &peers_1234,
            &party_to_server_ctx1,
        )?;
    }

    // Context 2 configs: servers 5,6 (new) + servers 3,4 with swapped roles
    // Server 5 → party 1, Server 6 → party 2
    for server_id in 5..=6 {
        let path = material_dir
            .path()
            .join(format!("compose_{}.toml", server_id));
        write_compose_config(
            &path,
            server_id,
            server_id - 4, // 5→1, 6→2
            &peers_ctx2,
            &party_to_server_ctx2,
        )?;
    }
    // Servers 3,4 need separate ctx2 configs with swapped roles
    // Server 4 → party 3 in ctx2 (was party 4 in ctx1)
    let compose_4_ctx2_path = material_dir.path().join("compose_4_ctx2.toml");
    write_compose_config(
        &compose_4_ctx2_path,
        4,
        3,
        &peers_ctx2,
        &party_to_server_ctx2,
    )?;
    // Server 3 → party 4 in ctx2 (was party 3 in ctx1)
    let compose_3_ctx2_path = material_dir.path().join("compose_3_ctx2.toml");
    write_compose_config(
        &compose_3_ctx2_path,
        3,
        4,
        &peers_ctx2,
        &party_to_server_ctx2,
    )?;

    // Generate CLI config for context 1 (servers 1,2,3,4)
    let fhe_params = FheParameter::Test;
    let config_path_1234 = material_dir.path().join("client_config_1234.toml");
    let cores_1234: Vec<CoreConf> = (1..=4)
        .map(|i| {
            let server = servers.get(&(i as u32)).unwrap();
            let server_config_path = material_dir.path().join(format!("compose_{i}.toml"));
            CoreConf {
                party_id: i,
                address: format!("localhost:{}", server.service_port),
                s3_endpoint: format!("file://{}", material_dir.path().display()),
                object_folder: format!("PUB-p{i}"),
                private_object_folder: Some(format!("PRIV-p{i}")),
                config_path: Some(server_config_path),
            }
        })
        .collect();
    let cfg_1234 = CoreClientConfig {
        kms_type: KmsType::Threshold,
        cores: cores_1234,
        decryption_mode: Some(DecryptionMode::NoiseFloodSmall),
        num_majority: 2,
        num_reconstruct: 3,
        fhe_params: Some(fhe_params),
    };
    write_core_client_toml(&config_path_1234, &cfg_1234)?;

    // Generate CLI config for context 2 (servers 5,6,4,3 as parties 1,2,3,4)
    // Note: servers 3 and 4 swap roles compared to context 1
    let config_path_5634 = material_dir.path().join("client_config_5634.toml");

    // Map: MPC party_id -> (physical server_id, compose config path)
    // Party 1 -> Server 5, Party 2 -> Server 6, Party 3 -> Server 4 (swapped), Party 4 -> Server 3 (swapped)
    // Servers 3,4 use ctx2-specific compose configs with swapped roles and peers_ctx2
    let ctx2_cores: Vec<(usize, u32, PathBuf)> = vec![
        (1, 5, material_dir.path().join("compose_5.toml")),
        (2, 6, material_dir.path().join("compose_6.toml")),
        (3, 4, compose_4_ctx2_path.clone()), // server 4 as party 3
        (4, 3, compose_3_ctx2_path.clone()), // server 3 as party 4
    ];
    let cores_5634: Vec<CoreConf> = ctx2_cores
        .iter()
        .map(|(party_id, server_id, compose_path)| {
            let server = servers.get(server_id).unwrap();
            CoreConf {
                party_id: *party_id,
                address: format!("localhost:{}", server.service_port),
                s3_endpoint: format!("file://{}", material_dir.path().display()),
                object_folder: format!("PUB-p{server_id}"),
                private_object_folder: Some(format!("PRIV-p{server_id}")),
                config_path: Some(compose_path.clone()),
            }
        })
        .collect();
    let cfg_5634 = CoreClientConfig {
        kms_type: KmsType::Threshold,
        cores: cores_5634,
        decryption_mode: Some(DecryptionMode::NoiseFloodSmall),
        num_majority: 2,
        num_reconstruct: 3,
        fhe_params: Some(fhe_params),
    };
    write_core_client_toml(&config_path_5634, &cfg_5634)?;

    Ok((material_dir, servers, config_path_1234, config_path_5634))
}

// ============================================================================
// TEST UTILITIES
// ============================================================================

/// Execute a CLI command and extract the single request ID from the result.
async fn run_cmd(config: &CmdConfig, test_path: &Path, label: &str) -> Result<RequestId> {
    info!("Doing {label}");
    let results = execute_cmd(config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do {label}: {e}"))?;
    info!("{label} done");
    assert_eq!(results.len(), 1, "{label}: expected 1 result");
    match results.first().unwrap() {
        (Some(id), _) => Ok(*id),
        _ => panic!("{label}: missing request ID in result"),
    }
}

/// Build a `CmdConfig` with common defaults.
fn cmd_config(config_path: &Path, command: CCCommand, max_iter: usize) -> CmdConfig {
    CmdConfig {
        file_conf: Some(vec![config_path.to_str().unwrap().to_string()]),
        command,
        logs: true,
        max_iter,
        expect_all_responses: true,
        download_all: false,
    }
}

/// Build a `CipherParameters` with sensible defaults, overriding only what varies per test case.
#[allow(clippy::too_many_arguments)]
fn cipher_params(
    to_encrypt: &str,
    data_type: FheType,
    key_id: KeyId,
    batch_size: usize,
    no_compression: bool,
    no_precompute_sns: bool,
    compressed_keys: bool,
    ciphertext_output_path: Option<PathBuf>,
) -> CipherParameters {
    CipherParameters {
        to_encrypt: to_encrypt.to_string(),
        data_type,
        no_compression,
        no_precompute_sns,
        key_id,
        context_id: None,
        epoch_id: None,
        batch_size,
        num_requests: 1,
        parallel_requests: 1,
        ciphertext_output_path,
        inter_request_delay_ms: 0,
        compressed_keys,
        extra_data: None,
    }
}

/// Helper to run insecure key generation via CLI (isolated version)
async fn insecure_key_gen(
    config_path: &Path,
    test_path: &Path,
    compressed: bool,
) -> Result<String> {
    let config = cmd_config(
        config_path,
        CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters {
                compressed,
                ..Default::default()
            },
        }),
        200,
    );
    let id = run_cmd(&config, test_path, "insecure key-gen").await?;
    Ok(id.to_string())
}

// ============================================================================
// CLI COMMAND HELPERS
// ============================================================================

/// Helper to run CRS generation via CLI (isolated version)
async fn crs_gen(config_path: &Path, test_path: &Path, insecure_crs_gen: bool) -> Result<String> {
    crs_gen_with_params(
        config_path,
        test_path,
        insecure_crs_gen,
        2048,
        200,
        *DEFAULT_EPOCH_ID,
        *DEFAULT_MPC_CONTEXT,
    )
    .await
}

/// CRS generation with configurable max_num_bits and max_iter.
/// Default-param tests need max_num_bits=2048 and higher max_iter for production-sized ZK ceremonies.
async fn crs_gen_with_params(
    config_path: &Path,
    test_path: &Path,
    insecure_crs_gen: bool,
    max_num_bits: u32,
    max_iter: usize,
    epoch_id: EpochId,
    context_id: ContextId,
) -> Result<String> {
    let crs_params = CrsParameters {
        max_num_bits,
        epoch_id: Some(epoch_id),
        context_id: Some(context_id),
        extra_data: None,
    };
    let command = if insecure_crs_gen {
        CCCommand::InsecureCrsGen(crs_params)
    } else {
        CCCommand::CrsGen(crs_params)
    };

    let config = cmd_config(config_path, command, max_iter);
    let id = run_cmd(&config, test_path, "CRS generation").await?;
    Ok(id.to_string())
}

/// Helper to run integration test commands via CLI (isolated version)
///
/// Mirrors the Docker-based `integration_test_commands` in integration_test.rs:
/// - PublicDecrypt/UserDecrypt across ebool, euint8 (compressed/uncompressed), euint16, euint256
/// - Encrypt to file + PublicDecrypt/UserDecrypt from file
/// - SnS precompute variants (no_precompute_sns=false)
async fn integration_test_commands(
    config_path: &Path,
    keys_folder: &Path,
    key_id: String,
) -> Result<()> {
    let key_id = KeyId::from_str(&key_id)?;
    let ctxt_path = keys_folder.join("test_encrypt_cipher.txt");
    let ctxt_with_sns_path = keys_folder.join("test_encrypt_cipher_with_sns.txt");

    let cp = |val: &str, dt: FheType, bs: usize, no_comp: bool, no_sns: bool| {
        cipher_params(val, dt, key_id, bs, no_comp, no_sns, false, None)
    };

    // Commands without SnS precompute (no_precompute_sns=true)
    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x1",
            FheType::Ebool,
            1,
            false,
            true,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0x1",
            FheType::Ebool,
            1,
            false,
            true,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x6F",
            FheType::Euint8,
            3,
            true,
            true,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x6F",
            FheType::Euint8,
            3,
            false,
            true,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0xFFFF",
            FheType::Euint16,
            3,
            false,
            true,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x96BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592B",
            FheType::Euint256,
            3,
            false,
            true,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0xC958D835E4B1922CE9B13BAD322CF67D81CE14B95D225928E4E9B5305EC4592C",
            FheType::Euint256,
            3,
            false,
            true,
        ))),
        CCCommand::Encrypt(cipher_params(
            "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF0395689B5305EC4592D",
            FheType::Euint256,
            key_id,
            1,
            false,
            true,
            false,
            Some(ctxt_path.clone()),
        )),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.clone(),
            batch_size: 3,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
            extra_data: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.clone(),
            batch_size: 3,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
            extra_data: None,
        })),
    ];

    // Commands with SnS precompute (no_precompute_sns=false)
    let commands_for_sns_precompute = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x1",
            FheType::Ebool,
            2,
            true,
            false,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0x78",
            FheType::Euint8,
            2,
            true,
            false,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0x1",
            FheType::Ebool,
            1,
            true,
            false,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x6F",
            FheType::Euint8,
            3,
            true,
            false,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F7820",
            FheType::Euint256,
            3,
            true,
            false,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0xC9BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592F",
            FheType::Euint256,
            3,
            true,
            false,
        ))),
        CCCommand::Encrypt(cipher_params(
            "0xC958D835E4B1922CE9B13CA037D537E521CE14B95D225928E4E9B5305EC4592E",
            FheType::Euint256,
            key_id,
            1,
            true,
            false,
            false,
            Some(ctxt_with_sns_path.clone()),
        )),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.clone(),
            batch_size: 3,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
            extra_data: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.clone(),
            batch_size: 3,
            num_requests: 3,
            parallel_requests: 1,
            inter_request_delay_ms: 0,
            extra_data: None,
        })),
    ];

    let all_commands = [commands, commands_for_sns_precompute].concat();

    for command in all_commands {
        let config = cmd_config(config_path, command.clone(), 500);

        let results = execute_cmd(&config, keys_folder)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        // Validate result count matches expected requests
        match &command {
            CCCommand::PublicDecrypt(cipher_arguments)
            | CCCommand::UserDecrypt(cipher_arguments) => {
                let num_expected_results = cipher_arguments.get_num_requests();
                assert_eq!(results.len(), num_expected_results);
            }
            _ => {}
        }

        // Also test the get result commands
        let req_id = results[0].0;

        let get_res_command = match command {
            CCCommand::PreprocKeyGen(_) => CCCommand::PreprocKeyGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::KeyGen(ref key_gen_parameters) => {
                CCCommand::KeyGenResult(KeyGenResultParameters {
                    request_id: req_id.unwrap(),
                    compressed: key_gen_parameters.shared_args.compressed,
                })
            }
            CCCommand::InsecureKeyGen(ref key_gen_parameters) => {
                CCCommand::InsecureKeyGenResult(KeyGenResultParameters {
                    request_id: req_id.unwrap(),
                    compressed: key_gen_parameters.shared_args.compressed,
                })
            }
            CCCommand::PublicDecrypt(_) => CCCommand::PublicDecryptResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::CrsGen(_) => CCCommand::CrsGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::InsecureCrsGen(_) => CCCommand::InsecureCrsGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            _ => CCCommand::DoNothing(NoParameters {}),
        };

        let expect_result = !matches!(&get_res_command, CCCommand::DoNothing(_));

        if expect_result {
            let config = cmd_config(config_path, get_res_command, 500);

            let mut results_bis = execute_cmd(&config, keys_folder)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            assert_eq!(results_bis.len(), 1);
            let (sid_bis, result_bis) = results_bis.remove(0);

            for (sid, result) in results {
                if sid_bis == sid {
                    assert_eq!(result_bis, result);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

/// Run a subset of integration test commands using compressed keys.
///
/// Compressed keys only store `CompressedXofKeySet` (no separate `PublicKey`/`ServerKey`),
/// so all commands must use `no_compression: false` to fetch the compressed keyset.
async fn integration_test_commands_compressed(
    config_path: &Path,
    keys_folder: &Path,
    key_id: String,
) -> Result<()> {
    let key_id = KeyId::from_str(&key_id)?;

    let cp = |val: &str, dt: FheType, bs: usize, no_sns: bool| {
        cipher_params(val, dt, key_id, bs, false, no_sns, true, None)
    };

    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x1",
            FheType::Ebool,
            2,
            true,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0x78",
            FheType::Euint8,
            2,
            true,
        ))),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(cp(
            "0x6F",
            FheType::Euint8,
            3,
            false,
        ))),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(cp(
            "0xC958D835E4B1922CE9B13BAD322CF67D81CE14B95D225928E4E9B5305EC4592C",
            FheType::Euint256,
            3,
            false,
        ))),
    ];

    for command in commands {
        let config = cmd_config(config_path, command.clone(), 500);

        let results = execute_cmd(&config, keys_folder)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        match &command {
            CCCommand::PublicDecrypt(cipher_arguments)
            | CCCommand::UserDecrypt(cipher_arguments) => {
                let num_expected_results = cipher_arguments.get_num_requests();
                assert_eq!(results.len(), num_expected_results);
            }
            _ => {}
        }

        // Also test the get result commands
        let req_id = results[0].0;

        let get_res_command = match command {
            CCCommand::PublicDecrypt(_) => CCCommand::PublicDecryptResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            _ => CCCommand::DoNothing(NoParameters {}),
        };

        let expect_result = !matches!(&get_res_command, CCCommand::DoNothing(_));

        if expect_result {
            let config = cmd_config(config_path, get_res_command, 500);

            let mut results_bis = execute_cmd(&config, keys_folder)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            assert_eq!(results_bis.len(), 1);
            let (sid_bis, result_bis) = results_bis.remove(0);

            for (sid, result) in results {
                if sid_bis == sid {
                    assert_eq!(result_bis, result);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }

    Ok(())
}

/// Helper to run backup restore via CLI (isolated version)
async fn restore_from_backup(config_path: &Path, test_path: &Path) -> Result<()> {
    let config = cmd_config(config_path, CCCommand::BackupRestore(NoParameters {}), 200);

    info!("Doing restore from backup");
    let restore_results = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    info!("Restore from backup done");

    assert_eq!(restore_results.len(), 1);
    assert_eq!(restore_results.first().unwrap().0, None);

    Ok(())
}

/// Helper to run preprocessing and keygen via CLI (isolated version)
/// Only used by PRSS tests which are gated by threshold_tests feature
#[cfg(feature = "threshold_tests")]
async fn real_preproc_and_keygen(
    config_path: &Path,
    test_path: &Path,
    max_iter: usize,
    compressed: bool,
) -> Result<String> {
    let preproc_config = cmd_config(
        config_path,
        CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id: None,
            epoch_id: None,
            compressed,
            from_existing_shares: false,
        }),
        max_iter,
    );

    let t0 = std::time::Instant::now();
    let preproc_id = run_cmd(&preproc_config, test_path, "preprocessing").await?;
    info!(
        "Preprocessing done with ID {preproc_id:?} (elapsed: {:.1}s)",
        t0.elapsed().as_secs_f64()
    );

    let keygen_config = cmd_config(
        config_path,
        CCCommand::KeyGen(KeyGenParameters {
            preproc_id,
            shared_args: SharedKeyGenParameters {
                compressed,
                ..Default::default()
            },
        }),
        max_iter,
    );

    let t1 = std::time::Instant::now();
    let key_id = run_cmd(&keygen_config, test_path, "key-gen").await?;
    info!("Key-gen done (elapsed: {:.1}s)", t1.elapsed().as_secs_f64());

    Ok(key_id.to_string())
}

/// Helper to run partial preprocessing and keygen via CLI (isolated version)
///
/// Uses `PartialPreprocKeyGen` with reduced offline generation to keep runtime
/// manageable for Default FHE parameters in CI while still exercising the
/// keygen flow.
#[cfg(feature = "threshold_tests")]
async fn real_partial_preproc_and_keygen(
    config_path: &Path,
    test_path: &Path,
    percentage_offline: u32,
    max_iter: usize,
) -> Result<String> {
    let preproc_config = cmd_config(
        config_path,
        CCCommand::PartialPreprocKeyGen(PartialKeyGenPreprocParameters {
            context_id: None,
            epoch_id: None,
            percentage_offline,
            store_dummy_preprocessing: true,
        }),
        max_iter,
    );

    let t0 = std::time::Instant::now();
    let preproc_id = run_cmd(
        &preproc_config,
        test_path,
        &format!("partial preprocessing ({percentage_offline}%)"),
    )
    .await?;
    info!(
        "Partial preprocessing done with ID {preproc_id:?} (elapsed: {:.1}s)",
        t0.elapsed().as_secs_f64()
    );

    let keygen_config = cmd_config(
        config_path,
        CCCommand::KeyGen(KeyGenParameters {
            preproc_id,
            shared_args: SharedKeyGenParameters::default(),
        }),
        max_iter,
    );

    let t1 = std::time::Instant::now();
    let key_id = run_cmd(&keygen_config, test_path, "key-gen").await?;
    info!("Key-gen done (elapsed: {:.1}s)", t1.elapsed().as_secs_f64());

    Ok(key_id.to_string())
}

// ============================================================================
// MPC CONTEXT HELPER FUNCTIONS
// ============================================================================

/// Store MPC context to file for test
async fn store_mpc_context_in_file(
    context_path: &Path,
    config_path: &Path,
    context_id: ContextId,
) -> Result<()> {
    // Load the core client config from file
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    let context = create_test_context_info_from_core_config(context_id, &cc_conf).await?;

    info!("Storing context {:?} to file {:?}", context, context_path);

    let mut buf = Vec::new();
    safe_serialize(&context, &mut buf, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| anyhow::anyhow!("Failed to serialize context: {}", e))?;

    tokio::fs::write(context_path, buf).await?;
    Ok(())
}

/// Execute a CLI command and assert it returns exactly one result (ignoring the ID).
async fn run_cmd_no_id(config: &CmdConfig, test_path: &Path, label: &str) -> Result<()> {
    info!("Doing {label}");
    let results = execute_cmd(config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do {label}: {e}"))?;
    info!("{label} done");
    assert_eq!(results.len(), 1, "{label}: expected 1 result");
    Ok(())
}

/// Create new MPC context via CLI (isolated version)
async fn new_mpc_context(config_path: &Path, context_path: &Path, test_path: &Path) -> Result<()> {
    let config = cmd_config(
        config_path,
        CCCommand::NewMpcContext(NewMpcContextParameters::SerializedContextPath(
            ContextPath {
                input_path: context_path.to_path_buf(),
            },
        )),
        200,
    );
    run_cmd_no_id(&config, test_path, "new MPC context").await
}

/// Initialize PRSS for a context via CLI (isolated version)
async fn new_prss(
    config_path: &Path,
    context_id: ContextId,
    epoch_id: EpochId,
    test_path: &Path,
) -> Result<()> {
    let config = cmd_config(
        config_path,
        CCCommand::NewEpoch(NewEpochParameters {
            new_epoch_id: epoch_id,
            new_context_id: context_id,
            previous_epoch_params: None,
        }),
        200,
    );
    run_cmd_no_id(&config, test_path, "PRSS initialization").await
}

/// Helper to run preprocessing and keygen with context/epoch via CLI (isolated version).
/// Returns both key_id and preproc_id.
async fn real_preproc_and_keygen_with_context(
    config_path: &Path,
    test_path: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> Result<(String, String)> {
    let preproc_config = cmd_config(
        config_path,
        CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id,
            epoch_id,
            compressed: false,
            from_existing_shares: false,
        }),
        200,
    );

    let preproc_id = run_cmd(&preproc_config, test_path, "preprocessing with context").await?;

    let keygen_config = cmd_config(
        config_path,
        CCCommand::KeyGen(KeyGenParameters {
            preproc_id,
            shared_args: SharedKeyGenParameters {
                context_id,
                epoch_id,
                ..Default::default()
            },
        }),
        200,
    );

    let key_id = run_cmd(&keygen_config, test_path, "key-gen with context").await?;

    Ok((key_id.to_string(), preproc_id.to_string()))
}

/// Helper to run reshare operation via CLI (isolated version)
#[cfg(feature = "threshold_tests")]
#[allow(clippy::too_many_arguments)]
async fn reshare(
    config_path: &Path,
    test_path: &Path,
    from_context_id: Option<ContextId>,
    from_epoch_id: Option<EpochId>,
    new_epoch_id: EpochId,
    previous_key_infos: Vec<PreviousKeyInfo>,
    previous_crs_infos: Vec<PreviousCrsInfo>,
) -> Result<Vec<(Option<RequestId>, String)>> {
    let ctx_id = from_context_id.expect("context_id required for reshare");
    let ep_id = from_epoch_id.expect("epoch_id required for reshare");
    let config = cmd_config(
        config_path,
        CCCommand::NewEpoch(NewEpochParameters {
            new_epoch_id,
            new_context_id: ctx_id,
            previous_epoch_params: Some(PreviousEpochParameters {
                context_id: ctx_id,
                epoch_id: ep_id,
                previous_keys: previous_key_infos,
                previous_crs: previous_crs_infos,
            }),
        }),
        200,
    );

    info!("Doing resharing");
    let resharing_result = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to do resharing: {}", e))?;
    info!("Resharing done");

    Ok(resharing_result)
}

// ============================================================================
// CUSTODIAN HELPER FUNCTIONS
// ============================================================================

/// Native implementation: Create new custodian context using isolated config
async fn new_custodian_context(
    config_path: &Path,
    test_path: &Path,
    custodian_threshold: u32,
    setup_msg_paths: Vec<PathBuf>,
) -> String {
    let config = cmd_config(
        config_path,
        CCCommand::NewCustodianContext(NewCustodianContextParameters {
            threshold: custodian_threshold,
            setup_msg_paths,
            mpc_context_id: DEFAULT_MPC_CONTEXT.to_string(),
        }),
        200,
    );
    run_cmd(&config, test_path, "new custodian context")
        .await
        .unwrap()
        .to_string()
}

/// Native implementation: Generate custodian keys using kms-custodian binary directly
async fn generate_custodian_keys_to_file(
    temp_dir: &Path,
    amount_custodians: usize,
) -> (Vec<String>, Vec<PathBuf>) {
    let mut seeds = Vec::new();
    let mut setup_msgs_paths = Vec::new();

    // Find the kms-custodian binary
    let custodian_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("kms-custodian");

    assert!(
        custodian_bin.exists(),
        "kms-custodian binary not found at {:?}. Run: cargo build --bin kms-custodian",
        custodian_bin
    );

    for cus_idx in 1..=amount_custodians {
        let cur_setup_path = temp_dir
            .join("CUSTODIAN")
            .join("setup-msg")
            .join(format!("setup-{}", cus_idx));

        // Ensure the dir exists
        create_dir_all(cur_setup_path.parent().unwrap()).unwrap();

        // Call kms-custodian binary directly (no Docker)
        let args = [
            "generate",
            "--randomness",
            "123456",
            "--custodian-role",
            &cus_idx.to_string(),
            "--custodian-name",
            &format!("skynet-{cus_idx}"),
            "--path",
            cur_setup_path.to_str().unwrap(),
        ];

        let cmd_output = Command::new(&custodian_bin).args(args).output().unwrap();

        assert!(
            cmd_output.status.success(),
            "kms-custodian generate failed: {}",
            String::from_utf8_lossy(&cmd_output.stderr)
        );

        let seed_phrase = extract_seed_phrase(cmd_output);
        seeds.push(seed_phrase);
        setup_msgs_paths.push(cur_setup_path);
    }

    (seeds, setup_msgs_paths)
}

fn extract_seed_phrase(out: Output) -> String {
    let errors = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "Command did not execute successfully: {} : {}",
        out.status,
        errors
    );
    assert!(errors.is_empty());
    let output_string = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let seed_phrase_line = output_string
        .lines()
        .find(|line| line.contains(SEED_PHRASE_DESC));
    seed_phrase_line
        .unwrap()
        .split_at(SEED_PHRASE_DESC.len())
        .1
        .trim()
        .to_string()
}

/// Native implementation: Initialize custodian backup using isolated config
async fn custodian_backup_init(
    config_path: &Path,
    test_path: &Path,
    operator_recovery_resp_paths: Vec<PathBuf>,
) -> String {
    let config = cmd_config(
        config_path,
        CCCommand::CustodianRecoveryInit(RecoveryInitParameters {
            operator_recovery_resp_paths,
            overwrite_ephemeral_key: false,
        }),
        200,
    );
    run_cmd(&config, test_path, "backup init")
        .await
        .unwrap()
        .to_string()
}

/// Native implementation: Re-encrypt custodian backups using kms-custodian binary directly
async fn custodian_reencrypt(
    temp_dir: &Path,
    amount_operators: usize,
    amount_custodians: usize,
    backup_id: RequestId,
    mpc_context_id: ContextId,
    seeds: &[String],
    recovery_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut response_paths = Vec::new();

    // Find the kms-custodian binary
    let custodian_bin = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("kms-custodian");

    assert!(
        custodian_bin.exists(),
        "kms-custodian binary not found at {:?}",
        custodian_bin
    );

    for operator_index in 1..=amount_operators {
        let pub_prefix = if amount_operators == 1 {
            "PUB".to_string()
        } else {
            format!("PUB-p{}", operator_index)
        };

        let cur_recovery_path = &recovery_paths[operator_index - 1];

        for custodian_index in 1..=amount_custodians {
            let cur_response_path = temp_dir
                .join("CUSTODIAN")
                .join("response")
                .join(backup_id.to_string())
                .join(format!(
                    "recovery-response-{}-{}",
                    operator_index, custodian_index,
                ));

            create_dir_all(cur_response_path.parent().unwrap()).unwrap();

            let verf_path = temp_dir
                .join(&pub_prefix)
                .join(PubDataType::VerfKey.to_string())
                .join(SIGNING_KEY_ID.to_string());

            // Call kms-custodian binary directly (no Docker)
            let args = [
                "decrypt",
                "--seed-phrase",
                &seeds[custodian_index - 1],
                "--custodian-role",
                &custodian_index.to_string(),
                "--operator-verf-key",
                verf_path.to_str().unwrap(),
                "--mpc-context-id",
                &mpc_context_id.to_string(),
                "-b",
                cur_recovery_path.to_str().unwrap(),
                "-o",
                cur_response_path.to_str().unwrap(),
            ];

            let cmd_output = Command::new(&custodian_bin).args(args).output().unwrap();

            assert!(
                cmd_output.status.success(),
                "kms-custodian decrypt failed: {}",
                String::from_utf8_lossy(&cmd_output.stderr)
            );

            response_paths.push(cur_response_path);
        }
    }
    response_paths
}

/// Native implementation: Recover custodian backup using isolated config
async fn custodian_backup_recovery(
    config_path: &Path,
    test_path: &Path,
    custodian_recovery_outputs: Vec<PathBuf>,
    backup_id: RequestId,
) -> String {
    let config = cmd_config(
        config_path,
        CCCommand::CustodianBackupRecovery(RecoveryParameters {
            custodian_context_id: backup_id,
            custodian_recovery_outputs,
        }),
        200,
    );
    run_cmd(&config, test_path, "backup recovery")
        .await
        .unwrap()
        .to_string()
}

// ---------------------------------------------------------------------------
// Checked-in client config conformance (strict TOML schema + runtime loader)
// ---------------------------------------------------------------------------

/// Mirror of shipped client TOML layout: unknown top-level or `[[cores]]` keys fail the test.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictCheckedInCoreClientToml {
    kms_type: String,
    num_majority: usize,
    num_reconstruct: usize,
    decryption_mode: Option<String>,
    fhe_params: Option<String>,
    cores: Vec<StrictCheckedInCoreToml>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)] // Presence validated by deny_unknown_fields; only party_id asserted in tests
struct StrictCheckedInCoreToml {
    party_id: usize,
    address: String,
    s3_endpoint: String,
    object_folder: String,
    private_object_folder: Option<String>,
    config_path: Option<String>,
}

#[test]
fn config_conformance_client_local_centralized() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/client_local_centralized.toml");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let strict: StrictCheckedInCoreClientToml = toml::from_str(&raw).expect(
        "strict TOML parse of client_local_centralized.toml failed (unknown or extra keys?)",
    );
    assert_eq!(strict.kms_type, "centralized");
    assert_eq!(strict.num_majority, 1);
    assert_eq!(strict.num_reconstruct, 1);
    assert_eq!(strict.decryption_mode.as_deref(), Some("NoiseFloodSmall"));
    assert_eq!(strict.fhe_params.as_deref(), Some("Test"));
    assert_eq!(strict.cores.len(), 1);
    assert_eq!(strict.cores[0].party_id, 1);
    // Use an inert env_prefix so no stray CORE_CLIENT__* env vars can pollute
    // the load.  This avoids the need for unsafe env::remove_var and lets the
    // test run concurrently with other tests that read the environment.
    let loaded: CoreClientConfig = Settings::builder()
        .path(path.to_str().expect("utf8 path"))
        .env_prefix("_CONF_TEST_NOOP")
        .build()
        .init_conf()
        .expect("Settings::init_conf for client_local_centralized.toml");
    assert_eq!(loaded.kms_type, KmsType::Centralized);
    assert_eq!(loaded.cores.len(), 1);
    assert_eq!(loaded.fhe_params, Some(FheParameter::Test));
}

#[test]
fn config_conformance_client_local_threshold() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/client_local_threshold.toml");
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let strict: StrictCheckedInCoreClientToml = toml::from_str(&raw)
        .expect("strict TOML parse of client_local_threshold.toml failed (unknown or extra keys?)");
    assert_eq!(strict.kms_type, "threshold");
    assert_eq!(strict.num_majority, 2);
    assert_eq!(strict.num_reconstruct, 3);
    assert_eq!(strict.decryption_mode.as_deref(), Some("NoiseFloodSmall"));
    assert_eq!(strict.fhe_params.as_deref(), Some("Test"));
    assert_eq!(strict.cores.len(), 4);
    for (i, core) in strict.cores.iter().enumerate() {
        assert_eq!(core.party_id, i + 1);
    }
    // Use an inert env_prefix — see config_conformance_client_local_centralized.
    let loaded: CoreClientConfig = Settings::builder()
        .path(path.to_str().expect("utf8 path"))
        .env_prefix("_CONF_TEST_NOOP")
        .build()
        .init_conf()
        .expect("Settings::init_conf for client_local_threshold.toml");
    assert_eq!(loaded.kms_type, KmsType::Threshold);
    assert_eq!(loaded.cores.len(), 4);
    assert_eq!(loaded.fhe_params, Some(FheParameter::Test));
}

// ============================================================================
// TESTS
// ============================================================================

/// Test centralized insecure key generation via CLI
#[tokio::test]
async fn test_centralized_insecure() -> Result<()> {
    init_logging();

    // Setup isolated centralized KMS server
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test("centralized_insecure").await?;

    // Run CLI commands against native server (use material_dir as keys_folder so CLI can access server keys)
    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen(&config_path, keys_folder, false).await?;
    integration_test_commands(&config_path, keys_folder, key_id).await?;

    // Also test with compressed keys
    let compressed_key_id = insecure_key_gen(&config_path, keys_folder, true).await?;
    integration_test_commands_compressed(&config_path, keys_folder, compressed_key_id).await?;

    Ok(())
}

/// Test centralized insecure compressed key generation via CLI
///
/// Mirrors `test_centralized_insecure_compressed_keygen` in `integration_test.rs`.
/// Runs insecure key generation with `compressed=true` against a native in-process server.
#[tokio::test]
async fn test_centralized_insecure_compressed_keygen() -> Result<()> {
    init_logging();

    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test("centralized_insecure_compressed_keygen").await?;

    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen(&config_path, keys_folder, true).await?;
    assert!(!key_id.is_empty());

    Ok(())
}

/// Test centralized CRS generation via CLI
#[tokio::test]
async fn test_centralized_crsgen_secure() -> Result<()> {
    init_logging();

    // Setup isolated centralized KMS server
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test("centralized_crsgen").await?;

    // Run CRS generation via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let crs_id = crs_gen(&config_path, keys_folder, false).await?;

    // Verify CRS ID format (hex string with double the length of ID_LENGTH)
    assert_eq!(crs_id.len(), ID_LENGTH * 2);

    Ok(())
}

/// Test centralized restore from backup via CLI (without custodians)
///
/// Note: This test mainly validates the CLI endpoints and content returned from KMS.
/// Full restore validation is done in service/client tests.
#[tokio::test]
async fn test_centralized_restore_from_backup() -> Result<()> {
    init_logging();

    // Setup isolated centralized KMS server with backup vault
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test_with_backup("centralized_restore").await?;

    // Run insecure CRS generation and backup restore via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _crs_id = crs_gen(&config_path, keys_folder, true).await?;
    restore_from_backup(&config_path, keys_folder).await?;

    Ok(())
}

/// Test centralized custodian backup via CLI
#[tokio::test]
async fn test_centralized_custodian_backup() -> Result<()> {
    init_logging();

    let amount_custodians = 5;
    let custodian_threshold = 2;

    // Setup isolated centralized KMS server with custodian backup vault (includes SecretSharingKeychain)
    let (material_dir, _server, config_path) =
        setup_isolated_centralized_cli_test_with_custodian_backup("centralized_custodian").await?;

    let temp_path = material_dir.path();

    // Generate custodian keys using native kms-custodian binary
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians).await;

    // Create custodian context
    let cus_backup_id = new_custodian_context(
        &config_path,
        temp_path,
        custodian_threshold,
        setup_msg_paths,
    )
    .await;

    let operator_recovery_resp_path = temp_path
        .join("CUSTODIAN")
        .join("recovery")
        .join(&cus_backup_id)
        .join("central");

    // Ensure the dir exists
    create_dir_all(operator_recovery_resp_path.parent().unwrap())?;

    // Initialize custodian backup
    let init_backup_id = custodian_backup_init(
        &config_path,
        temp_path,
        vec![operator_recovery_resp_path.clone()],
    )
    .await;
    assert_eq!(cus_backup_id, init_backup_id);

    // Re-encrypt with custodian keys
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        1,
        amount_custodians,
        init_backup_id.parse()?,
        *DEFAULT_MPC_CONTEXT,
        &seeds,
        &[operator_recovery_resp_path],
    )
    .await;

    // Recover backup using custodian outputs
    let recovery_backup_id = custodian_backup_recovery(
        &config_path,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id)?,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);

    // Restore from backup
    restore_from_backup(&config_path, temp_path).await?;

    Ok(())
}

/// Test threshold insecure key generation via CLI (Default FHE params, with PRSS)
///
/// Requires pre-generated Default PRSS material in `test-material/default`.
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_insecure() -> Result<()> {
    init_logging();

    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss_default("threshold_insecure", 4).await?;

    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen(&config_path, keys_folder, false).await?;
    integration_test_commands(&config_path, keys_folder, key_id).await?;

    let compressed_key_id = insecure_key_gen(&config_path, keys_folder, true).await?;
    integration_test_commands_compressed(&config_path, keys_folder, compressed_key_id).await?;

    Ok(())
}

/// Nightly test - threshold sequential preprocessing and keygen with nightly parameters
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn nightly_tests_threshold_sequential_preproc_keygen() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties for test context) with PRSS enabled
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("nightly_preproc", 4).await?;

    // Run sequential preprocessing and keygen operations (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let key_id_1 = real_preproc_and_keygen(&config_path, keys_folder, 200, false).await?;
    let key_id_2 = real_preproc_and_keygen(&config_path, keys_folder, 200, false).await?;

    // Verify different key IDs generated
    assert_ne!(key_id_1, key_id_2);

    Ok(())
}

/// Test threshold concurrent preprocessing and keygen operations
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_concurrent_preproc_keygen() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties for test context) with PRSS enabled
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("concurrent_preproc", 4).await?;

    // Each concurrent execute_cmd needs its own keys_folder to avoid file races.
    // With file:// endpoints, concurrent fetches of VerfAddress race on the same
    // file (tokio::fs::write uses O_TRUNC, creating a window where the file is empty).
    // We copy the CLIENT directory (client signing keys) so the server can validate
    // the client's signature.
    let keys_folder_1 = tempfile::tempdir()?;
    let keys_folder_2 = tempfile::tempdir()?;
    copy_dir_recursive(
        &material_dir.path().join("CLIENT"),
        &keys_folder_1.path().join("CLIENT"),
    )?;
    copy_dir_recursive(
        &material_dir.path().join("CLIENT"),
        &keys_folder_2.path().join("CLIENT"),
    )?;
    let _ = join_all([
        real_preproc_and_keygen(&config_path, keys_folder_1.path(), 200, false),
        real_preproc_and_keygen(&config_path, keys_folder_2.path(), 200, false),
    ])
    .await;

    Ok(())
}

/// Test threshold sequential CRS generation via CLI with production-sized params
/// Uses max_num_bits=2048 and secure ZK ceremony (same as Docker-based version)
#[tokio::test]
async fn nightly_tests_threshold_sequential_crs() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("threshold_seq_crs", 4).await?;

    // Run sequential CRS generation with production-sized params (max_num_bits=2048)
    // Secure ZK ceremony with Default params can take ~17min per CRS gen
    let keys_folder = material_dir.path();
    let crs_id_1 = crs_gen_with_params(
        &config_path,
        keys_folder,
        false,
        2048,
        5000,
        *DEFAULT_EPOCH_ID,
        *DEFAULT_MPC_CONTEXT,
    )
    .await?;
    let crs_id_2 = crs_gen_with_params(
        &config_path,
        keys_folder,
        false,
        2048,
        5000,
        *DEFAULT_EPOCH_ID,
        *DEFAULT_MPC_CONTEXT,
    )
    .await?;

    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);

    Ok(())
}

/// Test threshold concurrent CRS generation via CLI with production-sized params
///
/// Uses insecure CRS generation because the multi-party ZK ceremony cannot handle
/// concurrent sessions — the first ceremony completes but subsequent ones get stuck
/// with networking timeouts between parties.
#[tokio::test]
async fn test_threshold_concurrent_crs() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("threshold_concurrent_crs", 4).await?;

    // Each concurrent execute_cmd needs its own keys_folder to avoid file races
    // (see test_threshold_concurrent_preproc_keygen for details).
    let keys_folder_1 = tempfile::tempdir()?;
    let keys_folder_2 = tempfile::tempdir()?;
    copy_dir_recursive(
        &material_dir.path().join("CLIENT"),
        &keys_folder_1.path().join("CLIENT"),
    )?;
    copy_dir_recursive(
        &material_dir.path().join("CLIENT"),
        &keys_folder_2.path().join("CLIENT"),
    )?;
    let res = join_all([
        crs_gen_with_params(
            &config_path,
            keys_folder_1.path(),
            true,
            2048,
            5000,
            *DEFAULT_EPOCH_ID,
            *DEFAULT_MPC_CONTEXT,
        ),
        crs_gen_with_params(
            &config_path,
            keys_folder_2.path(),
            true,
            2048,
            5000,
            *DEFAULT_EPOCH_ID,
            *DEFAULT_MPC_CONTEXT,
        ),
    ])
    .await;

    // Verify different CRS IDs generated
    assert_ne!(res[0].as_ref().unwrap(), res[1].as_ref().unwrap());

    Ok(())
}

/// Test threshold insecure compressed key generation via CLI (Test FHE params, with PRSS)
///
/// Mirrors `test_threshold_insecure_compressed_keygen` in integration_test.rs.
/// Validates that insecure keygen with `compressed=true` produces a valid key ID
/// on a threshold cluster using Test FHE parameters.
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_insecure_compressed_keygen() -> Result<()> {
    init_logging();

    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("threshold_insecure_compressed_keygen", 4)
            .await?;

    let keys_folder = material_dir.path();
    let key_id = insecure_key_gen(&config_path, keys_folder, true).await?;
    assert!(!key_id.is_empty());

    Ok(())
}

/// Test threshold preprocessing and keygen with compressed keys via CLI (Test FHE params, with PRSS)
///
/// Mirrors `test_threshold_compressed_preproc_keygen` in integration_test.rs.
/// Runs two sequential preproc+keygen cycles with `compressed=true` and asserts
/// that both produce distinct key IDs.
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_compressed_preproc_keygen() -> Result<()> {
    init_logging();

    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("threshold_compressed_preproc_keygen", 4)
            .await?;

    let keys_folder = material_dir.path();
    let key_id_1 = real_preproc_and_keygen(&config_path, keys_folder, 200, true).await?;
    let key_id_2 = real_preproc_and_keygen(&config_path, keys_folder, 200, true).await?;

    assert_ne!(key_id_1, key_id_2);

    Ok(())
}

/// Test threshold MPC context switch via CLI (4-party, Test FHE params, with PRSS)
///
/// Mirrors `test_threshold_mpc_context_switch` in integration_test.rs.
/// Validates that after switching to a new MPC context:
/// 1. Insecure keygen produces a key
/// 2. The context can be switched to a new context ID
/// 3. A public-decrypt request succeeds in the new context
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_mpc_context_switch() -> Result<()> {
    init_logging();

    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss("threshold_mpc_context_switch", 4).await?;

    let test_path = material_dir.path();
    let context_path = material_dir.path().join("mpc_context_switch.bin");

    // Generate a key in the current (default) context
    let key_id = insecure_key_gen(&config_path, test_path, false).await?;

    // Create and store a new MPC context
    let context_id = derive_request_id("CONTEXT_ID")?.into();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await?;

    // Perform the context switch
    new_mpc_context(&config_path, &context_path, test_path).await?;

    // Verify that a public-decrypt request succeeds in the new context
    let mut params = cipher_params(
        "0x1",
        FheType::Ebool,
        KeyId::from_str(&key_id)?,
        1,
        false,
        true,
        false,
        None,
    );
    params.context_id = Some(context_id);
    let ddec_config = cmd_config(
        &config_path,
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(params)),
        200,
    );
    let results = execute_cmd(&ddec_config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    assert_eq!(results.len(), 1);

    Ok(())
}

/// Test threshold restore from backup via CLI (without custodians)
///
/// Note: This test mainly validates the CLI endpoints and content returned from KMS.
/// Full restore validation is done in service/client tests.
#[tokio::test]
async fn test_threshold_restore_from_backup() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties) with backup vaults
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_backup("threshold_restore", 4).await?;

    // Run insecure CRS generation and backup restore via CLI (use material_dir as keys_folder)
    let keys_folder = material_dir.path();
    let _crs_id = crs_gen(&config_path, keys_folder, true).await?;
    restore_from_backup(&config_path, keys_folder).await?;

    Ok(())
}

/// Test threshold custodian backup via CLI
#[tokio::test]
async fn test_threshold_custodian_backup() -> Result<()> {
    init_logging();

    let amount_custodians = 5;
    let custodian_threshold = 2;
    let amount_operators = 4;

    // Setup isolated threshold KMS servers with custodian backup vaults (includes SecretSharingKeychain)
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_custodian_backup(
            "threshold_custodian",
            amount_operators,
        )
        .await?;

    let temp_path = material_dir.path();

    // Generate custodian keys using native kms-custodian binary
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians).await;

    // Create custodian context
    let cus_backup_id = new_custodian_context(
        &config_path,
        temp_path,
        custodian_threshold,
        setup_msg_paths,
    )
    .await;
    // Paths to where the results of the backup init will be stored
    let mut operator_recovery_resp_paths = Vec::new();
    for cur_op_idx in 1..=amount_operators {
        let cur_resp_path = temp_path
            .join("CUSTODIAN")
            .join("recovery")
            .join(&cus_backup_id)
            .join(cur_op_idx.to_string());
        // Ensure the dir exists locally
        assert!(create_dir_all(cur_resp_path.parent().unwrap()).is_ok());
        operator_recovery_resp_paths.push(cur_resp_path);
    }

    // Initialize custodian backup
    let init_backup_id = custodian_backup_init(
        &config_path,
        temp_path,
        operator_recovery_resp_paths.clone(),
    )
    .await;
    assert_eq!(cus_backup_id, init_backup_id);

    // Re-encrypt with custodian keys
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        amount_operators,
        amount_custodians,
        init_backup_id.parse()?,
        *DEFAULT_MPC_CONTEXT,
        &seeds,
        &operator_recovery_resp_paths,
    )
    .await;

    // Recover backup using custodian outputs
    let recovery_backup_id = custodian_backup_recovery(
        &config_path,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id)?,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);

    // Restore from backup
    restore_from_backup(&config_path, temp_path).await?;

    Ok(())
}

/// Full generation test - threshold sequential preprocessing and keygen with Default params.
///
/// Requires pre-generated material in the test-material/default directory
/// (produced by `generate-test-material --features slow_tests -- default`):
/// - **PRSS**: loaded at server startup (`ensure_default_prss=true`); fast to generate but must exist before the test runs.
/// - **Keygen preprocessing** (offline DKG phase): run live by this test; takes hours with Default params.
///
/// Uses partial preprocessing to keep this test comfortably below CI timeout
/// while still validating Default-parameter preproc+keygen end-to-end.
/// Single round only: two rounds with Default params take ~4-6h, exceeding the 2h CI timeout.
/// The Test-param variant (`nightly_tests_threshold_sequential_preproc_keygen`) covers
/// sequential 2-round behavior.
///
// Extremely heavy test — requires dedicated infra with pre-generated Default-param
// PRSS material and multi-hour runtime budget. Do NOT run in regular CI or local dev.
// Only execute when a fully prepared full-generation environment is available.
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
#[ignore]
async fn nightly_full_gen_tests_default_threshold_sequential_preproc_keygen() -> Result<()> {
    init_logging();

    // Tuned for CI runtime budget with buffer.
    const PARTIAL_PREPROC_PERCENTAGE_OFFLINE: u32 = 1;

    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_with_prss_default("full_gen_preproc", 4).await?;

    let keys_folder = material_dir.path();
    let t0 = std::time::Instant::now();
    let key_id_1 = real_partial_preproc_and_keygen(
        &config_path,
        keys_folder,
        PARTIAL_PREPROC_PERCENTAGE_OFFLINE,
        200,
    )
    .await?;
    let key_id_2 = real_partial_preproc_and_keygen(
        &config_path,
        keys_folder,
        PARTIAL_PREPROC_PERCENTAGE_OFFLINE,
        200,
    )
    .await?;
    info!(
        "nightly_full_gen_tests_default_threshold_sequential_preproc_keygen (partial={}%) completed in {:.1}s",
        PARTIAL_PREPROC_PERCENTAGE_OFFLINE,
        t0.elapsed().as_secs_f64(),
    );
    assert_ne!(key_id_1, key_id_2);

    Ok(())
}

/// Full generation test - threshold sequential CRS generation with production-sized params
/// Uses max_num_bits=2048 and secure ZK ceremony (same as Docker-based version)
#[tokio::test]
async fn nightly_full_gen_tests_default_threshold_sequential_crs() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties for default context) with Default FHE params
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_default("full_gen_crs", 4).await?;

    // Run sequential CRS generation with production-sized params (max_num_bits=2048)
    // Secure ZK ceremony with Default params can take ~17min per CRS gen
    let keys_folder = material_dir.path();
    let crs_id_1 = crs_gen_with_params(
        &config_path,
        keys_folder,
        false,
        2048,
        5000,
        *DEFAULT_EPOCH_ID,
        *DEFAULT_MPC_CONTEXT,
    )
    .await?;
    let crs_id_2 = crs_gen_with_params(
        &config_path,
        keys_folder,
        false,
        2048,
        5000,
        *DEFAULT_EPOCH_ID,
        *DEFAULT_MPC_CONTEXT,
    )
    .await?;

    // Verify different CRS IDs generated
    assert_ne!(crs_id_1, crs_id_2);

    Ok(())
}

/// Test threshold MPC context initialization and PRSS setup
///
/// This test verifies the complete MPC context lifecycle:
/// 1. Create and store MPC context to file
/// 2. Initialize new MPC context in KMS servers
/// 3. Initialize PRSS for the context
/// 4. Run preprocessing and keygen using the context and PRSS
///
/// Note: This test starts from uninitialized threshold KMS servers (no PRSS or context)
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "threshold_tests"), ignore)]
async fn test_threshold_mpc_context_init() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties) WITHOUT PRSS initialization
    // This simulates servers that need context and PRSS setup
    // Note: 4 parties required to satisfy MPC context validation formula n = 3t + 1 (with t=1)
    // Uses signing_only spec to avoid pre-loaded PRSS conflicting with NewEpoch calls
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_signing_only("threshold_mpc_context_init", 4).await?;

    let test_path = material_dir.path();
    let context_path = material_dir.path().join("mpc_context.bin");

    // Step 1: Create and store MPC context to file
    let context_id = derive_request_id("CONTEXT_ID")?.into();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await?;

    // Step 2: Initialize the new MPC context in KMS servers
    new_mpc_context(&config_path, &context_path, test_path).await?;

    // Step 3: Initialize PRSS for this context
    let epoch_id = derive_request_id("EPOCH_ID")?.into();
    new_prss(&config_path, context_id, epoch_id, test_path).await?;

    // Step 4: Run preprocessing and keygen using the context and PRSS
    let (_key_id, _preproc_id) = real_preproc_and_keygen_with_context(
        &config_path,
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await?;

    info!("MPC context initialization test completed successfully");
    Ok(())
}

/// Test 6-party MPC context switching with party resharing (ISOLATED, NO TLS)
///
/// **NOTE:** This is the isolated test version WITHOUT TLS for fast execution.
/// For TLS-enabled threshold coverage, use Kind tests in
/// `tests/kind-testing/kubernetes_test_threshold.rs`.
///
/// This test validates party resharing/remapping across MPC contexts:
/// - First context: Physical servers 1,2,3,4 act as MPC parties 1,2,3,4
/// - Second context: Physical servers 5,6,4,3 act as MPC parties 1,2,3,4
/// - Servers 3 and 4 participate in BOTH contexts with SWAPPED roles (continuity + role change)
/// - Servers 5 and 6 REPLACE servers 1 and 2 in the second context
///
/// This test replicates party resharing scenario, which is critical for:
/// - Disaster recovery (replacing failed servers)
/// - Key rotation (changing physical server composition)
/// - Dynamic party management in production
///
/// **Architecture:**
/// - 6 physical servers total, each MPC context uses 4 parties (threshold=1)
/// - Servers 1-4 configured with peers [1,2,3,4]
/// - Servers 5,6,4,3 configured with peers [5,6,4,3] where 5→party1, 6→party2, 4→party3, 3→party4
///
/// **TLS Status:** Disabled (isolated test, localhost only)
/// **For TLS testing:** use `tests/kind-testing/kubernetes_test_threshold.rs`.
#[tokio::test]
#[serial] // PRSS requires sequential execution
#[cfg_attr(not(feature = "threshold_tests"), ignore)]
async fn test_threshold_mpc_context_switch_6() -> Result<()> {
    init_logging();

    // Setup 6 servers with per-server peer configuration for party resharing
    let (material_dir, servers, config_path_1234, config_path_5634) =
        setup_party_resharing_servers("threshold_context_switch_6").await?;

    let test_path = material_dir.path();

    // === CONTEXT 1: Servers 1,2,3,4 as parties 1,2,3,4 ===
    info!("========== CONTEXT 1 ==========");
    info!("Creating first context with servers [1, 2, 3, 4] as parties [1, 2, 3, 4]");

    let context_1_id = derive_request_id("CONTEXT_6P_SET_1")?.into();
    let epoch_1_id = derive_request_id("EPOCH_6P_SET_1")?.into();
    let context_1_path = material_dir.path().join("mpc_context_1.bin");

    store_mpc_context_in_file(&context_1_path, &config_path_1234, context_1_id).await?;
    new_mpc_context(&config_path_1234, &context_1_path, test_path).await?;
    new_prss(&config_path_1234, context_1_id, epoch_1_id, test_path).await?;

    // Generate key in context 1
    let (key_1_id, _) = real_preproc_and_keygen_with_context(
        &config_path_1234,
        test_path,
        Some(context_1_id),
        Some(epoch_1_id),
    )
    .await?;
    info!(
        "✅ Context 1 (servers 1,2,3,4): Key generated: {}",
        key_1_id
    );

    // === CONTEXT 2: Servers 5,6,4,3 as parties 1,2,3,4 (party resharing + role swap) ===
    info!("========== CONTEXT 2 (PARTY RESHARING) ==========");
    info!("Creating second context with servers [5, 6, 4, 3] as parties [1, 2, 3, 4]");
    info!("Note: Servers 5,6 REPLACE servers 1,2; servers 3,4 SWAP roles in this context");

    let context_2_id = derive_request_id("CONTEXT_6P_SET_2")?.into();
    let epoch_2_id = derive_request_id("EPOCH_6P_SET_2")?.into();
    let context_2_path = material_dir.path().join("mpc_context_2.bin");

    store_mpc_context_in_file(&context_2_path, &config_path_5634, context_2_id).await?;
    new_mpc_context(&config_path_5634, &context_2_path, test_path).await?;
    new_prss(&config_path_5634, context_2_id, epoch_2_id, test_path).await?;

    // Generate key in context 2 (with reshared parties)
    let (key_2_id, _) = real_preproc_and_keygen_with_context(
        &config_path_5634,
        test_path,
        Some(context_2_id),
        Some(epoch_2_id),
    )
    .await?;
    info!(
        "✅ Context 2 (servers 5,6,4,3): Key generated: {}",
        key_2_id
    );

    // === SWITCH BACK TO CONTEXT 1 ===
    info!("========== SWITCH BACK TO CONTEXT 1 ==========");
    info!("Switching back to context 1 (servers 1,2,3,4)");

    let (key_1b_id, _) = real_preproc_and_keygen_with_context(
        &config_path_1234,
        test_path,
        Some(context_1_id),
        Some(epoch_1_id),
    )
    .await?;
    info!("✅ Context 1 (switched back): Key generated: {}", key_1b_id);

    // === VALIDATION ===
    info!("========== VALIDATION ==========");
    assert_ne!(context_1_id, context_2_id, "Context IDs must be different");
    assert_ne!(
        key_1_id, key_2_id,
        "Keys from different contexts must be different"
    );
    assert_ne!(
        key_1_id, key_1b_id,
        "Different keys in same context must be different"
    );
    assert_ne!(
        key_2_id, key_1b_id,
        "Keys from different contexts must be different"
    );

    info!("✅ Party resharing validated:");
    info!("   - Context 1: servers 1,2,3,4 as parties 1,2,3,4");
    info!(
        "   - Context 2: servers 5,6,4,3 as parties 1,2,3,4 (5,6 replaced 1,2; 3↔4 swapped roles)"
    );
    info!("   - Servers 3,4 participated in BOTH contexts with DIFFERENT party roles");
    info!("   - All 3 keys are unique and isolated");
    info!("✅ 6-party MPC context switch with party resharing test completed successfully");

    // Cleanup: drop servers explicitly
    drop(servers);

    Ok(())
}

/// Test threshold reshare operation via CLI (isolated version)
///
/// This test validates the resharing workflow:
/// 1. Create and initialize MPC context
/// 2. Initialize PRSS for the context
/// 3. Run preprocessing and keygen with the context
/// 4. Download key materials (ServerKey, PublicKey)
/// 5. Run Crs generation
/// 6. Compute digests of the key materials
/// 7. Execute resharing command
#[cfg(feature = "threshold_tests")]
#[tokio::test]
#[serial]
async fn test_threshold_reshare() -> Result<()> {
    init_logging();

    // Setup isolated threshold KMS servers (4 parties) WITHOUT PRSS initialization
    // This simulates servers that need context and PRSS setup
    // Uses signing_only spec to avoid pre-loaded PRSS conflicting with NewEpoch calls
    let (material_dir, _servers, config_path) =
        setup_isolated_threshold_cli_test_signing_only("threshold_reshare", 4).await?;

    let test_path = material_dir.path();
    let context_path = material_dir.path().join("mpc_context.bin");

    // Step 1: Create and store MPC context to file
    let context_id = derive_request_id("CONTEXT_ID_RESHARE")?.into();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await?;

    // Step 2: Initialize the new MPC context in KMS servers
    new_mpc_context(&config_path, &context_path, test_path).await?;

    // Step 3: Initialize PRSS for this context
    let epoch_id = derive_request_id("EPOCH__ID_RESHARE")?.into();
    new_prss(&config_path, context_id, epoch_id, test_path).await?;

    // Step 4: Run preprocessing and keygen with the context (get both key_id and preproc_id)
    let (key_id_str, preproc_id_str) = real_preproc_and_keygen_with_context(
        &config_path,
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await?;

    // Step 5 : Run Crs generation
    let crs_id = crs_gen_with_params(
        &config_path,
        test_path,
        true,
        2048,
        5000,
        epoch_id,
        context_id,
    )
    .await?;

    // Step 6: Download the key materials
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()?;

    let ids = fetch_public_elements(
        &key_id_str,
        &[PubDataType::ServerKey, PubDataType::PublicKey],
        &cc_conf,
        test_path,
        false,
    )
    .await?;

    // Step 7: Read the key and crs materials from file and compute digests
    let key_id = RequestId::from_str(&key_id_str)?;
    // Use first party's storage prefix for reading materials
    let storage_prefix = format!("PUB-p{}", ids[0].party_id);
    let public_key =
        load_pk_from_pub_storage(Some(test_path), &key_id, Some(&storage_prefix)).await;
    let server_key: tfhe::ServerKey = load_material_from_pub_storage(
        Some(test_path),
        &key_id,
        PubDataType::ServerKey,
        Some(&storage_prefix),
    )
    .await;

    let server_key_digest = hex::encode(safe_serialize_hash_element_versioned(
        &DSEP_PUBDATA_KEY,
        &server_key,
    )?);
    let public_key_digest = hex::encode(safe_serialize_hash_element_versioned(
        &DSEP_PUBDATA_KEY,
        &public_key,
    )?);

    let _ids =
        fetch_public_elements(&crs_id, &[PubDataType::CRS], &cc_conf, test_path, false).await?;

    let crs_id = RequestId::from_str(&crs_id)?;
    let crs: CompactPkeCrs = load_material_from_pub_storage(
        Some(test_path),
        &crs_id,
        PubDataType::CRS,
        Some(&storage_prefix),
    )
    .await;

    let crs_digest = hex::encode(safe_serialize_hash_element_versioned(
        &DSEP_PUBDATA_CRS,
        &crs,
    )?);

    // Step 8: Execute resharing (must use a NEW epoch ID, different from the one created in Step 3)
    let new_epoch_id = derive_request_id("EPOCH_RESHARE_NEW")?.into();
    let preproc_id = RequestId::from_str(&preproc_id_str)?;
    let previous_key_info = PreviousKeyInfo {
        key_id: key_id.into(),
        preproc_id,
        key_digest: DigestKeySet::NonCompressedKeySet(server_key_digest, public_key_digest),
    };
    let previous_crs_info = PreviousCrsInfo {
        crs_id,
        digest: crs_digest,
    };
    let resharing_result = reshare(
        &config_path,
        test_path,
        Some(context_id),
        Some(epoch_id),
        new_epoch_id,
        vec![previous_key_info],
        vec![previous_crs_info],
    )
    .await?;

    info!("Resharing result: {:?}", resharing_result);
    assert_eq!(resharing_result.len(), 2);

    // The second element is the previous epoch_id used for reshare
    assert_eq!(resharing_result[1].0.unwrap(), epoch_id.into());

    info!("✅ Threshold reshare test completed successfully");
    Ok(())
}
